"""Hermetic safety checks for the isolated simulator Docker gate."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import policy
import pytest


def _root() -> Path | None:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "sim.sources.lock.json").exists():
            return candidate
    return None


def _lock() -> dict:
    root = _root()
    if root is not None:
        return json.loads((root / "sim.sources.lock.json").read_text(encoding="utf-8"))
    # The final image contains only this narrow test directory.  The complete
    # manifest was verified before image creation; the runtime fixture retains
    # the execution revision marker so policy mutations stay hermetic here.
    revision = (
        Path(__file__)
        .with_name("execution-revision.txt")
        .read_text(encoding="ascii")
        .strip()
    )
    return {
        "schema_version": 1,
        "purpose": "isolated-market-data-simulator",
        "classification": "SIMULATED",
        "readiness": {
            "paper_qualified": False,
            "alpha_ready": False,
            "live_ready": False,
            "strategy_policy": "REJECT_ALL",
        },
        "build": {"python": "3.11.15", "uv": "0.12.3"},
        "dependencies": {
            "kairos-core": {
                "repository": "https://github.com/Kairos-cryptoAI/kairos-core",
                "revision": "0" * 40,
            },
            "kairos-persistence": {
                "repository": "https://github.com/Kairos-cryptoAI/kairos-persistence",
                "revision": "1" * 40,
            },
            "kairos-execution-engine": {
                "repository": policy.EXECUTION_REPOSITORY,
                "revision": revision,
            },
        },
        "infrastructure": {
            "timescaledb": policy.TIMESCALE_IMAGE,
            "redis": policy.REDIS_IMAGE,
        },
        "gate": {
            "project": policy.PROJECT,
            "database": policy.DATABASE,
            "confirmation": policy.CONFIRMATION,
        },
    }


def _compose() -> dict:
    return json.loads(
        Path(__file__).with_name("compose.fixture.json").read_text(encoding="utf-8")
    )


def _environment() -> dict[str, str]:
    return {
        "KAIROS_SIM_GATE_CONFIRM": policy.CONFIRMATION,
        "KAIROS_SIM_GATE_PROJECT": policy.PROJECT,
        "KAIROS_SIM_CONTROLLER_DATABASE_URL": policy.DATABASE_URL,
    }


def test_manifest_and_dockerfile_pin_the_same_execution_revision() -> None:
    root = _root()
    if root is None:
        revision = (
            Path(__file__)
            .with_name("execution-revision.txt")
            .read_text(encoding="ascii")
            .strip()
        )
        assert policy.SHA256.fullmatch(revision)
        assert f"git fetch --depth=1 origin {revision}" in Path("Dockerfile").read_text(
            encoding="utf-8"
        )
        return
    lock = _lock()
    assert policy.validate_source_lock(lock) == []
    dockerfile = (root / "tests" / "sim_gate" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    assert policy.validate_dockerfile(dockerfile, lock) == []


def test_exact_isolated_model_is_accepted() -> None:
    assert policy.validate_compose(_compose(), _lock()) == []
    policy.validate_environment(_environment())
    policy.validate_database_url(policy.DATABASE_URL)


def test_container_runtime_environment_is_exact_when_present() -> None:
    """The image checks the actual Compose environment, not only a fixture."""

    if not os.getenv("KAIROS_SIM_GATE_CONFIRM"):
        return
    policy.validate_environment()
    policy.validate_database_url(os.environ["KAIROS_SIM_CONTROLLER_DATABASE_URL"])


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda config: config["services"]["sim-gate"].update(
                {"ports": ["443:443"]}
            ),
            "unsafe",
        ),
        (
            lambda config: config["services"]["sim-gate"].update(
                {"secrets": ["anything"]}
            ),
            "unsafe",
        ),
        (
            lambda config: config["services"]["sim-gate"]["environment"].update(
                {"EVEDEX_PRIVATE_KEY": "x"}
            ),
            "credential",
        ),
        (
            lambda config: config["networks"]["isolated"].update({"external": True}),
            "external",
        ),
        (lambda config: config.update({"volumes": {"shared": {}}}), "volumes"),
        (
            lambda config: config["services"]["sim-gate"].update({"read_only": False}),
            "read-only",
        ),
    ],
)
def test_escape_hatches_are_rejected(mutate, expected: str) -> None:
    config = copy.deepcopy(_compose())
    mutate(config)
    assert any(expected in error for error in policy.validate_compose(config, _lock()))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("KAIROS_EVEDEX_PRIVATE_KEY", "x"),
        ("KAIROS_TRADING_MODE", "PAPER"),
        ("KAIROS_OPENAI_API_KEY", "x"),
    ],
)
def test_runtime_credentials_and_non_sim_modes_are_rejected(
    key: str, value: str
) -> None:
    environment = _environment()
    environment[key] = value
    with pytest.raises(ValueError):
        policy.validate_environment(environment)
