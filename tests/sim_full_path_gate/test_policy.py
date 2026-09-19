"""Hermetic policy checks for the isolated full-path simulator gate."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import policy
import pytest


def _root() -> Path | None:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "sim-full-path.sources.lock.json").exists():
            return candidate
    return None


def _lock() -> dict:
    root = _root()
    if root is not None:
        return json.loads((root / "sim-full-path.sources.lock.json").read_text(encoding="utf-8"))
    return json.loads(Path(__file__).with_name("source-lock.json").read_text(encoding="utf-8"))


def _compose() -> dict:
    return json.loads(Path(__file__).with_name("compose.fixture.json").read_text(encoding="utf-8"))


def _environment() -> dict[str, str]:
    return {
        "KAIROS_SIM_FULL_PATH_GATE_CONFIRM": policy.CONFIRMATION,
        "KAIROS_SIM_FULL_PATH_GATE_PROJECT": policy.PROJECT,
        "KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL": policy.DATABASE_URL,
    }


def test_root_and_bundled_source_locks_are_byte_equivalent() -> None:
    root = _root()
    if root is not None:
        assert _lock() == json.loads(
            (Path(__file__).with_name("source-lock.json")).read_text(encoding="utf-8")
        )
    assert policy.validate_source_lock(_lock()) == []


def test_exact_isolated_model_is_accepted() -> None:
    assert policy.validate_compose(_compose()) == []
    policy.validate_environment(_environment())
    policy.validate_database_url(policy.DATABASE_URL)


def test_dockerfile_and_ignore_allow_only_narrow_test_inputs() -> None:
    root = _root()
    if root is None:
        dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
        # Docker does not copy its own .dockerignore into the build context.
        # Keep the in-container assertion identical to the source form so a
        # narrowed fixture cannot accidentally bypass the allow-list policy.
        dockerignore = (
            "*\n!Dockerfile\n!compose.fixture.json\n!policy.py\n!pyproject.toml\n"
            "!pytest.ini\n!source-lock.json\n"
            "!test_full_path.py\n!test_policy.py\n!uv.lock\n"
        )
    else:
        gate = root / "tests" / "sim_full_path_gate"
        dockerfile = (gate / "Dockerfile").read_text(encoding="utf-8")
        dockerignore = (gate / ".dockerignore").read_text(encoding="utf-8")
    assert policy.validate_dockerfile(dockerfile) == []
    assert policy.validate_dockerignore(dockerignore) == []


def test_sealed_dockerfile_command_and_build_inputs_reject_bypasses() -> None:
    root = _root()
    if root is None:
        dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
        dockerignore = "*\n!Dockerfile\n!compose.fixture.json\n!policy.py\n!pyproject.toml\n!pytest.ini\n!source-lock.json\n!test_full_path.py\n!test_policy.py\n!uv.lock\n"
    else:
        gate = root / "tests" / "sim_full_path_gate"
        dockerfile = (gate / "Dockerfile").read_text(encoding="utf-8")
        dockerignore = (gate / ".dockerignore").read_text(encoding="utf-8")
    bypassed = dockerfile.replace(
        policy._GATE_DOCKERFILE_CMD,
        'CMD ["python", "-c", "raise SystemExit(0)"]\n# test_full_path.py -p no:cacheprovider',
    )
    assert any("exact sealed test CMD" in error for error in policy.validate_dockerfile(bypassed))
    assert any(
        "unapproved build input" in error
        for error in policy.validate_dockerignore(dockerignore + "!keys.txt\n")
    )


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda config: config["services"]["gate"].update({"ports": ["443:443"]}), "unsafe"),
        (lambda config: config["services"]["gate"].update({"secrets": ["anything"]}), "unsafe"),
        (
            lambda config: config["services"]["gate"]["environment"].update(
                {"KAIROS_EVEDEX_PRIVATE_KEY": "x"}
            ),
            "credential",
        ),
        (lambda config: config["networks"]["isolated"].update({"external": True}), "internal"),
        (lambda config: config.update({"volumes": {"shared": {}}}), "durable"),
        (lambda config: config["services"]["gate"].update({"read_only": False}), "read-only"),
        (
            lambda config: config["services"]["gate"].update(
                {"command": ["python", "-c", "raise SystemExit(0)"]}
            ),
            "sealed Dockerfile",
        ),
        (
            lambda config: config["services"]["gate"].update(
                {"security_opt": ["no-new-privileges:true", "seccomp=unconfined"]}
            ),
            "capability",
        ),
        (
            lambda config: config["services"]["gate"]["build"].update({"ssh": ["default"]}),
            "build authority",
        ),
        (lambda config: config["networks"]["isolated"].update({"attachable": True}), "internal"),
    ],
)
def test_escape_hatches_are_rejected(mutate, expected: str) -> None:
    config = copy.deepcopy(_compose())
    mutate(config)
    assert any(expected in error for error in policy.validate_compose(config))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("KAIROS_EVEDEX_PRIVATE_KEY", "x"),
        ("KAIROS_TRADING_MODE", "PAPER"),
        ("KAIROS_OPENAI_API_KEY", "x"),
    ],
)
def test_runtime_credentials_and_non_simulated_modes_are_rejected(key: str, value: str) -> None:
    environment = _environment()
    environment[key] = value
    with pytest.raises(ValueError):
        policy.validate_environment(environment)


def test_container_runtime_environment_is_exact_when_present() -> None:
    if not os.getenv("KAIROS_SIM_FULL_PATH_GATE_CONFIRM"):
        return
    policy.validate_environment()
    policy.validate_database_url(os.environ["KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL"])
