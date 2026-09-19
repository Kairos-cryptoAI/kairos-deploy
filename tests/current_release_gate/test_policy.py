"""Hermetic contract checks for the current-source REJECT_ALL gate."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import policy

ROOT = next(
    (
        candidate
        for candidate in Path(__file__).resolve().parents
        if (candidate / "current-release-gate.sources.lock.json").exists()
    ),
    None,
)
LOCK = (
    json.loads((ROOT / "current-release-gate.sources.lock.json").read_text(encoding="utf-8"))
    if ROOT is not None
    else policy.LOCK
)
COMPOSE = json.loads((Path(__file__).with_name("compose.fixture.json")).read_text(encoding="utf-8"))


def test_sealed_source_lock_dockerfile_and_compose_are_accepted() -> None:
    assert policy.LOCK == LOCK
    assert policy.validate_source_lock(LOCK) == []
    assert (
        policy.validate_dockerfile(Path(__file__).with_name("Dockerfile").read_text(encoding="utf-8")) == []
    )
    assert policy.validate_compose(COMPOSE) == []


def test_escape_hatches_and_runtime_authority_are_rejected() -> None:
    broken = copy.deepcopy(COMPOSE)
    broken["services"]["gate"]["ports"] = ["443:443"]
    broken["services"]["gate"]["environment"]["KAIROS_OPENAI_API_KEY"] = "x"
    broken["networks"]["isolated"]["external"] = True
    broken["volumes"] = {"paper-data": {"external": True}}
    errors = policy.validate_compose(broken)
    assert any("unsafe" in error for error in errors)
    assert any("credential" in error for error in errors)
    assert any("external" in error for error in errors)
    assert any("durable" in error for error in errors)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("KAIROS_EVEDEX_PRIVATE_KEY", "x"),
        ("KAIROS_TRADING_MODE", "PAPER"),
        ("KAIROS_OPENAI_API_KEY", "x"),
    ],
)
def test_environment_credentials_and_mode_switches_are_rejected(key: str, value: str) -> None:
    environment = policy.expected_environment()
    environment[key] = value
    with pytest.raises(ValueError):
        policy.validate_environment(environment)


def test_mutable_or_ready_source_lock_is_rejected() -> None:
    broken = copy.deepcopy(LOCK)
    broken["dependencies"]["kairos-core"]["revision"] = "main"
    broken["readiness"]["alpha_ready"] = True
    errors = policy.validate_source_lock(broken)
    assert any("immutable" in error for error in errors)
    assert any("fail-closed" in error for error in errors)
