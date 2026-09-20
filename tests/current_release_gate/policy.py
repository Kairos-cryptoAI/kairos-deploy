"""Fail-closed policy for the current-source REJECT_ALL integration gate."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import re
from pathlib import Path
from typing import Any

PROJECT = "kairos-current-release-gate-20260920-r2"
CONFIRMATION = "CURRENT_RELEASE_REJECT_ALL_GATE_ONLY"
SHA256 = re.compile(r"^[0-9a-f]{40}$")
DEPENDENCIES = {
    "kairos-core": {
        "module": "kairos_core",
        "repository": "https://github.com/Kairos-cryptoAI/kairos-core",
    },
    "kairos-persistence": {
        "module": "kairos_persistence",
        "repository": "https://github.com/Kairos-cryptoAI/kairos-persistence",
    },
    "kairos-strategy-engine": {
        "module": "kairos_strategy",
        "repository": "https://github.com/Kairos-cryptoAI/kairos-strategy-engine",
    },
    "kairos-router": {
        "module": "kairos_router",
        "repository": "https://github.com/Kairos-cryptoAI/kairos-router",
    },
    "kairos-llm": {
        "module": "kairos_llm",
        "repository": "https://github.com/Kairos-cryptoAI/kairos-llm",
    },
    "kairos-aggregator": {
        "module": "kairos_aggregator",
        "repository": "https://github.com/Kairos-cryptoAI/kairos-aggregator",
    },
    "kairos-risk-manager": {
        "module": "kairos_risk",
        "repository": "https://github.com/Kairos-cryptoAI/kairos-risk-manager",
    },
    "kairos-execution-engine": {
        "module": "kairos_execution",
        "repository": "https://github.com/Kairos-cryptoAI/kairos-execution-engine",
    },
}
LOCK = json.loads(Path(__file__).with_name("source-lock.json").read_text(encoding="utf-8"))
FORBIDDEN_ENV_TOKENS = frozenset(
    {
        "API_KEY",
        "TOKEN",
        "SECRET",
        "PRIVATE",
        "SIGNING",
        "JWT",
        "EVEDEX",
        "OPENAI",
        "DEEPSEEK",
        "BRIGHTDATA",
        "X_BEARER",
        "TRADING_MODE",
    }
)
FORBIDDEN_SERVICE_OPTIONS = frozenset(
    {
        "ports",
        "volumes",
        "secrets",
        "configs",
        "env_file",
        "extra_hosts",
        "network_mode",
        "privileged",
        "devices",
        "device_cgroup_rules",
        "cap_add",
        "container_name",
        "links",
        "external_links",
        "pid",
        "ipc",
        "runtime",
        "user",
        "entrypoint",
    }
)


def _environment(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    result: dict[str, str] = {}
    for item in value or ():
        key, separator, item_value = str(item).partition("=")
        if separator:
            result[key] = item_value
    return result


def _same_memory_limit(value: Any, human: str) -> bool:
    return str(value) in {
        human,
        {"768m": "805306368"}[human],
    }


def _contains_forbidden_environment_token(value: object) -> bool:
    upper = str(value).upper()
    return any(token in upper for token in FORBIDDEN_ENV_TOKENS)


def expected_environment() -> dict[str, str]:
    return {
        "KAIROS_CURRENT_RELEASE_GATE_CONFIRM": CONFIRMATION,
        "KAIROS_CURRENT_RELEASE_GATE_PROJECT": PROJECT,
    }


def validate_environment(environment: dict[str, str] | None = None) -> None:
    """Require the exact disposable gate settings and no runtime credentials."""

    env = dict(os.environ if environment is None else environment)
    expected = expected_environment()
    if {key: env.get(key) for key in expected} != expected:
        raise ValueError("current-release gate requires exact explicit opt-in")
    for key, value in env.items():
        if not key.startswith("KAIROS_"):
            continue
        if _contains_forbidden_environment_token(key) or _contains_forbidden_environment_token(value):
            raise ValueError("credential or trading runtime environment is forbidden")
        if key not in expected:
            raise ValueError(f"unapproved Kairos runtime setting: {key}")
    if Path(".env").exists():
        raise ValueError("workspace .env is forbidden in the current-release gate")


def validate_source_lock(lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if lock.get("schema_version") != 1:
        errors.append("current-release source lock schema_version must be 1")
    if lock.get("purpose") != "current-release-reject-all-integration-gate":
        errors.append("current-release source lock purpose is invalid")
    if lock.get("classification") != "ENGINEERING_ONLY":
        errors.append("current-release gate must remain engineering-only")
    if lock.get("readiness") != {
        "paper_qualified": False,
        "alpha_ready": False,
        "live_ready": False,
        "strategy_policy": "REJECT_ALL",
    }:
        errors.append("current-release gate must retain fail-closed readiness")
    if lock.get("build") != {"python": "3.11.15", "uv": "0.12.3"}:
        errors.append("current-release gate must pin Python 3.11.15 and uv 0.12.3")
    if lock.get("gate") != {"project": PROJECT, "confirmation": CONFIRMATION}:
        errors.append("current-release gate target is not exact")
    dependencies = lock.get("dependencies") or {}
    if set(dependencies) != set(DEPENDENCIES):
        errors.append("current-release dependencies must match the exact release set")
    for name, expected in DEPENDENCIES.items():
        dependency = dependencies.get(name) or {}
        if dependency.get("repository") != expected["repository"]:
            errors.append(f"{name}: unexpected source repository")
        if not SHA256.fullmatch(str(dependency.get("revision", ""))):
            errors.append(f"{name}: revision must be an immutable full Git SHA")
    return errors


def validate_dockerfile(text: str) -> list[str]:
    errors: list[str] = []
    required = (
        "uv sync --locked --no-editable",
        "COPY --from=builder /app/.venv /app/.venv",
        "test_policy.py",
        "test_reject_all_path.py",
        "-p",
        "no:cacheprovider",
    )
    for value in required:
        if value not in text:
            errors.append(f"current-release Dockerfile missing required gate detail: {value}")
    lower = text.casefold()
    for token in ("keys.txt", "evedex", "openai", "deepseek", "brightdata", ".env"):
        if token in lower:
            errors.append(f"current-release Dockerfile must not reference {token}")
    return errors


def validate_dockerignore(text: str) -> list[str]:
    expected = "\n".join(
        (
            "*",
            "!Dockerfile",
            "!pyproject.toml",
            "!uv.lock",
            "!policy.py",
            "!source-lock.json",
            "!compose.fixture.json",
            "!test_policy.py",
            "!test_reject_all_path.py",
            "",
        )
    )
    if text.replace("\r\n", "\n") != expected:
        return ["current-release Docker context must use the exact allow-list"]
    return []


def validate_compose(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("name") != PROJECT:
        errors.append("current-release Compose project changed")
    if any(config.get(key) for key in ("volumes", "secrets", "configs")):
        errors.append("current-release Compose must not define durable resources")
    services = config.get("services") or {}
    if set(services) != {"gate"}:
        errors.append("current-release Compose must expose exactly one gate service")
        return errors
    networks = config.get("networks") or {}
    isolated = networks.get("isolated") or {}
    if set(networks) != {"isolated"} or isolated.get("internal") is not True:
        errors.append("current-release gate requires one internal network")
    if isolated.get("external"):
        errors.append("current-release gate network must not be external")
    gate = services["gate"]
    for option in FORBIDDEN_SERVICE_OPTIONS:
        if gate.get(option):
            errors.append(f"gate: unsafe current-release service option {option}")
    if set(gate.get("networks") or ()) != {"isolated"}:
        errors.append("gate must use only the internal network")
    if gate.get("restart") != "no":
        errors.append("gate must never restart automatically")
    build = gate.get("build") or {}
    context = str(build.get("context", "")).replace("\\", "/").rstrip("/")
    dockerfile = str(build.get("dockerfile", "")).replace("\\", "/").rstrip("/")
    if not (context == "tests/current_release_gate" or context.endswith("/tests/current_release_gate")):
        errors.append("gate build context must be the narrow current-release test directory")
    if not (dockerfile == "Dockerfile" or dockerfile.endswith("/Dockerfile")):
        errors.append("gate must use its dedicated Dockerfile")
    if build.get("additional_contexts"):
        errors.append("gate must not accept an additional build context")
    if gate.get("image") != "kairos-current-release-gate-tests:20260920-r2":
        errors.append("current-release gate image identity changed")
    environment = _environment(gate.get("environment"))
    if environment != expected_environment():
        errors.append("gate must receive only exact isolated settings")
    try:
        validate_environment(environment)
    except ValueError as exc:
        errors.append(str(exc))
    if gate.get("read_only") is not True:
        errors.append("gate root filesystem must be read-only")
    if gate.get("tmpfs") != ["/tmp:rw,nosuid,size=128m"]:
        errors.append("gate needs only its disposable tmpfs /tmp")
    if gate.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in (gate.get("security_opt") or []):
        errors.append("gate requires capability drop and no-new-privileges")
    if (
        not _same_memory_limit(gate.get("mem_limit"), "768m")
        or gate.get("cpus") != 1.0
        or gate.get("pids_limit") != 96
    ):
        errors.append("gate exact resource limits changed")
    return errors


def validate_installed_sources(lock: dict[str, Any]) -> None:
    """Reject editable/local sources and imports outside the immutable source set."""

    dependencies = lock["dependencies"]
    for name, expected in DEPENDENCIES.items():
        distribution = importlib.metadata.distribution(name)
        direct = json.loads(distribution.read_text("direct_url.json") or "{}")
        source = dependencies[name]
        vcs = direct.get("vcs_info") or {}
        if vcs.get("commit_id") != source["revision"]:
            raise ValueError(f"{name}: installed revision differs from source lock")
        if direct.get("dir_info", {}).get("editable"):
            raise ValueError(f"{name}: editable source is forbidden")
        expected_url = f"{expected['repository']}.git"
        if direct.get("url") != expected_url:
            raise ValueError(f"{name}: installed source repository differs from source lock")
        module = importlib.import_module(expected["module"])
        root = Path(distribution.locate_file("")).resolve()
        expected_file = Path(distribution.locate_file(f"{expected['module']}/__init__.py")).resolve()
        actual_file = getattr(module, "__file__", None)
        if (
            "site-packages" not in root.parts
            or not expected_file.is_relative_to(root)
            or actual_file is None
            or Path(actual_file).resolve() != expected_file
        ):
            raise ValueError(f"{name}: import is not the installed pinned distribution")
