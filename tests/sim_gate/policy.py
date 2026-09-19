"""Static safety policy for the disposable, offline simulator gate."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PROJECT = "kairos-sim"
DATABASE = "kairos_sim_controller_202609190001"
CONFIRMATION = "ISOLATED_SIMULATOR_GATE_ONLY"
DATABASE_URL = (
    f"postgresql://kairos:synthetic_sim_gate_only@timescaledb:5432/{DATABASE}"
)
TIMESCALE_IMAGE = (
    "timescale/timescaledb:2.28.3-pg16@"
    "sha256:61f891691050da6032023c01ea885730eeeba06b7c17b403e7d0b9c49c37dfe9"
)
REDIS_IMAGE = (
    "redis:8.2.8-alpine3.22@"
    "sha256:a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103"
)
EXECUTION_REPOSITORY = "https://github.com/Kairos-cryptoAI/kairos-execution-engine"
SHA256 = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_RUNTIME_TOKENS = frozenset(
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
        "PAPER",
        "LIVE",
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


def _normalized_path(value: Any) -> str:
    return str(value).replace("\\", "/").rstrip("/")


def _same_memory_limit(value: Any, human: str) -> bool:
    byte_values = {
        "128m": "134217728",
        "768m": "805306368",
        "1g": "1073741824",
    }
    return str(value) in {human, byte_values[human]}


def _contains_forbidden_runtime_token(value: Any) -> bool:
    upper = str(value).upper()
    return any(token in upper for token in FORBIDDEN_RUNTIME_TOKENS)


def validate_environment(environment: dict[str, str] | None = None) -> None:
    """Require exactly the isolated test database and reject credentials."""

    environment = dict(os.environ if environment is None else environment)
    expected = {
        "KAIROS_SIM_GATE_CONFIRM": CONFIRMATION,
        "KAIROS_SIM_GATE_PROJECT": PROJECT,
        "KAIROS_SIM_CONTROLLER_DATABASE_URL": DATABASE_URL,
    }
    for key, expected_value in expected.items():
        if environment.get(key) != expected_value:
            raise ValueError(f"{key} must select the exact isolated simulator target")
    for key, value in environment.items():
        if key.startswith("KAIROS_") and key not in expected:
            raise ValueError(f"unapproved Kairos runtime setting: {key}")
        if _contains_forbidden_runtime_token(key) or _contains_forbidden_runtime_token(
            value
        ):
            raise ValueError("credential environment or a non-SIM mode is forbidden")
    if Path(".env").exists():
        raise ValueError("workspace .env is forbidden in the simulator gate")


def validate_source_lock(lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if lock.get("schema_version") != 1:
        errors.append("simulator source lock schema_version must be 1")
    if lock.get("purpose") != "isolated-market-data-simulator":
        errors.append("simulator source lock purpose is invalid")
    if lock.get("classification") != "SIMULATED":
        errors.append("simulator source lock must classify all outcomes as SIMULATED")
    readiness = lock.get("readiness") or {}
    if readiness != {
        "paper_qualified": False,
        "alpha_ready": False,
        "live_ready": False,
        "strategy_policy": "REJECT_ALL",
    }:
        errors.append("simulator source lock must retain fail-closed readiness")
    if lock.get("build") != {"python": "3.11.15", "uv": "0.12.3"}:
        errors.append("simulator source lock must pin Python 3.11.15 and uv 0.12.3")
    expected_repositories = {
        "kairos-core": "https://github.com/Kairos-cryptoAI/kairos-core",
        "kairos-persistence": "https://github.com/Kairos-cryptoAI/kairos-persistence",
        "kairos-execution-engine": EXECUTION_REPOSITORY,
    }
    dependencies = lock.get("dependencies") or {}
    if set(dependencies) != set(expected_repositories):
        errors.append(
            "simulator source lock dependencies must match the exact SIM allow-list"
        )
    for name, repository in expected_repositories.items():
        dependency = dependencies.get(name) or {}
        if dependency.get("repository") != repository:
            errors.append(f"{name}: unexpected source repository")
        if not SHA256.fullmatch(str(dependency.get("revision", ""))):
            errors.append(f"{name}: revision must be an immutable full Git SHA")
    infrastructure = lock.get("infrastructure") or {}
    if infrastructure != {"timescaledb": TIMESCALE_IMAGE, "redis": REDIS_IMAGE}:
        errors.append(
            "simulator infrastructure must match the exact isolated image pins"
        )
    if lock.get("gate") != {
        "project": PROJECT,
        "database": DATABASE,
        "confirmation": CONFIRMATION,
    }:
        errors.append(
            "simulator gate target is not the exact isolated project and database"
        )
    return errors


def validate_dockerfile(text: str, lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    execution = (lock.get("dependencies") or {}).get("kairos-execution-engine") or {}
    revision = str(execution.get("revision", ""))
    required = (
        f"git fetch --depth=1 origin {revision}",
        f'test "$(git rev-parse FETCH_HEAD)" = {revision}',
        "uv sync --locked --group dev --no-editable",
        "test_simulation_controller_integration.py",
        "-p",
        "no:cacheprovider",
    )
    for value in required:
        if value not in text:
            errors.append(
                f"simulator Dockerfile is missing required immutable gate detail: {value}"
            )
    lower = text.casefold()
    for token in (
        "evedex",
        "paper",
        "live",
        "openai",
        "deepseek",
        "brightdata",
        "keys.txt",
    ):
        if token in lower:
            errors.append(f"simulator Dockerfile must not reference {token}")
    return errors


def validate_compose(config: dict[str, Any], lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("name") != PROJECT:
        errors.append("simulator Compose project must be kairos-sim")
    services = config.get("services") or {}
    if set(services) != {"timescaledb", "redis", "sim-gate"}:
        errors.append(
            "simulator Compose service set must be exactly timescaledb, redis and sim-gate"
        )
    for top_level in ("secrets", "volumes", "configs"):
        if config.get(top_level):
            errors.append(f"simulator Compose must not define {top_level}")
    networks = config.get("networks") or {}
    if (
        set(networks) != {"isolated"}
        or (networks.get("isolated") or {}).get("internal") is not True
    ):
        errors.append("simulator Compose requires one internal isolated network")
    if (networks.get("isolated") or {}).get("external"):
        errors.append("simulator network must not be external")
    for name, service in services.items():
        for option in FORBIDDEN_SERVICE_OPTIONS:
            if service.get(option):
                errors.append(f"{name}: unsafe simulator service option {option}")
        if set(service.get("networks") or ()) != {"isolated"}:
            errors.append(
                f"{name}: simulator service must use only the isolated network"
            )
        if service.get("restart") != "no":
            errors.append(
                f"{name}: simulator services must never restart automatically"
            )
    timescale = services.get("timescaledb") or {}
    if timescale.get("image") != TIMESCALE_IMAGE:
        errors.append("timescaledb must use the immutable simulator image pin")
    if _environment(timescale.get("environment")) != {
        "POSTGRES_USER": "kairos",
        "POSTGRES_PASSWORD": "synthetic_sim_gate_only",
        "POSTGRES_DB": DATABASE,
    }:
        errors.append("timescaledb must use only the synthetic simulator database")
    if timescale.get("tmpfs") != ["/var/lib/postgresql/data:rw,nosuid,size=512m"]:
        errors.append("timescaledb requires disposable tmpfs storage")
    if not _same_memory_limit(
        timescale.get("mem_limit"), "768m"
    ) or not _same_memory_limit(timescale.get("shm_size"), "128m"):
        errors.append("timescaledb simulator resource limits changed")
    redis = services.get("redis") or {}
    if redis.get("image") != REDIS_IMAGE:
        errors.append("redis must use the immutable simulator image pin")
    if redis.get("tmpfs") != ["/data:rw,nosuid,size=64m"] or not _same_memory_limit(
        redis.get("mem_limit"), "128m"
    ):
        errors.append("redis requires disposable simulator storage and limits")
    gate = services.get("sim-gate") or {}
    build = gate.get("build") or {}
    context = _normalized_path(build.get("context", ""))
    dockerfile = _normalized_path(build.get("dockerfile", ""))
    if not (context == "tests/sim_gate" or context.endswith("/tests/sim_gate")):
        errors.append(
            "sim-gate build context must be the narrow tests/sim_gate directory"
        )
    if not (dockerfile == "Dockerfile" or dockerfile.endswith("/Dockerfile")):
        errors.append("sim-gate must use its dedicated Dockerfile")
    if build.get("additional_contexts"):
        errors.append("sim-gate must not accept an additional build context")
    if gate.get("image") != "kairos-sim-gate-tests:20260919-r1":
        errors.append("sim-gate image identity changed")
    if _environment(gate.get("environment")) != {
        "KAIROS_SIM_GATE_CONFIRM": CONFIRMATION,
        "KAIROS_SIM_GATE_PROJECT": PROJECT,
        "KAIROS_SIM_CONTROLLER_DATABASE_URL": DATABASE_URL,
    }:
        errors.append("sim-gate must receive only the exact isolated SIM settings")
    if gate.get("read_only") is not True:
        errors.append("sim-gate root filesystem must be read-only")
    if gate.get("tmpfs") != ["/tmp:rw,nosuid,size=256m"]:
        errors.append("sim-gate needs only its disposable tmpfs /tmp")
    if gate.get("cap_drop") != ["ALL"] or "no-new-privileges:true" not in (
        gate.get("security_opt") or []
    ):
        errors.append("sim-gate requires capability drop and no-new-privileges")
    if (
        not _same_memory_limit(gate.get("mem_limit"), "1g")
        or gate.get("cpus") != 2.0
        or gate.get("pids_limit") != 128
    ):
        errors.append("sim-gate exact resource limits changed")
    gate_environment = _environment(gate.get("environment"))
    if _contains_forbidden_runtime_token(json.dumps(gate_environment, sort_keys=True)):
        errors.append("sim-gate: credential environment or a non-SIM mode is forbidden")
    expected_depends = {"timescaledb", "redis"}
    depends_on = gate.get("depends_on") or {}
    if set(depends_on) != expected_depends or any(
        not isinstance(depends_on.get(name), dict)
        or depends_on[name].get("condition") != "service_healthy"
        or depends_on[name].get("required", True) is not True
        for name in expected_depends
    ):
        errors.append("sim-gate must wait only for isolated data services")
    return errors


def validate_database_url(url: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "postgresql"
        or parsed.hostname != "timescaledb"
        or parsed.port != 5432
        or parsed.path != f"/{DATABASE}"
        or parsed.query
        or parsed.fragment
        or parsed.username != "kairos"
        or parsed.password != "synthetic_sim_gate_only"
    ):
        raise ValueError(
            "simulator gate database URL must select the exact isolated database"
        )
