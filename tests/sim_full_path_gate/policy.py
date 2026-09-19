"""Static and runtime isolation policy for the full-path simulator proof."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PROJECT = "kairos-sim-full-path-gate-20260919-r1"
DATABASE = "kairos_sim_full_path_gate_202609190001"
CONFIRMATION = "ISOLATED_SIMULATOR_FULL_PATH_GATE_ONLY"
DATABASE_URL = f"postgresql://kairos:synthetic_sim_full_path_gate_only@timescaledb:5432/{DATABASE}"
TIMESCALE_IMAGE = (
    "timescale/timescaledb:2.28.3-pg16@"
    "sha256:61f891691050da6032023c01ea885730eeeba06b7c17b403e7d0b9c49c37dfe9"
)
PINS = {
    "kairos-core": "52aba6b158a52754784162987e7af4ad24c06669",
    "kairos-persistence": "61c1483032ba4520f54f04618bbc2d0e830e27ae",
    "kairos-strategy-engine": "6ccbd053b07833f301e7c3beaf08ffe36f1467c4",
    "kairos-router": "cb744270b27788e9eefc8945179a46030c48a83b",
    "kairos-llm": "99f153bc9dddb13099c940e9a49d394140147d25",
    "kairos-aggregator": "2d187b0ad391cd8db50beb824e507b439e10c41d",
    "kairos-risk-manager": "a689e129ebf8f226f886995f3ea136a412bb58f5",
    "kairos-execution-engine": "5f37b99758d53cb0b23b7d2e08679858700f3b76",
}
MODULES = {
    "kairos-core": "kairos_core",
    "kairos-persistence": "kairos_persistence",
    "kairos-strategy-engine": "kairos_strategy",
    "kairos-router": "kairos_router",
    "kairos-llm": "kairos_llm",
    "kairos-aggregator": "kairos_aggregator",
    "kairos-risk-manager": "kairos_risk",
    "kairos-execution-engine": "kairos_execution",
}
SHA = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_ENVIRONMENT_TOKENS = frozenset(
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
    }
)
_RAW_NETWORK = {"internal": True}
_RENDERED_NETWORK = {
    "name": f"{PROJECT}_isolated",
    "ipam": {},
    "internal": True,
}
_TIMESCALE_COMMAND = [
    "postgres",
    "-c",
    "shared_buffers=64MB",
    "-c",
    "max_connections=40",
    "-c",
    "max_worker_processes=8",
    "-c",
    "timescaledb.max_background_workers=4",
]
_TIMESCALE_HEALTHCHECK = {
    "test": ["CMD-SHELL", f"pg_isready -U kairos -d {DATABASE}"],
    "interval": "2s",
    "timeout": "2s",
    "retries": 30,
}
_GATE_DOCKERFILE_CMD = (
    'CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", '
    '"--capture=tee-sys", "--tb=short", "test_policy.py", "test_full_path.py"]'
)
_DOCKERIGNORE_ALLOWLIST = frozenset(
    {
        "*",
        "!Dockerfile",
        "!compose.fixture.json",
        "!policy.py",
        "!pyproject.toml",
        "!pytest.ini",
        "!source-lock.json",
        "!test_full_path.py",
        "!test_policy.py",
        "!uv.lock",
    }
)
_GATE_SERVICE_KEYS = frozenset(
    {
        "build",
        "cap_drop",
        "command",
        "cpus",
        "depends_on",
        "entrypoint",
        "environment",
        "image",
        "mem_limit",
        "networks",
        "pids_limit",
        "read_only",
        "restart",
        "security_opt",
        "tmpfs",
    }
)
_TIMESCALE_SERVICE_KEYS = frozenset(
    {
        "command",
        "entrypoint",
        "environment",
        "healthcheck",
        "image",
        "mem_limit",
        "networks",
        "restart",
        "shm_size",
        "tmpfs",
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
    byte_values = {"128m": "134217728", "768m": "805306368", "1g": "1073741824"}
    return str(value) in {human, byte_values[human]}


def _network_names(value: Any) -> set[str]:
    if isinstance(value, dict):
        return {str(key) for key in value}
    return {str(item) for item in value or ()}


def _normalized_path(value: Any) -> str:
    return str(value).replace("\\", "/").rstrip("/")


def _contains_forbidden_environment_token(value: Any) -> bool:
    upper = str(value).upper()
    return any(token in upper for token in FORBIDDEN_ENVIRONMENT_TOKENS)


def validate_environment(environment: dict[str, str] | None = None) -> None:
    """Accept only the exact disposable database and explicit test opt-in."""

    environment = dict(os.environ if environment is None else environment)
    expected = {
        "KAIROS_SIM_FULL_PATH_GATE_CONFIRM": CONFIRMATION,
        "KAIROS_SIM_FULL_PATH_GATE_PROJECT": PROJECT,
        "KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL": DATABASE_URL,
    }
    for key, expected_value in expected.items():
        if environment.get(key) != expected_value:
            raise ValueError(f"{key} must select the exact isolated simulator target")
    for key, value in environment.items():
        if _contains_forbidden_environment_token(key) or _contains_forbidden_environment_token(value):
            raise ValueError("credential environment or a non-simulated mode is forbidden")
        if key.startswith("KAIROS_") and key not in expected:
            raise ValueError(f"unapproved Kairos runtime setting: {key}")
    if Path(".env").exists():
        raise ValueError("workspace .env is forbidden in the full-path simulator gate")


def validate_source_lock(lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if lock.get("schema_version") != 1:
        errors.append("full-path simulator source lock schema_version must be 1")
    if lock.get("purpose") != "isolated-full-path-market-data-simulator":
        errors.append("full-path simulator source lock purpose is invalid")
    if lock.get("classification") != "SIMULATED":
        errors.append("full-path simulator source lock must classify all outcomes as SIMULATED")
    if lock.get("readiness") != {
        "paper_qualified": False,
        "alpha_ready": False,
        "live_ready": False,
        "strategy_policy": "REJECT_ALL",
    }:
        errors.append("full-path simulator source lock must retain fail-closed readiness")
    if lock.get("build") != {"python": "3.11.15", "uv": "0.12.3"}:
        errors.append("full-path simulator source lock must pin Python 3.11.15 and uv 0.12.3")
    dependencies = lock.get("dependencies") or {}
    if set(dependencies) != set(PINS):
        errors.append("full-path simulator dependencies must match the exact source allow-list")
    for name, revision in PINS.items():
        dependency = dependencies.get(name) or {}
        if dependency.get("repository") != f"https://github.com/Kairos-cryptoAI/{name}":
            errors.append(f"{name}: unexpected source repository")
        if dependency.get("revision") != revision or not SHA.fullmatch(str(dependency.get("revision", ""))):
            errors.append(f"{name}: revision must match the immutable full Git SHA")
    if lock.get("infrastructure") != {"timescaledb": TIMESCALE_IMAGE}:
        errors.append("full-path simulator infrastructure must match the exact image pin")
    if lock.get("gate") != {
        "project": PROJECT,
        "database": DATABASE,
        "confirmation": CONFIRMATION,
    }:
        errors.append("full-path simulator gate target is not the exact isolated project and database")
    return errors


def validate_dockerignore(text: str) -> list[str]:
    lines = {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
    errors = [
        f"full-path simulator .dockerignore is missing {item}"
        for item in sorted(_DOCKERIGNORE_ALLOWLIST - lines)
    ]
    errors.extend(
        f"full-path simulator .dockerignore contains an unapproved build input {item}"
        for item in sorted(lines - _DOCKERIGNORE_ALLOWLIST)
    )
    return errors


def validate_dockerfile(text: str) -> list[str]:
    errors: list[str] = []
    for value in (
        "COPY pyproject.toml uv.lock ./",
        "uv sync --locked --no-editable",
        "USER 65532:65532",
    ):
        if value not in text:
            errors.append(f"full-path simulator Dockerfile is missing required detail: {value}")
    directives = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    command_directives = [
        line for line in directives if re.match(r"(?i)^CMD(?:\s|$)", line)
    ]
    if command_directives != [_GATE_DOCKERFILE_CMD]:
        errors.append("full-path simulator Dockerfile must use its exact sealed test CMD")
    if any(re.match(r"(?i)^ENTRYPOINT(?:\s|$)", line) for line in directives):
        errors.append("full-path simulator Dockerfile must not override its sealed test CMD with ENTRYPOINT")
    lower = text.casefold()
    for token in ("evedex", "paper", "live", "openai", "deepseek", "brightdata", "keys.txt"):
        if token in lower:
            errors.append(f"full-path simulator Dockerfile must not reference {token}")
    return errors


def validate_compose(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("name") != PROJECT:
        errors.append("full-path simulator Compose project must use its exact isolated name")
    if set(config) != {"name", "services", "networks"}:
        errors.append("full-path simulator Compose must not define unapproved top-level configuration")
    services = config.get("services") or {}
    if set(services) != {"timescaledb", "gate"}:
        errors.append("full-path simulator Compose service set must be exactly timescaledb and gate")
    for top_level in ("secrets", "volumes", "configs"):
        if config.get(top_level):
            errors.append(f"full-path simulator Compose must not define durable {top_level}")
    networks = config.get("networks") or {}
    isolated = networks.get("isolated") if isinstance(networks, dict) else None
    if (
        set(networks) != {"isolated"}
        or not isinstance(isolated, dict)
        or (isolated != _RAW_NETWORK and isolated != _RENDERED_NETWORK)
    ):
        errors.append("full-path simulator requires one new internal-only network")
    if set((services.get("gate") or {})) - _GATE_SERVICE_KEYS:
        errors.append("gate: unapproved full-path simulator service option")
    if set((services.get("timescaledb") or {})) - _TIMESCALE_SERVICE_KEYS:
        errors.append("timescaledb: unapproved full-path simulator service option")
    for name, service in services.items():
        for option in FORBIDDEN_SERVICE_OPTIONS:
            if service.get(option):
                errors.append(f"{name}: unsafe full-path simulator service option {option}")
        if _network_names(service.get("networks")) != {"isolated"} or service.get("restart") != "no":
            errors.append(f"{name}: simulator services must use only the isolated network and never restart")
    timescale = services.get("timescaledb") or {}
    if timescale.get("image") != TIMESCALE_IMAGE:
        errors.append("timescaledb must use the immutable full-path simulator image pin")
    if _environment(timescale.get("environment")) != {
        "POSTGRES_USER": "kairos",
        "POSTGRES_PASSWORD": "synthetic_sim_full_path_gate_only",
        "POSTGRES_DB": DATABASE,
    }:
        errors.append("timescaledb must use only the synthetic full-path simulator database")
    if timescale.get("tmpfs") != ["/var/lib/postgresql/data:rw,nosuid,size=512m"]:
        errors.append("timescaledb requires disposable tmpfs storage")
    if timescale.get("command") != _TIMESCALE_COMMAND or timescale.get("entrypoint") is not None:
        errors.append("timescaledb must retain its exact isolated database command")
    if timescale.get("healthcheck") != _TIMESCALE_HEALTHCHECK:
        errors.append("timescaledb must retain its exact isolated healthcheck")
    if not _same_memory_limit(timescale.get("mem_limit"), "768m") or not _same_memory_limit(
        timescale.get("shm_size"), "128m"
    ):
        errors.append("timescaledb full-path simulator resource limits changed")
    gate = services.get("gate") or {}
    build = gate.get("build") or {}
    if set(build) != {"context", "dockerfile"}:
        errors.append("full-path simulator gate build must not accept extra build authority")
    if not _normalized_path(build.get("context", "")).endswith("/tests/sim_full_path_gate") and _normalized_path(
        build.get("context", "")
    ) != "tests/sim_full_path_gate":
        errors.append("full-path simulator gate must use its narrow test build context")
    if build.get("dockerfile") != "Dockerfile":
        errors.append("full-path simulator gate must use its dedicated Dockerfile")
    if gate.get("command") is not None or gate.get("entrypoint") is not None:
        errors.append("full-path simulator gate must not override the sealed Dockerfile test command")
    if gate.get("image") != "kairos-sim-full-path-gate-tests:20260919-r1":
        errors.append("full-path simulator gate image identity changed")
    if _environment(gate.get("environment")) != {
        "KAIROS_SIM_FULL_PATH_GATE_CONFIRM": CONFIRMATION,
        "KAIROS_SIM_FULL_PATH_GATE_PROJECT": PROJECT,
        "KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL": DATABASE_URL,
    }:
        errors.append("full-path simulator gate must receive only exact isolated settings")
    if gate.get("depends_on") != {"timescaledb": {"condition": "service_healthy", "required": True}}:
        errors.append("full-path simulator gate must wait only for its isolated database")
    if gate.get("read_only") is not True:
        errors.append("full-path simulator gate root filesystem must be read-only")
    if gate.get("tmpfs") != ["/tmp:rw,nosuid,size=256m"]:
        errors.append("full-path simulator gate needs only disposable /tmp")
    if gate.get("cap_drop") != ["ALL"] or gate.get("security_opt") != ["no-new-privileges:true"]:
        errors.append("full-path simulator gate requires capability drop and no-new-privileges")
    if (
        not _same_memory_limit(gate.get("mem_limit"), "1g")
        or gate.get("cpus") != 2.0
        or gate.get("pids_limit") != 128
    ):
        errors.append("full-path simulator gate resource limits changed")
    try:
        validate_environment(_environment(gate.get("environment")))
    except ValueError as exc:
        errors.append(str(exc))
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
        or parsed.password != "synthetic_sim_full_path_gate_only"
    ):
        raise ValueError("full-path simulator database URL must select its exact isolated database")


def validate_installed_sources() -> None:
    """Ensure the container imports only non-editable immutable Git packages."""

    for name, revision in PINS.items():
        distribution = importlib.metadata.distribution(name)
        direct = json.loads(distribution.read_text("direct_url.json") or "{}")
        if direct.get("vcs_info", {}).get("commit_id") != revision:
            raise ValueError(f"{name}: installed package is not the pinned Git revision")
        if direct.get("dir_info", {}).get("editable"):
            raise ValueError(f"{name}: editable source replacement is forbidden")
        if direct.get("url") != f"https://github.com/Kairos-cryptoAI/{name}.git":
            raise ValueError(f"{name}: installed package has an unexpected source repository")
        module_name = MODULES[name]
        root = Path(distribution.locate_file("")).resolve()
        expected = Path(distribution.locate_file(f"{module_name}/__init__.py")).resolve()
        actual = getattr(importlib.import_module(module_name), "__file__", None)
        if (
            "site-packages" not in root.parts
            or not expected.is_relative_to(root)
            or actual is None
            or Path(actual).resolve() != expected
        ):
            raise ValueError(f"{name}: import is not from its installed immutable distribution")
