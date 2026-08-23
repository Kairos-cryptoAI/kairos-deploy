"""Validate the isolated, no-paid-API EVEDEX DEV PAPER deployment."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
from pathlib import Path
from typing import Any

import tomllib

# Keep the documented direct invocation (`python scripts/...py`) working on
# Windows and Linux, where Python otherwise adds only the scripts directory.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.validate_deployment import (
    EXPECTED_REDIS_FEATURE,
    EXPECTED_REDIS_IMAGE,
    IMAGE_PATTERN,
    SHA_PATTERN,
    _bindings,
    _context_map,
    _github_request,
    _is_true,
    _secret_sources,
    load_json,
    parse_dotenv,
)

PAPER_SOURCE_SERVICES = {
    "quant-scouts",
    "strategy-engine",
    "risk-manager",
    "canary-controller",
    "execution-engine",
    "ops-exporter",
}
PAPER_EXPECTED_SERVICES = PAPER_SOURCE_SERVICES | {
    "redis",
    "timescaledb",
    "prometheus",
    "grafana",
}
PAPER_REPOSITORIES = {
    "quant-scouts": "https://github.com/Kairos-cryptoAI/kairos-quant-scouts",
    "strategy-engine": "https://github.com/Kairos-cryptoAI/kairos-strategy-engine",
    "risk-manager": "https://github.com/Kairos-cryptoAI/kairos-risk-manager",
    "canary-controller": "https://github.com/Kairos-cryptoAI/kairos-risk-manager",
    "execution-engine": "https://github.com/Kairos-cryptoAI/kairos-execution-engine",
    "ops-exporter": "https://github.com/Kairos-cryptoAI/kairos-persistence",
}
PAPER_COMMANDS = {
    "quant-scouts": "kairos-quant-scouts",
    "strategy-engine": "kairos-strategy-engine",
    "risk-manager": "kairos-risk-manager",
    "canary-controller": "kairos-paper-canary",
    "execution-engine": "kairos-execution-engine",
    "ops-exporter": "kairos-persistence-exporter",
}
PAPER_EGRESS_SERVICES = {"quant-scouts", "execution-engine"}
PAPER_DEV_SYMBOLS = '["BTCUSDT","ETHUSDT","SOLUSDT","BNBUSDT","XRPUSDT"]'
PAPER_DEV_SYMBOL_MAP = (
    '{"BTCUSDT":"BTCUSD:DEV","ETHUSDT":"ETHUSD:DEV",'
    '"SOLUSDT":"SOLUSD:DEV","BNBUSDT":"BNBUSD:DEV","XRPUSDT":"XRPUSD:DEV"}'
)
PAPER_ACCOUNT_PATTERN = re.compile(
    r"kairos-paper-dev-[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?"
)
PAPER_ENDPOINTS = {
    "KAIROS_EVEDEX_EXCHANGE_URL": "https://trading-api.evedex.tech",
    "KAIROS_EVEDEX_AUTH_URL": "https://auth-api.evedex.tech",
    "KAIROS_EVEDEX_WEBSOCKET_URL": "wss://ws.evedex.tech/connection/websocket",
    "KAIROS_EVEDEX_WEBSOCKET_PREFIX": "futures-perp-dev",
    "KAIROS_EVEDEX_CHAIN_ID": "16182",
}
COMMON_BINDINGS = {
    "KAIROS_REDIS_URL": "/run/secrets/paper_redis_url",
    "KAIROS_PERSISTENCE_DATABASE_URL": "/run/secrets/paper_persistence_database_url",
}
PAPER_SECRET_FILES = {
    "paper_redis_password": "redis_password",
    "paper_redis_url": "redis_url",
    "paper_postgres_password": "postgres_password",
    "paper_persistence_database_url": "persistence_database_url",
    "paper_grafana_admin_password": "grafana_admin_password",
    "evedex_dev_api_key": "evedex_dev_api_key",
    "evedex_dev_private_key": "evedex_dev_private_key",
}
FORBIDDEN_PAPER_SERVICES = {
    "text-scouts",
    "router",
    "aggregator",
    "macro-strategist",
    "llm",
}
FORBIDDEN_PAPER_SECRET_SOURCES = {
    "openai_api_key",
    "deepseek_api_key",
    "x_bearer_token",
    "evedex_jwt",
    "evedex_private_key",
    "ccxt_api_key",
    "ccxt_secret",
}
FORBIDDEN_PAPER_ENV = {
    "KAIROS_DRY_RUN",
    "KAIROS_OPENAI_API_KEY",
    "KAIROS_DEEPSEEK_API_KEY",
    "KAIROS_X_BEARER_TOKEN",
    "KAIROS_EVEDEX_JWT",
    "KAIROS_EVEDEX_PRIVATE_KEY",
    "KAIROS_CCXT_API_KEY",
    "KAIROS_CCXT_SECRET",
}
PAPER_INTERPOLATION_KEYS = {
    "KAIROS_PAPER_SECRETS_DIR",
    "KAIROS_PAPER_ACCOUNT_ID",
    "KAIROS_EVEDEX_DEV_EXPECTED_ACCOUNT_ID",
    "POSTGRES_USER",
    "POSTGRES_DB",
    "GRAFANA_ADMIN_USER",
    "KAIROS_PAPER_METRICS_PORT",
    "KAIROS_PAPER_PROMETHEUS_PORT",
    "KAIROS_PAPER_GRAFANA_PORT",
}
PAPER_COMMON_ENVIRONMENT = {
    "KAIROS_ENVIRONMENT": "paper",
    "KAIROS_LOG_LEVEL": "INFO",
    "KAIROS_LOG_JSON": "true",
    "KAIROS_BUS_BACKEND": "redis",
    "KAIROS_TRADING_SYMBOLS": PAPER_DEV_SYMBOLS,
}
PAPER_SOURCE_ENVIRONMENT_KEYS = {
    "quant-scouts": {
        *PAPER_COMMON_ENVIRONMENT,
        "KAIROS_SECRET_BINDINGS",
        "KAIROS_ENABLE_VENUE_QUALITY_GATE",
        "KAIROS_EVEDEX_DEV_BASE_URL",
        "KAIROS_VENUE_QUALITY_INTERVAL_S",
        "KAIROS_MAXIMUM_ABS_BASIS_BPS",
        "KAIROS_MAXIMUM_EVEDEX_SPREAD_BPS",
        "KAIROS_MAXIMUM_EVEDEX_SLIPPAGE_BPS",
        "KAIROS_MAXIMUM_VENUE_BOOK_AGE_MS",
        "KAIROS_MAXIMUM_VENUE_TIMESTAMP_SKEW_MS",
    },
    "strategy-engine": {
        *PAPER_COMMON_ENVIRONMENT,
        "KAIROS_SECRET_BINDINGS",
        "KAIROS_TRADING_MODE",
        "KAIROS_ENABLED_STRATEGY_IDS",
    },
    "risk-manager": {
        *PAPER_COMMON_ENVIRONMENT,
        "KAIROS_SECRET_BINDINGS",
        "KAIROS_TRADING_MODE",
        "KAIROS_EVEDEX_PROFILE",
        "KAIROS_PAPER_ACCOUNT_ID",
        "KAIROS_PAPER_STRATEGY_ALLOWLIST",
        "KAIROS_REQUIRE_RECONCILED_ACCOUNT",
        "KAIROS_REQUIRE_STRATEGIC_ALLOCATION",
    },
    "canary-controller": {
        *PAPER_COMMON_ENVIRONMENT,
        "KAIROS_SECRET_BINDINGS",
        "KAIROS_TRADING_MODE",
        "KAIROS_EVEDEX_PROFILE",
        "KAIROS_PAPER_ACCOUNT_ID",
        "KAIROS_PAPER_STRATEGY_ALLOWLIST",
        "KAIROS_REQUIRE_RECONCILED_ACCOUNT",
        "KAIROS_REQUIRE_STRATEGIC_ALLOCATION",
    },
    "execution-engine": {
        *PAPER_COMMON_ENVIRONMENT,
        "KAIROS_SECRET_BINDINGS",
        "KAIROS_TRADING_MODE",
        "KAIROS_EXCHANGE",
        "KAIROS_ACCOUNT_ID",
        "KAIROS_EVEDEX_PROFILE",
        "KAIROS_EVEDEX_EXCHANGE_URL",
        "KAIROS_EVEDEX_AUTH_URL",
        "KAIROS_EVEDEX_WEBSOCKET_URL",
        "KAIROS_EVEDEX_WEBSOCKET_PREFIX",
        "KAIROS_EVEDEX_CHAIN_ID",
        "KAIROS_EVEDEX_DEV_SYMBOL_MAP",
        "KAIROS_EVEDEX_DEV_EXPECTED_ACCOUNT_ID",
        "KAIROS_EVEDEX_DEV_API_KEY_FILE",
        "KAIROS_EVEDEX_DEV_PRIVATE_KEY_FILE",
    },
    "ops-exporter": {
        *PAPER_COMMON_ENVIRONMENT,
        "KAIROS_SECRET_BINDINGS",
        "KAIROS_METRICS_HOST",
        "KAIROS_METRICS_PORT",
    },
}
PAPER_INFRASTRUCTURE_ENVIRONMENT_KEYS = {
    "redis": set(),
    "timescaledb": {"POSTGRES_USER", "POSTGRES_PASSWORD_FILE", "POSTGRES_DB"},
    "prometheus": set(),
    "grafana": {
        "GF_SECURITY_ADMIN_USER",
        "GF_SECURITY_ADMIN_PASSWORD__FILE",
        "GF_USERS_ALLOW_SIGN_UP",
        "GF_ANALYTICS_REPORTING_ENABLED",
        "GF_ANALYTICS_CHECK_FOR_UPDATES",
    },
}
PAPER_INFRASTRUCTURE_USERS = {
    "redis": "redis:redis",
    "timescaledb": "postgres:postgres",
}
PAPER_SERVICE_NETWORKS = {
    "redis": {"paper-bus"},
    "timescaledb": {"paper-data"},
    "quant-scouts": {
        "paper-bus",
        "paper-data",
        "paper-observability",
        "paper-egress",
    },
    "strategy-engine": {"paper-bus", "paper-data", "paper-observability"},
    "risk-manager": {"paper-bus", "paper-data", "paper-observability"},
    "canary-controller": {"paper-bus", "paper-data", "paper-observability"},
    "execution-engine": {
        "paper-bus",
        "paper-data",
        "paper-observability",
        "paper-egress",
    },
    "ops-exporter": {
        "paper-bus",
        "paper-data",
        "paper-observability",
        "paper-management",
    },
    "prometheus": {"paper-observability", "paper-management"},
    "grafana": {"paper-observability", "paper-management"},
}
FORBIDDEN_SERVICE_OPTIONS = {
    "cap_add",
    "cgroup",
    "cgroup_parent",
    "configs",
    "credential_spec",
    "device_cgroup_rules",
    "devices",
    "entrypoint",
    "external_links",
    "ipc",
    "links",
    "network_mode",
    "pid",
    "runtime",
    "user",
    "uts",
    "volumes_from",
}


def validate_paper_source_lock(lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if lock.get("schema_version") != 1:
        errors.append("paper source lock schema_version must be 1")
    build = lock.get("build", {}) or {}
    if (
        build.get("python") != "3.11.15"
        or build.get("uv") != "0.12.3"
        or build.get("node") != "22"
    ):
        errors.append(
            "paper source lock must pin Python 3.11.15, uv 0.12.3 and Node 22"
        )
    dependencies = lock.get("dependencies", {}) or {}
    for name in ("kairos-core", "kairos-persistence"):
        if not SHA_PATTERN.fullmatch(str(dependencies.get(name, ""))):
            errors.append(f"paper dependency {name} must have a full immutable Git SHA")
    redis = (lock.get("infrastructure", {}) or {}).get("redis", {}) or {}
    if redis.get("image") != EXPECTED_REDIS_IMAGE:
        errors.append("paper source lock must pin the required Redis 8.2.8 image")
    if redis.get("required_feature") != EXPECTED_REDIS_FEATURE:
        errors.append(
            "paper source lock must record the Redis ACKED-ref-policy feature"
        )
    services = lock.get("services", {}) or {}
    if set(services) != PAPER_SOURCE_SERVICES:
        errors.append(
            "paper source lock service set is incomplete or contains paid services"
        )
    for name in sorted(PAPER_SOURCE_SERVICES):
        source = services.get(name, {}) or {}
        if source.get("repository") != PAPER_REPOSITORIES[name]:
            errors.append(f"{name}: unexpected PAPER source repository")
        if not SHA_PATTERN.fullmatch(str(source.get("revision", ""))):
            errors.append(f"{name}: PAPER revision must be a full immutable Git SHA")
        if source.get("command") != PAPER_COMMANDS[name]:
            errors.append(f"{name}: unexpected PAPER command")
        if not source.get("package_dir"):
            errors.append(f"{name}: PAPER package_dir is required")
    if services.get("strategy-engine", {}).get("extra") != "runtime":
        errors.append("strategy-engine must install only its runtime extra")
    if services.get("execution-engine", {}).get("extra") != "evedex":
        errors.append("execution-engine must install its EVEDEX gateway extra")
    if services.get("ops-exporter", {}).get("revision") != dependencies.get(
        "kairos-persistence"
    ):
        errors.append(
            "ops-exporter revision must equal the PAPER persistence dependency"
        )
    return errors


def _validate_source_build(
    name: str,
    service: dict[str, Any],
    source: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    repository = str(source.get("repository", ""))
    revision = str(source.get("revision", ""))
    build = service.get("build", {}) or {}
    contexts = _context_map(build)
    if set(contexts) != {"service"}:
        errors.append(f"{name}: PAPER build contexts must match the exact allow-list")
    if contexts.get("service") != f"{repository}.git#{revision}":
        errors.append(f"{name}: PAPER build context differs from its immutable lock")
    try:
        local_context = Path(str(build.get("context", ""))).resolve(strict=False)
    except OSError:
        local_context = Path()
    if local_context != Path(__file__).resolve().parents[1]:
        errors.append(
            f"{name}: PAPER Docker build context must be this deployment repository"
        )
    expected_dockerfile = (
        "docker/Dockerfile.paper-execution"
        if name == "execution-engine"
        else "docker/Dockerfile"
    )
    if build.get("dockerfile") != expected_dockerfile:
        errors.append(f"{name}: PAPER Dockerfile differs from the reviewed allow-list")
    if build.get("pull") is not True:
        errors.append(f"{name}: PAPER builds must refresh digest-pinned base images")
    args = build.get("args", {}) or {}
    expected_arg_names = {
        "PACKAGE_DIR",
        "SERVICE_EXTRA",
        "SOURCE_REPOSITORY",
        "SOURCE_REVISION",
    }
    if set(args) != expected_arg_names:
        errors.append(f"{name}: PAPER build arguments must match the exact allow-list")
    for key, expected in {
        "PACKAGE_DIR": source.get("package_dir"),
        "SOURCE_REPOSITORY": repository,
        "SOURCE_REVISION": revision,
    }.items():
        if str(args.get(key, "")) != str(expected):
            errors.append(f"{name}: build argument {key} differs from the PAPER lock")
    expected_extra = source.get("extra", "")
    if str(args.get("SERVICE_EXTRA", "")) != str(expected_extra):
        errors.append(f"{name}: build extra differs from the PAPER lock")
    if service.get("command") != [source.get("command")]:
        errors.append(f"{name}: runtime command differs from the PAPER lock")
    return errors


def validate_paper_compose(config: dict[str, Any], lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("name") != "kairos-paper":
        errors.append("PAPER Compose project name must be exactly kairos-paper")
    services = config.get("services", {}) or {}
    if set(services) != PAPER_EXPECTED_SERVICES:
        errors.append(
            "rendered PAPER service set is incomplete or contains unexpected services"
        )
    if FORBIDDEN_PAPER_SERVICES & set(services):
        errors.append("PAPER technical canary must not start LLM/feed/review services")

    for name, service in services.items():
        environment = service.get("environment", {}) or {}
        networks = set(service.get("networks", {}) or [])
        if service.get("env_file"):
            errors.append(f"{name}: env_file is forbidden")
        if service.get("privileged"):
            errors.append(f"{name}: privileged mode is forbidden")
        for option in sorted(FORBIDDEN_SERVICE_OPTIONS):
            if option == "user" and name in PAPER_INFRASTRUCTURE_USERS:
                continue
            if service.get(option) not in (None, "", [], {}):
                errors.append(f"{name}: unsafe Compose option {option} is forbidden")
        if FORBIDDEN_PAPER_ENV & set(environment):
            errors.append(
                f"{name}: legacy/live/paid credential environment is forbidden"
            )
        if FORBIDDEN_PAPER_SECRET_SOURCES & _secret_sources(service):
            errors.append(f"{name}: live or paid provider secret is forbidden")
        if name not in PAPER_EGRESS_SERVICES and "paper-egress" in networks:
            errors.append(
                f"{name}: PAPER egress is forbidden outside the exact allow-list"
            )
        for volume in service.get("volumes", []) or []:
            source = str(
                volume.get("source", "") if isinstance(volume, dict) else volume
            )
            if "docker.sock" in source:
                errors.append(f"{name}: Docker socket mount is forbidden")
        if name in PAPER_SOURCE_SERVICES and (service.get("volumes") or []):
            errors.append(f"{name}: PAPER application bind/volume mounts are forbidden")
        expected_environment_keys = (
            PAPER_SOURCE_ENVIRONMENT_KEYS.get(name)
            if name in PAPER_SOURCE_SERVICES
            else PAPER_INFRASTRUCTURE_ENVIRONMENT_KEYS.get(name)
        )
        if (
            expected_environment_keys is not None
            and set(environment) != expected_environment_keys
        ):
            errors.append(
                f"{name}: environment keys must match the exact PAPER allow-list"
            )
        if networks != PAPER_SERVICE_NETWORKS.get(name, set()):
            errors.append(f"{name}: networks must match the exact PAPER isolation map")

    for name, expected_user in PAPER_INFRASTRUCTURE_USERS.items():
        if (services.get(name, {}) or {}).get("user") != expected_user:
            errors.append(f"{name}: must run as the pinned non-root image user")

    locked_services = lock.get("services", {}) or {}
    for name in sorted(PAPER_SOURCE_SERVICES):
        service = services.get(name, {}) or {}
        errors.extend(
            _validate_source_build(name, service, locked_services.get(name, {}))
        )
        if service.get("read_only") is not True:
            errors.append(f"{name}: PAPER root filesystem must be read-only")
        if service.get("cap_drop") != ["ALL"]:
            errors.append(f"{name}: all capabilities must be dropped")
        if service.get("security_opt") != ["no-new-privileges:true"]:
            errors.append(f"{name}: no-new-privileges must be enabled")
        if service.get("init") is not True:
            errors.append(f"{name}: the reviewed init wrapper must remain enabled")
        dependencies = service.get("depends_on", {}) or {}
        for dependency in ("redis", "timescaledb"):
            requirement = dependencies.get(dependency, {})
            if (
                not isinstance(requirement, dict)
                or requirement.get("condition") != "service_healthy"
            ):
                errors.append(f"{name}: must wait for healthy {dependency}")
        networks = set(service.get("networks", {}) or [])
        if not {"paper-bus", "paper-data", "paper-observability"}.issubset(networks):
            errors.append(
                f"{name}: isolated PAPER bus/data/observability networks are required"
            )
        if (name in PAPER_EGRESS_SERVICES) != ("paper-egress" in networks):
            errors.append(f"{name}: PAPER egress assignment violates the allow-list")
        bindings = _bindings(service)
        if bindings != COMMON_BINDINGS:
            errors.append(
                f"{name}: secret bindings must match the exact PAPER allow-list"
            )
        expected_secret_sources = {
            "paper_redis_url",
            "paper_persistence_database_url",
            *(
                ("evedex_dev_api_key", "evedex_dev_private_key")
                if name == "execution-engine"
                else ()
            ),
        }
        if _secret_sources(service) != expected_secret_sources:
            errors.append(
                f"{name}: secret source set must match the exact PAPER allow-list"
            )
        if name != "ops-exporter" and service.get("ports"):
            errors.append(
                f"{name}: application ports must not be published to the host"
            )
        for key, expected in PAPER_COMMON_ENVIRONMENT.items():
            if str((service.get("environment", {}) or {}).get(key, "")) != expected:
                errors.append(f"{name}: common PAPER setting {key} must be {expected}")

    for name in (
        "strategy-engine",
        "risk-manager",
        "canary-controller",
        "execution-engine",
    ):
        env = (services.get(name, {}) or {}).get("environment", {}) or {}
        if env.get("KAIROS_TRADING_MODE") != "PAPER":
            errors.append(f"{name}: KAIROS_TRADING_MODE must be PAPER")
        if str(env.get("KAIROS_ENVIRONMENT", "")).casefold() != "paper":
            errors.append(f"{name}: KAIROS_ENVIRONMENT must be paper")
        if env.get("KAIROS_TRADING_SYMBOLS") != PAPER_DEV_SYMBOLS:
            errors.append(f"{name}: exact five-symbol PAPER universe is required")

    strategy_env = (services.get("strategy-engine", {}) or {}).get(
        "environment", {}
    ) or {}
    if strategy_env.get("KAIROS_ENABLED_STRATEGY_IDS") != "[]":
        errors.append("strategy-engine: PAPER alpha must remain REJECT_ALL")

    risk_env = (services.get("risk-manager", {}) or {}).get("environment", {}) or {}
    if risk_env.get("KAIROS_EVEDEX_PROFILE") != "DEV":
        errors.append("risk-manager: EVEDEX profile must be DEV")
    if risk_env.get("KAIROS_PAPER_STRATEGY_ALLOWLIST") != '["technical-canary@1"]':
        errors.append("risk-manager: only the technical canary revision may be armed")
    if not PAPER_ACCOUNT_PATTERN.fullmatch(
        str(risk_env.get("KAIROS_PAPER_ACCOUNT_ID", ""))
    ):
        errors.append(
            "risk-manager: dedicated PAPER account must use the kairos-paper-dev-* namespace"
        )
    for flag in (
        "KAIROS_REQUIRE_RECONCILED_ACCOUNT",
        "KAIROS_REQUIRE_STRATEGIC_ALLOCATION",
    ):
        if not _is_true(risk_env.get(flag)):
            errors.append(f"risk-manager: {flag} must remain enabled")

    canary = services.get("canary-controller", {}) or {}
    canary_env = canary.get("environment", {}) or {}
    if (
        canary.get("profiles") != ["canary"]
        or str(canary.get("restart", "")).casefold() != "no"
    ):
        errors.append(
            "canary-controller: must remain an explicit one-shot canary profile"
        )
    if canary_env.get("KAIROS_PAPER_ACCOUNT_ID") != risk_env.get(
        "KAIROS_PAPER_ACCOUNT_ID"
    ):
        errors.append("canary-controller: dedicated account must match risk-manager")
    if canary_env.get("KAIROS_EVEDEX_PROFILE") != "DEV":
        errors.append("canary-controller: EVEDEX profile must be DEV")
    if canary_env.get("KAIROS_PAPER_STRATEGY_ALLOWLIST") != '["technical-canary@1"]':
        errors.append(
            "canary-controller: only the technical canary revision may be armed"
        )
    if _secret_sources(canary) - {"paper_redis_url", "paper_persistence_database_url"}:
        errors.append(
            "canary-controller: exchange and paid-provider credentials are forbidden"
        )

    quant_env = (services.get("quant-scouts", {}) or {}).get("environment", {}) or {}
    expected_quant = {
        "KAIROS_ENABLE_VENUE_QUALITY_GATE": "true",
        "KAIROS_EVEDEX_DEV_BASE_URL": "https://trading-api.evedex.tech",
        "KAIROS_VENUE_QUALITY_INTERVAL_S": "30",
        "KAIROS_MAXIMUM_ABS_BASIS_BPS": "25",
        "KAIROS_MAXIMUM_EVEDEX_SPREAD_BPS": "25",
        "KAIROS_MAXIMUM_EVEDEX_SLIPPAGE_BPS": "25",
        "KAIROS_MAXIMUM_VENUE_BOOK_AGE_MS": "5000",
        "KAIROS_MAXIMUM_VENUE_TIMESTAMP_SKEW_MS": "2000",
    }
    for key, expected in expected_quant.items():
        if str(quant_env.get(key, "")).casefold() != expected.casefold():
            errors.append(f"quant-scouts: {key} must be {expected}")

    execution = services.get("execution-engine", {}) or {}
    execution_env = execution.get("environment", {}) or {}
    if (
        execution.get("build", {}).get("dockerfile")
        != "docker/Dockerfile.paper-execution"
    ):
        errors.append(
            "execution-engine: PAPER must use the bundled Node sidecar Dockerfile"
        )
    for key, expected in PAPER_ENDPOINTS.items():
        if str(execution_env.get(key, "")) != expected:
            errors.append(f"execution-engine: {key} differs from official DEV")
    if execution_env.get("KAIROS_EVEDEX_PROFILE") != "DEV":
        errors.append("execution-engine: EVEDEX profile must be DEV")
    if str(execution_env.get("KAIROS_EXCHANGE", "")).casefold() != "evedex":
        errors.append("execution-engine: PAPER exchange must be exactly EVEDEX")
    if execution_env.get("KAIROS_EVEDEX_DEV_SYMBOL_MAP") != PAPER_DEV_SYMBOL_MAP:
        errors.append("execution-engine: exact EVEDEX DEV symbol map is required")
    if execution_env.get("KAIROS_ACCOUNT_ID") != risk_env.get(
        "KAIROS_PAPER_ACCOUNT_ID"
    ):
        errors.append("execution-engine: dedicated account must match risk-manager")
    if not str(execution_env.get("KAIROS_EVEDEX_DEV_EXPECTED_ACCOUNT_ID", "")).strip():
        errors.append(
            "execution-engine: expected remote DEV account identity is required"
        )
    execution_secrets = _secret_sources(execution)
    if not {"evedex_dev_api_key", "evedex_dev_private_key"}.issubset(execution_secrets):
        errors.append(
            "execution-engine: separate DEV API and signing key secrets are required"
        )
    if (
        execution_env.get("KAIROS_EVEDEX_DEV_API_KEY_FILE")
        != "/run/secrets/evedex_dev_api_key"
    ):
        errors.append("execution-engine: DEV API key must be passed only as a file")
    if execution_env.get("KAIROS_EVEDEX_DEV_PRIVATE_KEY_FILE") != (
        "/run/secrets/evedex_dev_private_key"
    ):
        errors.append("execution-engine: DEV private key must be passed only as a file")

    secret_definitions = config.get("secrets", {}) or {}
    if set(secret_definitions) != set(PAPER_SECRET_FILES):
        errors.append(
            "top-level secret definitions must match the exact PAPER allow-list"
        )
    resolved_paths: list[str] = []
    for name, basename in PAPER_SECRET_FILES.items():
        definition = secret_definitions.get(name, {}) or {}
        if definition.get("name") not in (None, f"kairos-paper_{name}"):
            errors.append(
                f"{name}: resolved secret resource aliases another Compose project"
            )
        resolved = str(definition.get("file", "")).replace("\\", "/")
        if not resolved.endswith(f"/{basename}"):
            errors.append(f"{name}: secret file must end with /{basename}")
        if resolved:
            resolved_paths.append(resolved.casefold())
    if len(resolved_paths) != len(set(resolved_paths)):
        errors.append("top-level PAPER secret files must resolve to distinct paths")
    secret_parents = {path.rsplit("/", maxsplit=1)[0] for path in resolved_paths}
    if len(secret_parents) != 1:
        errors.append("top-level PAPER secret files must share one dedicated directory")
    if any(
        parent.rstrip("/").rsplit("/", maxsplit=1)[-1] == "secrets"
        for parent in secret_parents
    ):
        errors.append(
            "PAPER secrets must not reuse the base deployment secret directory"
        )

    expected_infrastructure_secrets = {
        "redis": {"paper_redis_password"},
        "timescaledb": {"paper_postgres_password"},
        "prometheus": set(),
        "grafana": {"paper_grafana_admin_password"},
    }
    for name, expected in expected_infrastructure_secrets.items():
        if _secret_sources(services.get(name, {}) or {}) != expected:
            errors.append(
                f"{name}: infrastructure secret set must match the exact PAPER allow-list"
            )

    expected_volume_targets = {
        "redis": {
            "/data": ("volume", "paper-redis-data", False),
        },
        "timescaledb": {
            "/var/lib/postgresql/data": ("volume", "paper-ts-data", False),
            "/docker-entrypoint-initdb.d/001-kairos.sql": (
                "bind",
                "/timescaledb/schema.sql",
                True,
            ),
        },
        "prometheus": {
            "/prometheus": ("volume", "paper-prometheus-data", False),
            "/etc/prometheus/prometheus.yml": (
                "bind",
                "/monitoring/prometheus.yml",
                True,
            ),
            "/etc/prometheus/alerts.yml": (
                "bind",
                "/monitoring/alerts.yml",
                True,
            ),
        },
        "grafana": {
            "/var/lib/grafana": ("volume", "paper-grafana-data", False),
            "/etc/grafana/provisioning/datasources/kairos.yml": (
                "bind",
                "/monitoring/grafana-datasource.yml",
                True,
            ),
        },
    }
    for name, expected in expected_volume_targets.items():
        actual_volumes = (services.get(name, {}) or {}).get("volumes", []) or []
        actual_by_target = {
            str(volume.get("target", "")): volume
            for volume in actual_volumes
            if isinstance(volume, dict)
        }
        if set(actual_by_target) != set(expected):
            errors.append(
                f"{name}: volume targets must match the exact PAPER allow-list"
            )
            continue
        for target, (kind, source, read_only) in expected.items():
            volume = actual_by_target[target]
            actual_source = str(volume.get("source", "")).replace("\\", "/")
            source_matches = (
                actual_source == source
                if kind == "volume"
                else actual_source.endswith(source)
            )
            if (
                volume.get("type") != kind
                or not source_matches
                or bool(volume.get("read_only", False)) is not read_only
            ):
                errors.append(
                    f"{name}: volume {target} differs from the PAPER allow-list"
                )

    expected_named_volumes = {
        "paper-redis-data",
        "paper-ts-data",
        "paper-prometheus-data",
        "paper-grafana-data",
    }
    if set(config.get("volumes", {}) or {}) != expected_named_volumes:
        errors.append("top-level PAPER volumes must match the exact allow-list")
    for name in expected_named_volumes:
        definition = (config.get("volumes", {}) or {}).get(name, {}) or {}
        if definition.get("name") not in (None, f"kairos-paper_{name}"):
            errors.append(f"{name}: resolved volume aliases another Compose project")

    redis = services.get("redis", {}) or {}
    if redis.get("image") != EXPECTED_REDIS_IMAGE or redis.get("ports"):
        errors.append("PAPER Redis must use the pinned image without a host port")
    if "paper_redis_password" not in _secret_sources(redis):
        errors.append("PAPER Redis password secret is missing")
    timescale = services.get("timescaledb", {}) or {}
    if timescale.get("ports"):
        errors.append("PAPER TimescaleDB must not publish a host port")
    if (timescale.get("environment", {}) or {}).get("POSTGRES_PASSWORD_FILE") != (
        "/run/secrets/paper_postgres_password"
    ):
        errors.append("PAPER TimescaleDB must read its isolated password file")
    for name in ("redis", "timescaledb", "prometheus", "grafana"):
        if not IMAGE_PATTERN.fullmatch(
            str((services.get(name, {}) or {}).get("image", ""))
        ):
            errors.append(
                f"{name}: infrastructure image must use tag plus sha256 digest"
            )

    networks = config.get("networks", {}) or {}
    if set(networks) != set(
        PAPER_SERVICE_NETWORKS["execution-engine"] | {"paper-management"}
    ):
        errors.append("top-level PAPER networks must match the exact allow-list")
    for name in ("paper-bus", "paper-data", "paper-observability", "paper-management"):
        if (networks.get(name, {}) or {}).get("internal") is not True:
            errors.append(f"{name}: network must be internal")
    if (networks.get("paper-egress", {}) or {}).get("internal") is True:
        errors.append(
            "paper-egress: network must permit only allow-listed outbound clients"
        )
    for name, network in networks.items():
        if (network or {}).get("name") not in (None, f"kairos-paper_{name}"):
            errors.append(f"{name}: resolved network aliases another Compose project")
        if name != "paper-egress" and (network or {}).get("internal") is not True:
            errors.append(
                f"{name}: only paper-egress may provide external connectivity"
            )
    for name in ("ops-exporter", "prometheus", "grafana"):
        for port in (services.get(name, {}) or {}).get("ports", []) or []:
            host_ip = str(port.get("host_ip", "") if isinstance(port, dict) else port)
            if "127.0.0.1" not in host_ip:
                errors.append(f"{name}: observability ports must bind only to loopback")
    return errors


def validate_paper_environment(
    environment: dict[str, str], *, allow_example_values: bool = False
) -> list[str]:
    errors: list[str] = []
    unexpected = set(environment) - PAPER_INTERPOLATION_KEYS
    if unexpected:
        errors.append(
            "PAPER interpolation keys must match the reviewed allow-list; unexpected: "
            + ", ".join(sorted(unexpected))
        )
    required = {
        "KAIROS_PAPER_SECRETS_DIR",
        "KAIROS_PAPER_ACCOUNT_ID",
        "KAIROS_EVEDEX_DEV_EXPECTED_ACCOUNT_ID",
        "POSTGRES_USER",
        "POSTGRES_DB",
        "GRAFANA_ADMIN_USER",
    }
    for name in sorted(required):
        if not environment.get(name):
            errors.append(f"{name} must be set for PAPER")
    forbidden_names = FORBIDDEN_PAPER_ENV | {
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
        "GRAFANA_ADMIN_PASSWORD",
        "KAIROS_EVEDEX_DEV_API_KEY",
        "KAIROS_EVEDEX_DEV_PRIVATE_KEY",
    }
    for name in sorted(forbidden_names & set(environment)):
        errors.append(f"{name} must not be stored in the PAPER interpolation file")
    if not PAPER_ACCOUNT_PATTERN.fullmatch(
        str(environment.get("KAIROS_PAPER_ACCOUNT_ID", ""))
    ):
        errors.append(
            "KAIROS_PAPER_ACCOUNT_ID must use the dedicated kairos-paper-dev-* namespace"
        )
    if (
        environment.get("POSTGRES_USER") != "kairos"
        or environment.get("POSTGRES_DB") != "kairos"
    ):
        errors.append(
            "PAPER PostgreSQL identity must match the provisioned kairos/kairos DSN"
        )
    if (
        not allow_example_values
        and environment.get("KAIROS_EVEDEX_DEV_EXPECTED_ACCOUNT_ID")
        == "replace-with-dedicated-evedex-dev-account-id"
    ):
        errors.append(
            "replace the EVEDEX DEV account-id sentinel before PAPER preflight"
        )
    return errors


def verify_remote_paper_sources(
    lock: dict[str, Any], *, token: str | None = None
) -> list[str]:
    errors: list[str] = []
    dependencies = lock.get("dependencies", {}) or {}
    for name, source in sorted((lock.get("services", {}) or {}).items()):
        repository = str(source.get("repository", ""))
        revision = str(source.get("revision", ""))
        if not SHA_PATTERN.fullmatch(revision):
            continue
        slug = repository.removeprefix("https://github.com/")
        try:
            metadata = json.loads(
                _github_request(
                    f"https://api.github.com/repos/{slug}/commits/{revision}",
                    token=token,
                    accept="application/vnd.github+json",
                )
            )
            if metadata.get("sha") != revision:
                errors.append(f"{name}: GitHub resolved an unexpected PAPER revision")
            raw = f"https://raw.githubusercontent.com/{slug}/{revision}"
            pyproject = tomllib.loads(
                _github_request(
                    f"{raw}/pyproject.toml", token=token, accept="text/plain"
                ).decode()
            )
            project = pyproject.get("project", {}) or {}
            scripts = project.get("scripts", {}) or {}
            if source.get("command") not in scripts:
                errors.append(f"{name}: PAPER command is absent from project.scripts")
            sources = pyproject.get("tool", {}).get("uv", {}).get("sources", {}) or {}
            if (sources.get("kairos-core") or {}).get("rev") != dependencies.get(
                "kairos-core"
            ):
                errors.append(f"{name}: kairos-core SHA differs from the PAPER lock")
            if name == "ops-exporter":
                if revision != dependencies.get("kairos-persistence"):
                    errors.append(
                        "ops-exporter must run the locked persistence revision"
                    )
            elif (sources.get("kairos-persistence") or {}).get(
                "rev"
            ) != dependencies.get("kairos-persistence"):
                errors.append(
                    f"{name}: kairos-persistence SHA differs from the PAPER lock"
                )
            if name == "strategy-engine" and "runtime" not in (
                project.get("optional-dependencies", {}) or {}
            ):
                errors.append("strategy-engine: runtime optional dependency is missing")
            if (
                name in {"risk-manager", "canary-controller"}
                and "kairos-paper-canary" not in scripts
            ):
                errors.append("risk-manager: manually armed canary command is missing")
            if name == "execution-engine":
                package = json.loads(
                    _github_request(
                        f"{raw}/kairos_execution/evedex_sidecar/package.json",
                        token=token,
                        accept="application/json",
                    )
                )
                if (package.get("dependencies", {}) or {}).get(
                    "@evedex/exchange-bot-sdk"
                ) != "1.2.11":
                    errors.append(
                        "execution-engine: official EVEDEX SDK must be pinned to 1.2.11"
                    )
                if (package.get("engines", {}) or {}).get("node") != "22.x":
                    errors.append(
                        "execution-engine: sidecar runtime must require exact Node 22.x"
                    )
            lock_text = _github_request(
                f"{raw}/uv.lock", token=token, accept="text/plain"
            ).decode()
            if dependencies.get("kairos-core") not in lock_text:
                errors.append(f"{name}: uv.lock lacks pinned PAPER kairos-core SHA")
            if (
                name != "ops-exporter"
                and dependencies.get("kairos-persistence") not in lock_text
            ):
                errors.append(
                    f"{name}: uv.lock lacks pinned PAPER kairos-persistence SHA"
                )
        except (OSError, ValueError, KeyError, urllib.error.HTTPError) as exc:
            errors.append(
                f"{name}: remote PAPER source verification failed ({type(exc).__name__})"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-lock", type=Path, default=Path("paper.sources.lock.json")
    )
    parser.add_argument("--compose-json", type=Path)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--verify-remote", action="store_true")
    parser.add_argument("--allow-example-values", action="store_true")
    args = parser.parse_args(argv)
    try:
        lock = load_json(args.source_lock)
        errors = validate_paper_source_lock(lock)
        if args.compose_json:
            errors.extend(validate_paper_compose(load_json(args.compose_json), lock))
        if args.env_file:
            errors.extend(
                validate_paper_environment(
                    parse_dotenv(args.env_file),
                    allow_example_values=args.allow_example_values,
                )
            )
        if args.verify_remote:
            errors.extend(
                verify_remote_paper_sources(lock, token=os.getenv("GITHUB_TOKEN"))
            )
    except (
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"PAPER deployment validation could not start: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Kairos PAPER deployment validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
