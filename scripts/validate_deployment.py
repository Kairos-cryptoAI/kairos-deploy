"""Validate immutable sources and the rendered Kairos Compose security model."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import tomllib

APP_SERVICES = {
    "quant-scouts",
    "strategy-engine",
    "text-scouts",
    "router",
    "aggregator",
    "macro-strategist",
    "risk-manager",
    "execution-engine",
}
SOURCE_SERVICES = APP_SERVICES | {"ops-exporter"}
EXPECTED_SERVICES = SOURCE_SERVICES | {"redis", "timescaledb", "prometheus", "grafana"}
EGRESS_SERVICES = {
    "quant-scouts",
    "text-scouts",
    "aggregator",
    "macro-strategist",
    "execution-engine",
}
LLM_SERVICES = {"text-scouts", "aggregator", "macro-strategist"}
PERSISTENCE_SERVICES = SOURCE_SERVICES - {"ops-exporter"}
X_RUNTIME_BUDGET_MICROUSD = 2_000_000
EXPECTED_REPOSITORIES = {
    **{
        name: f"https://github.com/Kairos-cryptoAI/kairos-{name}"
        for name in APP_SERVICES
    },
    "ops-exporter": "https://github.com/Kairos-cryptoAI/kairos-persistence",
}
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
IMAGE_PATTERN = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
EXPECTED_REDIS_IMAGE = (
    "redis:8.2.8-alpine3.22@"
    "sha256:a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103"
)
EXPECTED_REDIS_FEATURE = "XACKDEL ref_policy=ACKED"
FORBIDDEN_SECRET_ENV = {
    "KAIROS_REDIS_PASSWORD",
    "KAIROS_PERSISTENCE_DATABASE_URL",
    "KAIROS_DEEPSEEK_API_KEY",
    "KAIROS_OPENAI_API_KEY",
    "KAIROS_X_BEARER_TOKEN",
    "KAIROS_BRIGHTDATA_API_TOKEN",
    "KAIROS_REDDIT_CLIENT_ID",
    "KAIROS_REDDIT_CLIENT_SECRET",
    "KAIROS_EVEDEX_JWT",
    "KAIROS_EVEDEX_PRIVATE_KEY",
    "KAIROS_CCXT_API_KEY",
    "KAIROS_CCXT_SECRET",
    "POSTGRES_PASSWORD",
    "GRAFANA_ADMIN_PASSWORD",
    "REDIS_PASSWORD",
}
COMMON_BINDINGS = {
    "KAIROS_REDIS_URL": "/run/secrets/redis_url",
    "KAIROS_PERSISTENCE_DATABASE_URL": "/run/secrets/persistence_database_url",
}
BASE_SECRET_FILES = {
    "redis_password": "redis_password",
    "redis_url": "redis_url",
    "postgres_password": "postgres_password",
    "persistence_database_url": "persistence_database_url",
    "grafana_admin_password": "grafana_admin_password",
    "deepseek_api_key": "deepseek_api_key",
    "openai_api_key": "openai_api_key",
    "x_bearer_token": "x_bearer_token",
}
BASE_COMMON_ENVIRONMENT_KEYS = {
    "KAIROS_ENVIRONMENT",
    "KAIROS_LOG_LEVEL",
    "KAIROS_LOG_JSON",
    "KAIROS_BUS_BACKEND",
    "KAIROS_SECRET_BINDINGS",
    "KAIROS_TRADING_SYMBOLS",
}
BASE_SOURCE_ENVIRONMENT_KEYS = {
    "quant-scouts": {*BASE_COMMON_ENVIRONMENT_KEYS},
    "strategy-engine": {
        *BASE_COMMON_ENVIRONMENT_KEYS,
        "KAIROS_TRADING_MODE",
        "KAIROS_ENABLED_STRATEGY_IDS",
    },
    "text-scouts": {
        *BASE_COMMON_ENVIRONMENT_KEYS,
        "KAIROS_REDDIT_USER_AGENT",
        "KAIROS_X_MONTHLY_BUDGET_MICROUSD",
        "KAIROS_X_POST_READ_UNIT_COST_MICROUSD",
        "KAIROS_X_USER_READ_UNIT_COST_MICROUSD",
    },
    "router": {*BASE_COMMON_ENVIRONMENT_KEYS},
    "aggregator": {*BASE_COMMON_ENVIRONMENT_KEYS},
    "macro-strategist": {*BASE_COMMON_ENVIRONMENT_KEYS},
    "risk-manager": {
        *BASE_COMMON_ENVIRONMENT_KEYS,
        "KAIROS_REQUIRE_RECONCILED_ACCOUNT",
        "KAIROS_ACCOUNT_SNAPSHOT_MAX_AGE_S",
        "KAIROS_REQUIRE_STRATEGIC_ALLOCATION",
    },
    "execution-engine": {
        *BASE_COMMON_ENVIRONMENT_KEYS,
        "KAIROS_EXCHANGE",
        "KAIROS_TRADING_MODE",
        "KAIROS_ACCOUNT_ID",
        "KAIROS_ACCOUNT_SNAPSHOT_INTERVAL_S",
        "KAIROS_DRY_RUN_EQUITY_USD",
        "KAIROS_EVEDEX_EXCHANGE_URL",
        "KAIROS_EVEDEX_CHAIN_ID",
    },
    "ops-exporter": {
        *BASE_COMMON_ENVIRONMENT_KEYS,
        "KAIROS_METRICS_HOST",
        "KAIROS_METRICS_PORT",
    },
}
BASE_INFRASTRUCTURE_ENVIRONMENT_KEYS = {
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
BASE_INFRASTRUCTURE_USERS = {
    "redis": "redis:redis",
    "timescaledb": "postgres:postgres",
}
BASE_SERVICE_NETWORKS = {
    "redis": {"bus"},
    "timescaledb": {"data"},
    "quant-scouts": {"bus", "data", "observability", "egress"},
    "strategy-engine": {"bus", "data", "observability"},
    "text-scouts": {"bus", "data", "observability", "egress"},
    "router": {"bus", "data", "observability"},
    "aggregator": {"bus", "data", "observability", "egress"},
    "macro-strategist": {"bus", "data", "observability", "egress"},
    "risk-manager": {"bus", "data", "observability"},
    "execution-engine": {"bus", "data", "observability", "egress"},
    "ops-exporter": {"bus", "data", "observability", "management"},
    "prometheus": {"observability", "management"},
    "grafana": {"observability", "management"},
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


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _context_map(build: dict[str, Any]) -> dict[str, str]:
    contexts = build.get("additional_contexts", {})
    if isinstance(contexts, dict):
        return {str(key): str(value) for key, value in contexts.items()}
    result: dict[str, str] = {}
    for item in contexts if isinstance(contexts, list) else []:
        name, separator, value = str(item).partition("=")
        if separator:
            result[name] = value
    return result


def _secret_sources(service: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for item in service.get("secrets", []) or []:
        if isinstance(item, dict):
            result.add(str(item.get("source", "")))
        else:
            result.add(str(item))
    return result


def _bindings(service: dict[str, Any]) -> dict[str, str]:
    raw = str((service.get("environment", {}) or {}).get("KAIROS_SECRET_BINDINGS", ""))
    result: dict[str, str] = {}
    for item in filter(None, (part.strip() for part in raw.split(","))):
        name, separator, path = item.partition("=")
        if separator and name and path:
            result[name] = path
    return result


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return data


def validate_source_lock(lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if lock.get("schema_version") != 1:
        errors.append("sources.lock.json schema_version must be 1")
    build = lock.get("build", {}) or {}
    if build.get("python") != "3.11.15":
        errors.append("source lock must pin Python 3.11.15")
    if build.get("uv") != "0.12.3":
        errors.append("source lock must pin uv 0.12.3")
    dependencies = lock.get("dependencies", {}) or {}
    for name in ("kairos-core", "kairos-llm", "kairos-persistence"):
        if not SHA_PATTERN.fullmatch(str(dependencies.get(name, ""))):
            errors.append(f"dependency {name} must have a full immutable Git SHA")
    redis = (lock.get("infrastructure", {}) or {}).get("redis", {}) or {}
    if redis.get("image") != EXPECTED_REDIS_IMAGE:
        errors.append(
            "source lock must pin the Redis 8.2.8 runtime required by kairos-core"
        )
    if redis.get("required_feature") != EXPECTED_REDIS_FEATURE:
        errors.append(
            "source lock must document the Redis XACKDEL ACKED-ref-policy requirement"
        )

    services = lock.get("services", {}) or {}
    if set(services) != SOURCE_SERVICES:
        errors.append("source lock service set does not match Compose build sources")
    for name in sorted(SOURCE_SERVICES):
        entry = services.get(name, {}) or {}
        if entry.get("repository") != EXPECTED_REPOSITORIES[name]:
            errors.append(f"{name}: unexpected source repository")
        if not SHA_PATTERN.fullmatch(str(entry.get("revision", ""))):
            errors.append(f"{name}: revision must be a full immutable Git SHA")
        if not str(entry.get("package_dir", "")):
            errors.append(f"{name}: package_dir is required")
        if not str(entry.get("command", "")):
            errors.append(f"{name}: command is required")
    if services.get("execution-engine", {}).get("extra") != "evedex":
        errors.append("execution-engine must install the evedex extra")
    if services.get("strategy-engine", {}).get("extra") != "runtime":
        errors.append("strategy-engine must install the runtime extra")
    return errors


def _validate_source_service(
    name: str, service: dict[str, Any], source: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    repository = str(source.get("repository", ""))
    revision = str(source.get("revision", ""))
    build = service.get("build", {}) or {}
    contexts = _context_map(build)
    if set(contexts) != {"service"}:
        errors.append(f"{name}: named build contexts must match the exact allow-list")
    if contexts.get("service") != f"{repository}.git#{revision}":
        errors.append(f"{name}: named build context differs from sources.lock.json")
    try:
        local_context = Path(str(build.get("context", ""))).resolve(strict=False)
    except OSError:
        local_context = Path()
    if local_context != Path(__file__).resolve().parents[1]:
        errors.append(
            f"{name}: Docker build context must be this deployment repository"
        )
    if build.get("dockerfile") != "docker/Dockerfile":
        errors.append(f"{name}: Dockerfile differs from the reviewed allow-list")
    if build.get("pull") is not True:
        errors.append(f"{name}: builds must refresh digest-pinned base images")
    args = build.get("args", {}) or {}
    expected_arg_names = {"PACKAGE_DIR", "SOURCE_REPOSITORY", "SOURCE_REVISION"}
    if source.get("extra"):
        expected_arg_names.add("SERVICE_EXTRA")
    if set(args) != expected_arg_names:
        errors.append(f"{name}: build arguments must match the exact allow-list")
    if str(args.get("SOURCE_REVISION", "")) != revision:
        errors.append(f"{name}: OCI source revision differs from the source lock")
    if str(args.get("SOURCE_REPOSITORY", "")) != repository:
        errors.append(f"{name}: OCI source repository differs from the source lock")
    if str(args.get("PACKAGE_DIR", "")) != str(source.get("package_dir", "")):
        errors.append(f"{name}: package directory differs from the source lock")
    if str(args.get("SERVICE_EXTRA", "")) != str(source.get("extra", "")):
        errors.append(f"{name}: build extra differs from the source lock")
    if service.get("command", []) != [str(source.get("command", ""))]:
        errors.append(f"{name}: command differs from the source lock")
    return errors


def validate_compose(
    config: dict[str, Any], lock: dict[str, Any], *, live: bool = False
) -> list[str]:
    errors: list[str] = []
    if config.get("name") != "kairos":
        errors.append("base Compose project name must be exactly kairos")
    services = config.get("services", {}) or {}
    if set(services) != EXPECTED_SERVICES:
        errors.append(
            "rendered Compose service set is incomplete or contains unexpected services"
        )

    for name, service in services.items():
        if service.get("env_file"):
            errors.append(f"{name}: env_file is forbidden")
        if service.get("privileged"):
            errors.append(f"{name}: privileged containers are forbidden")
        for option in sorted(FORBIDDEN_SERVICE_OPTIONS):
            if option == "user" and name in BASE_INFRASTRUCTURE_USERS:
                continue
            if service.get(option) not in (None, "", [], {}):
                errors.append(f"{name}: unsafe Compose option {option} is forbidden")
        for volume in service.get("volumes", []) or []:
            source = str(
                volume.get("source", "") if isinstance(volume, dict) else volume
            )
            if "docker.sock" in source:
                errors.append(f"{name}: mounting the Docker socket is forbidden")
        environment = service.get("environment", {}) or {}
        expected_environment_keys = (
            BASE_SOURCE_ENVIRONMENT_KEYS.get(name)
            if name in SOURCE_SERVICES
            else BASE_INFRASTRUCTURE_ENVIRONMENT_KEYS.get(name)
        )
        if (
            expected_environment_keys is not None
            and set(environment) != expected_environment_keys
        ):
            errors.append(f"{name}: environment keys must match the exact allow-list")
        if set(service.get("networks", {}) or []) != BASE_SERVICE_NETWORKS.get(
            name, set()
        ):
            errors.append(f"{name}: networks must match the exact isolation map")
        for secret in sorted(FORBIDDEN_SECRET_ENV & set(environment)):
            errors.append(
                f"{name}: secret {secret} must be file-mounted, not an environment value"
            )

    for name, expected_user in BASE_INFRASTRUCTURE_USERS.items():
        if (services.get(name, {}) or {}).get("user") != expected_user:
            errors.append(f"{name}: must run as the pinned non-root image user")

    source_services = lock.get("services", {}) or {}
    for name in sorted(SOURCE_SERVICES):
        service = services.get(name, {}) or {}
        errors.extend(
            _validate_source_service(name, service, source_services.get(name, {}))
        )
        if service.get("read_only") is not True:
            errors.append(f"{name}: root filesystem must be read-only")
        if service.get("cap_drop") != ["ALL"]:
            errors.append(f"{name}: all Linux capabilities must be dropped")
        if service.get("security_opt") != ["no-new-privileges:true"]:
            errors.append(f"{name}: no-new-privileges must be enabled")
        if service.get("init") is not True:
            errors.append(f"{name}: the reviewed init wrapper must remain enabled")
        dependencies = service.get("depends_on") or {}
        for dependency in ("redis", "timescaledb"):
            requirement = dependencies.get(dependency, {})
            if (
                not isinstance(requirement, dict)
                or requirement.get("condition") != "service_healthy"
            ):
                errors.append(f"{name}: must wait for healthy {dependency}")
        networks = set(service.get("networks", {}) or [])
        if name not in EGRESS_SERVICES and "egress" in networks:
            errors.append(f"{name}: egress is forbidden outside the exact allow-list")
        if name in SOURCE_SERVICES and (service.get("volumes") or []):
            errors.append(f"{name}: application bind/volume mounts are forbidden")
        if not {"bus", "data", "observability"}.issubset(networks):
            errors.append(f"{name}: bus, data, and observability networks are required")
        if name in APP_SERVICES and (name in EGRESS_SERVICES) != ("egress" in networks):
            errors.append(f"{name}: egress network assignment violates the allow-list")
        if name == "ops-exporter" and "management" not in networks:
            errors.append(
                "ops-exporter: management network is required for loopback publishing"
            )
        if name in APP_SERVICES and "management" in networks:
            errors.append(
                f"{name}: management network is forbidden for application services"
            )
        bindings = _bindings(service)
        if not all(
            bindings.get(key) == value for key, value in COMMON_BINDINGS.items()
        ):
            errors.append(
                f"{name}: durable Redis/database secret bindings are required"
            )
        if not {"redis_url", "persistence_database_url"}.issubset(
            _secret_sources(service)
        ):
            errors.append(f"{name}: durable Redis/database secret files are required")
        common_environment = service.get("environment", {}) or {}
        if str(common_environment.get("KAIROS_BUS_BACKEND", "")).casefold() != "redis":
            errors.append(f"{name}: durable runtime requires the Redis bus backend")
        if not _is_true(common_environment.get("KAIROS_LOG_JSON")):
            errors.append(f"{name}: structured JSON logs must remain enabled")

    execution = services.get("execution-engine", {}) or {}
    execution_env = execution.get("environment", {}) or {}
    if (execution.get("build", {}).get("args", {}) or {}).get(
        "SERVICE_EXTRA"
    ) != "evedex":
        errors.append("execution-engine must build with SERVICE_EXTRA=evedex")
    execution_secrets = _secret_sources(execution)
    execution_bindings = _bindings(execution)
    if "KAIROS_DRY_RUN" in execution_env:
        errors.append("execution-engine: retired KAIROS_DRY_RUN switch must be removed")
    if live:
        if execution_env.get("KAIROS_TRADING_MODE") != "LIVE":
            errors.append("live Compose must explicitly select TradingMode=LIVE")
        if {"evedex_jwt", "evedex_private_key"} & execution_secrets:
            errors.append(
                "live Compose must not mount retired static EVEDEX credentials"
            )
        if {
            "KAIROS_EVEDEX_JWT",
            "KAIROS_EVEDEX_PRIVATE_KEY",
        } & set(execution_bindings):
            errors.append(
                "live Compose must not bind retired static EVEDEX credentials"
            )
    else:
        if execution_env.get("KAIROS_TRADING_MODE") != "DRY_RUN":
            errors.append("base Compose must explicitly select TradingMode=DRY_RUN")
        if {"evedex_jwt", "evedex_private_key"} & execution_secrets:
            errors.append("base Compose must not mount EVEDEX live credentials")

    expected_provider_secrets = {
        "text-scouts": {
            "KAIROS_DEEPSEEK_API_KEY": (
                "deepseek_api_key",
                "/run/secrets/deepseek_api_key",
            ),
            "KAIROS_X_BEARER_TOKEN": ("x_bearer_token", "/run/secrets/x_bearer_token"),
        },
        "aggregator": {
            "KAIROS_OPENAI_API_KEY": ("openai_api_key", "/run/secrets/openai_api_key")
        },
        "macro-strategist": {
            "KAIROS_OPENAI_API_KEY": ("openai_api_key", "/run/secrets/openai_api_key")
        },
    }
    for name, expected in expected_provider_secrets.items():
        service = services.get(name, {}) or {}
        bindings = _bindings(service)
        sources = _secret_sources(services.get(name, {}) or {})
        for environment_name, (source, path) in expected.items():
            if source not in sources:
                errors.append(
                    f"{name}: expected provider secret file {source} is missing"
                )
            if bindings.get(environment_name) != path:
                errors.append(
                    f"{name}: expected provider binding {environment_name} is missing"
                )

    for name in sorted(SOURCE_SERVICES):
        service = services.get(name, {}) or {}
        providers = expected_provider_secrets.get(name, {})
        expected_sources = {"redis_url", "persistence_database_url"} | {
            source for source, _path in providers.values()
        }
        expected_bindings = {
            **COMMON_BINDINGS,
            **{
                environment_name: path
                for environment_name, (_source, path) in providers.items()
            },
        }
        if _secret_sources(service) != expected_sources:
            errors.append(f"{name}: secret source set must match the exact allow-list")
        if _bindings(service) != expected_bindings:
            errors.append(f"{name}: secret bindings must match the exact allow-list")

    secret_definitions = config.get("secrets", {}) or {}
    if set(secret_definitions) != set(BASE_SECRET_FILES):
        errors.append(
            "top-level secret definitions must match the exact base allow-list"
        )
    resolved_paths: list[str] = []
    for name, basename in BASE_SECRET_FILES.items():
        definition = secret_definitions.get(name, {}) or {}
        if definition.get("name") not in (None, f"kairos_{name}"):
            errors.append(f"{name}: resolved secret aliases another Compose project")
        resolved = str(definition.get("file", "")).replace("\\", "/")
        if not resolved.endswith(f"/{basename}"):
            errors.append(f"{name}: secret file must end with /{basename}")
        if resolved:
            resolved_paths.append(resolved.casefold())
    if len(resolved_paths) != len(set(resolved_paths)):
        errors.append("top-level secret files must resolve to distinct paths")

    text_environment = services.get("text-scouts", {}).get("environment", {}) or {}
    try:
        x_runtime_budget = int(text_environment["KAIROS_X_MONTHLY_BUDGET_MICROUSD"])
    except (KeyError, TypeError, ValueError):
        errors.append("text-scouts: X monthly runtime budget must be an integer")
    else:
        if x_runtime_budget != X_RUNTIME_BUDGET_MICROUSD:
            errors.append(
                "text-scouts: X monthly budget must equal the $2 qualification ceiling"
            )

    strategy_env = services.get("strategy-engine", {}).get("environment", {}) or {}
    if strategy_env.get("KAIROS_TRADING_MODE") != "DRY_RUN":
        errors.append("strategy-engine: base topology must remain DRY_RUN")
    if strategy_env.get("KAIROS_ENABLED_STRATEGY_IDS") != "[]":
        errors.append("strategy-engine: rejected alpha sleeves must remain disabled")

    risk_env = services.get("risk-manager", {}).get("environment", {}) or {}
    if not _is_true(risk_env.get("KAIROS_REQUIRE_RECONCILED_ACCOUNT")):
        errors.append("risk-manager reconciliation gate must stay enabled")
    if not _is_true(risk_env.get("KAIROS_REQUIRE_STRATEGIC_ALLOCATION")):
        errors.append("risk-manager strategic allocation gate must stay enabled")
    try:
        if float(execution_env["KAIROS_ACCOUNT_SNAPSHOT_INTERVAL_S"]) >= float(
            risk_env["KAIROS_ACCOUNT_SNAPSHOT_MAX_AGE_S"]
        ):
            errors.append(
                "account snapshot cadence must be faster than Risk freshness window"
            )
    except (KeyError, TypeError, ValueError):
        errors.append("account snapshot cadence and freshness window must be numeric")

    redis = services.get("redis", {}) or {}
    redis_image = str(redis.get("image", ""))
    if redis_image != EXPECTED_REDIS_IMAGE:
        errors.append("Redis image must match the pinned 8.2.8 runtime")
    redis_command = " ".join(str(part) for part in (redis.get("command") or []))
    redis_health = " ".join(
        str(part) for part in ((redis.get("healthcheck") or {}).get("test") or [])
    )
    if redis.get("ports"):
        errors.append("Redis must not publish a host port")
    if (
        "requirepass" not in redis_command
        or "/run/secrets/redis_password" not in redis_command
    ):
        errors.append("Redis must read and enforce its password file")
    if "/run/secrets/redis_password" not in redis_health:
        errors.append("Redis healthcheck must authenticate from its password file")
    if "redis_password" not in _secret_sources(redis):
        errors.append("Redis password secret is missing")

    timescale = services.get("timescaledb", {}) or {}
    if timescale.get("ports"):
        errors.append("TimescaleDB must not publish a host port")
    if (timescale.get("environment", {}) or {}).get("POSTGRES_PASSWORD_FILE") != (
        "/run/secrets/postgres_password"
    ):
        errors.append("TimescaleDB must use POSTGRES_PASSWORD_FILE")
    timescale_health = " ".join(
        str(part) for part in ((timescale.get("healthcheck") or {}).get("test") or [])
    )
    if "/proc/1/comm" not in timescale_health or "pg_isready" not in timescale_health:
        errors.append("TimescaleDB healthcheck must exclude the temporary init server")
    grafana = services.get("grafana", {}) or {}
    if (grafana.get("environment", {}) or {}).get(
        "GF_SECURITY_ADMIN_PASSWORD__FILE"
    ) != ("/run/secrets/grafana_admin_password"):
        errors.append("Grafana must use an admin password file")
    expected_infrastructure_secrets = {
        "redis": {"redis_password"},
        "timescaledb": {"postgres_password"},
        "prometheus": set(),
        "grafana": {"grafana_admin_password"},
    }
    for name, expected in expected_infrastructure_secrets.items():
        if _secret_sources(services.get(name, {}) or {}) != expected:
            errors.append(
                f"{name}: infrastructure secret set must match the exact allow-list"
            )
    expected_volume_targets = {
        "redis": {"/data": ("volume", "redis-data", False)},
        "timescaledb": {
            "/var/lib/postgresql/data": ("volume", "ts-data", False),
            "/docker-entrypoint-initdb.d/001-kairos.sql": (
                "bind",
                "/timescaledb/schema.sql",
                True,
            ),
        },
        "prometheus": {
            "/prometheus": ("volume", "prometheus-data", False),
            "/etc/prometheus/prometheus.yml": (
                "bind",
                "/monitoring/prometheus.yml",
                True,
            ),
            "/etc/prometheus/alerts.yml": (
                "bind",
                "/monitoring/alerts.base.yml",
                True,
            ),
        },
        "grafana": {
            "/var/lib/grafana": ("volume", "grafana-data", False),
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
            errors.append(f"{name}: volume targets must match the exact allow-list")
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
                errors.append(f"{name}: volume {target} differs from the allow-list")
    expected_named_volumes = {
        "redis-data",
        "ts-data",
        "prometheus-data",
        "grafana-data",
    }
    if set(config.get("volumes", {}) or {}) != expected_named_volumes:
        errors.append("top-level volumes must match the exact allow-list")
    for name in expected_named_volumes:
        definition = (config.get("volumes", {}) or {}).get(name, {}) or {}
        if definition.get("name") not in (None, f"kairos_{name}"):
            errors.append(f"{name}: resolved volume aliases another Compose project")

    for name in ("ops-exporter", "prometheus", "grafana"):
        service_networks = set(services.get(name, {}).get("networks", {}) or [])
        if "management" not in service_networks:
            errors.append(f"{name}: management network is required")
        health_test = " ".join(
            str(part)
            for part in (
                (services.get(name, {}).get("healthcheck") or {}).get("test") or []
            )
        )
        if "127.0.0.1" not in health_test:
            errors.append(f"{name}: a loopback healthcheck is required")
        for port in services.get(name, {}).get("ports", []) or []:
            host_ip = str(port.get("host_ip", "") if isinstance(port, dict) else port)
            if "127.0.0.1" not in host_ip:
                errors.append(f"{name}: published ports must bind to 127.0.0.1")
    for name in ("redis", "timescaledb", "prometheus", "grafana"):
        if not IMAGE_PATTERN.fullmatch(str(services.get(name, {}).get("image", ""))):
            errors.append(f"{name}: image must use tag plus sha256 digest")
    networks = config.get("networks", {}) or {}
    expected_networks = {"bus", "data", "observability", "management", "egress"}
    if set(networks) != expected_networks:
        errors.append("top-level networks must match the exact allow-list")
    for name, network in networks.items():
        if (network or {}).get("name") not in (None, f"kairos_{name}"):
            errors.append(f"{name}: resolved network aliases another Compose project")
    for name in ("bus", "data", "observability", "management"):
        if networks.get(name, {}).get("internal") is not True:
            errors.append(f"{name}: network must be internal")
    if networks.get("egress", {}).get("internal") is True:
        errors.append("egress must remain the sole external connectivity network")
    return errors


def parse_dotenv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key.strip():
            raise ValueError(f"{path}:{number}: expected KEY=VALUE")
        result[key.strip()] = value.strip().strip("'\"")
    return result


def validate_environment(environment: dict[str, str]) -> list[str]:
    errors: list[str] = []
    required = {
        "KAIROS_SECRETS_DIR",
        "POSTGRES_USER",
        "POSTGRES_DB",
        "GRAFANA_ADMIN_USER",
    }
    for name in sorted(required):
        if not environment.get(name):
            errors.append(f"{name} must be set")
    for name in sorted(FORBIDDEN_SECRET_ENV & set(environment)):
        errors.append(f"{name} must not be stored in the Compose interpolation file")
    if "KAIROS_DRY_RUN" in environment:
        errors.append("KAIROS_DRY_RUN is retired and must be removed")
    return errors


def _github_request(url: str, *, token: str | None, accept: str) -> bytes:
    if urlsplit(url).scheme != "https":
        raise ValueError("remote source verification requires HTTPS")
    headers = {
        "Accept": accept,
        "User-Agent": "kairos-deploy-validator/2.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
        return response.read()


def verify_remote_sources(
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
                errors.append(f"{name}: GitHub resolved an unexpected revision")
            raw_base = f"https://raw.githubusercontent.com/{slug}/{revision}"
            if (
                _github_request(
                    f"{raw_base}/.python-version", token=token, accept="text/plain"
                )
                .decode()
                .strip()
                != "3.11"
            ):
                errors.append(f"{name}: .python-version must be 3.11")
            pyproject = tomllib.loads(
                _github_request(
                    f"{raw_base}/pyproject.toml", token=token, accept="text/plain"
                ).decode()
            )
            if (
                pyproject.get("tool", {}).get("uv", {}).get("required-version")
                != "==0.12.3"
            ):
                errors.append(f"{name}: pyproject must require uv ==0.12.3")
            sources = pyproject.get("tool", {}).get("uv", {}).get("sources", {})
            if (sources.get("kairos-core") or {}).get("rev") != dependencies.get(
                "kairos-core"
            ):
                errors.append(f"{name}: kairos-core SHA differs from deployment lock")
            llm_source = sources.get("kairos-llm") or {}
            if name in LLM_SERVICES:
                if llm_source.get("rev") != dependencies.get("kairos-llm"):
                    errors.append(
                        f"{name}: kairos-llm SHA differs from deployment lock"
                    )
            elif llm_source:
                errors.append(f"{name}: unexpected kairos-llm source dependency")
            persistence_source = sources.get("kairos-persistence") or {}
            if name in PERSISTENCE_SERVICES and persistence_source.get(
                "rev"
            ) != dependencies.get("kairos-persistence"):
                errors.append(
                    f"{name}: kairos-persistence SHA differs from deployment lock"
                )
            project = pyproject.get("project", {})
            if source.get("command") not in (project.get("scripts", {}) or {}):
                errors.append(
                    f"{name}: deployment command is absent from project.scripts"
                )
            packages = (
                pyproject.get("tool", {})
                .get("hatch", {})
                .get("build", {})
                .get("targets", {})
                .get("wheel", {})
                .get("packages", [])
            )
            if source.get("package_dir") not in packages:
                errors.append(
                    f"{name}: package_dir is absent from Hatch wheel packages"
                )
            if name == "execution-engine" and not project.get(
                "optional-dependencies", {}
            ).get("evedex"):
                errors.append("execution-engine: evedex optional dependency is missing")
            lock_text = _github_request(
                f"{raw_base}/uv.lock", token=token, accept="text/plain"
            ).decode()
            if dependencies.get("kairos-core") not in lock_text:
                errors.append(f"{name}: uv.lock lacks pinned kairos-core SHA")
            if name in LLM_SERVICES and dependencies.get("kairos-llm") not in lock_text:
                errors.append(f"{name}: uv.lock lacks pinned kairos-llm SHA")
            if (
                name in PERSISTENCE_SERVICES
                and dependencies.get("kairos-persistence") not in lock_text
            ):
                errors.append(f"{name}: uv.lock lacks pinned kairos-persistence SHA")
        except (OSError, ValueError, KeyError, urllib.error.HTTPError) as exc:
            errors.append(
                f"{name}: remote source verification failed ({type(exc).__name__})"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, default=Path("sources.lock.json"))
    parser.add_argument("--compose-json", type=Path)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--verify-remote", action="store_true")
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(argv)
    try:
        lock = load_json(args.source_lock)
        errors = validate_source_lock(lock)
        if args.compose_json:
            errors.extend(
                validate_compose(load_json(args.compose_json), lock, live=args.live)
            )
        if args.env_file:
            errors.extend(validate_environment(parse_dotenv(args.env_file)))
        if args.verify_remote:
            errors.extend(verify_remote_sources(lock, token=os.getenv("GITHUB_TOKEN")))
    except (
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"deployment validation could not start: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Kairos deployment validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
