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
    for name in ("kairos-core", "kairos-llm"):
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
    return errors


def _validate_source_service(
    name: str, service: dict[str, Any], source: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    repository = str(source.get("repository", ""))
    revision = str(source.get("revision", ""))
    build = service.get("build", {}) or {}
    if _context_map(build).get("service") != f"{repository}.git#{revision}":
        errors.append(f"{name}: named build context differs from sources.lock.json")
    args = build.get("args", {}) or {}
    if str(args.get("SOURCE_REVISION", "")) != revision:
        errors.append(f"{name}: OCI source revision differs from the source lock")
    if str(args.get("PACKAGE_DIR", "")) != str(source.get("package_dir", "")):
        errors.append(f"{name}: package directory differs from the source lock")
    if service.get("command", []) != [str(source.get("command", ""))]:
        errors.append(f"{name}: command differs from the source lock")
    return errors


def validate_compose(
    config: dict[str, Any], lock: dict[str, Any], *, live: bool = False
) -> list[str]:
    errors: list[str] = []
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
        for volume in service.get("volumes", []) or []:
            source = str(
                volume.get("source", "") if isinstance(volume, dict) else volume
            )
            if "docker.sock" in source:
                errors.append(f"{name}: mounting the Docker socket is forbidden")
        environment = service.get("environment", {}) or {}
        for secret in sorted(FORBIDDEN_SECRET_ENV & set(environment)):
            errors.append(
                f"{name}: secret {secret} must be file-mounted, not an environment value"
            )

    source_services = lock.get("services", {}) or {}
    for name in sorted(SOURCE_SERVICES):
        service = services.get(name, {}) or {}
        errors.extend(
            _validate_source_service(name, service, source_services.get(name, {}))
        )
        if service.get("read_only") is not True:
            errors.append(f"{name}: root filesystem must be read-only")
        if "ALL" not in (service.get("cap_drop") or []):
            errors.append(f"{name}: all Linux capabilities must be dropped")
        if "no-new-privileges:true" not in (service.get("security_opt") or []):
            errors.append(f"{name}: no-new-privileges must be enabled")
        dependencies = service.get("depends_on") or {}
        for dependency in ("redis", "timescaledb"):
            requirement = dependencies.get(dependency, {})
            if (
                not isinstance(requirement, dict)
                or requirement.get("condition") != "service_healthy"
            ):
                errors.append(f"{name}: must wait for healthy {dependency}")
        networks = set(service.get("networks", {}) or [])
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

    execution = services.get("execution-engine", {}) or {}
    execution_env = execution.get("environment", {}) or {}
    if (execution.get("build", {}).get("args", {}) or {}).get(
        "SERVICE_EXTRA"
    ) != "evedex":
        errors.append("execution-engine must build with SERVICE_EXTRA=evedex")
    execution_secrets = _secret_sources(execution)
    execution_bindings = _bindings(execution)
    if live:
        if _is_true(execution_env.get("KAIROS_DRY_RUN")):
            errors.append("live Compose must set execution-engine dry-run to false")
        for name, path in {
            "KAIROS_EVEDEX_JWT": "/run/secrets/evedex_jwt",
            "KAIROS_EVEDEX_PRIVATE_KEY": "/run/secrets/evedex_private_key",
        }.items():
            if execution_bindings.get(name) != path:
                errors.append(f"live Compose must bind {name} from its secret file")
        if not {"evedex_jwt", "evedex_private_key"}.issubset(execution_secrets):
            errors.append("live Compose must mount both EVEDEX credential files")
    else:
        if not _is_true(execution_env.get("KAIROS_DRY_RUN")):
            errors.append("base Compose must keep execution-engine in dry-run")
        if {"evedex_jwt", "evedex_private_key"} & execution_secrets:
            errors.append("base Compose must not mount EVEDEX live credentials")

    expected_provider_secrets = {
        "text-scouts": {"deepseek_api_key"},
        "aggregator": {"openai_api_key"},
        "macro-strategist": {"openai_api_key"},
    }
    for name, expected in expected_provider_secrets.items():
        sources = _secret_sources(services.get(name, {}) or {})
        if not expected.issubset(sources):
            errors.append(f"{name}: expected provider secret file is missing")

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
    for name in ("bus", "data", "observability"):
        if networks.get(name, {}).get("internal") is not True:
            errors.append(f"{name}: network must be internal")
    if (
        "management" not in networks
        or networks.get("management", {}).get("internal") is True
    ):
        errors.append("management: a non-internal host-publishing network is required")
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
    if not _is_true(environment.get("KAIROS_DRY_RUN", "true")):
        errors.append("base environment must keep KAIROS_DRY_RUN=true")
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
