"""Validate Kairos source pins, rendered Compose security, and production secrets."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

APP_SERVICES = {
    "quant-scouts",
    "text-scouts",
    "router",
    "aggregator",
    "macro-strategist",
    "risk-manager",
    "execution-engine",
}
EGRESS_SERVICES = {
    "quant-scouts",
    "text-scouts",
    "aggregator",
    "macro-strategist",
    "execution-engine",
}
LLM_SERVICES = {"text-scouts", "aggregator", "macro-strategist"}
EXPECTED_SERVICES = APP_SERVICES | {"redis", "timescaledb", "prometheus", "grafana"}
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
IMAGE_PATTERN = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
EXPECTED_REDIS_IMAGE = (
    "redis:8.2.8-alpine3.22@"
    "sha256:a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103"
)
EXPECTED_REDIS_FEATURE = "XACKDEL ref_policy=ACKED"
REDIS_PASSWORD_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{32,}$")
PRIVATE_KEY_PATTERN = re.compile(r"^0x[0-9A-Fa-f]{64}$")
PLACEHOLDER_PATTERN = re.compile(r"replace-with|changeme|example|\.\.\.", re.IGNORECASE)

SECRET_OWNERS = {
    "KAIROS_DEEPSEEK_API_KEY": {"text-scouts", "aggregator"},
    "KAIROS_OPENAI_API_KEY": {"aggregator", "macro-strategist"},
    "KAIROS_BRIGHTDATA_API_TOKEN": {"text-scouts"},
    "KAIROS_BRIGHTDATA_X_DATASET_ID": {"text-scouts"},
    "KAIROS_REDDIT_CLIENT_ID": {"text-scouts"},
    "KAIROS_REDDIT_CLIENT_SECRET": {"text-scouts"},
    "KAIROS_EVEDEX_JWT": {"execution-engine"},
    "KAIROS_EVEDEX_PRIVATE_KEY": {"execution-engine"},
    "KAIROS_CCXT_API_KEY": {"execution-engine"},
    "KAIROS_CCXT_SECRET": {"execution-engine"},
    "POSTGRES_PASSWORD": {"timescaledb"},
    "GRAFANA_ADMIN_PASSWORD": {"grafana"},
    "REDIS_PASSWORD": {"redis"},
}


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _context_map(build: dict[str, Any]) -> dict[str, str]:
    contexts = build.get("additional_contexts", {})
    if isinstance(contexts, dict):
        return {str(key): str(value) for key, value in contexts.items()}
    result: dict[str, str] = {}
    if isinstance(contexts, list):
        for item in contexts:
            name, separator, value = str(item).partition("=")
            if separator:
                result[name] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    # PowerShell 5 writes a UTF-8 BOM for `Set-Content -Encoding utf8`.
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def validate_source_lock(lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if lock.get("schema_version") != 1:
        errors.append("sources.lock.json schema_version must be 1")

    build = lock.get("build", {})
    if build.get("python") != "3.11.15":
        errors.append("source lock must pin Python 3.11.15")
    if build.get("uv") != "0.12.3":
        errors.append("source lock must pin uv 0.12.3")

    dependencies = lock.get("dependencies", {})
    for name in ("kairos-core", "kairos-llm"):
        if not SHA_PATTERN.fullmatch(str(dependencies.get(name, ""))):
            errors.append(f"dependency {name} must have a full immutable Git SHA")

    redis_runtime = (lock.get("infrastructure", {}) or {}).get("redis", {}) or {}
    if redis_runtime.get("image") != EXPECTED_REDIS_IMAGE:
        errors.append("source lock must pin the Redis 8.2.8 runtime required by kairos-core")
    if redis_runtime.get("required_feature") != EXPECTED_REDIS_FEATURE:
        errors.append("source lock must document the Redis XACKDEL ACKED-ref-policy requirement")

    services = lock.get("services", {})
    if set(services) != APP_SERVICES:
        errors.append("source lock service set does not match the Compose application services")
    for service_name in sorted(APP_SERVICES):
        entry = services.get(service_name, {})
        repository = str(entry.get("repository", ""))
        revision = str(entry.get("revision", ""))
        if repository != f"https://github.com/Kairos-cryptoAI/kairos-{service_name}":
            errors.append(f"{service_name}: unexpected source repository {repository!r}")
        if not SHA_PATTERN.fullmatch(revision):
            errors.append(f"{service_name}: revision must be a full immutable Git SHA")
        if not str(entry.get("package_dir", "")):
            errors.append(f"{service_name}: package_dir is required")
        if not str(entry.get("command", "")):
            errors.append(f"{service_name}: command is required")
    if services.get("execution-engine", {}).get("extra") != "evedex":
        errors.append("execution-engine must install the evedex extra")
    return errors


def validate_compose(config: dict[str, Any], lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    services = config.get("services", {})
    if set(services) != EXPECTED_SERVICES:
        errors.append("rendered Compose service set is incomplete or contains unexpected services")

    for service_name, service in services.items():
        if service.get("env_file"):
            errors.append(f"{service_name}: env_file is forbidden; use an explicit allow-list")
        if service.get("privileged"):
            errors.append(f"{service_name}: privileged containers are forbidden")
        for volume in service.get("volumes", []) or []:
            source = str(volume.get("source", "") if isinstance(volume, dict) else volume)
            if "docker.sock" in source:
                errors.append(f"{service_name}: mounting the Docker socket is forbidden")

        environment = service.get("environment", {}) or {}
        for secret_name, owners in SECRET_OWNERS.items():
            if secret_name in environment and service_name not in owners:
                errors.append(f"{service_name}: must not receive {secret_name}")

    source_services = lock.get("services", {})
    for service_name in sorted(APP_SERVICES):
        service = services.get(service_name, {})
        environment = service.get("environment", {}) or {}
        redis_url = str(environment.get("KAIROS_REDIS_URL", ""))
        if not redis_url.startswith("redis://:") or "@redis:6379/0" not in redis_url:
            errors.append(f"{service_name}: KAIROS_REDIS_URL must contain Redis authentication")
        if "KAIROS_REDIS_PASSWORD" in environment:
            errors.append(f"{service_name}: raw Redis password must not be injected separately")

        if service.get("read_only") is not True:
            errors.append(f"{service_name}: root filesystem must be read-only")
        if "ALL" not in (service.get("cap_drop") or []):
            errors.append(f"{service_name}: all Linux capabilities must be dropped")
        if "no-new-privileges:true" not in (service.get("security_opt") or []):
            errors.append(f"{service_name}: no-new-privileges must be enabled")

        redis_dependency = (service.get("depends_on") or {}).get("redis", {})
        if not isinstance(redis_dependency, dict) or redis_dependency.get("condition") != "service_healthy":
            errors.append(f"{service_name}: must wait for a healthy Redis")

        networks = set(service.get("networks", {}) or [])
        if not {"bus", "observability"}.issubset(networks):
            errors.append(f"{service_name}: bus and observability networks are required")
        if (service_name in EGRESS_SERVICES) != ("egress" in networks):
            errors.append(f"{service_name}: egress network assignment violates the allow-list")

        source = source_services.get(service_name, {})
        repository = str(source.get("repository", ""))
        revision = str(source.get("revision", ""))
        build = service.get("build", {}) or {}
        context = _context_map(build).get("service", "")
        if context != f"{repository}.git#{revision}":
            errors.append(f"{service_name}: named build context differs from sources.lock.json")
        args = build.get("args", {}) or {}
        if str(args.get("SOURCE_REVISION", "")) != revision:
            errors.append(f"{service_name}: OCI source revision differs from the source lock")
        if str(args.get("PACKAGE_DIR", "")) != str(source.get("package_dir", "")):
            errors.append(f"{service_name}: package directory differs from the source lock")
        expected_command = str(source.get("command", ""))
        command = service.get("command", [])
        if command != [expected_command]:
            errors.append(f"{service_name}: command differs from the source lock")

    execution = services.get("execution-engine", {})
    execution_env = execution.get("environment", {}) or {}
    if (execution.get("build", {}).get("args", {}) or {}).get("SERVICE_EXTRA") != "evedex":
        errors.append("execution-engine must build with SERVICE_EXTRA=evedex")
    for required in ("KAIROS_EVEDEX_JWT", "KAIROS_EVEDEX_PRIVATE_KEY"):
        if not str(execution_env.get(required, "")):
            errors.append(f"execution-engine must receive non-empty {required}")

    risk_env = (services.get("risk-manager", {}).get("environment", {}) or {})
    if not _is_true(risk_env.get("KAIROS_REQUIRE_RECONCILED_ACCOUNT")):
        errors.append("risk-manager reconciliation gate must stay enabled")
    if not _is_true(risk_env.get("KAIROS_REQUIRE_STRATEGIC_ALLOCATION")):
        errors.append("risk-manager strategic allocation gate must stay enabled")
    try:
        if float(execution_env["KAIROS_ACCOUNT_SNAPSHOT_INTERVAL_S"]) >= float(
            risk_env["KAIROS_ACCOUNT_SNAPSHOT_MAX_AGE_S"]
        ):
            errors.append("account snapshot cadence must be faster than the Risk freshness window")
    except (KeyError, TypeError, ValueError):
        errors.append("account snapshot cadence and freshness window must be numeric")

    redis = services.get("redis", {})
    redis_runtime = (lock.get("infrastructure", {}) or {}).get("redis", {}) or {}
    redis_image = str(redis.get("image", ""))
    if redis_image != redis_runtime.get("image") or redis_image != EXPECTED_REDIS_IMAGE:
        errors.append("Redis image must match the pinned 8.2.8 runtime required for XACKDEL ACKED")
    redis_command = " ".join(str(part) for part in (redis.get("command") or []))
    if redis.get("ports"):
        errors.append("Redis must not publish a host port")
    if "requirepass" not in redis_command:
        errors.append("Redis must enforce password authentication")
    if not redis.get("healthcheck"):
        errors.append("Redis must have an authenticated healthcheck")
    if "REDIS_PASSWORD" not in (redis.get("environment", {}) or {}):
        errors.append("Redis must receive its password")

    if services.get("timescaledb", {}).get("ports"):
        errors.append("TimescaleDB must not publish a host port")
    for service_name in ("prometheus", "grafana"):
        for port in services.get(service_name, {}).get("ports", []) or []:
            host_ip = str(port.get("host_ip", "") if isinstance(port, dict) else port)
            if "127.0.0.1" not in host_ip:
                errors.append(f"{service_name}: published ports must bind to 127.0.0.1")

    for service_name in ("redis", "timescaledb", "prometheus", "grafana"):
        image = str(services.get(service_name, {}).get("image", ""))
        if not IMAGE_PATTERN.fullmatch(image):
            errors.append(f"{service_name}: image must use tag plus sha256 digest")

    networks = config.get("networks", {}) or {}
    for network_name in ("bus", "data", "observability"):
        if networks.get(network_name, {}).get("internal") is not True:
            errors.append(f"{network_name}: network must be internal")
    return errors


def parse_dotenv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        if not separator or not key.strip():
            raise ValueError(f"{path}:{line_number}: expected KEY=VALUE")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        result[key.strip()] = value
    return result


def validate_environment(environment: dict[str, str]) -> list[str]:
    errors: list[str] = []
    required = {
        "KAIROS_REDIS_PASSWORD",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "POSTGRES_DB",
        "GRAFANA_ADMIN_USER",
        "GRAFANA_ADMIN_PASSWORD",
        "KAIROS_DEEPSEEK_API_KEY",
        "KAIROS_OPENAI_API_KEY",
        "KAIROS_EVEDEX_JWT",
        "KAIROS_EVEDEX_PRIVATE_KEY",
    }
    for name in sorted(required):
        value = environment.get(name, "")
        if not value:
            errors.append(f"{name} must be set")
        elif PLACEHOLDER_PATTERN.search(value):
            errors.append(f"{name} still contains an example placeholder")

    redis_password = environment.get("KAIROS_REDIS_PASSWORD", "")
    if redis_password and not REDIS_PASSWORD_PATTERN.fullmatch(redis_password):
        errors.append("KAIROS_REDIS_PASSWORD must be at least 32 URL-safe characters")
    for name in ("POSTGRES_PASSWORD", "GRAFANA_ADMIN_PASSWORD"):
        value = environment.get(name, "")
        if value and len(value) < 20:
            errors.append(f"{name} must contain at least 20 characters")
    infrastructure_passwords = [
        environment.get("KAIROS_REDIS_PASSWORD", ""),
        environment.get("POSTGRES_PASSWORD", ""),
        environment.get("GRAFANA_ADMIN_PASSWORD", ""),
    ]
    populated_passwords = [value for value in infrastructure_passwords if value]
    if len(set(populated_passwords)) != len(populated_passwords):
        errors.append("Redis, PostgreSQL, and Grafana must use distinct passwords")

    private_key = environment.get("KAIROS_EVEDEX_PRIVATE_KEY", "")
    if private_key and not PRIVATE_KEY_PATTERN.fullmatch(private_key):
        errors.append("KAIROS_EVEDEX_PRIVATE_KEY must be 0x followed by 64 hexadecimal characters")
    jwt = environment.get("KAIROS_EVEDEX_JWT", "")
    if jwt and len(jwt) < 20:
        errors.append("KAIROS_EVEDEX_JWT is unexpectedly short")

    for left, right in (
        ("KAIROS_BRIGHTDATA_API_TOKEN", "KAIROS_BRIGHTDATA_X_DATASET_ID"),
        ("KAIROS_REDDIT_CLIENT_ID", "KAIROS_REDDIT_CLIENT_SECRET"),
    ):
        if bool(environment.get(left)) != bool(environment.get(right)):
            errors.append(f"{left} and {right} must be configured together")
    return errors


def _github_request(url: str, *, token: str | None, accept: str) -> bytes:
    headers = {
        "Accept": accept,
        "User-Agent": "kairos-deploy-validator/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def verify_remote_sources(lock: dict[str, Any], *, token: str | None = None) -> list[str]:
    errors: list[str] = []
    dependencies = lock.get("dependencies", {})
    for service_name, source in sorted((lock.get("services", {}) or {}).items()):
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
                errors.append(f"{service_name}: GitHub resolved an unexpected revision")

            raw_base = f"https://raw.githubusercontent.com/{slug}/{revision}"
            python_version = _github_request(
                f"{raw_base}/.python-version", token=token, accept="text/plain"
            ).decode("utf-8").strip()
            if python_version != "3.11":
                errors.append(f"{service_name}: .python-version must be 3.11")
            pyproject = tomllib.loads(
                _github_request(f"{raw_base}/pyproject.toml", token=token, accept="text/plain").decode(
                    "utf-8"
                )
            )
            if pyproject.get("tool", {}).get("uv", {}).get("required-version") != "==0.12.3":
                errors.append(f"{service_name}: pyproject must require uv ==0.12.3")
            sources = pyproject.get("tool", {}).get("uv", {}).get("sources", {})
            if (sources.get("kairos-core") or {}).get("rev") != dependencies.get("kairos-core"):
                errors.append(f"{service_name}: kairos-core SHA differs from the deployment lock")
            llm_source = sources.get("kairos-llm") or {}
            if service_name in LLM_SERVICES:
                if llm_source.get("rev") != dependencies.get("kairos-llm"):
                    errors.append(f"{service_name}: kairos-llm SHA differs from the deployment lock")
            elif llm_source:
                errors.append(f"{service_name}: unexpected kairos-llm source dependency")

            project = pyproject.get("project", {})
            if source.get("command") not in (project.get("scripts", {}) or {}):
                errors.append(f"{service_name}: deployment command is absent from project.scripts")
            packages = (
                pyproject.get("tool", {})
                .get("hatch", {})
                .get("build", {})
                .get("targets", {})
                .get("wheel", {})
                .get("packages", [])
            )
            if source.get("package_dir") not in packages:
                errors.append(f"{service_name}: package_dir is absent from Hatch wheel packages")
            if service_name == "execution-engine":
                extras = project.get("optional-dependencies", {})
                if not extras.get("evedex"):
                    errors.append("execution-engine: evedex optional dependency is missing")
            lock_text = _github_request(
                f"{raw_base}/uv.lock", token=token, accept="text/plain"
            ).decode("utf-8")
            if dependencies.get("kairos-core") not in lock_text:
                errors.append(f"{service_name}: uv.lock does not contain the pinned kairos-core SHA")
            if service_name in LLM_SERVICES and dependencies.get("kairos-llm") not in lock_text:
                errors.append(f"{service_name}: uv.lock does not contain the pinned kairos-llm SHA")
        except (OSError, ValueError, KeyError, urllib.error.HTTPError) as exc:
            errors.append(f"{service_name}: remote source verification failed ({type(exc).__name__})")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, default=Path("sources.lock.json"))
    parser.add_argument("--compose-json", type=Path)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--verify-remote", action="store_true")
    args = parser.parse_args(argv)

    try:
        lock = load_json(args.source_lock)
        errors = validate_source_lock(lock)
        if args.compose_json:
            errors.extend(validate_compose(load_json(args.compose_json), lock))
        if args.env_file:
            errors.extend(validate_environment(parse_dotenv(args.env_file)))
        if args.verify_remote:
            errors.extend(verify_remote_sources(lock, token=os.getenv("GITHUB_TOKEN")))
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
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
