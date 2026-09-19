"""Fail-closed test targets. No connection or migration occurs in validation."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
from pathlib import Path

PROJECT = "kairos-release-gate-20260919-r2"
DATABASE = "kairos_execution_test_202609190002"
# Deliberately public synthetic credential, valid only in this new internal project.
DATABASE_URL = f"postgresql://kairos:synthetic_release_gate_only@timescaledb:5432/{DATABASE}"
REDIS_URL = "redis://redis:6379/0"
CONFIRMATION = "ISOLATED_SYNTHETIC_RELEASE_GATE_ONLY"
DATA_IMAGES = {
    "timescaledb": (
        "timescale/timescaledb:2.28.3-pg16@sha256:"
        "61f891691050da6032023c01ea885730eeeba06b7c17b403e7d0b9c49c37dfe9"
    ),
    "redis": (
        "redis:8.2.8-alpine3.22@sha256:a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103"
    ),
}
RESOURCE_LIMITS = {
    "timescaledb": {"mem_limit": "768m"},
    "redis": {"mem_limit": "128m"},
    "gate": {"mem_limit": "1g", "cpus": 2.0, "pids_limit": 128},
}
PINS = {
    "kairos-core": "91cd95c8e5bd4393ed04606df08c205583092df7",
    "kairos-persistence": "526c30feddcaf4b7147449e6e513fec61c43d75f",
    "kairos-strategy-engine": "6a16440747dee357b40a18434634449f05b7b824",
    "kairos-router": "053e90b6adaf0f7db5374f76934bc33095be0b0e",
    "kairos-llm": "d824343d67f001ae0cce51bf8af9427529f7b76c",
    "kairos-aggregator": "cef492848ae0687f2f720bc0723953e0e0e1cc97",
    "kairos-risk-manager": "a10649ce2e6b802214ff48436c93fd2322f140bf",
    "kairos-execution-engine": "73122e825b333281d4fd4acce1c57f90c4cc511c",
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


def validate_environment(environment=None):
    env = os.environ if environment is None else environment
    expected = {
        "KAIROS_RELEASE_GATE_CONFIRM": CONFIRMATION,
        "KAIROS_RELEASE_GATE_PROJECT": PROJECT,
        "KAIROS_EXECUTION_TEST_DATABASE": DATABASE,
        "KAIROS_PERSISTENCE_DATABASE_URL": DATABASE_URL,
        "KAIROS_REDIS_URL": REDIS_URL,
    }
    if any(env.get(key) != value for key, value in expected.items()):
        raise ValueError("release gate requires its exact isolated synthetic targets and explicit opt-in")
    forbidden = ("OPENAI", "DEEPSEEK", "BEARER", "PRIVATE_KEY", "SIGNING_KEY", "API_KEY", "JWT")
    if any(value and any(token in key.upper() for token in forbidden) for key, value in env.items()):
        raise ValueError("real credential environment variables are forbidden in the release gate")
    if Path(".env").exists():
        raise ValueError("release gate must not load a workspace .env")


async def connect_verified(database):
    """Pin the pool's actual server identity BEFORE normal service auto-migration."""
    validate_environment()
    if database.settings.database_url != DATABASE_URL:
        raise ValueError("service persistence target differs from the verified test DSN")
    await database.connect()
    if await database.pool.fetchval("SELECT current_database()") != DATABASE:
        await database.close()
        raise ValueError("connected server is not the explicitly selected disposable database")


async def require_fresh_database(database):
    """Fail before migrate or fixture writes when a prior run left any schema."""
    await connect_verified(database)
    if await database.pool.fetchval("SELECT count(*) FROM pg_tables WHERE schemaname='public'"):
        raise ValueError(
            "release gate requires a fresh database; preserve previous evidence instead of cleaning it"
        )


def validate_installed_sources():
    for name, revision in PINS.items():
        distribution = importlib.metadata.distribution(name)
        direct = json.loads(distribution.read_text("direct_url.json") or "{}")
        if direct.get("vcs_info", {}).get("commit_id") != revision:
            raise ValueError(f"release gate dependency is not the pinned Git installation: {name}")
        if direct.get("dir_info", {}).get("editable"):
            raise ValueError("editable production dependency replacements are forbidden")
        expected_url = f"https://github.com/Kairos-cryptoAI/{name}.git"
        if direct.get("url") != expected_url:
            raise ValueError("release gate dependency repository differs from the published source")
        package = MODULES[name]
        root = Path(distribution.locate_file("")).resolve()
        expected = Path(distribution.locate_file(f"{package}/__init__.py")).resolve()
        actual_file = getattr(importlib.import_module(package), "__file__", None)
        if (
            "site-packages" not in root.parts
            or not expected.is_relative_to(root)
            or actual_file is None
            or Path(actual_file).resolve() != expected
        ):
            raise ValueError(f"production package import is not the installed pinned distribution: {name}")


def validate_compose(document):
    """Static isolation policy; this function never invokes Docker."""
    if document.get("name") != PROJECT or set(document.get("services", {})) != {
        "timescaledb",
        "redis",
        "gate",
    }:
        raise ValueError("unexpected release gate project or service set")
    if document.get("networks") != {"isolated": {"internal": True}}:
        raise ValueError("release gate network must be new, internal and unshared")
    if document.get("volumes") or document.get("secrets") or document.get("configs"):
        raise ValueError("release gate must not reuse persistent volumes, secrets or configs")
    forbidden = (
        "ports",
        "volumes",
        "secrets",
        "configs",
        "env_file",
        "extra_hosts",
        "network_mode",
        "privileged",
        "devices",
        "pid",
        "ipc",
        "cap_add",
        "container_name",
    )
    for name, service in document["services"].items():
        if any(service.get(key) for key in forbidden):
            raise ValueError(f"unsafe release gate service bindings: {name}")
        if service.get("networks") != ["isolated"] or service.get("restart") != "no":
            raise ValueError("gate services must stay isolated and never restart automatically")
        if any(service.get(key) != value for key, value in RESOURCE_LIMITS[name].items()):
            raise ValueError(f"release gate service requires its exact resource limits: {name}")
    gate = document["services"]["gate"]
    validate_environment(gate.get("environment", {}))
    if gate.get("build") != {"context": ".", "dockerfile": "Dockerfile"}:
        raise ValueError("release gate must build only its narrow test context")
    if gate.get("read_only") is not True or gate.get("cap_drop") != ["ALL"]:
        raise ValueError("release gate runner must be read-only and unprivileged")
    if gate.get("security_opt") != ["no-new-privileges:true"]:
        raise ValueError("release gate runner must forbid new privileges")
    postgres = document["services"]["timescaledb"]
    if postgres.get("environment") != {
        "POSTGRES_USER": "kairos",
        "POSTGRES_PASSWORD": "synthetic_release_gate_only",
        "POSTGRES_DB": DATABASE,
    }:
        raise ValueError("release gate PostgreSQL credentials must be synthetic and fixed")
    for name, image in DATA_IMAGES.items():
        if document["services"][name].get("image") != image:
            raise ValueError("release gate data service image must match its exact pinned image")
    if postgres.get("tmpfs") != ["/var/lib/postgresql/data:rw,nosuid,size=512m"]:
        raise ValueError("release gate PostgreSQL data must be disposable tmpfs")
    if document["services"]["redis"].get("tmpfs") != ["/data:rw,nosuid,size=64m"]:
        raise ValueError("release gate Redis data must be disposable tmpfs")
