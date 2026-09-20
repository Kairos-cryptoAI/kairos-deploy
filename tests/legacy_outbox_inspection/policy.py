"""Static fail-closed policy for historical 001--012 outbox evidence collection."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


PROJECT = "kairos-legacy-outbox-inspection-20260920-r1"
INSPECT_PROFILE = "legacy-outbox-inspect"
INSPECTION_CLASSIFICATION = "LEGACY_BOOTSTRAPPED_RUNTIME_001_012_READ_ONLY"
SCHEMA_PROFILE = "LEGACY_BOOTSTRAPPED_RUNTIME_001_012"
PERSISTENCE_REPOSITORY = "https://github.com/Kairos-cryptoAI/kairos-persistence"
PERSISTENCE_REVISION = "1ca8bf38d265ece7a95f749a268075549f80c043"
BOOTSTRAP_REPOSITORY = "https://github.com/Kairos-cryptoAI/kairos-deploy"
BOOTSTRAP_REVISION = "2b9aa6f569c0afe379714df767a89c5b5141bd8a"
BOOTSTRAP_PATH = "timescaledb/schema.sql"
BOOTSTRAP_GIT_BLOB_SHA1 = "6bcee345a368d4f59e55592fe6a175885fd9aa2e"
BOOTSTRAP_SHA256 = "e8160ecc8d931751e0afa37c2d17917205f3b7770b1176fb95d50a049c248928"
BOOTSTRAP_TIMESCALEDB_IMAGE = (
    "timescale/timescaledb:2.29.1-pg16@sha256:"
    "252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
)
TRUSTED_SIGNER_FINGERPRINT = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
EXPECTED_DATABASE = "kairos"
EXPECTED_SCHEMA_FINGERPRINT = "a2fec9fe81d6af73a1e44038a0e71c21d9aaf2e3933ea8c76793d9e6f25b9adf"
DOCKERFILE_SHA256 = "bba0dacdfded424cf08aa0d6925ea50a15c72cf8744caaa4df7d983dc74f2472"
DOCKERIGNORE_SHA256 = "1a37cd8475a303ae97bf1030150ad641124e4f95eb5d5346b24e6f770be4c5a5"
RUNNER_SHA256 = "a9e6cdaff96e336916062adbb2d6ed33915257ae12e6717a894d14f006bbbcd7"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
INSPECTOR_IMAGE_REFERENCE = re.compile(
    r"^(?:kairos-legacy-outbox-inspector:inspection-[0-9a-f]{16}|sha256:[0-9a-f]{64})$"
)

LEGACY_MIGRATIONS = (
    "001_audit_and_idempotency.sql",
    "002_durable_runtime.sql",
    "003_execution_effect_journal.sql",
    "004_execution_recovery_delay.sql",
    "005_source_state_and_usage.sql",
    "006_paper_trade_lifecycle.sql",
    "007_execution_runtime_health.sql",
    "008_public_execution_events.sql",
    "009_paper_canary_arms.sql",
    "010_runtime_compensation_reserve.sql",
    "011_execution_mutation_budget.sql",
    "012_outbox_producer_order.sql",
)
LEGACY_MIGRATION_SHA256 = {
    "001_audit_and_idempotency.sql": "e1bd549846225dbbf627b5204edb8298d39f10c856aa22ba570ee1b14d68bccb",
    "002_durable_runtime.sql": "19f65eb325579fb0b5820c1ac3e4869e776af7b63248681b9803ca6d5a9d9739",
    "003_execution_effect_journal.sql": "dd1fb9ef84375890d675bfdda3bf87ff0715e4c7f08bb0ac89e9967668d249df",
    "004_execution_recovery_delay.sql": "5a68a639316d3fdd530e86e6c1747e1924d618d427097bc2d481760a811744fa",
    "005_source_state_and_usage.sql": "f9d2cdb7bde828591c796158791eb8670e3b868aa40fc618cbbc06fa98b3e83c",
    "006_paper_trade_lifecycle.sql": "57d32944c98d84d9870dc7cd11630e542ae7038f45721f515d98f31291309393",
    "007_execution_runtime_health.sql": "24bf34bc82fe6e9f7a7217795600ac414df24f6b7c6da756243a697bf9defc57",
    "008_public_execution_events.sql": "0adc1093b350ccb55049c5f8065e8a315cff1bac36f309e09984122608b3ea40",
    "009_paper_canary_arms.sql": "c457ba2e1aacfec2b7810abd0cfbe4ef82cb5b132513ac3a9b6f759df7a2969a",
    "010_runtime_compensation_reserve.sql": "8f960c0a34cc855549b45c89d81c8e46760de90e3acfeb3216fc5444aaef4190",
    "011_execution_mutation_budget.sql": "b407a8089132b4f12cf692d5c04b0bcda0cc3022d0e1afb36dc7da27260a312f",
    "012_outbox_producer_order.sql": "53abce1864959c0dade0afea57daf2486a58c0d94ceebf6c0fee0797019328e8",
}

LOCK = json.loads(Path(__file__).with_name("source-lock.json").read_text(encoding="utf-8"))
EXPECTED_PROFILE_CONFIG_KEYS = {"name", "networks", "secrets", "services"}
EXPECTED_SERVICE_KEYS = {
    "profiles",
    "build",
    "cap_drop",
    "cpus",
    "command",
    "entrypoint",
    "image",
    "mem_limit",
    "networks",
    "pids_limit",
    "read_only",
    "restart",
    "secrets",
    "security_opt",
    "tmpfs",
}
FORBIDDEN_DOCKERFILE_TEXT = frozenset(
    {
        "evedex",
        "openai",
        "deepseek",
        "brightdata",
        "keys.txt",
        "docker.sock",
        "redis",
        "publisher",
        "dispatcher",
        "apply",
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
    return str(value) in {human, {"384m": "402653184"}[human]}


def _secret_sources(service: dict[str, Any]) -> set[str]:
    return {
        str(item.get("source", "")) if isinstance(item, dict) else str(item)
        for item in service.get("secrets", []) or []
    }


def validate_source_lock(lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(lock) != {
        "schema_version",
        "purpose",
        "classification",
        "readiness",
        "build",
        "artifacts",
        "dependencies",
        "trusted_receipt_signer",
        "profile",
    }:
        errors.append("legacy outbox source lock fields differ from the reviewed allow-list")
    if lock.get("schema_version") != 2:
        errors.append("legacy outbox source lock schema_version must be 2")
    if lock.get("purpose") != "read-only-legacy-bootstrapped-001-012-outbox-inspection":
        errors.append("legacy outbox source lock purpose is invalid")
    if lock.get("classification") != "ENGINEERING_RECOVERY_ONLY":
        errors.append("legacy outbox inspector must remain recovery-only")
    if lock.get("readiness") != {
        "paper_qualified": False,
        "alpha_ready": False,
        "live_ready": False,
        "strategy_policy": "REJECT_ALL",
    }:
        errors.append("legacy outbox inspector must retain fail-closed readiness")
    if lock.get("build") != {"python": "3.11.15", "uv": "0.12.3"}:
        errors.append("legacy outbox inspector must pin Python 3.11.15 and uv 0.12.3")
    if lock.get("artifacts") != {
        "dockerfile_sha256": DOCKERFILE_SHA256,
        "dockerignore_sha256": DOCKERIGNORE_SHA256,
        "runner_sha256": RUNNER_SHA256,
    }:
        errors.append("legacy outbox inspector artifact hashes changed")
    if lock.get("dependencies") != {
        "kairos-persistence": {"repository": PERSISTENCE_REPOSITORY, "revision": PERSISTENCE_REVISION}
    }:
        errors.append("legacy outbox dependencies must match the reviewed persistence source pin")
    elif not SHA1.fullmatch(str(lock["dependencies"]["kairos-persistence"]["revision"])):
        errors.append("legacy outbox persistence revision must be an immutable full Git SHA")
    if lock.get("trusted_receipt_signer") != {"fingerprint": TRUSTED_SIGNER_FINGERPRINT}:
        errors.append("legacy outbox receipt signer changed")
    expected_profile = {
        "project": PROJECT,
        "inspect_profile": INSPECT_PROFILE,
        "schema_profile": SCHEMA_PROFILE,
        "bootstrap": {
            "repository": BOOTSTRAP_REPOSITORY,
            "revision": BOOTSTRAP_REVISION,
            "path": BOOTSTRAP_PATH,
            "git_blob_sha1": BOOTSTRAP_GIT_BLOB_SHA1,
            "sha256": BOOTSTRAP_SHA256,
            "timescaledb_image": BOOTSTRAP_TIMESCALEDB_IMAGE,
        },
        "required_database": EXPECTED_DATABASE,
        "required_migrations": list(LEGACY_MIGRATIONS),
        "migration_sha256": LEGACY_MIGRATION_SHA256,
        "expected_schema_fingerprint_sha256": EXPECTED_SCHEMA_FINGERPRINT,
        "maximum_receipt_age_seconds": 7200,
    }
    if lock.get("profile") != expected_profile:
        errors.append("legacy outbox profile must remain the exact bootstrapped 001--012 read-only profile")
    bootstrap = (lock.get("profile") or {}).get("bootstrap")
    if not isinstance(bootstrap, dict) or not (
        SHA1.fullmatch(str(bootstrap.get("revision", "")))
        and SHA1.fullmatch(str(bootstrap.get("git_blob_sha1", "")))
        and SHA256.fullmatch(str(bootstrap.get("sha256", "")))
        and "@sha256:" in str(bootstrap.get("timescaledb_image", ""))
    ):
        errors.append("legacy bootstrap provenance must use immutable commit, blob, content, and image identities")
    return errors


def validate_dockerfile(text: str) -> list[str]:
    errors: list[str] = []
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != DOCKERFILE_SHA256:
        errors.append("legacy outbox Dockerfile hash differs from the reviewed artifact")
    required = (
        "git clone --filter=blob:none --no-checkout",
        "fetch --depth=1 origin",
        "uv sync --locked --no-editable --no-dev",
        "USER 65532:65532",
        'ENTRYPOINT ["python", "/app/legacy_outbox_inspection.py"]',
        "ARG RUNNER_SHA256",
        "sha256sum --check --status /tmp/runner.sha256",
    )
    for value in required:
        if value not in text:
            errors.append(f"legacy outbox Dockerfile missing required detail: {value}")
    lower = text.casefold()
    for token in FORBIDDEN_DOCKERFILE_TEXT:
        if token in lower:
            errors.append(f"legacy outbox Dockerfile must not reference {token}")
    return errors


def validate_dockerignore(text: str) -> list[str]:
    expected = """*
!Dockerfile
!runner.py
!source-lock.json
"""
    errors = []
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != DOCKERIGNORE_SHA256:
        errors.append("legacy outbox Docker context hash differs from the reviewed artifact")
    if text.replace("\r\n", "\n") != expected:
        errors.append("legacy outbox Docker context must use the exact allow-list")
    return errors


def validate_compose(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(config) != EXPECTED_PROFILE_CONFIG_KEYS:
        errors.append("legacy outbox profile must use the exact reviewed Compose top-level fields")
    if config.get("name") != PROJECT:
        errors.append("legacy outbox Compose project changed")
    if config.get("volumes") or config.get("configs"):
        errors.append("legacy outbox profile must not define durable resources")
    services = config.get("services") or {}
    if set(services) != {"legacy-outbox-inspector"}:
        return errors + ["legacy outbox profile must expose only its inspector"]
    networks = config.get("networks") or {}
    if set(networks) != {"legacy-data"}:
        errors.append("legacy outbox profile must use exactly one scoped data network")
    elif (
        not isinstance(networks["legacy-data"], dict)
        or set(networks["legacy-data"]) != {"name", "ipam", "external"}
        or networks["legacy-data"].get("external") is not True
        or networks["legacy-data"].get("ipam") != {}
        or not str(networks["legacy-data"].get("name", "")).strip()
    ):
        errors.append("legacy data network must be the exact explicit external scoped network")
    secret_definitions = config.get("secrets") or {}
    if set(secret_definitions) != {"legacy_outbox_expectation", "legacy_outbox_database_url"}:
        errors.append("legacy outbox secret definitions changed")
    for name, definition in secret_definitions.items():
        if (
            not isinstance(definition, dict)
            or set(definition) != {"name", "file"}
            or definition.get("name") != f"{PROJECT}_{name}"
            or not str(definition.get("file", "")).strip()
        ):
            errors.append(f"{name}: must be an explicit local file secret")

    service = services["legacy-outbox-inspector"]
    if set(service) != EXPECTED_SERVICE_KEYS:
        errors.append("legacy inspector service fields differ from the reviewed allow-list")
    if service.get("profiles") != [INSPECT_PROFILE]:
        errors.append("legacy inspector must require its explicit profile")
    if service.get("depends_on") or _environment(service.get("environment")):
        errors.append("legacy inspector must not start dependencies or accept runtime environment")
    if service.get("entrypoint") != ["python", "/app/legacy_outbox_inspection.py"]:
        errors.append("legacy inspector must use the dedicated read-only entrypoint")
    command = service.get("command")
    if not isinstance(command, list) or command[:5] != [
        "--expectation",
        "/run/secrets/legacy_outbox_expectation",
        "--database-url-file",
        "/run/secrets/legacy_outbox_database_url",
        "--backup-manifest-sha256",
    ] or len(command) != 10 or command[6] != "--backup-sha256" or command[8] != "--backup-created-at-utc" or not (
        SHA256.fullmatch(str(command[5])) and SHA256.fullmatch(str(command[7]))
    ) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z", str(command[9])):
        errors.append("legacy inspector command must remain exact and read-only")
    if service.get("read_only") is not True:
        errors.append("legacy inspector root filesystem must be read-only")
    if service.get("tmpfs") != ["/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64m"]:
        errors.append("legacy inspector must use only bounded disposable tmpfs")
    if service.get("cap_drop") != ["ALL"] or service.get("security_opt") != ["no-new-privileges:true"]:
        errors.append("legacy inspector must drop all capabilities and prevent privilege escalation")
    if service.get("restart") != "no":
        errors.append("legacy inspector automatic restart is forbidden")
    if not _same_memory_limit(service.get("mem_limit"), "384m") or service.get("cpus") != 0.5 or service.get("pids_limit") != 64:
        errors.append("legacy inspector resource limits changed")
    if service.get("networks") != {"legacy-data": None}:
        errors.append("legacy inspector network scope changed")
    if _secret_sources(service) != {"legacy_outbox_expectation", "legacy_outbox_database_url"} or any(
        not isinstance(item, dict)
        or set(item) != {"source", "target"}
        or item.get("source") != item.get("target")
        for item in service.get("secrets", []) or []
    ):
        errors.append("legacy inspector secret scope changed")
    build = service.get("build") or {}
    if set(build) != {"context", "dockerfile", "args", "pull"}:
        errors.append("legacy inspector build fields differ from the reviewed allow-list")
    context = str(build.get("context", "")).replace("\\", "/").rstrip("/")
    dockerfile = str(build.get("dockerfile", "")).replace("\\", "/").rstrip("/")
    if not (context == "tests/legacy_outbox_inspection" or context.endswith("/tests/legacy_outbox_inspection")):
        errors.append("legacy inspector build context must be its narrow directory")
    if not (dockerfile == "Dockerfile" or dockerfile.endswith("/Dockerfile")):
        errors.append("legacy inspector must use its dedicated Dockerfile")
    if build.get("args") != {
        "PERSISTENCE_REPOSITORY": PERSISTENCE_REPOSITORY,
        "PERSISTENCE_REVISION": PERSISTENCE_REVISION,
        "RUNNER_SHA256": RUNNER_SHA256,
    } or build.get("pull") is not True:
        errors.append("legacy inspector build must use the reviewed exact persistence source pin")
    if build.get("additional_contexts"):
        errors.append("legacy inspector additional build contexts are forbidden")
    if not isinstance(service.get("image"), str) or not INSPECTOR_IMAGE_REFERENCE.fullmatch(service["image"]):
        errors.append("legacy inspector image must be a reviewed unique tag or immutable local image ID")
    return errors


def validate_normal_up_compose(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(config) != {"name", "services"}:
        errors.append("normal-up rendering must use only the exact inert Compose fields")
    if config.get("name") != PROJECT:
        errors.append("normal-up rendering changed the legacy outbox project identity")
    if (config.get("services") or {}) != {}:
        errors.append("normal-up rendering must contain no legacy outbox services")
    if config.get("networks") or config.get("secrets") or config.get("volumes") or config.get("configs"):
        errors.append("normal-up rendering must not create legacy outbox resources")
    return errors
