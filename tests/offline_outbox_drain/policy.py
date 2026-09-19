"""Static fail-closed policy for a signed bounded offline outbox drain."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

PROJECT = "kairos-offline-outbox-drain-20260920-r1"
INSPECT_PROFILE = "offline-outbox-drain-inspect"
APPLY_PROFILE = "offline-outbox-drain-apply"
APPLY_CONFIRMATION = "OFFLINE_OUTBOX_SIGNED_PREFIX_ONLY"
TRUSTED_SIGNER_FINGERPRINT = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
CORE_REVISION = "52aba6b158a52754784162987e7af4ad24c06669"
PERSISTENCE_REVISION = "9219e5ef46c748703d949b324d84f6814ba0f196"
MAXIMUM_RECEIPT_AGE_SECONDS = 300
MAXIMUM_ROWS = 100
MAXIMUM_DURATION_SECONDS = 300
ALLOWED_PRODUCER = "kairos-quant-scouts"
ALLOWED_TOPIC = "kairos.market.closed_bar.v1"
REQUIRED_MIGRATIONS = (
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
    "013_campaign_source_budgets.sql",
    "014_bounded_canary_sessions.sql",
    "015_canary_dispatch_claims.sql",
    "016_global_canary_session_guard.sql",
    "017_simulator_journal.sql",
    "018_offline_outbox_reconciliation.sql",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
LOCK = json.loads(Path(__file__).with_name("source-lock.json").read_text(encoding="utf-8"))

FORBIDDEN_SERVICE_OPTIONS = frozenset(
    {
        "ports",
        "volumes",
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
FORBIDDEN_TEXT = frozenset(
    {
        "evedex",
        "openai",
        "deepseek",
        "brightdata",
        "keys.txt",
        "docker.sock",
        "paper_canary",
        "collector",
        "strategy",
        "execution",
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


def _profile() -> dict[str, object]:
    return {
        "project": PROJECT,
        "inspect_profile": INSPECT_PROFILE,
        "apply_profile": APPLY_PROFILE,
        "apply_confirmation": APPLY_CONFIRMATION,
        "maximum_receipt_age_seconds": MAXIMUM_RECEIPT_AGE_SECONDS,
        "maximum_rows": MAXIMUM_ROWS,
        "maximum_duration_seconds": MAXIMUM_DURATION_SECONDS,
        "required_migrations": list(REQUIRED_MIGRATIONS),
        "allowed_producer": ALLOWED_PRODUCER,
        "allowed_topic": ALLOWED_TOPIC,
    }


def validate_source_lock(lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if lock.get("schema_version") != 1:
        errors.append("offline outbox drain source lock schema_version must be 1")
    if lock.get("purpose") != "operator-assisted-bounded-offline-outbox-drain":
        errors.append("offline outbox drain source lock purpose is invalid")
    if lock.get("classification") != "ENGINEERING_RECOVERY_ONLY":
        errors.append("offline outbox drain must remain recovery-only")
    if lock.get("readiness") != {
        "paper_qualified": False,
        "alpha_ready": False,
        "live_ready": False,
        "strategy_policy": "REJECT_ALL",
    }:
        errors.append("offline outbox drain must retain fail-closed readiness")
    if lock.get("build") != {"python": "3.11.15", "uv": "0.12.3"}:
        errors.append("offline outbox drain must pin Python 3.11.15 and uv 0.12.3")
    expected_dependencies = {
        "kairos-core": {
            "repository": "https://github.com/Kairos-cryptoAI/kairos-core",
            "revision": CORE_REVISION,
        },
        "kairos-persistence": {
            "repository": "https://github.com/Kairos-cryptoAI/kairos-persistence",
            "revision": PERSISTENCE_REVISION,
        },
    }
    dependencies = lock.get("dependencies")
    if dependencies != expected_dependencies:
        errors.append("offline outbox drain dependencies must match reviewed exact source pins")
    elif not all(SHA1.fullmatch(str(item["revision"])) for item in dependencies.values()):
        errors.append("offline outbox drain dependencies must use immutable full Git SHAs")
    signer = lock.get("trusted_receipt_signer")
    if not isinstance(signer, dict) or signer.get("fingerprint") != TRUSTED_SIGNER_FINGERPRINT:
        errors.append("offline outbox drain trusted receipt signer changed")
    elif signer.get("public_key_file") != "tests/offline_outbox_drain/trusted-signer.asc":
        errors.append("offline outbox drain trusted receipt key location changed")
    elif not SHA256.fullmatch(str(signer.get("public_key_sha256", ""))):
        errors.append("offline outbox drain trusted receipt key hash is invalid")
    if lock.get("profile") != _profile():
        errors.append("offline outbox drain profile must remain exact and bounded")
    return errors


def validate_trusted_signer(path: Path, lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        content = path.read_bytes()
    except OSError:
        return ["offline outbox drain trusted signer file is missing"]
    signer = lock.get("trusted_receipt_signer") or {}
    if hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest() != signer.get("public_key_sha256"):
        errors.append("offline outbox drain trusted signer file hash differs from source lock")
    text = content.decode("ascii", errors="replace")
    if not text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----") or not text.rstrip().endswith(
        "-----END PGP PUBLIC KEY BLOCK-----"
    ):
        errors.append("offline outbox drain trusted signer must be a detached public key block")
    return errors


def validate_dockerfile(text: str) -> list[str]:
    errors: list[str] = []
    required = (
        "git clone --filter=blob:none --no-checkout",
        "fetch --depth=1 origin",
        "uv sync --locked --no-editable --no-dev",
        "gpg=2.2.40-1.1+deb12u2",
        "gpg-agent=2.2.40-1.1+deb12u2",
        "gpgv=2.2.40-1.1+deb12u2",
        "USER 65532:65532",
        "ENTRYPOINT [\"python\", \"/app/offline_outbox_drain.py\"]",
    )
    for value in required:
        if value not in text:
            errors.append(f"offline outbox drain Dockerfile missing required detail: {value}")
    lower = text.casefold()
    for token in FORBIDDEN_TEXT:
        if token in lower:
            errors.append(f"offline outbox drain Dockerfile must not reference {token}")
    return errors


def validate_dockerignore(text: str) -> list[str]:
    expected = """*
!Dockerfile
!runner.py
!source-lock.json
!trusted-signer.asc
"""
    if text.replace("\r\n", "\n") != expected:
        return ["offline outbox drain Docker context must use the exact allow-list"]
    return []


def _validate_runtime_service(
    name: str,
    service: dict[str, Any],
    *,
    profile: str,
    networks: set[str],
    secrets: set[str],
) -> list[str]:
    errors: list[str] = []
    if service.get("profiles") != [profile]:
        errors.append(f"{name}: must require exactly the {profile} profile")
    if service.get("depends_on"):
        errors.append(f"{name}: must not start or wait for other services")
    if _environment(service.get("environment")):
        errors.append(f"{name}: runtime environment is forbidden")
    for option in FORBIDDEN_SERVICE_OPTIONS:
        if service.get(option):
            errors.append(f"{name}: unsafe service option {option}")
    if service.get("entrypoint") != ["python", "/app/offline_outbox_drain.py"]:
        errors.append(f"{name}: must use the dedicated one-shot runner entrypoint")
    if service.get("command") != [
        "--mode",
        "inspect",
        "--plan",
        "/run/secrets/offline_outbox_drain_plan",
        "--database-url-file",
        "/run/secrets/offline_outbox_drain_database_url",
    ]:
        errors.append(f"{name}: must default to inspect-only mode")
    if service.get("read_only") is not True:
        errors.append(f"{name}: root filesystem must be read-only")
    if service.get("tmpfs") != ["/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64m"]:
        errors.append(f"{name}: must use only bounded disposable tmpfs")
    if service.get("cap_drop") != ["ALL"] or service.get("security_opt") != ["no-new-privileges:true"]:
        errors.append(f"{name}: must drop all capabilities and prevent privilege escalation")
    if service.get("restart") != "no":
        errors.append(f"{name}: automatic restart is forbidden")
    if not _same_memory_limit(service.get("mem_limit"), "384m") or service.get("cpus") != 0.5 or service.get(
        "pids_limit"
    ) != 64:
        errors.append(f"{name}: bounded resource limits changed")
    if set(service.get("networks") or ()) != networks:
        errors.append(f"{name}: network scope changed")
    if _secret_sources(service) != secrets:
        errors.append(f"{name}: secret scope changed")
    build = service.get("build") or {}
    context = str(build.get("context", "")).replace("\\", "/").rstrip("/")
    dockerfile = str(build.get("dockerfile", "")).replace("\\", "/").rstrip("/")
    expected_args = {
        "PERSISTENCE_REPOSITORY": "https://github.com/Kairos-cryptoAI/kairos-persistence",
        "PERSISTENCE_REVISION": PERSISTENCE_REVISION,
    }
    if not (context == "tests/offline_outbox_drain" or context.endswith("/tests/offline_outbox_drain")):
        errors.append(f"{name}: build context must be the narrow drain directory")
    if not (dockerfile == "Dockerfile" or dockerfile.endswith("/Dockerfile")):
        errors.append(f"{name}: must use the dedicated drain Dockerfile")
    if build.get("args") != expected_args or build.get("pull") is not True:
        errors.append(f"{name}: build must use the reviewed exact persistence source pin")
    if build.get("additional_contexts"):
        errors.append(f"{name}: additional build contexts are forbidden")
    if service.get("image") != "kairos-offline-outbox-drain:20260920-r1":
        errors.append(f"{name}: image identity changed")
    return errors


def validate_compose(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("name") != PROJECT:
        errors.append("offline outbox drain Compose project changed")
    if config.get("volumes") or config.get("configs"):
        errors.append("offline outbox drain profile must not define durable resources")
    services = config.get("services") or {}
    if set(services) != {"outbox-drain-inspector", "outbox-drainer"}:
        errors.append("offline outbox drain profile must expose only the inspector and drainer")
        return errors
    networks = config.get("networks") or {}
    if set(networks) != {"offline-data", "offline-bus"}:
        errors.append("offline outbox drain profile must use exactly scoped data and bus networks")
    for name in ("offline-data", "offline-bus"):
        network = networks.get(name) or {}
        if network.get("external") is not True or not str(network.get("name", "")).strip():
            errors.append(f"{name}: must be a supplied external scoped network")
    secret_definitions = config.get("secrets") or {}
    expected_secret_names = {
        "offline_outbox_drain_plan",
        "offline_outbox_drain_receipt",
        "offline_outbox_drain_receipt_signature",
        "offline_outbox_drain_database_url",
        "offline_outbox_drain_redis_url",
    }
    if set(secret_definitions) != expected_secret_names:
        errors.append("offline outbox drain profile secret definitions changed")
    for name, definition in secret_definitions.items():
        if not isinstance(definition, dict) or not str(definition.get("file", "")).strip():
            errors.append(f"{name}: must be a local explicit file secret")
        if definition.get("external"):
            errors.append(f"{name}: external secrets are forbidden")
    errors.extend(
        _validate_runtime_service(
            "outbox-drain-inspector",
            services["outbox-drain-inspector"],
            profile=INSPECT_PROFILE,
            networks={"offline-data"},
            secrets={"offline_outbox_drain_plan", "offline_outbox_drain_database_url"},
        )
    )
    errors.extend(
        _validate_runtime_service(
            "outbox-drainer",
            services["outbox-drainer"],
            profile=APPLY_PROFILE,
            networks={"offline-data", "offline-bus"},
            secrets={
                "offline_outbox_drain_plan",
                "offline_outbox_drain_receipt",
                "offline_outbox_drain_receipt_signature",
                "offline_outbox_drain_database_url",
                "offline_outbox_drain_redis_url",
            },
        )
    )
    return errors


def normal_up_services(config: dict[str, Any]) -> set[str]:
    return {name for name, service in (config.get("services") or {}).items() if not (service.get("profiles") or [])}


def validate_normal_up_compose(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("name") != PROJECT:
        errors.append("normal-up rendering changed the offline outbox drain project identity")
    if (config.get("services") or {}) != {}:
        errors.append("normal-up rendering must contain no offline outbox drain services")
    if config.get("networks") or config.get("secrets") or config.get("volumes") or config.get("configs"):
        errors.append("normal-up rendering must not create drain resources")
    return errors
