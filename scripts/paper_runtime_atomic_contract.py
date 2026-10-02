"""Offline contracts for a separately reviewed, clone-only atomic recovery proof.

No database, Docker, secret, publisher or primary-write entrypoint lives here.
The old read-only controller/catalog remain the authority for frozen identities.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

import paper_runtime_schema_upgrade as readonly


CATALOG = readonly.CATALOG
LEGACY_TABLES = readonly.TABLES
LEGACY_PROFILE = CATALOG.LEGACY_MIGRATIONS
RUNTIME_PROFILE = CATALOG.TARGET_MIGRATIONS
NEW_TABLES = tuple(sorted((
    "campaign_source_budgets", "paper_canary_database_identity", "paper_readonly_runs",
    "paper_readonly_samples", "paper_readonly_receipts", "paper_canary_sessions",
    "paper_canary_attempts", "paper_canary_dispatch_claims",
)))
RUNTIME_TABLES = tuple(sorted((*LEGACY_TABLES, *NEW_TABLES)))
NEW_OUTBOX_FIELDS = ("reconciliation_state", "reconciliation_id", "reconciliation_started_at", "reconciliation_outcome_at")
OLD_QUARANTINE_FIELDS = ("lease_owner", "lease_until", "last_error")
EXACT_ROW_ID = 117625
DATABASE_MODULE_SHA256 = "44382a74bba25839e76ec8ab2b01f68d58f58ce4510ed8294fb827bce3dc345b"
CLONE_DATABASE = re.compile(r"kairos_paper_atomic_[0-9a-f]{12}\Z")
PLAN_KIND = "kairos.paper-runtime-atomic-clone-plan.v1"
INTENT_KIND = "kairos.paper-runtime-atomic-precommit-intent.v1"
RECEIPT_KIND = "kairos.paper-runtime-atomic-clone-proof.v1"
NEXT_GATE = "SEPARATE_ATOMIC_PRIMARY_RUNTIME_AND_ONE_ROW_QUARANTINE_PROOF_REVIEW"
READINESS = {"paper_qualified": False, "alpha_ready": False, "live_ready": False, "strategy_policy": "REJECT_ALL"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 128 * 1024


class AtomicError(RuntimeError):
    """Redacted, fail-closed contract error; never include rows or driver messages."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def require_hash(value: object) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise AtomicError("invalid SHA256 binding")
    return value


def utc(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise AtomicError("invalid UTC timestamp") from None
    if not isinstance(value, str) or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AtomicError("invalid UTC timestamp")
    return parsed.astimezone(UTC)


def fresh(value: object, now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise AtomicError("clock must be timezone-aware")
    age = now.astimezone(UTC) - utc(value)
    if age.total_seconds() < 0 or age > CATALOG.MAXIMUM_EVIDENCE_AGE:
        raise AtomicError("evidence is future-dated or stale")


def read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise AtomicError("bounded regular JSON evidence is required")
    try:
        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise AtomicError("duplicate JSON evidence key")
                result[key] = value
            return result
        value = json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(AtomicError("non-finite JSON evidence")))
    except (ValueError, UnicodeError, OSError):
        raise AtomicError("JSON evidence is unreadable") from None
    if not isinstance(value, dict):
        raise AtomicError("JSON evidence must be an object")
    return value


def validate_history(value: object, *, runtime: bool) -> dict[str, Any]:
    required = {"database", "migrations", "schema_fingerprint_sha256", "tables", "public_sequences", "public_execution_events_max_sequence"}
    if not isinstance(value, dict) or set(value) != required or value["database"] != CATALOG.EXPECTED_DATABASE:
        raise AtomicError("history shape or logical database differs")
    expected_profile = RUNTIME_PROFILE if runtime else LEGACY_PROFILE
    expected_tables = RUNTIME_TABLES if runtime else LEGACY_TABLES
    if tuple(value["migrations"]) != expected_profile or not isinstance(value["tables"], dict) or tuple(sorted(value["tables"])) != expected_tables:
        raise AtomicError("history inventory/profile differs")
    require_hash(value["schema_fingerprint_sha256"])
    if not runtime and value["schema_fingerprint_sha256"] != CATALOG.EXPECTED_LEGACY_FINGERPRINT:
        raise AtomicError("legacy fingerprint differs")
    for item in value["tables"].values():
        if not isinstance(item, dict) or set(item) != {"count", "row_digest_sha256"} or type(item["count"]) is not int or item["count"] < 0:
            raise AtomicError("history table digest shape differs")
        require_hash(item["row_digest_sha256"])
    if not isinstance(value["public_sequences"], dict):
        raise AtomicError("sequence inventory differs")
    for name, item in value["public_sequences"].items():
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", name) is None or not isinstance(item, dict) or set(item) != {"last_value", "is_called"} or type(item["last_value"]) is not int or type(item["is_called"]) is not bool:
            raise AtomicError("sequence state shape differs")
    if type(value["public_execution_events_max_sequence"]) is not int or value["public_execution_events_max_sequence"] < 0:
        raise AtomicError("watermark shape differs")
    expected_count = len(expected_profile)
    if value["tables"]["schema_migrations"]["count"] != expected_count:
        raise AtomicError("migration row count differs")
    return value


def verify_preflight(value: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    required = {"schema_version", "classification", "result", "created_at_utc", "controller_sha256", "worker_sha256", "catalog_sha256", "source_identity", "source_backup_sha256", "source_manifest_sha256", "accepted_clone_receipt_sha256", "accepted_clone_signature_sha256", "immutable_runner", "source_snapshot", "restored_snapshot", "primary_mutations", "primary_apply_implemented", "consumers_started", "publisher_calls", "redis_contacted", "required_next_gate", "consumer_restart_permitted", "readiness", "receipt_sha256"}
    if set(value) != required or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["classification"] != "PAPER_RUNTIME_READONLY_TARGET_ROLE_AND_RESTORE_BINDING" or value["result"] != "PASS_READ_ONLY_PRIMARY_AND_CLONE":
        raise AtomicError("accepted read-only receipt shape/scope differs")
    if value["receipt_sha256"] != digest({k: v for k, v in value.items() if k != "receipt_sha256"}):
        raise AtomicError("read-only receipt content binding differs")
    fresh(value["created_at_utc"], now)
    for name in ("primary_mutations", "consumers_started", "publisher_calls"):
        if type(value[name]) is not int or value[name] != 0:
            raise AtomicError("read-only boundary differs")
    if any(value[name] is not False for name in ("primary_apply_implemented", "redis_contacted", "consumer_restart_permitted")) or value["required_next_gate"] != NEXT_GATE or value["readiness"] != READINESS or value["immutable_runner"] != CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE:
        raise AtomicError("accepted authority/frozen runner differs")
    for name in ("controller_sha256", "worker_sha256", "catalog_sha256", "source_backup_sha256", "source_manifest_sha256", "accepted_clone_receipt_sha256", "accepted_clone_signature_sha256"):
        require_hash(value[name])
    for name, current in readonly._code_identity().items():
        if value[name] != current:
            raise AtomicError("accepted read-only source bytes changed")
    identity = value["source_identity"]
    if not isinstance(identity, dict) or set(identity) != {"compose_project", "container_id", "database", "image_id", "network", "network_id", "volume"} or identity["compose_project"] != readonly.SOURCE_PROJECT or identity["database"] != readonly.SOURCE_DATABASE or identity["network"] != readonly.SOURCE_NETWORK or identity["volume"] != readonly.SOURCE_VOLUME:
        raise AtomicError("fixed PAPER source identity differs")
    require_hash(identity["container_id"])
    require_hash(identity["network_id"])
    if not isinstance(identity["image_id"], str) or not identity["image_id"].startswith("sha256:"):
        raise AtomicError("source image identity differs")
    require_hash(identity["image_id"][7:])
    try:
        source = readonly._validate_snapshot(value["source_snapshot"], primary=True)
        restored = readonly._validate_snapshot(value["restored_snapshot"], primary=False)
    except Exception:
        raise AtomicError("accepted all-history snapshot proof differs") from None
    validate_history(source["history"], runtime=False)
    validate_history(restored["history"], runtime=False)
    if source["history"] != restored["history"]:
        raise AtomicError("accepted restore did not preserve all legacy history")
    return value


@dataclass(frozen=True)
class AtomicPlan:
    """Immutable serialized result of the host's verified evidence chain.

    This object is NOT primary apply authority. All write APIs reject primary.
    Offline from_document checks shape/bindings; prepare_plan checks signatures.
    """

    serialized: bytes

    @property
    def document(self) -> dict[str, Any]:
        return json.loads(self.serialized)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.serialized).hexdigest()

    @classmethod
    def from_document(cls, value: dict[str, Any], *, now: datetime) -> AtomicPlan:
        required = {"schema_version", "kind", "created_at_utc", "preflight_created_at_utc", "backup_created_at_utc", "clone_created_at_utc", "inspection_created_at_utc", "recovery_created_at_utc", "preflight_sha256", "preflight_signature_sha256", "source_identity", "backup_sha256", "manifest_sha256", "accepted_clone_receipt_sha256", "identity", "reconciliation_id", "lease_owner_sha256", "lease_until_utc", "reason", "legacy_history", "runtime_schema_fingerprint_sha256", "runner", "persistence_revision", "repository_sha256", "database_module_sha256", "profile", "primary_apply_implemented", "consumer_restart_permitted", "readiness"}
        if not isinstance(value, dict) or set(value) != required or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["kind"] != PLAN_KIND:
            raise AtomicError("atomic clone plan shape differs")
        fresh(value["created_at_utc"], now)
        for name in ("preflight_created_at_utc", "backup_created_at_utc", "clone_created_at_utc", "inspection_created_at_utc", "recovery_created_at_utc"):
            fresh(value[name], now)
            if utc(value["created_at_utc"]) < utc(value[name]):
                raise AtomicError("plan predates accepted evidence")
        if utc(value["created_at_utc"]) < utc(value["preflight_created_at_utc"]):
            raise AtomicError("plan predates accepted preflight")
        if value["runner"] != CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE or value["persistence_revision"] != CATALOG.EXPECTED_PERSISTENCE_REVISION or value["repository_sha256"] != CATALOG.EXPECTED_PERSISTENCE_REPOSITORY_SHA256 or value["database_module_sha256"] != DATABASE_MODULE_SHA256 or tuple(value["profile"]) != RUNTIME_PROFILE:
            raise AtomicError("plan changes immutable old runtime profile")
        if value["primary_apply_implemented"] is not False or value["consumer_restart_permitted"] is not False or value["readiness"] != READINESS:
            raise AtomicError("plan broadens recovery authority")
        for name in ("preflight_sha256", "preflight_signature_sha256", "backup_sha256", "manifest_sha256", "accepted_clone_receipt_sha256", "lease_owner_sha256", "runtime_schema_fingerprint_sha256"):
            require_hash(value[name])
        identity = value["identity"]
        if not isinstance(identity, dict) or set(identity) != set(CATALOG.IDENTITY_FIELDS) or type(identity["id"]) is not int or identity["id"] != EXACT_ROW_ID or type(identity["publish_attempts"]) is not int or identity["publish_attempts"] < 0:
            raise AtomicError("plan must name the one signed outbox row")
        for name in ("producer", "message_id", "topic"):
            if not isinstance(identity[name], str) or not identity[name].strip() or len(identity[name]) > 512:
                raise AtomicError("exact identity text is invalid")
        require_hash(identity["payload_sha256"])
        if not isinstance(value["reconciliation_id"], str) or not value["reconciliation_id"].strip() or len(value["reconciliation_id"]) > 200 or value["reason"] != "legacy expired lease clone-only quarantine rehearsal":
            raise AtomicError("quarantine evidence differs from accepted clone contract")
        utc(value["lease_until_utc"])
        validate_history(value["legacy_history"], runtime=False)
        encoded = canonical(value)
        if len(encoded) > MAX_JSON_BYTES:
            raise AtomicError("plan exceeds fixed bound")
        return cls(encoded)


def compare_history(before: dict[str, Any], projected_after: dict[str, Any]) -> None:
    """The worker reconstructs only exact-row fields and old migration rows.

    No wholesale column mask is allowed on other outbox rows or any other table.
    """
    validate_history(before, runtime=False)
    validate_history(projected_after, runtime=False)
    if before != projected_after:
        raise AtomicError("all-27 legacy field-specific preservation failed")


def classify_readonly_outcome(plan: AtomicPlan, intent: dict[str, Any], observed_history: object, *, other_clients: int = 0) -> str:
    """Classify only; never return a retry instruction or perform a write."""
    if type(other_clients) is not int or other_clients != 0:
        return "INDETERMINATE"
    if set(intent) != {"schema_version", "kind", "plan_sha256", "legacy_history_sha256", "committed_history_sha256", "prepared_at_utc", "backend_pid", "quarantine_calls"} or intent["kind"] != INTENT_KIND or type(intent["schema_version"]) is not int or intent["schema_version"] != 1 or intent["plan_sha256"] != plan.sha256 or intent["legacy_history_sha256"] != digest(plan.document["legacy_history"]) or type(intent["quarantine_calls"]) is not int or intent["quarantine_calls"] != 1:
        raise AtomicError("precommit intent binding differs")
    require_hash(intent["committed_history_sha256"])
    utc(intent["prepared_at_utc"])
    if type(intent["backend_pid"]) is not int or intent["backend_pid"] <= 0:
        raise AtomicError("precommit connection identity differs")
    try:
        if digest(observed_history) == intent["legacy_history_sha256"]:
            validate_history(observed_history, runtime=False)
            return "ROLLED_BACK"
        if digest(observed_history) == intent["committed_history_sha256"]:
            validate_history(observed_history, runtime=True)
            return "COMMITTED_EXACT"
    except (AtomicError, TypeError, ValueError):
        return "INDETERMINATE"
    return "INDETERMINATE"
