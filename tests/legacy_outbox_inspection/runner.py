"""Read-only evidence collection for one expired outbox lease on schema 001--012.

This is deliberately not a compatibility switch for the newer offline
reconciler.  That tool relies on migration 018's durable reconciliation
columns.  This runner knows only the legacy profile and can never publish,
claim, migrate, lock, quarantine, or otherwise mutate the source database.

An eligible receipt is evidence for a later *isolated clone* rehearsal only.
It cannot authorize a source-database migration, a source mutation, PAPER, or
LIVE operation.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # Unit tests keep the pure receipt boundary dependency-free.
    import asyncpg
except ModuleNotFoundError:  # pragma: no cover - the sealed runtime image has asyncpg
    asyncpg = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parent
SOURCE_LOCK_PATH = ROOT / "source-lock.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z$"
)
CONNECTION_URI = re.compile(r"(?i)(?:postgres(?:ql)?|redis(?:s)?):\/\/")
DRIVER_ERRORS = (
    (asyncpg.PostgresError, asyncpg.InterfaceError) if asyncpg is not None else ()
)
INSPECTION_CLASSIFICATION = "LEGACY_BOOTSTRAPPED_RUNTIME_001_012_READ_ONLY"


class LegacyInspectionInputError(ValueError):
    """An input, schema, or receipt boundary is malformed or unsafe."""


@dataclass(frozen=True)
class SourceBackup:
    """A verified local dump identity bound into clone-only evidence."""

    manifest_sha256: str
    backup_sha256: str
    created_at_utc: str

    @classmethod
    def from_values(
        cls,
        *,
        manifest_sha256: str,
        backup_sha256: str,
        created_at_utc: str,
    ) -> "SourceBackup":
        if (
            not isinstance(manifest_sha256, str)
            or not isinstance(backup_sha256, str)
            or not SHA256.fullmatch(manifest_sha256)
            or not SHA256.fullmatch(backup_sha256)
        ):
            raise LegacyInspectionInputError("source backup hashes must be lowercase SHA-256 values")
        if not isinstance(created_at_utc, str) or not UTC_TIMESTAMP.fullmatch(created_at_utc):
            raise LegacyInspectionInputError("source backup created_at_utc is not an exact UTC timestamp")
        try:
            parsed = datetime.fromisoformat(created_at_utc.replace("Z", "+00:00"))
        except ValueError as exc:
            raise LegacyInspectionInputError("source backup created_at_utc is invalid") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise LegacyInspectionInputError("source backup created_at_utc must include a timezone")
        return cls(
            manifest_sha256=manifest_sha256,
            backup_sha256=backup_sha256,
            # Preserve the source manifest's lexical UTC identity.  Python
            # datetimes have microsecond precision and would silently drop a
            # valid seventh fractional digit from the evidence receipt.
            created_at_utc=created_at_utc,
        )

    def payload(self) -> dict[str, str]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "sha256": self.backup_sha256,
            "created_at_utc": self.created_at_utc,
        }


@dataclass(frozen=True)
class ExactIdentity:
    """The immutable identity pre-committed by the operator."""

    id: int
    producer: str
    message_id: str
    topic: str
    payload_sha256: str
    publish_attempts: int

    def __post_init__(self) -> None:
        if not isinstance(self.id, int) or isinstance(self.id, bool) or self.id <= 0:
            raise LegacyInspectionInputError("expectation identity id must be a positive integer")
        for name, value in (
            ("producer", self.producer),
            ("message_id", self.message_id),
            ("topic", self.topic),
        ):
            if not isinstance(value, str) or not value.strip():
                raise LegacyInspectionInputError(f"expectation identity {name} must be a non-empty string")
        if not isinstance(self.payload_sha256, str) or not SHA256.fullmatch(self.payload_sha256):
            raise LegacyInspectionInputError("expectation payload_sha256 must be a lowercase SHA-256")
        if (
            not isinstance(self.publish_attempts, int)
            or isinstance(self.publish_attempts, bool)
            or self.publish_attempts < 0
        ):
            raise LegacyInspectionInputError("expectation publish_attempts must be a non-negative integer")


@dataclass(frozen=True)
class LegacyExpectation:
    """One legacy row and a later clone-only reconciliation correlation ID."""

    identity: ExactIdentity
    reconciliation_id: str

    @classmethod
    def from_json(cls, value: object) -> "LegacyExpectation":
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "identity",
            "reconciliation_id",
        }:
            raise LegacyInspectionInputError(
                "expectation must contain exactly schema_version, identity, reconciliation_id"
            )
        if value.get("schema_version") != 1:
            raise LegacyInspectionInputError("expectation schema_version must be 1")
        raw_identity = value.get("identity")
        if not isinstance(raw_identity, Mapping) or set(raw_identity) != {
            "id",
            "producer",
            "message_id",
            "topic",
            "payload_sha256",
            "publish_attempts",
        }:
            raise LegacyInspectionInputError(
                "expectation identity must contain every immutable outbox field"
            )
        reconciliation_id = value.get("reconciliation_id")
        if (
            not isinstance(reconciliation_id, str)
            or not reconciliation_id.strip()
            or len(reconciliation_id) > 200
        ):
            raise LegacyInspectionInputError(
                "expectation reconciliation_id must be a non-empty string of at most 200 characters"
            )
        try:
            return cls(
                identity=ExactIdentity(
                    id=raw_identity["id"],
                    producer=raw_identity["producer"],
                    message_id=raw_identity["message_id"],
                    topic=raw_identity["topic"],
                    payload_sha256=raw_identity["payload_sha256"],
                    publish_attempts=raw_identity["publish_attempts"],
                ),
                reconciliation_id=reconciliation_id.strip(),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise LegacyInspectionInputError(f"invalid exact expectation: {type(exc).__name__}") from exc

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "identity": identity_payload(self.identity),
            "reconciliation_id": self.reconciliation_id,
        }


def canonical_json(value: object) -> str:
    """Canonical bytes used for hashes and receipts."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def identity_payload(identity: ExactIdentity) -> dict[str, object]:
    return {
        "id": identity.id,
        "producer": identity.producer,
        "message_id": identity.message_id,
        "topic": identity.topic,
        "payload_sha256": identity.payload_sha256,
        "publish_attempts": identity.publish_attempts,
    }


def source_lock() -> dict[str, Any]:
    try:
        value = json.loads(SOURCE_LOCK_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyInspectionInputError("source lock cannot be parsed") from exc
    if not isinstance(value, dict):
        raise LegacyInspectionInputError("source lock must be a JSON object")
    return value


def assert_runner_integrity() -> None:
    """Bind executable evidence logic to the reviewed source-lock artifact."""

    artifacts = source_lock().get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise LegacyInspectionInputError("source lock runner artifact is unavailable")
    expected = artifacts.get("runner_sha256")
    actual = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if not isinstance(expected, str) or not SHA256.fullmatch(expected) or actual != expected:
        raise LegacyInspectionInputError("legacy inspection runner hash differs from the reviewed artifact")


def read_json(path: Path, *, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyInspectionInputError(f"{label} cannot be parsed") from exc


def read_nonempty_secret(path: Path, *, label: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise LegacyInspectionInputError(f"{label} is unavailable") from exc
    if not value:
        raise LegacyInspectionInputError(f"{label} is empty")
    return value


def _canonical_outbox_payload(payload: object) -> tuple[dict[str, Any], str]:
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("outbox payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise TypeError("outbox payload must be a JSON object")
    encoded = canonical_json(payload)
    return json.loads(encoded), hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _utc_timestamp(value: object) -> str | None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _lease_evidence(row: Mapping[str, object] | None) -> dict[str, str] | None:
    if row is None:
        return None
    owner = row.get("lease_owner")
    lease_until = _utc_timestamp(row.get("lease_until"))
    if not isinstance(owner, str) or not owner or lease_until is None:
        return None
    return {
        "lease_owner_sha256": hashlib.sha256(owner.encode("utf-8")).hexdigest(),
        "lease_until_utc": lease_until,
    }


def assert_receipt_redacted(receipt: Mapping[str, object]) -> None:
    """Reject source payloads, DSNs, and raw lease ownership before persistence."""

    forbidden = {
        "payload",
        "database_url",
        "redis_url",
        "password",
        "secret",
        "token",
        "private_key",
        "lease_owner",
        "dsn",
        "connection_string",
    }

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if str(key).casefold() in forbidden:
                    raise LegacyInspectionInputError("receipt contains forbidden sensitive material")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str) and CONNECTION_URI.search(value):
            raise LegacyInspectionInputError("receipt contains a connection string")

    visit(receipt)


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def verify_inspection_receipt(
    receipt: object,
    *,
    expectation: LegacyExpectation,
    source_backup: SourceBackup,
    require_eligible: bool,
) -> dict[str, object]:
    """Verify one redacted receipt before an operator persists or signs it.

    This is pure host-side validation.  It deliberately accepts a structurally
    valid ``REJECTED`` receipt only when requested, so an operator can retain
    diagnostic evidence while still receiving a non-zero inspection result.
    It never upgrades that evidence into a mutation authorization.
    """

    assert_runner_integrity()
    if not isinstance(receipt, Mapping):
        raise LegacyInspectionInputError("inspection receipt must be a JSON object")
    expected_fields = {
        "schema_version",
        "kind",
        "classification",
        "source_lock_sha256",
        "expectation_sha256",
        "source_backup",
        "identity",
        "reconciliation_id",
        "inspection",
        "inspected_at_utc",
        "receipt_sha256",
    }
    if set(receipt) != expected_fields:
        raise LegacyInspectionInputError("inspection receipt fields are not exact")
    assert_receipt_redacted(receipt)
    if (
        receipt.get("schema_version") != 1
        or receipt.get("kind") != "kairos.legacy-outbox-inspection.v1"
        or receipt.get("classification") != INSPECTION_CLASSIFICATION
        or receipt.get("source_lock_sha256") != sha256_json(source_lock())
        or receipt.get("expectation_sha256") != sha256_json(expectation.payload())
        or receipt.get("source_backup") != source_backup.payload()
        or receipt.get("identity") != identity_payload(expectation.identity)
        or receipt.get("reconciliation_id") != expectation.reconciliation_id
        or not _is_utc_timestamp(receipt.get("inspected_at_utc"))
    ):
        raise LegacyInspectionInputError("inspection receipt provenance is invalid")
    digest = receipt.get("receipt_sha256")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if not isinstance(digest, str) or not SHA256.fullmatch(digest) or digest != sha256_json(unsigned):
        raise LegacyInspectionInputError("inspection receipt hash is invalid")

    inspection = receipt.get("inspection")
    if not isinstance(inspection, Mapping) or set(inspection) != {
        "result",
        "schema_profile",
        "row_state",
        "checks",
        "observations",
    }:
        raise LegacyInspectionInputError("inspection receipt result is malformed")
    result = inspection.get("result")
    if result not in {"ELIGIBLE_FOR_CLONE_REHEARSAL", "REJECTED"}:
        raise LegacyInspectionInputError("inspection receipt result is not clone-only")
    profile = source_lock().get("profile")
    expected_schema_profile = profile.get("schema_profile") if isinstance(profile, Mapping) else None
    if (
        not isinstance(expected_schema_profile, str)
        or not expected_schema_profile
        or inspection.get("schema_profile") != expected_schema_profile
        or inspection.get("row_state") not in {
        "NOT_FOUND",
        "LEASE_NOT_EXPIRED",
        "EXPIRED_LEASE",
        }
    ):
        raise LegacyInspectionInputError("inspection receipt state is invalid")
    checks = inspection.get("checks")
    expected_checks = {
        "backup_bound",
        "database_name_exact",
        "migration_history_exact",
        "schema_fingerprint_exact",
        "row_found",
        "identity_matches",
        "payload_hash_matches",
        "audit_matches",
        "unpublished",
        "not_dead_lettered",
        "lease_expired",
        "lease_evidence_bound",
    }
    if (
        not isinstance(checks, Mapping)
        or set(checks) != expected_checks
        or any(type(value) is not bool for value in checks.values())
    ):
        raise LegacyInspectionInputError("inspection receipt checks are malformed")
    observations = inspection.get("observations")
    if not isinstance(observations, Mapping) or set(observations) != {
        "audit_row_count",
        "available",
        "has_earlier_unpublished_predecessor",
        "lease",
    }:
        raise LegacyInspectionInputError("inspection receipt observations are malformed")
    audit_count = observations.get("audit_row_count")
    if (
        not isinstance(audit_count, int)
        or isinstance(audit_count, bool)
        or audit_count < 0
        or audit_count > 2
        or type(observations.get("available")) is not bool
        or type(observations.get("has_earlier_unpublished_predecessor")) is not bool
    ):
        raise LegacyInspectionInputError("inspection receipt observations are invalid")
    lease = observations.get("lease")
    if lease is not None:
        if (
            not isinstance(lease, Mapping)
            or set(lease) != {"lease_owner_sha256", "lease_until_utc"}
            or not isinstance(lease.get("lease_owner_sha256"), str)
            or not SHA256.fullmatch(lease["lease_owner_sha256"])
            or not _is_utc_timestamp(lease.get("lease_until_utc"))
        ):
            raise LegacyInspectionInputError("inspection receipt lease evidence is invalid")
    if result == "ELIGIBLE_FOR_CLONE_REHEARSAL":
        if not all(checks.values()) or inspection.get("row_state") != "EXPIRED_LEASE" or lease is None:
            raise LegacyInspectionInputError("eligible receipt does not prove the exact expired lease")
    if require_eligible and result != "ELIGIBLE_FOR_CLONE_REHEARSAL":
        raise LegacyInspectionInputError("inspection receipt is not eligible for clone rehearsal")
    return dict(receipt)


def build_inspection_receipt(
    expectation: LegacyExpectation,
    *,
    source_backup: SourceBackup,
    database_name: str,
    migrations: tuple[str, ...],
    schema_fingerprint_sha256: str,
    row: Mapping[str, object] | None,
    audit_rows: list[Mapping[str, object]],
    has_unpublished_predecessor: bool,
    inspected_at: datetime | None = None,
) -> dict[str, object]:
    """Create a redacted read-only receipt for a later clone-only rehearsal."""

    profile = source_lock().get("profile")
    if not isinstance(profile, Mapping):
        raise LegacyInspectionInputError("source lock profile is invalid")
    expected_migrations = tuple(profile.get("required_migrations") or ())
    expected_database = profile.get("required_database")
    expected_schema_fingerprint = profile.get("expected_schema_fingerprint_sha256")
    expected_schema_profile = profile.get("schema_profile")
    if not isinstance(expected_schema_profile, str) or not expected_schema_profile:
        raise LegacyInspectionInputError("source lock schema profile is invalid")
    identity = expectation.identity
    checks: dict[str, bool] = {
        "backup_bound": True,
        "database_name_exact": database_name == expected_database,
        "migration_history_exact": migrations == expected_migrations,
        "schema_fingerprint_exact": schema_fingerprint_sha256 == expected_schema_fingerprint,
        "row_found": row is not None,
        "identity_matches": False,
        "payload_hash_matches": False,
        "audit_matches": False,
        "unpublished": False,
        "not_dead_lettered": False,
        "lease_expired": False,
        "lease_evidence_bound": False,
    }
    observations: dict[str, object] = {
        "audit_row_count": len(audit_rows),
        "available": False,
        "has_earlier_unpublished_predecessor": bool(has_unpublished_predecessor),
        "lease": None,
    }
    row_state = "NOT_FOUND"
    if row is not None:
        checks["identity_matches"] = all(
            row.get(key) == value for key, value in identity_payload(identity).items()
        )
        checks["unpublished"] = row.get("published_at") is None
        checks["not_dead_lettered"] = row.get("dead_lettered_at") is None
        checks["lease_expired"] = row.get("lease_expired") is True
        observations["available"] = row.get("available") is True
        lease = _lease_evidence(row)
        observations["lease"] = lease
        checks["lease_evidence_bound"] = lease is not None
        row_state = "EXPIRED_LEASE" if checks["lease_expired"] else "LEASE_NOT_EXPIRED"
        try:
            canonical, actual_hash = _canonical_outbox_payload(row.get("payload"))
            checks["payload_hash_matches"] = (
                actual_hash == identity.payload_sha256 and canonical.get("message_id") == identity.message_id
            )
        except (TypeError, ValueError):
            checks["payload_hash_matches"] = False
        if len(audit_rows) == 1:
            try:
                audit = audit_rows[0]
                canonical_audit, audit_hash = _canonical_outbox_payload(audit.get("payload"))
                checks["audit_matches"] = (
                    audit.get("topic") == identity.topic
                    and audit_hash == identity.payload_sha256
                    and canonical_audit.get("message_id") == identity.message_id
                )
            except (TypeError, ValueError):
                checks["audit_matches"] = False

    # Producer backlog and row availability are preserved as observations.  A
    # later quarantine freezes an ambiguous known lease; it does not publish or
    # overtake predecessor effects, so neither fact can turn this inspection
    # into a mutation authorization.
    result = "ELIGIBLE_FOR_CLONE_REHEARSAL" if all(checks.values()) else "REJECTED"
    lock = source_lock()
    receipt: dict[str, object] = {
        "schema_version": 1,
        "kind": "kairos.legacy-outbox-inspection.v1",
        "classification": INSPECTION_CLASSIFICATION,
        "source_lock_sha256": sha256_json(lock),
        "expectation_sha256": sha256_json(expectation.payload()),
        "source_backup": source_backup.payload(),
        "identity": identity_payload(identity),
        "reconciliation_id": expectation.reconciliation_id,
        "inspection": {
            "result": result,
            "schema_profile": expected_schema_profile,
            "row_state": row_state,
            "checks": checks,
            "observations": observations,
        },
        "inspected_at_utc": (inspected_at or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }
    receipt["receipt_sha256"] = sha256_json(receipt)
    assert_receipt_redacted(receipt)
    verify_inspection_receipt(
        receipt,
        expectation=expectation,
        source_backup=source_backup,
        require_eligible=False,
    )
    return receipt


_SCHEMA_FINGERPRINT_QUERY = r"""
WITH inventory AS (
    SELECT 'extension|' || e.extname || '|' || e.extversion AS item FROM pg_extension e WHERE e.extname='timescaledb'
    UNION ALL
    SELECT 'relation|' || c.relkind::text || '|' || c.relname || '|' || CASE WHEN c.relkind IN ('v','m') THEN md5(pg_get_viewdef(c.oid, true)) ELSE '' END
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
    UNION ALL
    SELECT 'column|' || c.relname || '|' || a.attnum::text || '|' || a.attname || '|' || format_type(a.atttypid, a.atttypmod) || '|' || a.attnotnull::text || '|' || a.attidentity::text || '|' || a.attgenerated::text || '|' || COALESCE(md5(pg_get_expr(ad.adbin, ad.adrelid, true)), '') || '|' || COALESCE(coll.collname, '')
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum LEFT JOIN pg_collation coll ON coll.oid=a.attcollation
    WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f') AND a.attnum > 0 AND NOT a.attisdropped
    UNION ALL
    SELECT 'constraint|' || c.relname || '|' || con.conname || '|' || con.contype::text || '|' || md5(pg_get_constraintdef(con.oid, true))
    FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
    UNION ALL
    SELECT 'index|' || t.relname || '|' || i.relname || '|' || x.indisunique::text || '|' || x.indisprimary::text || '|' || x.indisvalid::text || '|' || md5(pg_get_indexdef(i.oid))
    FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public'
    UNION ALL
    SELECT 'trigger|' || c.relname || '|' || tg.tgname || '|' || md5(pg_get_triggerdef(tg.oid, true))
    FROM pg_trigger tg JOIN pg_class c ON c.oid=tg.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT tg.tgisinternal
    UNION ALL
    SELECT 'sequence|' || c.relname || '|' || s.seqstart::text || '|' || s.seqincrement::text || '|' || s.seqmin::text || '|' || s.seqmax::text || '|' || s.seqcache::text || '|' || s.seqcycle::text
    FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
    UNION ALL
    SELECT 'type|' || t.typtype::text || '|' || t.typname || '|' || COALESCE(format_type(t.typbasetype, t.typtypmod), '')
    FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype IN ('b','c','d','e','r')
)
-- Keep the two-character ``\\n`` separator used by the pinned legacy
-- fingerprint producer.  A real newline would yield a different hash.
SELECT COALESCE(string_agg(item, E'\\n' ORDER BY item), '') FROM inventory;
"""


async def inspect_database(
    expectation: LegacyExpectation,
    database_url: str,
    *,
    source_backup: SourceBackup,
) -> dict[str, object]:
    """Use bounded SELECTs inside one serializable read-only transaction."""

    if asyncpg is None:  # pragma: no cover - production image always has asyncpg
        raise LegacyInspectionInputError("asyncpg is unavailable in this runner environment")
    connection = await asyncpg.connect(
        database_url,
        server_settings={"default_transaction_read_only": "on"},
        command_timeout=15,
    )
    try:
        async with connection.transaction(isolation="serializable", readonly=True, deferrable=True):
            database_name = str(await connection.fetchval("SELECT current_database()"))
            migrations = tuple(
                str(item["version"])
                for item in await connection.fetch("SELECT version FROM schema_migrations ORDER BY version")
            )
            schema_inventory = await connection.fetchval(_SCHEMA_FINGERPRINT_QUERY)
            if not isinstance(schema_inventory, str):
                raise LegacyInspectionInputError("legacy schema inventory is unavailable")
            row = await connection.fetchrow(
                """SELECT id, producer, message_id, topic, payload, payload_sha256,
                          publish_attempts, published_at, dead_lettered_at,
                          lease_owner, lease_until,
                          (lease_until IS NOT NULL AND lease_until < now()) AS lease_expired,
                          (available_at <= now()) AS available
                     FROM message_outbox
                    WHERE id=$1""",
                expectation.identity.id,
            )
            audit_rows = await connection.fetch(
                """SELECT topic, payload
                     FROM event_audit
                    WHERE message_id=$1
                    ORDER BY produced_at ASC
                    LIMIT 2""",
                expectation.identity.message_id,
            )
            predecessor = await connection.fetchval(
                """SELECT EXISTS(
                       SELECT 1
                         FROM message_outbox
                        WHERE producer=$1
                          AND id < $2
                          AND published_at IS NULL
                          AND dead_lettered_at IS NULL
                    )""",
                expectation.identity.producer,
                expectation.identity.id,
            )
    finally:
        await connection.close()
    return build_inspection_receipt(
        expectation,
        source_backup=source_backup,
        database_name=database_name,
        migrations=migrations,
        schema_fingerprint_sha256=hashlib.sha256(schema_inventory.encode("utf-8")).hexdigest(),
        row=dict(row) if row is not None else None,
        audit_rows=[dict(item) for item in audit_rows],
        has_unpublished_predecessor=bool(predecessor),
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--expectation", required=True, type=Path)
    result.add_argument("--database-url-file", required=True, type=Path)
    result.add_argument("--backup-manifest-sha256", required=True)
    result.add_argument("--backup-sha256", required=True)
    result.add_argument("--backup-created-at-utc", required=True)
    return result


async def run(args: argparse.Namespace) -> dict[str, object]:
    assert_runner_integrity()
    expectation = LegacyExpectation.from_json(read_json(args.expectation, label="exact expectation"))
    database_url = read_nonempty_secret(args.database_url_file, label="database URL file")
    source_backup = SourceBackup.from_values(
        manifest_sha256=args.backup_manifest_sha256,
        backup_sha256=args.backup_sha256,
        created_at_utc=args.backup_created_at_utc,
    )
    return await inspect_database(expectation, database_url, source_backup=source_backup)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        output = asyncio.run(run(args))
        # A structurally valid rejected receipt remains useful evidence, but
        # an operator must never mistake it for a successful inspection.
        code = 0 if output["inspection"]["result"] == "ELIGIBLE_FOR_CLONE_REHEARSAL" else 3
    except (LegacyInspectionInputError, OSError, RuntimeError, TypeError, ValueError) as exc:
        output = {
            "schema_version": 1,
            "kind": "kairos.legacy-outbox-inspection-result.v1",
            "classification": INSPECTION_CLASSIFICATION,
            "state": "STARTUP_REJECTED",
            "error_type": type(exc).__name__,
        }
        code = 4
    except DRIVER_ERRORS as exc:
        output = {
            "schema_version": 1,
            "kind": "kairos.legacy-outbox-inspection-result.v1",
            "classification": INSPECTION_CLASSIFICATION,
            "state": "STARTUP_REJECTED",
            "error_type": type(exc).__name__,
        }
        code = 4
    print(canonical_json(output))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
