"""Fail-closed signed-prefix inspection and bounded offline outbox drain.

The tool is a recovery primitive, not a service: it never starts migrations,
subscribes, collects data, creates audit/outbox facts, or retries a transport
publish.  An explicit plan is inspected read-only first.  A fresh signed
receipt binds the exact producer prefix before a separately armed apply can
perform at most 100 one-shot Redis publishes.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # Unit tests exercise the pure receipt boundary without a runtime wheel.
    import asyncpg
except ModuleNotFoundError:  # pragma: no cover - production image always has asyncpg
    asyncpg = None  # type: ignore[assignment]

DRIVER_ERRORS = (
    (asyncpg.PostgresError, asyncpg.InterfaceError) if asyncpg is not None else ()
)
ROOT = Path(__file__).resolve().parent
SOURCE_LOCK_PATH = ROOT / "source-lock.json"
TRUSTED_SIGNER_PATH = ROOT / "trusted-signer.asc"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DATABASE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


class DrainInputError(ValueError):
    """The operator input, receipt, or database state is unsafe for a drain."""


@dataclass(frozen=True)
class PrefixIdentity:
    """Immutable identity of one pre-inspected outbox member."""

    id: int
    producer: str
    message_id: str
    topic: str
    payload_sha256: str
    publish_attempts: int

    def __post_init__(self) -> None:
        if not isinstance(self.id, int) or isinstance(self.id, bool) or self.id <= 0:
            raise DrainInputError("prefix identity id must be a positive integer")
        for name, value in (
            ("producer", self.producer),
            ("message_id", self.message_id),
            ("topic", self.topic),
        ):
            if not isinstance(value, str) or not value.strip():
                raise DrainInputError(f"prefix identity {name} must be a non-empty string")
        if not isinstance(self.payload_sha256, str) or not SHA256.fullmatch(self.payload_sha256):
            raise DrainInputError("prefix identity payload_sha256 must be a lowercase SHA-256")
        if (
            not isinstance(self.publish_attempts, int)
            or isinstance(self.publish_attempts, bool)
            or self.publish_attempts < 0
        ):
            raise DrainInputError("prefix identity publish_attempts must be a non-negative integer")


@dataclass(frozen=True)
class DrainPlan:
    """Operator precommitment to one bounded producer-scoped recovery attempt."""

    database_name: str
    producer: str
    topic: str
    drain_id: str
    maximum_rows: int
    maximum_duration_seconds: int

    @classmethod
    def from_json(cls, value: object) -> DrainPlan:
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "database_name",
            "producer",
            "topic",
            "drain_id",
            "maximum_rows",
            "maximum_duration_seconds",
        }:
            raise DrainInputError(
                "drain plan must contain exactly schema_version, database_name, producer, topic, drain_id, "
                "maximum_rows, maximum_duration_seconds"
            )
        if value.get("schema_version") != 1:
            raise DrainInputError("drain plan schema_version must be 1")
        profile = source_lock().get("profile")
        if not isinstance(profile, Mapping):
            raise DrainInputError("drain source lock profile is invalid")
        database_name = value.get("database_name")
        producer = value.get("producer")
        topic = value.get("topic")
        drain_id = value.get("drain_id")
        maximum_rows = value.get("maximum_rows")
        maximum_duration_seconds = value.get("maximum_duration_seconds")
        if not isinstance(database_name, str) or not DATABASE_NAME.fullmatch(database_name):
            raise DrainInputError("drain plan database_name must be a PostgreSQL identifier")
        if producer != profile.get("allowed_producer") or topic != profile.get("allowed_topic"):
            raise DrainInputError("drain plan producer/topic is not allow-listed by the immutable source lock")
        if not isinstance(drain_id, str) or not drain_id.strip() or len(drain_id.strip()) > 160:
            raise DrainInputError("drain plan drain_id must be a non-empty string of at most 160 characters")
        if (
            not isinstance(maximum_rows, int)
            or isinstance(maximum_rows, bool)
            or not 1 <= maximum_rows <= int(profile.get("maximum_rows", 0))
        ):
            raise DrainInputError("drain plan maximum_rows is outside the immutable bounded range")
        if (
            not isinstance(maximum_duration_seconds, int)
            or isinstance(maximum_duration_seconds, bool)
            or not 30 <= maximum_duration_seconds <= int(profile.get("maximum_duration_seconds", 0))
        ):
            raise DrainInputError("drain plan maximum_duration_seconds is outside the immutable bounded range")
        return cls(
            database_name=database_name,
            producer=producer,
            topic=topic,
            drain_id=drain_id.strip(),
            maximum_rows=maximum_rows,
            maximum_duration_seconds=maximum_duration_seconds,
        )

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "database_name": self.database_name,
            "producer": self.producer,
            "topic": self.topic,
            "drain_id": self.drain_id,
            "maximum_rows": self.maximum_rows,
            "maximum_duration_seconds": self.maximum_duration_seconds,
        }


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def identity_payload(identity: PrefixIdentity) -> dict[str, object]:
    return {
        "id": identity.id,
        "producer": identity.producer,
        "message_id": identity.message_id,
        "topic": identity.topic,
        "payload_sha256": identity.payload_sha256,
        "publish_attempts": identity.publish_attempts,
    }


def identities_payload(identities: tuple[PrefixIdentity, ...]) -> list[dict[str, object]]:
    return [identity_payload(identity) for identity in identities]


def identities_from_json(value: object) -> tuple[PrefixIdentity, ...]:
    if not isinstance(value, list) or not value:
        raise DrainInputError("inspection receipt must contain a non-empty exact prefix")
    identities: list[PrefixIdentity] = []
    prior_id = 0
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {
            "id",
            "producer",
            "message_id",
            "topic",
            "payload_sha256",
            "publish_attempts",
        }:
            raise DrainInputError("inspection receipt identity is malformed")
        identity = PrefixIdentity(
            id=raw["id"],
            producer=raw["producer"],
            message_id=raw["message_id"],
            topic=raw["topic"],
            payload_sha256=raw["payload_sha256"],
            publish_attempts=raw["publish_attempts"],
        )
        if identity.id <= prior_id:
            raise DrainInputError("inspection receipt prefix identities must be strictly ordered")
        identities.append(identity)
        prior_id = identity.id
    return tuple(identities)


def source_lock() -> dict[str, Any]:
    value = json.loads(SOURCE_LOCK_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DrainInputError("source lock must be a JSON object")
    return value


def read_json(path: Path, *, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DrainInputError(f"{label} cannot be parsed") from exc


def read_nonempty_secret(path: Path, *, label: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise DrainInputError(f"{label} is unavailable") from exc
    if not value:
        raise DrainInputError(f"{label} is empty")
    return value


def _datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise DrainInputError("receipt inspected_at_utc must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DrainInputError("receipt inspected_at_utc is invalid") from exc
    if parsed.tzinfo is None:
        raise DrainInputError("receipt inspected_at_utc must include a timezone")
    return parsed.astimezone(UTC)


def _receipt_without_hash(receipt: Mapping[str, object]) -> dict[str, object]:
    return {str(key): value for key, value in receipt.items() if key != "receipt_sha256"}


def _canonical_outbox_payload(payload: object) -> tuple[dict[str, Any], str]:
    try:
        from kairos_persistence import AuditRepository

        return AuditRepository._canonical_outbox_payload(payload)
    except ModuleNotFoundError:
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            raise TypeError("outbox payload must be a JSON object")
        encoded = canonical_json(payload)
        return json.loads(encoded), hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def assert_receipt_redacted(receipt: Mapping[str, object]) -> None:
    forbidden = {
        "payload",
        "database_url",
        "redis_url",
        "password",
        "secret",
        "token",
        "private_key",
    }

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if str(key).casefold() in forbidden:
                    raise DrainInputError("receipt contains forbidden sensitive material")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str) and ("postgres://" in value or "redis://" in value):
            raise DrainInputError("receipt contains a connection string")

    visit(receipt)


def _inspection_payload(
    plan: DrainPlan,
    *,
    inspection: Mapping[str, object],
    inspected_at: datetime,
) -> dict[str, object]:
    lock = source_lock()
    return {
        "schema_version": 1,
        "kind": "kairos.offline-outbox-drain-inspection.v1",
        "classification": "OFFLINE_SIGNED_PREFIX_ONLY",
        "source_lock_sha256": sha256_json(lock),
        "source": lock["dependencies"],
        "plan_sha256": sha256_json(plan.payload()),
        "plan": plan.payload(),
        "inspection": dict(inspection),
        "inspected_at_utc": inspected_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }


def build_inspection_receipt(
    plan: DrainPlan,
    *,
    database_name: str,
    migrations: tuple[str, ...],
    rows: list[Mapping[str, object]],
    audit_rows: Mapping[str, list[Mapping[str, object]]],
    global_counts: Mapping[str, int],
    inspected_at: datetime | None = None,
) -> dict[str, object]:
    """Build a payload-redacted exact-prefix inspection receipt."""

    profile = source_lock()["profile"]
    required_migrations = tuple(profile["required_migrations"])
    checks: dict[str, bool] = {
        "database_matches": database_name == plan.database_name,
        "schema_matches": migrations == required_migrations,
        "no_global_leases": global_counts.get("leased", 0) == 0,
        "no_global_ambiguous_reconciliations": global_counts.get("ambiguous", 0) == 0,
        "no_global_dead_letters": global_counts.get("dead_lettered", 0) == 0,
        "prefix_nonempty": bool(rows),
        "prefix_within_cap": len(rows) <= plan.maximum_rows,
        "prefix_rows_match": True,
        "prefix_audit_matches": True,
    }
    identities: list[PrefixIdentity] = []
    prior_id = 0
    for row in rows:
        try:
            identity = PrefixIdentity(
                id=row["id"],
                producer=row["producer"],
                message_id=row["message_id"],
                topic=row["topic"],
                payload_sha256=row["payload_sha256"],
                publish_attempts=row["publish_attempts"],
            )
            payload, payload_sha256 = _canonical_outbox_payload(row["payload"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            checks["prefix_rows_match"] = False
            continue
        if (
            identity.id <= prior_id
            or identity.producer != plan.producer
            or identity.topic != plan.topic
            or row.get("published_at") is not None
            or row.get("dead_lettered_at") is not None
            or row.get("lease_clear") is not True
            or row.get("available") is not True
            or row.get("reconciliation_state") != "NONE"
            or payload_sha256 != identity.payload_sha256
            or payload.get("message_id") != identity.message_id
        ):
            checks["prefix_rows_match"] = False
        prior_id = identity.id
        identities.append(identity)
        matching_audit = audit_rows.get(identity.message_id, [])
        if len(matching_audit) != 1:
            checks["prefix_audit_matches"] = False
            continue
        try:
            audit_payload, audit_hash = _canonical_outbox_payload(matching_audit[0]["payload"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            checks["prefix_audit_matches"] = False
            continue
        if (
            matching_audit[0].get("topic") != identity.topic
            or audit_hash != identity.payload_sha256
            or audit_payload != payload
            or audit_payload.get("message_id") != identity.message_id
        ):
            checks["prefix_audit_matches"] = False
    exact_identities = tuple(identities)
    identity_values = identities_payload(exact_identities)
    checks["prefix_rows_match"] = checks["prefix_rows_match"] and len(identity_values) == len(rows)
    eligible = all(checks.values())
    inspection: dict[str, object] = {
        "result": "ELIGIBLE" if eligible else ("EMPTY" if not rows and checks["schema_matches"] else "REJECTED"),
        "checks": checks,
        "database_name": database_name,
        "migrations": list(migrations),
        "global": {
            "leased": int(global_counts.get("leased", 0)),
            "ambiguous": int(global_counts.get("ambiguous", 0)),
            "dead_lettered": int(global_counts.get("dead_lettered", 0)),
            "producer_pending": int(global_counts.get("producer_pending", 0)),
        },
        "selected_count": len(identity_values),
        "identities": identity_values,
        "identities_sha256": sha256_json(identity_values),
    }
    receipt = _inspection_payload(plan, inspection=inspection, inspected_at=inspected_at or datetime.now(UTC))
    receipt["receipt_sha256"] = sha256_json(receipt)
    assert_receipt_redacted(receipt)
    return receipt


async def inspect_database(plan: DrainPlan, database_url: str) -> dict[str, object]:
    """Read a bounded prefix only; no migration, claim, audit, or publish occurs."""

    if asyncpg is None:  # pragma: no cover - guarded by the runtime image
        raise DrainInputError("asyncpg is unavailable in this runner environment")
    connection = await asyncpg.connect(
        database_url,
        server_settings={"default_transaction_read_only": "on"},
        command_timeout=15,
    )
    try:
        async with connection.transaction(readonly=True):
            database_name = str(await connection.fetchval("SELECT current_database()"))
            migrations = tuple(
                str(item["version"])
                for item in await connection.fetch("SELECT version FROM schema_migrations ORDER BY version")
            )
            required_migrations = tuple(source_lock()["profile"]["required_migrations"])
            if migrations != required_migrations:
                return build_inspection_receipt(
                    plan,
                    database_name=database_name,
                    migrations=migrations,
                    rows=[],
                    audit_rows={},
                    global_counts={"leased": 0, "ambiguous": 0, "dead_lettered": 0, "producer_pending": 0},
                )
            counts = await connection.fetchrow(
                """SELECT count(*) FILTER (
                              WHERE published_at IS NULL
                                AND dead_lettered_at IS NULL
                                AND lease_until IS NOT NULL
                          ) AS leased,
                          count(*) FILTER (
                              WHERE published_at IS NULL
                                AND dead_lettered_at IS NULL
                                AND reconciliation_state <> 'NONE'
                          ) AS ambiguous,
                          count(*) FILTER (WHERE dead_lettered_at IS NOT NULL) AS dead_lettered,
                          count(*) FILTER (
                              WHERE producer=$1
                                AND topic=$2
                                AND published_at IS NULL
                                AND dead_lettered_at IS NULL
                          ) AS producer_pending
                     FROM message_outbox""",
                plan.producer,
                plan.topic,
            )
            rows = await connection.fetch(
                """SELECT id, producer, message_id, topic, payload, payload_sha256,
                              publish_attempts, published_at, dead_lettered_at,
                              (lease_until IS NULL) AS lease_clear,
                              (available_at <= now()) AS available, reconciliation_state
                         FROM message_outbox
                        WHERE producer=$1
                          AND published_at IS NULL
                        ORDER BY id
                        LIMIT $2""",
                plan.producer,
                plan.maximum_rows,
            )
            audit_rows: dict[str, list[Mapping[str, object]]] = {}
            for row in rows:
                message_id = str(row["message_id"])
                audit_rows[message_id] = [
                    dict(item)
                    for item in await connection.fetch(
                        "SELECT topic, payload FROM event_audit WHERE message_id=$1",
                        message_id,
                    )
                ]
    finally:
        await connection.close()
    return build_inspection_receipt(
        plan,
        database_name=database_name,
        migrations=migrations,
        rows=[dict(row) for row in rows],
        audit_rows=audit_rows,
        global_counts=dict(counts),
    )


def _trusted_signer_fingerprint() -> str:
    signer = source_lock().get("trusted_receipt_signer")
    if not isinstance(signer, Mapping) or not isinstance(signer.get("fingerprint"), str):
        raise DrainInputError("source lock trusted signer is invalid")
    return str(signer["fingerprint"])


def verify_receipt_signature(receipt_path: Path, signature_path: Path) -> None:
    if not receipt_path.is_file() or not signature_path.is_file() or not TRUSTED_SIGNER_PATH.is_file():
        raise DrainInputError("receipt, signature, or trusted signer is unavailable")
    with tempfile.TemporaryDirectory(prefix="kairos-offline-outbox-drain-") as directory:
        keyring = Path(directory) / "trusted.gpg"
        environment = {**os.environ, "GNUPGHOME": directory}
        imported = subprocess.run(
            [
                "gpg",
                "--batch",
                "--no-default-keyring",
                "--keyring",
                str(keyring),
                "--import",
                str(TRUSTED_SIGNER_PATH),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if imported.returncode != 0:
            raise DrainInputError("trusted receipt signer import failed")
        verified = subprocess.run(
            ["gpgv", "--status-fd", "1", "--keyring", str(keyring), str(signature_path), str(receipt_path)],
            check=False,
            capture_output=True,
            text=True,
        )
    valid = any(
        line.startswith("[GNUPG:] VALIDSIG ") and line.split()[2] == _trusted_signer_fingerprint()
        for line in verified.stdout.splitlines()
    )
    if verified.returncode != 0 or not valid:
        raise DrainInputError("inspection receipt signature is invalid or from an untrusted signer")


def receipt_identities(receipt: Mapping[str, object]) -> tuple[PrefixIdentity, ...]:
    inspection = receipt.get("inspection")
    if not isinstance(inspection, Mapping):
        raise DrainInputError("inspection receipt inspection is invalid")
    identities = identities_from_json(inspection.get("identities"))
    values = identities_payload(identities)
    if inspection.get("identities_sha256") != sha256_json(values):
        raise DrainInputError("inspection receipt prefix hash is invalid")
    return identities


def validate_apply_receipt(
    receipt: object,
    plan: DrainPlan,
    *,
    expected_file_sha256: str,
    actual_file_sha256: str,
    now: datetime | None = None,
) -> tuple[PrefixIdentity, ...]:
    if not SHA256.fullmatch(expected_file_sha256) or not SHA256.fullmatch(actual_file_sha256):
        raise DrainInputError("receipt file hashes must be lowercase SHA-256 values")
    if expected_file_sha256 != actual_file_sha256:
        raise DrainInputError("inspection receipt file hash differs from the explicitly armed value")
    if not isinstance(receipt, Mapping):
        raise DrainInputError("inspection receipt must be a JSON object")
    if receipt.get("receipt_sha256") != sha256_json(_receipt_without_hash(receipt)):
        raise DrainInputError("inspection receipt content hash does not match its signed content")
    assert_receipt_redacted(receipt)
    lock = source_lock()
    if receipt.get("kind") != "kairos.offline-outbox-drain-inspection.v1":
        raise DrainInputError("inspection receipt kind is invalid")
    if receipt.get("classification") != "OFFLINE_SIGNED_PREFIX_ONLY":
        raise DrainInputError("inspection receipt classification is invalid")
    if receipt.get("source_lock_sha256") != sha256_json(lock):
        raise DrainInputError("inspection receipt source lock differs from this runner")
    if receipt.get("plan_sha256") != sha256_json(plan.payload()) or receipt.get("plan") != plan.payload():
        raise DrainInputError("inspection receipt plan differs from the supplied drain plan")
    inspection = receipt.get("inspection")
    if not isinstance(inspection, Mapping) or inspection.get("result") != "ELIGIBLE":
        raise DrainInputError("only an eligible inspection receipt can authorize a drain")
    identities = receipt_identities(receipt)
    if len(identities) > plan.maximum_rows:
        raise DrainInputError("inspection receipt exceeds the signed drain cap")
    if any(identity.producer != plan.producer or identity.topic != plan.topic for identity in identities):
        raise DrainInputError("inspection receipt contains an identity outside the signed scope")
    maximum_age = int(lock["profile"]["maximum_receipt_age_seconds"])
    age_seconds = ((now or datetime.now(UTC)) - _datetime(receipt.get("inspected_at_utc"))).total_seconds()
    if age_seconds < 0 or age_seconds > maximum_age:
        raise DrainInputError("inspection receipt is stale or has a future timestamp")
    return identities


async def _fresh_prefix_matches(
    plan: DrainPlan,
    *,
    database_url: str,
    signed_identities: tuple[PrefixIdentity, ...],
) -> None:
    fresh = await inspect_database(plan, database_url)
    inspection = fresh.get("inspection")
    if not isinstance(inspection, Mapping) or inspection.get("result") != "ELIGIBLE":
        raise DrainInputError("database no longer satisfies the signed drain preconditions")
    if receipt_identities(fresh) != signed_identities:
        raise DrainInputError("database prefix differs from the signed inspection receipt")


def _drain_row_id(plan: DrainPlan, identity: PrefixIdentity) -> str:
    value = f"{plan.drain_id}:{identity.id}"
    if len(value) > 200:
        raise DrainInputError("derived exact drain identity exceeds the persistence bound")
    return value


def _result_state_value(result: object) -> str:
    state = getattr(result, "state", None)
    return str(getattr(state, "value", state))


def _acceptance_payload(
    plan: DrainPlan,
    *,
    receipt_sha256: str,
    signed_identities: tuple[PrefixIdentity, ...],
    acknowledged: tuple[PrefixIdentity, ...],
    state: str,
    terminal: object | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": 1,
        "kind": "kairos.offline-outbox-drain-acceptance.v1",
        "classification": "OFFLINE_SIGNED_PREFIX_ONLY",
        "source_lock_sha256": sha256_json(source_lock()),
        "plan_sha256": sha256_json(plan.payload()),
        "database_name": plan.database_name,
        "producer": plan.producer,
        "topic": plan.topic,
        "drain_id": plan.drain_id,
        "inspection_receipt_sha256": receipt_sha256,
        "selected_count": len(signed_identities),
        "acknowledged_count": len(acknowledged),
        "acknowledged_identities": identities_payload(acknowledged),
        "acknowledged_identities_sha256": sha256_json(identities_payload(acknowledged)),
        "state": state,
    }
    if terminal is not None:
        result["terminal_state"] = _result_state_value(terminal)
        rejection = getattr(terminal, "rejection", None)
        if rejection is not None:
            result["rejection"] = str(rejection)
        unknown_quarantined = getattr(terminal, "unknown_quarantined", None)
        if unknown_quarantined is not None:
            result["unknown_quarantined"] = bool(unknown_quarantined)
        failure_kind = getattr(terminal, "failure_kind", None)
        if failure_kind is not None:
            result["failure_kind"] = str(failure_kind)
    assert_receipt_redacted(result)
    return result


async def apply_prefix(
    plan: DrainPlan,
    *,
    database_url: str,
    redis_url: str,
    signed_identities: tuple[PrefixIdentity, ...],
    receipt_sha256: str,
) -> tuple[int, dict[str, object]]:
    """Drain only the signed exact prefix, serially and within its wall-clock cap."""

    if asyncpg is None:  # pragma: no cover - guarded by the runtime image
        raise DrainInputError("asyncpg is unavailable in this runner environment")
    from kairos_core.bus.redis_streams import RedisStreamsBus
    from kairos_persistence import AuditRepository, OfflineOutboxIdentity, OfflineOutboxPrefixDrainer

    pool = await asyncpg.create_pool(dsn=database_url, min_size=1, max_size=1, command_timeout=15)
    bus = RedisStreamsBus(redis_url)
    acknowledged: list[PrefixIdentity] = []
    deadline = time.monotonic() + plan.maximum_duration_seconds
    try:
        drainer = OfflineOutboxPrefixDrainer(AuditRepository(pool))

        async def publisher(topic: str, payload: dict[str, Any]) -> None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("drain deadline reached before Redis publish")
            await asyncio.wait_for(bus.publish(topic, payload), timeout=remaining)

        for identity in signed_identities:
            if time.monotonic() >= deadline:
                return 2, _acceptance_payload(
                    plan,
                    receipt_sha256=receipt_sha256,
                    signed_identities=signed_identities,
                    acknowledged=tuple(acknowledged),
                    state="TIME_CAP_REACHED",
                )
            result = await drainer.drain_exact(
                OfflineOutboxIdentity(**identity_payload(identity)),
                drain_id=_drain_row_id(plan, identity),
                publisher=publisher,
            )
            state = _result_state_value(result)
            if state == "PUBLISH_ACKNOWLEDGED":
                acknowledged.append(identity)
                continue
            return (2 if state == "CLAIM_REJECTED" else 3), _acceptance_payload(
                plan,
                receipt_sha256=receipt_sha256,
                signed_identities=signed_identities,
                acknowledged=tuple(acknowledged),
                state=state,
                terminal=result,
            )
        terminal_state = "DRAINED_CAP" if len(signed_identities) == plan.maximum_rows else "DRAINED_EMPTY"
        return 0, _acceptance_payload(
            plan,
            receipt_sha256=receipt_sha256,
            signed_identities=signed_identities,
            acknowledged=tuple(acknowledged),
            state=terminal_state,
        )
    finally:
        await bus.close()
        await pool.close()


def parser() -> argparse.ArgumentParser:
    profile = source_lock()["profile"]
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--mode", choices=("inspect", "apply"), default="inspect")
    argument_parser.add_argument("--plan", type=Path, required=True)
    argument_parser.add_argument("--database-url-file", type=Path, required=True)
    argument_parser.add_argument("--redis-url-file", type=Path)
    argument_parser.add_argument("--receipt", type=Path)
    argument_parser.add_argument("--receipt-signature", type=Path)
    argument_parser.add_argument("--expected-receipt-sha256")
    argument_parser.add_argument("--apply-confirmation")
    argument_parser.add_argument(
        "--maximum-receipt-age-seconds",
        type=int,
        default=int(profile["maximum_receipt_age_seconds"]),
    )
    return argument_parser


async def run(args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    plan = DrainPlan.from_json(read_json(args.plan, label="drain plan"))
    database_url = read_nonempty_secret(args.database_url_file, label="database URL file")
    if args.mode == "inspect":
        return 0, await inspect_database(plan, database_url)

    profile = source_lock()["profile"]
    if args.apply_confirmation != profile["apply_confirmation"]:
        raise DrainInputError("apply requires the exact immutable apply confirmation")
    if args.maximum_receipt_age_seconds != profile["maximum_receipt_age_seconds"]:
        raise DrainInputError("apply cannot extend the immutable receipt lifetime")
    if not all((args.redis_url_file, args.receipt, args.receipt_signature, args.expected_receipt_sha256)):
        raise DrainInputError("apply requires Redis, receipt, signature, and exact receipt hash")
    verify_receipt_signature(args.receipt, args.receipt_signature)
    receipt_bytes = args.receipt.read_bytes()
    receipt = read_json(args.receipt, label="inspection receipt")
    signed_identities = validate_apply_receipt(
        receipt,
        plan,
        expected_file_sha256=args.expected_receipt_sha256,
        actual_file_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
    )
    await _fresh_prefix_matches(plan, database_url=database_url, signed_identities=signed_identities)
    redis_url = read_nonempty_secret(args.redis_url_file, label="Redis URL file")
    return await apply_prefix(
        plan,
        database_url=database_url,
        redis_url=redis_url,
        signed_identities=signed_identities,
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
    )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        code, output = asyncio.run(run(args))
    except (DrainInputError, OSError, json.JSONDecodeError) as exc:
        output = {
            "schema_version": 1,
            "kind": "kairos.offline-outbox-drain-acceptance.v1",
            "classification": "OFFLINE_SIGNED_PREFIX_ONLY",
            "state": "STARTUP_REJECTED",
            "error_type": type(exc).__name__,
        }
        code = 4
    except (RuntimeError, TypeError, ValueError) as exc:
        output = {
            "schema_version": 1,
            "kind": "kairos.offline-outbox-drain-acceptance.v1",
            "classification": "OFFLINE_SIGNED_PREFIX_ONLY",
            "state": "STARTUP_REJECTED",
            "error_type": type(exc).__name__,
        }
        code = 4
    except DRIVER_ERRORS as exc:
        output = {
            "schema_version": 1,
            "kind": "kairos.offline-outbox-drain-acceptance.v1",
            "classification": "OFFLINE_SIGNED_PREFIX_ONLY",
            "state": "STARTUP_REJECTED",
            "error_type": type(exc).__name__,
        }
        code = 4
    print(canonical_json(output))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
