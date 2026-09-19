"""Fail-closed exact-row offline outbox inspection and reconciliation runner.

The tool has two deliberately different modes.  ``inspect`` is the default and
opens PostgreSQL with a read-only transaction.  ``apply`` is unreachable unless
the caller supplies every immutable field for one row, a fresh inspection
receipt, its detached signature, the exact receipt hash, and the literal
confirmation from the immutable source lock.  It never starts a dispatcher,
enumerates a queue, retries a publish, or accepts a row identifier by itself.
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
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # Unit tests intentionally validate the pure receipt boundary without a runtime wheel.
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


class ReconciliationInputError(ValueError):
    """An operator input is malformed, stale, unverifiable, or unsafe."""


@dataclass(frozen=True)
class ExactIdentity:
    """A dependency-free copy of the immutable expectation shape.

    The actual ``OfflineOutboxIdentity`` is constructed immediately before the
    persistence API call.  Keeping this parsing boundary dependency-free makes
    it possible to audit receipt validation without an installed runtime wheel.
    """

    id: int
    producer: str
    message_id: str
    topic: str
    payload_sha256: str
    publish_attempts: int

    def __post_init__(self) -> None:
        if not isinstance(self.id, int) or isinstance(self.id, bool) or self.id <= 0:
            raise ReconciliationInputError("expectation identity id must be a positive integer")
        for name, value in (
            ("producer", self.producer),
            ("message_id", self.message_id),
            ("topic", self.topic),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ReconciliationInputError(f"expectation identity {name} must be a non-empty string")
        if not isinstance(self.payload_sha256, str) or not SHA256.fullmatch(self.payload_sha256):
            raise ReconciliationInputError("expectation payload_sha256 must be a lowercase SHA-256")
        if (
            not isinstance(self.publish_attempts, int)
            or isinstance(self.publish_attempts, bool)
            or self.publish_attempts < 0
        ):
            raise ReconciliationInputError("expectation publish_attempts must be a non-negative integer")


@dataclass(frozen=True)
class ExactExpectation:
    """Immutable pre-commitment to exactly one existing durable row."""

    identity: ExactIdentity
    reconciliation_id: str

    @classmethod
    def from_json(cls, value: object) -> ExactExpectation:
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "identity",
            "reconciliation_id",
        }:
            raise ReconciliationInputError("expectation must contain exactly schema_version, identity, reconciliation_id")
        if value.get("schema_version") != 1:
            raise ReconciliationInputError("expectation schema_version must be 1")
        identity = value.get("identity")
        if not isinstance(identity, Mapping) or set(identity) != {
            "id",
            "producer",
            "message_id",
            "topic",
            "payload_sha256",
            "publish_attempts",
        }:
            raise ReconciliationInputError("expectation identity must contain every immutable outbox field")
        reconciliation_id = value.get("reconciliation_id")
        if not isinstance(reconciliation_id, str) or not reconciliation_id.strip() or len(reconciliation_id) > 200:
            raise ReconciliationInputError("expectation reconciliation_id must be a non-empty string of at most 200 characters")
        try:
            return cls(
                identity=ExactIdentity(
                    id=identity["id"],
                    producer=identity["producer"],
                    message_id=identity["message_id"],
                    topic=identity["topic"],
                    payload_sha256=identity["payload_sha256"],
                    publish_attempts=identity["publish_attempts"],
                ),
                reconciliation_id=reconciliation_id.strip(),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ReconciliationInputError(f"invalid exact expectation: {type(exc).__name__}") from exc

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "identity": identity_payload(self.identity),
            "reconciliation_id": self.reconciliation_id,
        }


def canonical_json(value: object) -> str:
    """Canonical bytes for hashes and receipts; rejects non-finite JSON values."""

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
    value = json.loads(SOURCE_LOCK_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReconciliationInputError("source lock must be a JSON object")
    return value


def source_lock_sha256() -> str:
    return sha256_json(source_lock())


def read_json(path: Path, *, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReconciliationInputError(f"{label} cannot be parsed") from exc


def read_nonempty_secret(path: Path, *, label: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise ReconciliationInputError(f"{label} is unavailable") from exc
    if not value:
        raise ReconciliationInputError(f"{label} is empty")
    return value


def _datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise ReconciliationInputError("receipt inspected_at_utc must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReconciliationInputError("receipt inspected_at_utc is invalid") from exc
    if parsed.tzinfo is None:
        raise ReconciliationInputError("receipt inspected_at_utc must include a timezone")
    return parsed.astimezone(UTC)


def _receipt_without_hash(receipt: Mapping[str, object]) -> dict[str, object]:
    return {str(key): value for key, value in receipt.items() if key != "receipt_sha256"}


def _receipt_payload(
    expectation: ExactExpectation,
    *,
    inspection: Mapping[str, object],
    inspected_at: datetime,
) -> dict[str, object]:
    lock = source_lock()
    return {
        "schema_version": 1,
        "kind": "kairos.offline-outbox-inspection.v1",
        "classification": "OFFLINE_EXACT_ROW_ONLY",
        "source_lock_sha256": sha256_json(lock),
        "source": lock["dependencies"],
        "expectation_sha256": sha256_json(expectation.payload()),
        "identity": identity_payload(expectation.identity),
        "reconciliation_id": expectation.reconciliation_id,
        "inspection": dict(inspection),
        "inspected_at_utc": inspected_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }


def _canonical_outbox_payload(payload: object) -> tuple[dict[str, Any], str]:
    """Use the installed persistence implementation when available.

    The local fallback mirrors its canonical JSON rules and only exists so the
    receipt parser can be tested without opening a database or installing deps.
    """

    try:
        from kairos_persistence import AuditRepository

        return AuditRepository._canonical_outbox_payload(payload)
    except ModuleNotFoundError:
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ValueError("outbox payload is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise TypeError("outbox payload must be a JSON object")
        encoded = canonical_json(payload)
        return json.loads(encoded), hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_inspection_receipt(
    expectation: ExactExpectation,
    *,
    row: Mapping[str, object] | None,
    audit_rows: list[Mapping[str, object]],
    has_unpublished_predecessor: bool,
    inspected_at: datetime | None = None,
) -> dict[str, object]:
    """Create a redacted signed-receipt candidate from read-only query results."""

    identity = expectation.identity
    checks: dict[str, bool] = {
        "row_found": row is not None,
        "identity_matches": False,
        "payload_hash_matches": False,
        "audit_matches": False,
        "unpublished": False,
        "not_dead_lettered": False,
        "lease_expired": False,
        "available": False,
        "reconciliation_clear": False,
        "no_earlier_unpublished_predecessor": not has_unpublished_predecessor,
    }
    row_state = "NOT_FOUND"
    if row is not None:
        immutable = identity_payload(identity)
        checks["identity_matches"] = all(row.get(key) == value for key, value in immutable.items())
        row_state = str(row.get("reconciliation_state", "UNKNOWN"))
        checks["unpublished"] = row.get("published_at") is None
        checks["not_dead_lettered"] = row.get("dead_lettered_at") is None
        checks["lease_expired"] = row.get("lease_expired") is True
        checks["available"] = row.get("available") is True
        checks["reconciliation_clear"] = row_state == "NONE"
        payload = row.get("payload")
        try:
            canonical, actual_hash = _canonical_outbox_payload(payload)
            checks["payload_hash_matches"] = (
                actual_hash == identity.payload_sha256
                and canonical.get("message_id") == identity.message_id
            )
        except (TypeError, ValueError):
            checks["payload_hash_matches"] = False
        if len(audit_rows) == 1:
            audit = audit_rows[0]
            audit_payload = audit.get("payload")
            try:
                canonical_audit, audit_hash = _canonical_outbox_payload(audit_payload)
                checks["audit_matches"] = (
                    audit.get("topic") == identity.topic
                    and audit_hash == identity.payload_sha256
                    and canonical_audit.get("message_id") == identity.message_id
                )
            except (TypeError, ValueError):
                checks["audit_matches"] = False

    eligible = all(checks.values())
    inspection: dict[str, object] = {
        "result": "ELIGIBLE" if eligible else "REJECTED",
        "row_state": row_state,
        "checks": checks,
        "audit_row_count": len(audit_rows),
    }
    payload = _receipt_payload(
        expectation,
        inspection=inspection,
        inspected_at=inspected_at or datetime.now(UTC),
    )
    payload["receipt_sha256"] = sha256_json(payload)
    assert_receipt_redacted(payload)
    return payload


def assert_receipt_redacted(receipt: Mapping[str, object]) -> None:
    """Reject payload, connection, and secret material before it can be written."""

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
                    raise ReconciliationInputError("receipt contains forbidden sensitive material")
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, str) and ("postgres://" in value or "redis://" in value):
            raise ReconciliationInputError("receipt contains a connection string")

    visit(receipt)


async def inspect_database(expectation: ExactExpectation, database_url: str) -> dict[str, object]:
    """Perform only bounded exact-row SELECTs in a read-only PostgreSQL session."""

    if asyncpg is None:  # pragma: no cover - guarded by the runtime image
        raise ReconciliationInputError("asyncpg is unavailable in this runner environment")
    connection = await asyncpg.connect(
        database_url,
        server_settings={"default_transaction_read_only": "on"},
        command_timeout=15,
    )
    try:
        async with connection.transaction(readonly=True):
            row = await connection.fetchrow(
                """SELECT id, producer, message_id, topic, payload, payload_sha256,
                          publish_attempts, published_at, dead_lettered_at,
                          (lease_until IS NOT NULL AND lease_until < now()) AS lease_expired,
                          (available_at <= now()) AS available, reconciliation_state
                     FROM message_outbox
                    WHERE id=$1""",
                expectation.identity.id,
            )
            audit_rows = await connection.fetch(
                """SELECT topic, payload
                     FROM event_audit
                    WHERE message_id=$1""",
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
        row=dict(row) if row is not None else None,
        audit_rows=[dict(item) for item in audit_rows],
        has_unpublished_predecessor=bool(predecessor),
    )


def _trusted_signer_fingerprint() -> str:
    value = source_lock().get("trusted_receipt_signer")
    if not isinstance(value, Mapping) or not isinstance(value.get("fingerprint"), str):
        raise ReconciliationInputError("source lock trusted signer is invalid")
    return str(value["fingerprint"])


def verify_receipt_signature(receipt_path: Path, signature_path: Path) -> None:
    """Verify a detached signature against the sole reviewed public signer."""

    if not receipt_path.is_file() or not signature_path.is_file() or not TRUSTED_SIGNER_PATH.is_file():
        raise ReconciliationInputError("receipt, signature, or trusted signer is unavailable")
    expected = _trusted_signer_fingerprint()
    with tempfile.TemporaryDirectory(prefix="kairos-offline-outbox-") as directory:
        keyring = Path(directory) / "trusted.gpg"
        gpg_environment = {**os.environ, "GNUPGHOME": directory}
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
            env=gpg_environment,
        )
        if imported.returncode != 0:
            raise ReconciliationInputError("trusted receipt signer import failed")
        verified = subprocess.run(
            ["gpgv", "--status-fd", "1", "--keyring", str(keyring), str(signature_path), str(receipt_path)],
            check=False,
            capture_output=True,
            text=True,
        )
    valid = any(
        line.startswith("[GNUPG:] VALIDSIG ") and line.split()[2] == expected
        for line in verified.stdout.splitlines()
    )
    if verified.returncode != 0 or not valid:
        raise ReconciliationInputError("inspection receipt signature is invalid or from an untrusted signer")


def validate_apply_receipt(
    receipt: object,
    expectation: ExactExpectation,
    *,
    expected_file_sha256: str,
    actual_file_sha256: str,
    now: datetime | None = None,
) -> None:
    """Make stale, edited, rejected, or differently-scoped receipts unusable."""

    if not SHA256.fullmatch(expected_file_sha256) or not SHA256.fullmatch(actual_file_sha256):
        raise ReconciliationInputError("receipt file hashes must be lowercase SHA-256 values")
    if expected_file_sha256 != actual_file_sha256:
        raise ReconciliationInputError("inspection receipt file hash differs from the explicitly armed value")
    if not isinstance(receipt, Mapping):
        raise ReconciliationInputError("inspection receipt must be a JSON object")
    received_hash = receipt.get("receipt_sha256")
    if received_hash != sha256_json(_receipt_without_hash(receipt)):
        raise ReconciliationInputError("inspection receipt content hash does not match its signed content")
    assert_receipt_redacted(receipt)
    expected_lock = source_lock()
    if receipt.get("kind") != "kairos.offline-outbox-inspection.v1":
        raise ReconciliationInputError("receipt kind is invalid")
    if receipt.get("classification") != "OFFLINE_EXACT_ROW_ONLY":
        raise ReconciliationInputError("receipt classification is invalid")
    if receipt.get("source_lock_sha256") != sha256_json(expected_lock):
        raise ReconciliationInputError("inspection receipt source lock differs from this runner")
    if receipt.get("expectation_sha256") != sha256_json(expectation.payload()):
        raise ReconciliationInputError("inspection receipt expectation differs from supplied exact row")
    if receipt.get("identity") != identity_payload(expectation.identity):
        raise ReconciliationInputError("inspection receipt identity differs from supplied exact row")
    if receipt.get("reconciliation_id") != expectation.reconciliation_id:
        raise ReconciliationInputError("inspection receipt reconciliation ID differs from supplied expectation")
    inspection = receipt.get("inspection")
    if not isinstance(inspection, Mapping) or inspection.get("result") != "ELIGIBLE":
        raise ReconciliationInputError("only an eligible inspection receipt can authorize an apply attempt")
    maximum_age = int((expected_lock.get("profile") or {}).get("maximum_receipt_age_seconds", 0))
    if maximum_age <= 0:
        raise ReconciliationInputError("source lock receipt lifetime is invalid")
    age_seconds = ((now or datetime.now(UTC)) - _datetime(receipt.get("inspected_at_utc"))).total_seconds()
    if age_seconds < 0 or age_seconds > maximum_age:
        raise ReconciliationInputError("inspection receipt is stale or has a future timestamp")


def _result_state_value(result: object) -> str:
    state = getattr(result, "state", None)
    return str(getattr(state, "value", state))


def result_payload(result: Any) -> dict[str, object]:
    """Redacted terminal result for the sole exact-row reconciliation attempt."""

    payload: dict[str, object] = {
        "schema_version": 1,
        "kind": "kairos.offline-outbox-reconciliation-result.v1",
        "classification": "OFFLINE_EXACT_ROW_ONLY",
        "identity": identity_payload(result.identity),
        "state": _result_state_value(result),
    }
    if result.rejection is not None:
        payload["rejection"] = str(result.rejection)
    if result.unknown_quarantined is not None:
        payload["unknown_quarantined"] = result.unknown_quarantined
    if result.failure_kind is not None:
        payload["failure_kind"] = result.failure_kind
    assert_receipt_redacted(payload)
    return payload


def reconciliation_exit_code(result: object) -> int:
    """Map persistence terminal states without ever authorizing a retry."""

    state = _result_state_value(result)
    if state == "PUBLISH_ACKNOWLEDGED":
        return 0
    if state == "CLAIM_REJECTED":
        return 2
    # An unknown state is treated exactly like a lost ACK: the caller receives
    # a non-zero terminal status and must not turn it into another publish.
    return 3


async def apply_exact_row(
    expectation: ExactExpectation,
    *,
    database_url: str,
    redis_url: str,
) -> Any:
    """Call the persistence exact-row API once; do not own retry or dispatch."""

    if asyncpg is None:  # pragma: no cover - guarded by the runtime image
        raise ReconciliationInputError("asyncpg is unavailable in this runner environment")
    from kairos_core.bus.redis_streams import RedisStreamsBus
    from kairos_persistence import (
        AuditRepository,
        OfflineOutboxIdentity,
        OfflineOutboxReconciler,
    )

    pool = await asyncpg.create_pool(dsn=database_url, min_size=1, max_size=1, command_timeout=15)
    bus = RedisStreamsBus(redis_url)
    try:
        reconciler = OfflineOutboxReconciler(AuditRepository(pool))

        async def publisher(topic: str, payload: dict[str, Any]) -> None:
            await bus.publish(topic, payload)

        identity = OfflineOutboxIdentity(**identity_payload(expectation.identity))
        return await reconciler.reconcile(
            identity,
            reconciliation_id=expectation.reconciliation_id,
            publisher=publisher,
        )
    finally:
        await bus.close()
        await pool.close()


def parser() -> argparse.ArgumentParser:
    lock = source_lock()
    profile = lock["profile"]
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--mode", choices=("inspect", "apply"), default="inspect")
    argument_parser.add_argument("--expectation", type=Path, required=True)
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
    expectation = ExactExpectation.from_json(read_json(args.expectation, label="expectation"))
    database_url = read_nonempty_secret(args.database_url_file, label="database URL file")
    if args.mode == "inspect":
        receipt = await inspect_database(expectation, database_url)
        return 0, receipt

    profile = source_lock()["profile"]
    if args.apply_confirmation != profile["apply_confirmation"]:
        raise ReconciliationInputError("apply requires the exact immutable apply confirmation")
    if args.maximum_receipt_age_seconds != profile["maximum_receipt_age_seconds"]:
        raise ReconciliationInputError("apply cannot extend the immutable receipt lifetime")
    if not all((args.redis_url_file, args.receipt, args.receipt_signature, args.expected_receipt_sha256)):
        raise ReconciliationInputError("apply requires Redis, receipt, signature, and exact receipt hash")
    verify_receipt_signature(args.receipt, args.receipt_signature)
    receipt_bytes = args.receipt.read_bytes()
    receipt = read_json(args.receipt, label="inspection receipt")
    validate_apply_receipt(
        receipt,
        expectation,
        expected_file_sha256=args.expected_receipt_sha256,
        actual_file_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
    )
    redis_url = read_nonempty_secret(args.redis_url_file, label="Redis URL file")
    result = await apply_exact_row(expectation, database_url=database_url, redis_url=redis_url)
    output = result_payload(result)
    return reconciliation_exit_code(result), output


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        code, output = asyncio.run(run(args))
    except (ReconciliationInputError, OSError) as exc:
        # Never echo DSNs, payloads, or implementation exception text.
        output = {
            "schema_version": 1,
            "kind": "kairos.offline-outbox-reconciliation-result.v1",
            "classification": "OFFLINE_EXACT_ROW_ONLY",
            "state": "STARTUP_REJECTED",
            "error_type": type(exc).__name__,
        }
        code = 4
    except (RuntimeError, TypeError, ValueError) as exc:
        output = {
            "schema_version": 1,
            "kind": "kairos.offline-outbox-reconciliation-result.v1",
            "classification": "OFFLINE_EXACT_ROW_ONLY",
            "state": "STARTUP_REJECTED",
            "error_type": type(exc).__name__,
        }
        code = 4
    except DRIVER_ERRORS as exc:
        output = {
            "schema_version": 1,
            "kind": "kairos.offline-outbox-reconciliation-result.v1",
            "classification": "OFFLINE_EXACT_ROW_ONLY",
            "state": "STARTUP_REJECTED",
            "error_type": type(exc).__name__,
        }
        code = 4
    print(canonical_json(output))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
