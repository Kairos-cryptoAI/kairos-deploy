"""DB-only worker used inside an isolated legacy outbox clone rehearsal.

This file is deliberately copied only into a generated clone staging volume.
It is executed by the reviewed, immutable kairos-persistence image while it
shares the clone's ``--network none`` namespace.  It has no Redis client,
provider client, or generic runtime startup path.

The host controller verifies the source backup, signed inspection receipt,
image identity, and migration bytes before this worker is invoked.  This
worker performs one narrow additional proof: the exact expired legacy lease
can be quarantined on the clone through AuditRepository's DB-only primitive.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

import asyncpg
from kairos_persistence.repository import (
    AuditRepository,
    OfflineOutboxExpiredLease,
    OfflineOutboxIdentity,
    OfflineOutboxQuarantineState,
)


SHA256 = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_PROFILE = (
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
    "018_offline_outbox_reconciliation.sql",
)
QUARANTINE_REASON = "legacy expired lease clone-only quarantine rehearsal"


class CloneRunnerInputError(ValueError):
    """The host-to-clone contract is malformed or unsuitable."""


class FailingNoNetworkPublisher:
    """A witness proving this DB-only path never invokes a publisher."""

    def __init__(self) -> None:
        self.calls = 0

    async def publish(self, *_: object, **__: object) -> None:
        self.calls += 1
        raise RuntimeError("synthetic no-network publisher must never be called")


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not isinstance(value, str) or not value:
        raise CloneRunnerInputError(f"missing required clone runner environment: {name}")
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _utc(value: object) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise CloneRunnerInputError("clone outbox timestamp is not UTC-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CloneRunnerInputError("lease timestamp is not ISO-8601 UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CloneRunnerInputError("lease timestamp is not UTC-aware")
    return parsed.astimezone(UTC)


def _expectation(path: Path) -> tuple[OfflineOutboxIdentity, str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloneRunnerInputError("clone expectation is unavailable") from exc
    if not isinstance(value, Mapping) or set(value) != {"schema_version", "identity", "reconciliation_id"}:
        raise CloneRunnerInputError("clone expectation has an unexpected shape")
    if value.get("schema_version") != 1 or not isinstance(value.get("identity"), Mapping):
        raise CloneRunnerInputError("clone expectation provenance is invalid")
    raw = value["identity"]
    expected_identity_fields = {
        "id",
        "producer",
        "message_id",
        "topic",
        "payload_sha256",
        "publish_attempts",
    }
    if set(raw) != expected_identity_fields:
        raise CloneRunnerInputError("clone expectation must bind every outbox identity field")
    reconciliation_id = value.get("reconciliation_id")
    if not isinstance(reconciliation_id, str) or not reconciliation_id.strip() or len(reconciliation_id) > 200:
        raise CloneRunnerInputError("clone reconciliation ID is invalid")
    try:
        identity = OfflineOutboxIdentity(
            id=raw["id"],
            producer=raw["producer"],
            message_id=raw["message_id"],
            topic=raw["topic"],
            payload_sha256=raw["payload_sha256"],
            publish_attempts=raw["publish_attempts"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CloneRunnerInputError("clone immutable outbox identity is invalid") from exc
    return identity, reconciliation_id.strip()


def _redacted_row(row: asyncpg.Record) -> dict[str, object]:
    owner = row["lease_owner"]
    return {
        "id": int(row["id"]),
        "producer": str(row["producer"]),
        "message_id": str(row["message_id"]),
        "topic": str(row["topic"]),
        "payload_sha256": str(row["payload_sha256"]),
        "publish_attempts": int(row["publish_attempts"]),
        "published": row["published_at"] is not None,
        "dead_lettered": row["dead_lettered_at"] is not None,
        "lease_owner_sha256": hashlib.sha256(owner.encode("utf-8")).hexdigest()
        if isinstance(owner, str) and owner
        else None,
        "lease_until_utc": _utc(row["lease_until"]) if row["lease_until"] is not None else None,
        "reconciliation_state": str(row["reconciliation_state"]),
        "reconciliation_id": row["reconciliation_id"],
    }


async def _run() -> dict[str, object]:
    expectation_path = Path(_required_environment("KAIROS_CLONE_EXPECTATION_PATH"))
    identity, reconciliation_id = _expectation(expectation_path)
    expected_owner_sha256 = _required_environment("KAIROS_CLONE_LEASE_OWNER_SHA256")
    if SHA256.fullmatch(expected_owner_sha256) is None:
        raise CloneRunnerInputError("clone lease owner hash is invalid")
    expected_until = _parse_utc(_required_environment("KAIROS_CLONE_LEASE_UNTIL_UTC"))
    dsn = _required_environment("KAIROS_CLONE_DATABASE_URL")
    publisher = FailingNoNetworkPublisher()

    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=1, command_timeout=20)
    try:
        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT id, producer, message_id, topic, payload_sha256,
                          publish_attempts, published_at, dead_lettered_at,
                          lease_owner, lease_until, reconciliation_state,
                          reconciliation_id
                     FROM message_outbox
                    WHERE id=$1""",
                identity.id,
            )
            if row is None:
                raise CloneRunnerInputError("clone exact outbox row is missing")
            owner = row["lease_owner"]
            if not isinstance(owner, str) or not owner:
                raise CloneRunnerInputError("clone exact outbox lease owner is missing")
            if hashlib.sha256(owner.encode("utf-8")).hexdigest() != expected_owner_sha256:
                raise CloneRunnerInputError("clone exact outbox lease owner hash differs")
            if _utc(row["lease_until"]) != _utc(expected_until):
                raise CloneRunnerInputError("clone exact outbox lease timestamp differs")
            before = _redacted_row(row)

        repository = AuditRepository(pool)
        lease = OfflineOutboxExpiredLease(owner=owner, until=expected_until)
        first = await repository.quarantine_expired_outbox_exact(
            identity,
            expired_lease=lease,
            reconciliation_id=reconciliation_id,
            reason=QUARANTINE_REASON,
        )
        second = await repository.quarantine_expired_outbox_exact(
            identity,
            expired_lease=lease,
            reconciliation_id=reconciliation_id,
            reason=QUARANTINE_REASON,
        )
        if first.state is not OfflineOutboxQuarantineState.QUARANTINED:
            raise CloneRunnerInputError("first clone quarantine did not succeed")
        if second.state is not OfflineOutboxQuarantineState.ALREADY_QUARANTINED:
            raise CloneRunnerInputError("repeat clone quarantine was not idempotent")

        async with pool.acquire() as connection:
            row = await connection.fetchrow(
                """SELECT id, producer, message_id, topic, payload_sha256,
                          publish_attempts, published_at, dead_lettered_at,
                          lease_owner, lease_until, reconciliation_state,
                          reconciliation_id
                     FROM message_outbox
                    WHERE id=$1""",
                identity.id,
            )
            migrations = tuple(
                str(item["version"])
                for item in await connection.fetch("SELECT version FROM schema_migrations ORDER BY version")
            )
            simulator_relations = int(
                await connection.fetchval(
                    """SELECT COUNT(*) FROM pg_class c
                         JOIN pg_namespace n ON n.oid=c.relnamespace
                        WHERE n.nspname='public' AND c.relname LIKE 'sim\\_%' ESCAPE '\\'"""
                )
            )
        if row is None:
            raise CloneRunnerInputError("clone exact outbox row disappeared")
        after = _redacted_row(row)
        if (
            after["published"]
            or after["dead_lettered"]
            or after["publish_attempts"] != identity.publish_attempts
            or after["lease_owner_sha256"] is not None
            or after["lease_until_utc"] is not None
            or after["reconciliation_state"] != "PUBLISH_OUTCOME_UNKNOWN"
            or after["reconciliation_id"] != reconciliation_id
            or migrations != RUNTIME_PROFILE
            or simulator_relations != 0
            or publisher.calls != 0
        ):
            raise CloneRunnerInputError("clone quarantine postconditions are not exact")
        return {
            "schema_version": 1,
            "kind": "kairos.legacy-outbox-clone-quarantine-result.v1",
            "first_state": first.state.value,
            "repeat_state": second.state.value,
            "before_sha256": _sha256_json(before),
            "after_sha256": _sha256_json(after),
            "after": after,
            "runtime_profile": list(migrations),
            "simulator_relations": simulator_relations,
            "publisher_calls": publisher.calls,
        }
    finally:
        await pool.close()


def main() -> int:
    try:
        result = asyncio.run(_run())
    except (CloneRunnerInputError, OSError, RuntimeError, TypeError, ValueError) as exc:
        # Never include DB URL, raw lease owner, payload, or driver detail in a
        # host-visible error.  The host records only this redacted class name.
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "kairos.legacy-outbox-clone-quarantine-result.v1",
                    "state": "REJECTED",
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
