"""Disposable real-PostgreSQL proof for the legacy inspector.

CI mounts this file into a sealed inspector image only after creating a fresh
internal TimescaleDB fixture.  It never appears in the operational image and
does not contact a runtime database, Redis, an exchange, or a provider API.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path

import asyncpg
import kairos_persistence

from legacy_outbox_inspection import ExactIdentity, LegacyExpectation, SourceBackup, inspect_database


def _payload() -> dict[str, object]:
    return {
        "kind": "kairos.market.closed_bar.v1",
        "message_id": "legacy-integration-message-1",
        "symbol": "BTCUSDT",
        "venue": "BINANCE_UM",
    }


async def _apply_legacy_profile(connection: asyncpg.Connection) -> None:
    migrations_root = Path(kairos_persistence.__file__).resolve().parent / "migrations"
    names = tuple(str(value) for value in (__import__("legacy_outbox_inspection").source_lock()["profile"]["required_migrations"]))
    async with connection.transaction():
        await connection.execute(
            "CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        for name in names:
            await connection.execute((migrations_root / name).read_text(encoding="utf-8"))
            await connection.execute("INSERT INTO schema_migrations(version) VALUES($1)", name)


async def main() -> None:
    database_url = os.environ["KAIROS_LEGACY_TEST_DATABASE_URL"]
    connection = await asyncpg.connect(database_url)
    try:
        await _apply_legacy_profile(connection)
        payload = _payload()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        await connection.execute(
            """INSERT INTO event_audit(produced_at, message_id, topic, source, schema_version, payload)
               VALUES(now(), $1, $2, 'synthetic-only', 'v1', $3::jsonb)""",
            payload["message_id"],
            "kairos.market.closed_bar.v1",
            encoded,
        )
        row_id = await connection.fetchval(
            """INSERT INTO message_outbox(
                       message_id, topic, payload, payload_sha256, producer,
                       publish_attempts, available_at, lease_owner, lease_until
                   ) VALUES($1, $2, $3::jsonb, $4, $5, 1, now(), $6, now()-interval '1 minute')
                   RETURNING id""",
            payload["message_id"],
            "kairos.market.closed_bar.v1",
            encoded,
            digest,
            "kairos-quant-scouts",
            "synthetic-legacy-worker",
        )
        before = dict(
            await connection.fetchrow(
                """SELECT id, published_at, dead_lettered_at, publish_attempts, lease_owner, lease_until
                     FROM message_outbox WHERE id=$1""",
                row_id,
            )
        )
    finally:
        await connection.close()

    expectation = LegacyExpectation(
        identity=ExactIdentity(
            id=int(row_id),
            producer="kairos-quant-scouts",
            message_id=str(payload["message_id"]),
            topic="kairos.market.closed_bar.v1",
            payload_sha256=digest,
            publish_attempts=1,
        ),
        reconciliation_id="synthetic-legacy-clone-rehearsal",
    )
    backup = SourceBackup.from_values(
        manifest_sha256="a" * 64,
        backup_sha256="b" * 64,
        created_at_utc="2026-09-20T03:00:00.000000Z",
    )
    receipt = await inspect_database(expectation, database_url, source_backup=backup)
    if receipt["inspection"]["result"] != "ELIGIBLE_FOR_CLONE_REHEARSAL":
        checks = receipt["inspection"].get("checks")
        if not isinstance(checks, dict) or not all(isinstance(value, bool) for value in checks.values()):
            raise RuntimeError("synthetic legacy inspection emitted malformed safe checks")
        raise RuntimeError(
            "synthetic legacy inspection did not become clone-rehearsal eligible: "
            + json.dumps(checks, sort_keys=True, separators=(",", ":"))
        )
    encoded_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if "synthetic-legacy-worker" in encoded_receipt or '"payload"' in encoded_receipt:
        raise RuntimeError("synthetic legacy receipt exposed forbidden durable material")

    connection = await asyncpg.connect(database_url)
    try:
        after = dict(
            await connection.fetchrow(
                """SELECT id, published_at, dead_lettered_at, publish_attempts, lease_owner, lease_until
                     FROM message_outbox WHERE id=$1""",
                row_id,
            )
        )
        versions = tuple(str(item["version"]) for item in await connection.fetch("SELECT version FROM schema_migrations ORDER BY version"))
    finally:
        await connection.close()
    if after != before:
        raise RuntimeError("read-only legacy inspection changed the synthetic row")
    expected_versions = tuple(__import__("legacy_outbox_inspection").source_lock()["profile"]["required_migrations"])
    if versions != expected_versions:
        raise RuntimeError("synthetic fixture did not retain the exact legacy migration profile")
    print(json.dumps({"classification": "SYNTHETIC_ONLY", "state": "PASS_LEGACY_READ_ONLY"}))


if __name__ == "__main__":
    asyncio.run(main())
