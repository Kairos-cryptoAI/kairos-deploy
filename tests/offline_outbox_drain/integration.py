"""Disposable PostgreSQL/Redis proof for the signed-prefix drain primitive.

This file is never included in the operational runner image. CI mounts it into
that image only after creating isolated throwaway infrastructure.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os

import asyncpg
from kairos_persistence.config import PersistenceSettings
from kairos_persistence.database import Database
from redis import asyncio as aioredis

from offline_outbox_drain import DrainPlan, apply_prefix, inspect_database, receipt_identities


def _payload(index: int) -> dict[str, object]:
    return {
        "message_id": f"integration-bar-{index}",
        "symbol": "BTCUSDT",
        "venue": "BINANCE_UM",
        "open_time_ms": 1_700_000_000_000 + index * 60_000,
    }


async def main() -> None:
    database_url = os.environ["KAIROS_DRAIN_TEST_DATABASE_URL"]
    redis_url = os.environ["KAIROS_DRAIN_TEST_REDIS_URL"]
    database = Database(PersistenceSettings(database_url=database_url, command_timeout_s=15))
    await database.connect()
    try:
        await database.migrate()
    finally:
        await database.close()

    connection = await asyncpg.connect(database_url)
    try:
        for index in range(1, 4):
            payload = _payload(index)
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            await connection.execute(
                """INSERT INTO event_audit(
                           produced_at, message_id, topic, source, schema_version, payload
                       ) VALUES(now() + ($1::text || ' milliseconds')::interval, $2, $3, $4, $5, $6::jsonb)""",
                str(index),
                payload["message_id"],
                "kairos.market.closed_bar.v1",
                "kairos-quant-scouts",
                "v1",
                encoded,
            )
            await connection.execute(
                """INSERT INTO message_outbox(
                           message_id, topic, payload, payload_sha256, producer
                       ) VALUES($1, $2, $3::jsonb, $4, $5)""",
                payload["message_id"],
                "kairos.market.closed_bar.v1",
                encoded,
                digest,
                "kairos-quant-scouts",
            )
    finally:
        await connection.close()

    plan = DrainPlan.from_json(
        {
            "schema_version": 1,
            "database_name": "kairos_outbox_drain_test_20260920",
            "producer": "kairos-quant-scouts",
            "topic": "kairos.market.closed_bar.v1",
            "drain_id": "ci-disposable-drain",
            "maximum_rows": 2,
            "maximum_duration_seconds": 30,
        }
    )
    inspection = await inspect_database(plan, database_url)
    if inspection["inspection"]["result"] != "ELIGIBLE":
        raise RuntimeError("synthetic signed-prefix inspection did not become eligible")
    identities = receipt_identities(inspection)
    if len(identities) != 2:
        raise RuntimeError("synthetic inspection did not bind exactly the requested cap")
    code, acceptance = await apply_prefix(
        plan,
        database_url=database_url,
        redis_url=redis_url,
        signed_identities=identities,
        receipt_sha256="a" * 64,
    )
    if code != 0 or acceptance["state"] != "DRAINED_CAP" or acceptance["acknowledged_count"] != 2:
        raise RuntimeError("synthetic signed-prefix drain did not acknowledge exactly its cap")

    connection = await asyncpg.connect(database_url)
    try:
        facts = await connection.fetchrow(
            """SELECT count(*) FILTER (WHERE published_at IS NOT NULL) AS published,
                      count(*) FILTER (WHERE published_at IS NULL) AS pending,
                      count(*) FILTER (WHERE reconciliation_state='PUBLISH_OUTCOME_UNKNOWN') AS unknown,
                      count(*) AS total
                 FROM message_outbox"""
        )
        if dict(facts) != {"published": 2, "pending": 1, "unknown": 0, "total": 3}:
            raise RuntimeError("synthetic drain changed an unexpected durable row")
        if await connection.fetchval("SELECT count(*) FROM event_audit") != 3:
            raise RuntimeError("synthetic drain created an unexpected audit fact")
    finally:
        await connection.close()

    redis = aioredis.from_url(redis_url, decode_responses=True)
    try:
        if await redis.xlen("kairos.market.closed_bar.v1") != 2:
            raise RuntimeError("synthetic drain did not submit exactly two Redis entries")
    finally:
        await redis.aclose()
    print(json.dumps({"classification": "SYNTHETIC_ONLY", "state": "PASS", "published": 2, "pending": 1}))


if __name__ == "__main__":
    asyncio.run(main())
