"""Exact one-message recovery for the stopped October 12 non-trading epoch.

There is no legacy target, arbitrary message, bulk replay, lease/cursor reset,
schema mutation, automatic retry, trading handler, or provider in this path.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_worker as epoch
else:
    import runtime_epoch_worker as epoch

OWNER = "69893dc7b7c647f49967387e7efca9fb"
MESSAGE_ID = "818be38f9fc7e2f8d96e37ecce3ff1f03a351de196b8ae9d1654c3a5745d7a1e"
PAYLOAD_SHA256 = "32565da92091d27fdef72b2b39e6800fc9aceac837f70ddb05812d0c74a429ba"
OUTBOX_ID = 4559
OPEN_TIME_MS = 1_791_766_920_000
EXPECTED_COUNTS = {"audit": 334355, "outbox": 4546, "inbox": 4545}


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_incident_config(mode: str, config: dict) -> None:
    common = {
        "owner",
        "database",
        "pg_host",
        "redis_host",
        "admin_password",
        "producer_password",
        "consumer_password",
        "redis_producer_password",
        "redis_consumer_password",
    }
    restore_fields = {
        "restore_host",
        "restore_database",
        "restore_admin_password",
        "expected_seed",
    }
    if mode == "incident-verify-restore":
        common = {"owner", "database", "pg_host", "redis_host", "admin_password"}
    expected = common | (
        {"expected_state"}
        if mode == "incident-drain"
        else restore_fields
        if mode == "incident-verify-restore"
        else set()
    )
    if (
        mode not in {"incident-state", "incident-drain", "incident-verify-restore"}
        or set(config) != expected
        or config["owner"] != OWNER
        or config["database"] != "kairos_epoch_" + OWNER[:12]
        or config["pg_host"] != "kairos-epoch-" + OWNER[:12] + "-pg"
        or config["redis_host"] != "kairos-epoch-" + OWNER[:12] + "-redis"
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(config[field])) is None
            for field in common
            if field.endswith("password")
        )
    ):
        raise epoch.EpochError("EXACT_INCIDENT_PRIVATE_CONFIG_REQUIRED")
    if mode == "incident-drain" and not isinstance(config["expected_state"], dict):
        raise epoch.EpochError("INCIDENT_FULL_PRESTATE_REQUIRED")
    if mode == "incident-verify-restore" and (
        config["restore_host"] != "kairos-epoch-" + OWNER[:12] + "-restore"
        or config["restore_database"]
        != "kairos_recovery_" + OWNER[:12] + "_epochrestore"
        or not isinstance(config["expected_seed"], dict)
        or re.fullmatch(r"[0-9a-f]{64}", str(config["restore_admin_password"])) is None
    ):
        raise epoch.EpochError("EXACT_DISPOSABLE_INCIDENT_RESTORE_REQUIRED")


def validate_incident_queue(
    outbox: list, inbox: list, *, allow_pending: bool
) -> tuple[dict, dict]:
    from kairos_core.contracts import ClosedBarEventV1
    from kairos_persistence.runtime import canonical_payload

    expected_inbox = EXPECTED_COUNTS["inbox"] + (0 if allow_pending else 1)
    if len(outbox) != EXPECTED_COUNTS["outbox"] or len(inbox) != expected_inbox:
        raise epoch.EpochError("INCIDENT_EXACT_QUEUE_COUNTS_REQUIRED")
    inbox_by_id = {}
    for row in inbox:
        if (
            row["consumer"] != "kairos-epoch-consumer-" + OWNER[:12] + ":bars"
            or row["topic"] != epoch.TOPIC
            or row["status"] != "COMPLETED"
            or row["message_id"] in inbox_by_id
        ):
            raise epoch.EpochError("INCIDENT_INBOX_IDENTITY_CONFLICT")
        inbox_by_id[row["message_id"]] = row
    published = {}
    pending = []
    for row in outbox:
        payload = (
            json.loads(row["payload"])
            if isinstance(row["payload"], str)
            else row["payload"]
        )
        event = ClosedBarEventV1.model_validate(payload)
        encoded, hashed = canonical_payload(payload)
        if (
            row["topic"] != epoch.TOPIC
            or row["producer"] != epoch.SOURCE
            or row["message_id"] != event.message_id
            or hashed != row["payload_sha256"]
            or event.source != epoch.SOURCE
            or event.symbol not in epoch.SYMBOLS
            or row["lease_owner"] is not None
            or row["lease_until"] is not None
            or row["dead_lettered_at"] is not None
            or row["reconciliation_state"] != "NONE"
            or row["last_error"] is not None
        ):
            raise epoch.EpochError("INCIDENT_OUTBOX_IDENTITY_CONFLICT")
        if row["published_at"] is None:
            if (
                not allow_pending
                or row["id"] != OUTBOX_ID
                or event.message_id != MESSAGE_ID
                or hashed != PAYLOAD_SHA256
                or event.symbol != "BTCUSDT"
                or event.open_time_ms != OPEN_TIME_MS
                or row["publish_attempts"] != 0
                or event.message_id in inbox_by_id
            ):
                raise epoch.EpochError("ONLY_EXACT_COMMITTED_BTC_PENDING_ALLOWED")
            pending.append(
                {"id": OUTBOX_ID, "message_id": MESSAGE_ID, "payload_sha256": hashed}
            )
        else:
            if type(row["publish_attempts"]) is not int or row["publish_attempts"] < 1:
                raise epoch.EpochError("INCIDENT_PUBLISHED_ROW_ACK_REQUIRED")
            completed = inbox_by_id.pop(event.message_id, None)
            if completed is None or completed["payload_sha256"] != hashed:
                raise epoch.EpochError("INCIDENT_COMPLETED_PUBLICATION_CONFLICT")
            published[event.message_id] = (hashed, encoded)
    if inbox_by_id or len(pending) != (1 if allow_pending else 0):
        raise epoch.EpochError("INCIDENT_QUEUE_EXTRA_OR_MISSING_ROW")
    return {
        "outbox_rows": len(outbox),
        "inbox_rows": len(inbox),
        "pending": pending,
    }, published


async def incident_snapshot(
    config: dict,
    *,
    allow_pending: bool,
    workers_stopped: bool = True,
    connection=None,
    database: str | None = None,
) -> tuple[dict, dict]:
    from controlled_runtime_worker import Budget, _table_digest

    owns_connection = connection is None
    if (
        database is not None
        and database != "kairos_recovery_" + OWNER[:12] + "_epochrestore"
    ):
        raise epoch.EpochError("EXACT_DISPOSABLE_INCIDENT_DATABASE_REQUIRED")
    if owns_connection:
        connection = await epoch.connect(config, "kairos")
    try:
        if await connection.fetchval("SELECT current_database()") != (
            database or config["database"]
        ):
            raise epoch.EpochError("INCIDENT_DATABASE_IDENTITY_CONFLICT")
        await epoch.verify_schema(connection)
        if workers_stopped:
            await epoch.validate_no_epoch_workers(connection)
        async with connection.transaction(isolation="repeatable_read", readonly=True):
            names = [
                row["relname"]
                for row in await connection.fetch(
                    "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition ORDER BY c.relname"
                )
            ]
            epoch.validate_epoch_table_inventory(names)
            budget = Budget()
            tables = {
                name: await _table_digest(connection, name, budget) for name in names
            }
            if any(
                tables[name]["count"]
                for name in names
                if name not in epoch.BOOT_ALLOWED_NONEMPTY_TABLES
            ):
                raise epoch.EpochError("INCIDENT_NONTRADING_TABLE_NOT_EMPTY")
            epoch.validate_boot_database_identity(tables)
            history = await epoch.boot_history_snapshot(connection)
            if (
                tables["event_audit"] != history["audit"]
                or history["audit"]["count"] != EXPECTED_COUNTS["audit"]
            ):
                raise epoch.EpochError("INCIDENT_AUDIT_HISTORY_CONFLICT")
            outbox = await connection.fetch(
                "SELECT id,message_id,topic,payload,payload_sha256,producer,published_at,publish_attempts,last_error,lease_owner,lease_until,dead_lettered_at,reconciliation_state FROM message_outbox ORDER BY id"
            )
            inbox = await connection.fetch(
                "SELECT consumer,message_id,topic,payload_sha256,status FROM message_inbox ORDER BY consumer,message_id"
            )
            queue, published = validate_incident_queue(
                outbox, inbox, allow_pending=allow_pending
            )
            mismatch = await connection.fetchval(
                "SELECT count(*) FROM message_outbox o WHERE NOT EXISTS(SELECT 1 FROM event_audit a WHERE a.message_id=o.message_id AND a.topic=o.topic AND a.source=o.producer AND a.payload=o.payload)"
            )
            if mismatch:
                raise epoch.EpochError("INCIDENT_AUDIT_OUTBOX_PAYLOAD_CONFLICT")
            absent = await connection.fetchval(
                "SELECT count(*) FROM event_audit WHERE topic=$1 AND (payload->>'open_time_ms')::bigint=$2 AND payload->>'symbol'<>'BTCUSDT'",
                epoch.TOPIC,
                OPEN_TIME_MS,
            )
            if absent:
                raise epoch.EpochError("INCIDENT_UNKNOWN_APPEND_NOT_ABSENT")
            sequences = {}
            for row in await connection.fetch(
                "SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename"
            ):
                name = row["sequencename"]
                if re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name) is None:
                    raise epoch.EpochError("INCIDENT_SEQUENCE_IDENTITY_REJECTED")
                sequences[name] = dict(
                    await connection.fetchrow(
                        f'SELECT last_value,is_called FROM public."{name}"'
                    )
                )
            queue_prefixes = {}
            for table in ("message_outbox", "message_inbox"):
                row = await connection.fetchrow(
                    f"SELECT count(*) n,encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex') sha FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') row_sha FROM {table} t WHERE message_id<>$1) r",
                    MESSAGE_ID,
                )
                queue_prefixes[table] = dict(row)
            state = {
                "state": "PASS_INCIDENT_STATE",
                "matched_public_tables": len(tables),
                "tables": tables,
                "anchors": history["anchors"],
                "original_prefix": history["original_prefix"],
                "sequences": sequences,
                "queue": queue,
                "preserved_queue_prefixes": queue_prefixes,
                "trading_started": False,
            }
            return state, published
    finally:
        if owns_connection:
            await connection.close()


async def verify_incident_restore(config: dict) -> dict:
    """Full SQL state equality, including the one exact pending row, on a fresh clone."""
    import asyncpg

    restored = await asyncpg.connect(
        f"postgresql://kairos:{config['restore_admin_password']}@{config['restore_host']}:5432/{config['restore_database']}",
        timeout=15,
        command_timeout=120,
    )
    try:
        # Await every sibling before closing its shared/borrowed connection.
        async with asyncio.TaskGroup() as tasks:
            original_task = tasks.create_task(
                incident_snapshot(config, allow_pending=True)
            )
            restored_task = tasks.create_task(
                incident_snapshot(
                    config,
                    allow_pending=True,
                    connection=restored,
                    database=config["restore_database"],
                )
            )
        original, _ = original_task.result()
        clone, _ = restored_task.result()
        expected = {
            k: v
            for k, v in config["expected_seed"].items()
            if k not in {"redis", "owner", "mode", "new_epoch_database"}
        }
        if original != expected or clone != original:
            raise epoch.EpochError("INCIDENT_RESTORE_FULL_STATE_CONFLICT")
        return {
            **original,
            "state": "PASS_INCIDENT_ISOLATED_RESTORE",
            "pending_row_preserved": True,
            "trading_started": False,
        }
    finally:
        await restored.close()


async def redis_snapshot(config: dict, published: dict, *, allow_pending: bool) -> dict:
    import redis.asyncio as aioredis

    producer = aioredis.Redis(
        host=config["redis_host"],
        username="kairos_epoch_producer",
        password=config["redis_producer_password"],
        decode_responses=True,
        socket_timeout=15,
    )
    consumer = aioredis.Redis(
        host=config["redis_host"],
        username="kairos_epoch_consumer",
        password=config["redis_consumer_password"],
        decode_responses=True,
        socket_timeout=15,
    )
    ledger = "kairos.runtime." + OWNER + ".publication"
    try:
        await producer.ping()
        receipt_ids = set()
        receipts = {}
        for message_id, (hashed, encoded) in published.items():
            raw = await producer.hget(ledger, message_id)
            value = json.loads(raw) if raw else None
            if (
                not isinstance(value, list)
                or len(value) != 2
                or value[0] != hashed
                or re.fullmatch(r"[0-9]+-[0-9]+", str(value[1])) is None
            ):
                raise epoch.EpochError("INCIDENT_REDIS_RECEIPT_CONFLICT")
            rows = await producer.xrange(epoch.TOPIC, min=value[1], max=value[1])
            if len(rows) != 1 or rows[0][1] != {"data": encoded}:
                raise epoch.EpochError("INCIDENT_REDIS_STREAM_IDENTITY_CONFLICT")
            receipt_ids.add(value[1])
            receipts[message_id] = value
        if allow_pending and await producer.hget(ledger, MESSAGE_ID) is not None:
            raise epoch.EpochError("INCIDENT_PENDING_ALREADY_HAS_REDIS_EFFECT")
        rows = await producer.xrange(epoch.TOPIC, min="-", max="+")
        epoch.validate_boot_stream_rows(rows, published, receipt_ids)
        groups = await producer.xinfo_groups(epoch.TOPIC)
        group = groups[0] if len(groups) == 1 else None
        pel = await consumer.xpending(epoch.TOPIC, "bars")
        if (
            not group
            or group.get("name") != "bars"
            or pel.get("pending") != 0
            or group.get("last-delivered-id") != rows[-1][0]
        ):
            raise epoch.EpochError("INCIDENT_REDIS_CONSUMER_NOT_DRAINED")
        btc_receipt = None if allow_pending else receipts[MESSAGE_ID][1]
        preserved_rows = [row for row in rows if row[0] != btc_receipt]
        preserved_receipts = {
            key: value for key, value in receipts.items() if key != MESSAGE_ID
        }
        return {
            "published_receipts": len(receipt_ids),
            "stream_entries": len(rows),
            "pending_deliveries": 0,
            "pending_btc_receipt_absent": allow_pending,
            "stream_sha256": digest(rows),
            "publication_receipts_sha256": digest(receipts),
            "preserved_stream_sha256": digest(preserved_rows),
            "preserved_publication_receipts_sha256": digest(preserved_receipts),
            "btc_receipt": btc_receipt,
            "trading_started": False,
        }
    finally:
        await producer.aclose()
        await consumer.aclose()


async def observe_incident(config: dict) -> dict:
    state, published = await incident_snapshot(config, allow_pending=True)
    return {
        **state,
        "redis": await redis_snapshot(config, published, allow_pending=True),
    }


def validate_redis_drain_preservation(before: dict, after: dict, receipt: str) -> None:
    if (
        before.get("pending_btc_receipt_absent") is not True
        or before.get("btc_receipt") is not None
        or after.get("pending_btc_receipt_absent") is not False
        or after.get("btc_receipt") != receipt
        or after.get("published_receipts") != before.get("published_receipts", -2) + 1
        or after.get("stream_entries") != before.get("stream_entries", -2) + 1
        or after.get("pending_deliveries") != 0
        or after.get("preserved_stream_sha256") != before.get("stream_sha256")
        or after.get("preserved_publication_receipts_sha256")
        != before.get("publication_receipts_sha256")
        or not all(
            re.fullmatch(r"[0-9a-f]{64}", str(before.get(field)))
            for field in (
                "stream_sha256",
                "publication_receipts_sha256",
            )
        )
    ):
        raise epoch.EpochError("INCIDENT_REDIS_EXACT_ONE_ENTRY_DELTA_REQUIRED")


async def drain_incident(config: dict, output: Path) -> dict:
    import redis.asyncio as aioredis

    connection = await epoch.connect(config, "kairos_epoch_producer")
    producer = aioredis.Redis(
        host=config["redis_host"],
        username="kairos_epoch_producer",
        password=config["redis_producer_password"],
        decode_responses=True,
        socket_timeout=15,
    )
    locks = []
    task = None
    stop = asyncio.Event()
    try:
        for key in epoch.BOOT_ADVISORY_LOCKS:
            if not await connection.fetchval("SELECT pg_try_advisory_lock($1)", key):
                raise epoch.EpochError("INCIDENT_WORKER_ALREADY_RUNNING")
            locks.append(key)
        before, published = await incident_snapshot(
            config, allow_pending=True, workers_stopped=False
        )
        before["redis"] = await redis_snapshot(config, published, allow_pending=True)
        expected = dict(config["expected_state"])
        for key in ("owner", "mode", "new_epoch_database"):
            expected.pop(key, None)
        if before != expected:
            raise epoch.EpochError("INCIDENT_FULL_PRESTATE_CHANGED")
        async with connection.transaction():
            row = await connection.fetchrow(
                "SELECT message_id,payload,payload_sha256 FROM message_outbox WHERE id=$1 AND message_id=$2 AND payload_sha256=$3 AND published_at IS NULL AND publish_attempts=0 AND lease_owner IS NULL AND lease_until IS NULL AND reconciliation_state='NONE' AND dead_lettered_at IS NULL FOR UPDATE",
                OUTBOX_ID,
                MESSAGE_ID,
                PAYLOAD_SHA256,
            )
            if row is None:
                raise epoch.EpochError("INCIDENT_EXACT_PENDING_ROW_CHANGED")
            from kairos_persistence.runtime import canonical_payload

            payload = (
                json.loads(row["payload"])
                if isinstance(row["payload"], str)
                else row["payload"]
            )
            encoded, hashed = canonical_payload(payload)
            if hashed != PAYLOAD_SHA256:
                raise epoch.EpochError("INCIDENT_EXACT_PENDING_HASH_CHANGED")
            epoch.write_status(
                output / "one-publication-intent.json",
                {
                    "message_id": MESSAGE_ID,
                    "payload_sha256": hashed,
                    "outbox_id": OUTBOX_ID,
                    "automatic_retry": False,
                    "trading_started": False,
                },
                immutable=True,
            )
            receipt = await producer.eval(
                epoch.PUBLICATION_LUA,
                2,
                epoch.TOPIC,
                "kairos.runtime." + OWNER + ".publication",
                MESSAGE_ID,
                hashed,
                encoded,
            )
            if (
                not isinstance(receipt, str)
                or re.fullmatch(r"[0-9]+-[0-9]+", receipt) is None
            ):
                raise epoch.EpochError("INCIDENT_POSITIVE_RECEIPT_REQUIRED")
            epoch.write_status(
                output / "one-publication-ack.json",
                {
                    "message_id": MESSAGE_ID,
                    "receipt": receipt,
                    "outbox_id": OUTBOX_ID,
                    "trading_started": False,
                },
                immutable=True,
            )
            acknowledged = await connection.fetchval(
                "UPDATE message_outbox SET published_at=now(),publish_attempts=publish_attempts+1,last_error=NULL WHERE id=$1 AND message_id=$2 AND payload_sha256=$3 AND published_at IS NULL AND publish_attempts=0 RETURNING id",
                OUTBOX_ID,
                MESSAGE_ID,
                PAYLOAD_SHA256,
            )
            if acknowledged != OUTBOX_ID:
                raise epoch.EpochError("INCIDENT_SQL_ACK_REQUIRED")
        task = asyncio.create_task(epoch.consume(config, stop))
        deadline = time.monotonic() + 30
        while True:
            if task.done():
                await task
                raise epoch.EpochError("INCIDENT_CONSUMER_STOPPED")
            checker = await epoch.connect(config, "kairos_epoch_consumer")
            try:
                completed = await checker.fetchval(
                    "SELECT count(*) FROM message_inbox WHERE consumer=$1 AND message_id=$2 AND topic=$3 AND payload_sha256=$4 AND status='COMPLETED'",
                    "kairos-epoch-consumer-" + OWNER[:12] + ":bars",
                    MESSAGE_ID,
                    epoch.TOPIC,
                    PAYLOAD_SHA256,
                )
            finally:
                await checker.close()
            groups = await producer.xinfo_groups(epoch.TOPIC)
            group = groups[0] if len(groups) == 1 else None
            if (
                completed == 1
                and group
                and group.get("name") == "bars"
                and group.get("pending") == 0
                and group.get("last-delivered-id") == receipt
            ):
                break
            if time.monotonic() > deadline:
                raise epoch.EpochError("INCIDENT_COMPLETION_DEADLINE")
            await asyncio.sleep(0.25)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        task = None
        after, published = await incident_snapshot(
            config, allow_pending=False, workers_stopped=False
        )
        if (
            before["tables"]["event_audit"] != after["tables"]["event_audit"]
            or before["sequences"] != after["sequences"]
        ):
            raise epoch.EpochError("INCIDENT_DRAIN_CHANGED_HISTORY_OR_SEQUENCE")
        if any(
            before["tables"][name] != after["tables"][name]
            for name in before["tables"]
            if name not in {"message_outbox", "message_inbox"}
        ):
            raise epoch.EpochError("INCIDENT_DRAIN_CHANGED_UNRELATED_TABLE")
        if before["preserved_queue_prefixes"] != after["preserved_queue_prefixes"]:
            raise epoch.EpochError("INCIDENT_DRAIN_CHANGED_PREEXISTING_QUEUE_ROWS")
        final_redis = await redis_snapshot(config, published, allow_pending=False)
        validate_redis_drain_preservation(before["redis"], final_redis, receipt)
        return {
            "state": "PASS_EXACT_INCIDENT_DRAIN",
            "before_sha256": digest(before),
            "after_sha256": digest(after),
            "message_id": MESSAGE_ID,
            "outbox_id": OUTBOX_ID,
            "redis_receipt": receipt,
            "published_messages": 1,
            "completed_inbox_increment": 1,
            "redis": final_redis,
            "history_preserved": True,
            "unrelated_tables_preserved": True,
            "trading_started": False,
        }
    finally:
        stop.set()
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await producer.aclose()
        try:
            for key in reversed(locks):
                if not connection.is_closed():
                    await connection.fetchval("SELECT pg_advisory_unlock($1)", key)
        finally:
            await connection.close()


async def dispatch_incident(mode: str, config: dict, output: Path) -> dict:
    validate_incident_config(mode, config)
    if mode == "incident-state":
        return await observe_incident(config)
    if mode == "incident-verify-restore":
        return await verify_incident_restore(config)
    return await drain_incident(config, output)
