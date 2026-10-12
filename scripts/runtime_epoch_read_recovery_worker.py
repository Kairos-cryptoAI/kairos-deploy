"""Exact, non-publishing recovery of the five admitted R5 inbox gaps.

This worker is deliberately separate from the historical incident workers.
It can only observe the owned CLOSED_BAR epoch or complete the five fixed
already-published messages. It never publishes, resets a stream/group, or
changes event history.
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
EXPECTED_COUNTS = {"audit": 336429, "outbox": 5336, "inbox": 5331}
CONSUMER_SERVICE = "kairos-epoch-consumer-" + OWNER[:12]
RESTORE_HOST = "kairos-epoch-" + OWNER[:12] + "-restore-transport05"
RESTORE_DATABASE = "kairos_recovery_" + OWNER[:12] + "_epochrestore"
TARGETS = (
    {
        "outbox_id": 5345,
        "symbol": "SOLUSDT",
        "message_id": "91a0626659175b377d467a97dbf620bb1f91690506fa8941ffdb2017271b4f41",
        "payload_sha256": "8ff9c16fbb9c2ca1407a25b6ad7ef526e6e75c1a3606f3600a04bddc834b5fd1",
        "open_time_ms": 1_791_791_760_000,
    },
    {
        "outbox_id": 5346,
        "symbol": "ETHUSDT",
        "message_id": "ce850023d1162eecc0950d5f9156a4ed2f784c5885724a348d84ebab8f960a6e",
        "payload_sha256": "60ce58c2e32c365b32010d852795a12903548b5a777580a31a0abaf10e6d5809",
        "open_time_ms": 1_791_791_760_000,
    },
    {
        "outbox_id": 5347,
        "symbol": "BTCUSDT",
        "message_id": "11996f5f0d4cccdb650fae4bc7c01fd8e361e602bb2019a5935d1b1c13f2e8bb",
        "payload_sha256": "6162f0c715a97996b0cbb783e4b6186520112f5846cc0f29f2f3304029423525",
        "open_time_ms": 1_791_791_760_000,
    },
    {
        "outbox_id": 5348,
        "symbol": "BNBUSDT",
        "message_id": "2deea0c9d9acdef97066122b36c06d1410e416bede02b02d683a38d840ae25e6",
        "payload_sha256": "c06c835a94f0c3cbcb3f4c13612a9d9b74e44f03d5dd9f7c6f330c5522d1bc05",
        "open_time_ms": 1_791_791_760_000,
    },
    {
        "outbox_id": 5349,
        "symbol": "XRPUSDT",
        "message_id": "a13b7fc84c6a864060fcb63e73732047548f092c24fc893fa224e2de1839e1a1",
        "payload_sha256": "14438c5825cdfaacaf0d69889cacbe6d68cf8ff9fe3d6e6c92f04320802837b1",
        "open_time_ms": 1_791_791_760_000,
    },
)
TARGET_BY_ID = {row["message_id"]: row for row in TARGETS}
TARGET_IDS = frozenset(TARGET_BY_ID)
TARGET_OUTBOX_IDS = frozenset(row["outbox_id"] for row in TARGETS)
PREFIX_EXCLUDED = ",".join(f"${index}" for index in range(1, len(TARGETS) + 1))


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _stream_id_key(value: str) -> tuple[int, int]:
    return tuple(int(part) for part in value.split("-", 1))


def _common_fields() -> set[str]:
    return {
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


def _state_fields() -> set[str]:
    return _common_fields() - {
        "producer_password",
        "consumer_password",
        "redis_producer_password",
        "redis_consumer_password",
    }


def validate_config(mode: str, config: dict) -> None:
    restore = mode == "r5-verify-restore"
    fields = _state_fields() if restore else _common_fields()
    if mode == "r5-drain":
        fields.add("expected_state")
    elif restore:
        fields.update(
            {
                "restore_host",
                "restore_database",
                "restore_admin_password",
                "expected_seed",
            }
        )
    if (
        mode not in {"r5-state", "r5-verify-restore", "r5-drain"}
        or not isinstance(config, dict)
        or set(config) != fields
        or config.get("owner") != OWNER
        or config.get("database") != "kairos_epoch_" + OWNER[:12]
        or config.get("pg_host") != "kairos-epoch-" + OWNER[:12] + "-pg"
        or config.get("redis_host") != "kairos-epoch-" + OWNER[:12] + "-redis"
        or any(
            not isinstance(config.get(key), str)
            or re.fullmatch(r"[0-9a-f]{64}", config[key]) is None
            for key in fields
            if key.endswith("password")
        )
    ):
        raise epoch.EpochError("EXACT_R5_PRIVATE_CONFIG_REQUIRED")
    if mode == "r5-drain" and not isinstance(config["expected_state"], dict):
        raise epoch.EpochError("R5_FULL_PRESTATE_REQUIRED")
    if restore and (
        config["restore_host"] != RESTORE_HOST
        or config["restore_database"] != RESTORE_DATABASE
        or not isinstance(config["expected_seed"], dict)
    ):
        raise epoch.EpochError("EXACT_R5_DISPOSABLE_RESTORE_REQUIRED")
    if mode == "r5-drain":
        validate_expected_state(config["expected_state"], include_redis=True)
    if restore:
        validate_expected_state(config["expected_seed"], include_redis=True)


def validate_expected_state(value: dict, *, include_redis: bool) -> dict:
    """Validate the complete signed-state payload shape before comparing it."""
    expected = dict(value)
    if (
        expected.get("owner") != OWNER
        or expected.get("mode") != "r5-state"
        or expected.get("new_epoch_database") != "kairos_epoch_" + OWNER[:12]
    ):
        raise epoch.EpochError("EXACT_R5_SIGNED_STATE_BINDING_REQUIRED")
    for key in ("owner", "mode", "new_epoch_database"):
        expected.pop(key, None)
    keys = {
        "state",
        "matched_public_tables",
        "tables",
        "sequences",
        "anchors",
        "original_prefix",
        "queue",
        "preserved_queue_prefixes",
        "trading_started",
    }
    if include_redis:
        keys.add("redis")
    if (
        set(expected) != keys
        or expected.get("state") != "PASS_R5_STATE"
        or expected.get("matched_public_tables")
        != len(epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES)
        or expected.get("trading_started") is not False
        or not isinstance(expected.get("tables"), dict)
        or set(expected.get("tables", {}))
        != set(epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES)
        or not isinstance(expected.get("sequences"), dict)
        or not isinstance(expected.get("anchors"), dict)
        or not isinstance(expected.get("queue"), dict)
        or not isinstance(expected.get("preserved_queue_prefixes"), dict)
        or expected.get("original_prefix")
        != {
            "rows": epoch.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": epoch.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": epoch.ORIGINAL_PREFIX_LAST_OPEN_MS,
        }
    ):
        raise epoch.EpochError("EXACT_R5_FULL_STATE_REQUIRED")
    tables = expected["tables"]
    if any(
        not isinstance(row, dict)
        or type(row.get("count")) is not int
        or row["count"] < 0
        or re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))) is None
        for row in tables.values()
    ):
        raise epoch.EpochError("EXACT_R5_TABLE_DIGESTS_REQUIRED")
    if (
        tables["event_audit"]["count"] != EXPECTED_COUNTS["audit"]
        or tables["message_outbox"]["count"] != EXPECTED_COUNTS["outbox"]
        or tables["message_inbox"]["count"] != EXPECTED_COUNTS["inbox"]
        or any(
            tables[table]["count"] != 0
            for table in epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES
            if table not in epoch.BOOT_ALLOWED_NONEMPTY_TABLES
        )
    ):
        raise epoch.EpochError("EXACT_R5_TABLE_COUNTS_REQUIRED")
    epoch.validate_boot_database_identity(tables)
    epoch.validate_history_snapshot(
        tables["event_audit"]["count"],
        expected["anchors"],
        {"anchors": expected["anchors"]},
    )
    queue = expected["queue"]
    if (
        set(queue)
        != {
            "outbox_rows",
            "inbox_rows",
            "completed_inbox",
            "pending_outbox",
            "unresolved_inbox",
            "trading_rows",
            "missing_inbox_message_ids",
        }
        or queue["outbox_rows"] != EXPECTED_COUNTS["outbox"]
        or queue["inbox_rows"] != EXPECTED_COUNTS["inbox"]
        or queue["completed_inbox"] != EXPECTED_COUNTS["inbox"]
        or queue["pending_outbox"] != 0
        or queue["unresolved_inbox"] != 0
        or queue["trading_rows"] != 0
        or any(
            type(queue[key]) is not int
            for key in (
                "outbox_rows",
                "inbox_rows",
                "completed_inbox",
                "pending_outbox",
                "unresolved_inbox",
                "trading_rows",
            )
        )
        or queue["missing_inbox_message_ids"] != sorted(TARGET_IDS)
    ):
        raise epoch.EpochError("EXACT_R5_QUEUE_PRESTATE_REQUIRED")
    if set(expected["preserved_queue_prefixes"]) != {"message_outbox", "message_inbox"}:
        raise epoch.EpochError("EXACT_R5_QUEUE_PREFIXES_REQUIRED")
    for prefix in expected["preserved_queue_prefixes"].values():
        if (
            not isinstance(prefix, dict)
            or type(prefix.get("n")) is not int
            or re.fullmatch(r"[0-9a-f]{64}", str(prefix.get("sha", ""))) is None
        ):
            raise epoch.EpochError("EXACT_R5_QUEUE_PREFIXES_REQUIRED")
    if (
        expected["preserved_queue_prefixes"]["message_outbox"]["n"]
        != EXPECTED_COUNTS["outbox"] - len(TARGETS)
        or expected["preserved_queue_prefixes"]["message_inbox"]["n"]
        != EXPECTED_COUNTS["inbox"]
    ):
        raise epoch.EpochError("EXACT_R5_QUEUE_PREFIXES_REQUIRED")
    if include_redis:
        redis = expected["redis"]
        redis_keys = {
            "stream_entries",
            "publication_receipts",
            "publication_receipts_sha256",
            "publication_message_ids_sha256",
            "stream_sha256",
            "stream_last_id",
            "consumer_group",
            "last_delivered_id",
            "pending_deliveries",
            "pending_target_message_ids",
            "trading_started",
        }
        if (
            not isinstance(redis, dict)
            or set(redis) != redis_keys
            or redis.get("publication_receipts") != EXPECTED_COUNTS["outbox"]
            or type(redis.get("publication_receipts")) is not int
            or type(redis.get("stream_entries")) is not int
            or redis["stream_entries"] != EXPECTED_COUNTS["outbox"] + 1
            or redis.get("consumer_group") != "bars"
            or type(redis.get("pending_deliveries")) is not int
            or not isinstance(redis.get("pending_target_message_ids"), list)
            or any(
                not isinstance(item, str)
                for item in redis["pending_target_message_ids"]
            )
            or redis["pending_deliveries"]
            != len(redis.get("pending_target_message_ids", []))
            or redis["pending_deliveries"] > len(TARGETS)
            or len(set(redis.get("pending_target_message_ids", [])))
            != redis["pending_deliveries"]
            or not set(redis.get("pending_target_message_ids", [])).issubset(TARGET_IDS)
            or not isinstance(redis.get("stream_last_id"), str)
            or re.fullmatch(r"[0-9]+-[0-9]+", redis["stream_last_id"]) is None
            or not isinstance(redis.get("last_delivered_id"), str)
            or re.fullmatch(r"[0-9]+-[0-9]+", redis["last_delivered_id"]) is None
            or redis.get("trading_started") is not False
            or any(
                re.fullmatch(r"[0-9a-f]{64}", str(redis.get(key, ""))) is None
                for key in (
                    "publication_receipts_sha256",
                    "publication_message_ids_sha256",
                    "stream_sha256",
                )
            )
        ):
            raise epoch.EpochError("EXACT_R5_REDIS_PRESTATE_REQUIRED")
    return expected


def _payload(row: dict):
    value = row["payload"]
    return json.loads(value) if isinstance(value, str) else value


def validate_queue(outbox: list, inbox: list) -> tuple[dict, dict, set[str]]:
    from kairos_core.contracts import ClosedBarEventV1
    from kairos_persistence.runtime import canonical_payload

    if len(outbox) != EXPECTED_COUNTS["outbox"] or len(inbox) not in {
        EXPECTED_COUNTS["inbox"],
        EXPECTED_COUNTS["outbox"],
    }:
        raise epoch.EpochError("R5_EXACT_QUEUE_COUNTS_REQUIRED")
    inbox_by_id = {}
    for row in inbox:
        if (
            row["consumer"] != CONSUMER_SERVICE + ":bars"
            or row["topic"] != epoch.TOPIC
            or row["status"] != "COMPLETED"
            or row["message_id"] in inbox_by_id
        ):
            raise epoch.EpochError("R5_INBOX_IDENTITY_CONFLICT")
        inbox_by_id[row["message_id"]] = row
    completed_ids = set(inbox_by_id)

    durable = {}
    missing = set()
    for row in outbox:
        payload = _payload(row)
        event = ClosedBarEventV1.model_validate(payload)
        encoded, hashed = canonical_payload(payload)
        if (
            row["topic"] != epoch.TOPIC
            or row["producer"] != epoch.SOURCE
            or row["published_at"] is None
            or type(row["publish_attempts"]) is not int
            or row["publish_attempts"] != 1
            or row["last_error"] is not None
            or row["lease_owner"] is not None
            or row["lease_until"] is not None
            or row["dead_lettered_at"] is not None
            or row["reconciliation_state"] != "NONE"
            or row["message_id"] != event.message_id
            or event.source != epoch.SOURCE
            or event.symbol not in epoch.SYMBOLS
            or hashed != row["payload_sha256"]
            or row["message_id"] in durable
        ):
            raise epoch.EpochError("R5_OUTBOX_IDENTITY_OR_STATE_CONFLICT")
        target = TARGET_BY_ID.get(row["message_id"])
        if target and (
            row["id"] != target["outbox_id"]
            or hashed != target["payload_sha256"]
            or event.symbol != target["symbol"]
            or event.open_time_ms != target["open_time_ms"]
        ):
            raise epoch.EpochError("R5_EXACT_TARGET_ROW_CONFLICT")
        inbox_row = inbox_by_id.pop(row["message_id"], None)
        if inbox_row is None:
            if target is None:
                raise epoch.EpochError("R5_UNEXPECTED_INBOX_GAP")
            missing.add(row["message_id"])
        elif inbox_row["payload_sha256"] != hashed:
            raise epoch.EpochError("R5_COMPLETED_INBOX_HASH_CONFLICT")
        durable[row["message_id"]] = (hashed, encoded)
    if inbox_by_id or missing not in (TARGET_IDS, set()):
        raise epoch.EpochError("R5_EXACT_MISSING_INBOX_SET_REQUIRED")
    if len(inbox) == EXPECTED_COUNTS["inbox"] and missing != TARGET_IDS:
        raise epoch.EpochError("R5_EXACT_MISSING_INBOX_SET_REQUIRED")
    if len(inbox) == EXPECTED_COUNTS["outbox"] and missing:
        raise epoch.EpochError("R5_PARTIAL_TARGET_COMPLETION_REJECTED")
    return (
        {
            "outbox_rows": len(outbox),
            "inbox_rows": len(inbox),
            "completed_inbox": len(inbox),
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "trading_rows": 0,
            "missing_inbox_message_ids": sorted(missing),
        },
        durable,
        completed_ids,
    )


async def _sql_snapshot(
    config: dict, *, connection=None, database=None
) -> tuple[dict, dict, set[str]]:
    from controlled_runtime_worker import Budget, _table_digest

    owns = connection is None
    if owns:
        connection = await epoch.connect(config, "kairos")
    try:
        target_database = database or config["database"]
        if await connection.fetchval("SELECT current_database()") != target_database:
            raise epoch.EpochError("R5_DATABASE_IDENTITY_CONFLICT")
        await epoch.verify_schema(connection)
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
                raise epoch.EpochError("R5_NONTRADING_TABLE_NOT_EMPTY")
            epoch.validate_boot_database_identity(tables)
            history = await epoch.boot_history_snapshot(connection)
            if (
                tables["event_audit"] != history["audit"]
                or history["audit"]["count"] != EXPECTED_COUNTS["audit"]
            ):
                raise epoch.EpochError("R5_AUDIT_HISTORY_CONFLICT")
            outbox = await connection.fetch(
                "SELECT id,message_id,topic,payload,payload_sha256,producer,published_at,publish_attempts,last_error,lease_owner,lease_until,dead_lettered_at,reconciliation_state FROM message_outbox ORDER BY id"
            )
            inbox = await connection.fetch(
                "SELECT consumer,message_id,topic,payload_sha256,status FROM message_inbox ORDER BY consumer,message_id"
            )
            queue, durable, completed_ids = validate_queue(outbox, inbox)
            if await connection.fetchval(
                "SELECT count(*) FROM message_outbox o WHERE NOT EXISTS(SELECT 1 FROM event_audit a WHERE a.message_id=o.message_id AND a.topic=o.topic AND a.source=o.producer AND a.payload=o.payload)"
            ):
                raise epoch.EpochError("R5_AUDIT_OUTBOX_IDENTITY_CONFLICT")
            sequences = {}
            for row in await connection.fetch(
                "SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename"
            ):
                name = row["sequencename"]
                if re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name) is None:
                    raise epoch.EpochError("R5_SEQUENCE_IDENTITY_REJECTED")
                sequences[name] = dict(
                    await connection.fetchrow(
                        f'SELECT last_value,is_called FROM public."{name}"'
                    )
                )
            ids = [target["message_id"] for target in TARGETS]
            preserved = {}
            for table in ("message_outbox", "message_inbox"):
                row = await connection.fetchrow(
                    f"SELECT count(*) n,encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex') sha FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') row_sha FROM {table} t WHERE message_id NOT IN ({PREFIX_EXCLUDED})) r",
                    *ids,
                )
                preserved[table] = dict(row)
            return (
                {
                    "state": "PASS_R5_STATE",
                    "matched_public_tables": len(tables),
                    "tables": tables,
                    "sequences": sequences,
                    "anchors": history["anchors"],
                    "original_prefix": history["original_prefix"],
                    "queue": queue,
                    "preserved_queue_prefixes": preserved,
                    "trading_started": False,
                },
                durable,
                completed_ids,
            )
    finally:
        if owns:
            await connection.close()


async def _redis_snapshot(
    config: dict, durable: dict, completed_ids: set[str], missing_ids: set[str]
) -> dict:
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
    ledger_key = "kairos.runtime." + OWNER + ".publication"
    try:
        receipts = {}
        receipt_ids = set()
        target_receipt_ids = set()
        for message_id, (payload_hash, encoded) in durable.items():
            # Producer ACL intentionally allows HGET for fixed IDs, not HGETALL.
            raw = await producer.hget(ledger_key, message_id)
            value = json.loads(raw) if raw else None
            if (
                not isinstance(value, list)
                or len(value) != 2
                or value[0] != payload_hash
                or re.fullmatch(r"[0-9]+-[0-9]+", str(value[1])) is None
            ):
                raise epoch.EpochError("R5_REDIS_RECEIPT_CONFLICT")
            stream_id = value[1]
            rows = await producer.xrange(epoch.TOPIC, min=stream_id, max=stream_id)
            if len(rows) != 1 or rows[0][1] != {"data": encoded}:
                raise epoch.EpochError("R5_REDIS_STREAM_RECEIPT_CONFLICT")
            receipts[message_id] = [payload_hash, stream_id]
            receipt_ids.add(stream_id)
            if message_id in TARGET_IDS:
                target_receipt_ids.add(stream_id)
        stream = await producer.xrange(epoch.TOPIC, min="-", max="+")
        epoch.validate_boot_stream_rows(stream, durable, receipt_ids)
        groups = await producer.xinfo_groups(epoch.TOPIC)
        group = groups[0] if len(groups) == 1 else None
        pending = await consumer.xpending(epoch.TOPIC, "bars") if group else None
        details = (
            await consumer.xpending_range(
                epoch.TOPIC, "bars", min="-", max="+", count=16
            )
            if group
            else []
        )
        pending_ids = [str(item["message_id"]) for item in details]
        pending_stream_ids = set(pending_ids)
        last_delivered = str(group["last-delivered-id"]) if group else "0-0"
        if re.fullmatch(r"[0-9]+-[0-9]+", last_delivered) is None:
            raise epoch.EpochError("R5_REDIS_GROUP_CURSOR_INVALID")
        target_map = {
            stream_id: message_id
            for message_id, (_hash, stream_id) in receipts.items()
            if message_id in TARGET_IDS
        }
        delivered_targets = {
            stream_id
            for stream_id in target_map
            if _stream_id_key(stream_id) <= _stream_id_key(last_delivered)
        }
        completed_target_receipts = {
            stream_id
            for stream_id, message_id in target_map.items()
            if message_id in completed_ids
        }
        missing_target_receipts = {
            stream_id
            for stream_id, message_id in target_map.items()
            if message_id in missing_ids
        }
        if (
            not group
            or group.get("name") != "bars"
            or not pending
            or type(pending.get("pending")) is not int
            or pending["pending"] != len(details)
            or len(details) > len(TARGETS)
            or not pending_stream_ids.issubset(target_receipt_ids)
            or len(pending_stream_ids) != len(details)
            or not missing_target_receipts.intersection(delivered_targets).issubset(
                pending_stream_ids
            )
            or not pending_stream_ids.issubset(delivered_targets)
            or not delivered_targets.issubset(
                pending_stream_ids | completed_target_receipts
            )
            or not completed_target_receipts.issubset(delivered_targets)
            or last_delivered not in {row[0] for row in stream}
            or any(
                re.fullmatch(
                    r"consumer-[A-Za-z0-9_.-]{1,128}",
                    str(item.get("consumer", "")),
                )
                is None
                for item in details
            )
            or (
                not missing_ids
                and (
                    pending["pending"] != 0
                    or last_delivered != (stream[-1][0] if stream else None)
                )
            )
        ):
            raise epoch.EpochError("R5_REDIS_PENDING_SET_CONFLICT")
        pending_messages = sorted(target_map[stream_id] for stream_id in pending_ids)
        return {
            "stream_entries": len(stream),
            "publication_receipts": len(receipt_ids),
            "publication_receipts_sha256": digest(receipts),
            "publication_message_ids_sha256": hashlib.sha256(
                json.dumps(sorted(durable), separators=(",", ":")).encode()
            ).hexdigest(),
            "stream_sha256": digest(stream),
            "stream_last_id": stream[-1][0] if stream else None,
            "consumer_group": "bars",
            "last_delivered_id": last_delivered,
            "pending_deliveries": len(details),
            "pending_target_message_ids": pending_messages,
            "trading_started": False,
        }
    finally:
        await producer.aclose()
        await consumer.aclose()


async def state_snapshot(
    config: dict, *, connection=None, database=None
) -> tuple[dict, dict]:
    state, durable, completed_ids = await _sql_snapshot(
        config, connection=connection, database=database
    )
    missing_ids = set(state["queue"]["missing_inbox_message_ids"])
    state["redis"] = await _redis_snapshot(config, durable, completed_ids, missing_ids)
    return state, durable


async def observe(config: dict) -> dict:
    state, _durable = await state_snapshot(config)
    return state


async def verify_restore(config: dict) -> dict:
    import asyncpg

    original = await epoch.connect(config, "kairos")
    restored = await asyncpg.connect(
        f"postgresql://kairos:{config['restore_admin_password']}@{config['restore_host']}:5432/{config['restore_database']}",
        timeout=15,
        command_timeout=120,
    )
    try:
        async with asyncio.TaskGroup() as group:
            original_task = group.create_task(
                _sql_snapshot(config, connection=original)
            )
            restored_task = group.create_task(
                _sql_snapshot(
                    config, connection=restored, database=config["restore_database"]
                )
            )
        source, _, _ = original_task.result()
        clone, _, _ = restored_task.result()
        expected = validate_expected_state(config["expected_seed"], include_redis=True)
        expected.pop("redis", None)
        if source != expected or clone != source:
            raise epoch.EpochError("R5_FULL_RESTORE_STATE_CONFLICT")
        return {
            **source,
            "state": "PASS_R5_ISOLATED_RESTORE",
            "source_clone_sql_equal": True,
            "redis_excluded_from_restore_equality": True,
            "trading_started": False,
        }
    finally:
        await original.close()
        await restored.close()


class _AckTrackingTransport:
    """Set the stop signal only after all five transport ACKs really return."""

    def __init__(self, transport, stop: asyncio.Event):
        self._transport = transport
        self._stop = stop
        self.acked_targets: set[str] = set()

    async def subscribe(self, *args, **kwargs):
        async for envelope in self._transport.subscribe(*args, **kwargs):
            yield envelope

    async def ack(self, topic, envelope, *, group=None):
        await self._transport.ack(topic, envelope, group=group)
        message_id = envelope.payload.get("message_id")
        if message_id in TARGET_IDS:
            self.acked_targets.add(message_id)
            if self.acked_targets == TARGET_IDS:
                self._stop.set()

    async def close(self):
        await self._transport.close()


async def _consume_exact(
    config: dict, stop: asyncio.Event, completed: set[str]
) -> dict:
    from kairos_core.contracts import ClosedBarEventV1
    from kairos_persistence.config import PersistenceSettings
    from kairos_persistence.database import Database, MigrationProfile
    from kairos_persistence.runtime import DurableMessageBus, canonical_payload

    url = f"redis://kairos_epoch_consumer:{config['redis_consumer_password']}@{config['redis_host']}:6379/0"
    telemetry = {"transport_failures": 0, "recoveries": 0, "pending_replays": 0}
    transport = _AckTrackingTransport(
        epoch.create_runtime_transport(url, stop, telemetry), stop
    )
    settings = PersistenceSettings(
        database_url=epoch.dsn(config, "kairos_epoch_consumer"),
        pool_min_size=1,
        pool_max_size=2,
    )
    database = Database(settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME)
    bus = DurableMessageBus(
        transport,
        service_name=CONSUMER_SERVICE,
        settings=settings,
        database=database,
        consumer_only=True,
        verify_schema_only=True,
        required_migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
    )
    try:
        async for envelope in bus.subscribe(epoch.TOPIC, group="bars"):
            event = ClosedBarEventV1.model_validate(envelope.payload)
            target = TARGET_BY_ID.get(event.message_id)
            _encoded, payload_hash = canonical_payload(envelope.payload)
            if (
                target is None
                or event.source != epoch.SOURCE
                or event.symbol != target["symbol"]
                or event.open_time_ms != target["open_time_ms"]
                or payload_hash != target["payload_sha256"]
                or envelope.topic != epoch.TOPIC
                or event.message_id not in TARGET_IDS
            ):
                raise epoch.EpochError("R5_UNEXPECTED_DELIVERY_REJECTED")
            await bus.ack(epoch.TOPIC, envelope, group="bars")
            completed.add(event.message_id)
            # Do not stop at handler completion: DurableMessageBus commits the
            # inbox after this yield resumes, then the wrapper signals stop
            # only once the transport confirms the fifth XACK.
    finally:
        await bus.close()
    return {**telemetry, "target_ack_message_ids": sorted(transport.acked_targets)}


async def drain(config: dict, output: Path) -> dict:
    # Revalidate the signed/frozen full state immediately before consumption.
    before, _ = await state_snapshot(config)
    expected = dict(config["expected_state"])
    for key in ("owner", "mode", "new_epoch_database"):
        expected.pop(key, None)
    if before != expected:
        raise epoch.EpochError("R5_FULL_PRESTATE_CHANGED")
    expected_pel = before["redis"]["pending_target_message_ids"]
    if len(expected_pel) > len(TARGETS) or not set(expected_pel).issubset(TARGET_IDS):
        raise epoch.EpochError("R5_PENDING_TARGET_SET_REQUIRED")
    stop = asyncio.Event()
    completed: set[str] = set()
    task = asyncio.create_task(_consume_exact(config, stop, completed))
    deadline = time.monotonic() + 60
    checker = None
    transport_metrics = {}
    try:
        while True:
            if task.done():
                await task
                transport_metrics = task.result() or {}
                if completed != TARGET_IDS:
                    raise epoch.EpochError(
                        "R5_CONSUMER_STOPPED_BEFORE_EXACT_COMPLETION"
                    )
                if (
                    set(transport_metrics.get("target_ack_message_ids", []))
                    != TARGET_IDS
                ):
                    raise epoch.EpochError("R5_TRANSPORT_ACK_SET_INCOMPLETE")
                break
            checker = await epoch.connect(config, "kairos_epoch_consumer")
            try:
                rows = await checker.fetch(
                    "SELECT message_id,payload_sha256,status FROM message_inbox WHERE consumer=$1 AND topic=$2 AND message_id=ANY($3::text[]) ORDER BY message_id",
                    CONSUMER_SERVICE + ":bars",
                    epoch.TOPIC,
                    sorted(TARGET_IDS),
                )
            finally:
                await checker.close()
                checker = None
            if len(rows) == len(TARGETS) and not all(
                row["status"] == "COMPLETED"
                and row["payload_sha256"]
                == TARGET_BY_ID[row["message_id"]]["payload_sha256"]
                for row in rows
            ):
                raise epoch.EpochError("R5_COMPLETED_TARGET_INBOX_CONFLICT")
            if time.monotonic() >= deadline:
                raise epoch.EpochError("R5_EXACT_COMPLETION_DEADLINE")
            await asyncio.sleep(0.2)
        stop.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        task = None
        after, _durable = await state_snapshot(config)
        before_sql = {key: value for key, value in before.items() if key != "redis"}
        after_sql = {key: value for key, value in after.items() if key != "redis"}
        if (
            before_sql["tables"]["event_audit"] != after_sql["tables"]["event_audit"]
            or before_sql["tables"]["message_outbox"]
            != after_sql["tables"]["message_outbox"]
            or before_sql["sequences"] != after_sql["sequences"]
            or before_sql["anchors"] != after_sql["anchors"]
            or before_sql["original_prefix"] != after_sql["original_prefix"]
            or before_sql["preserved_queue_prefixes"]
            != after_sql["preserved_queue_prefixes"]
            or any(
                before_sql["tables"][name] != after_sql["tables"][name]
                for name in before_sql["tables"]
                if name not in {"message_inbox"}
            )
            or after_sql["queue"]["missing_inbox_message_ids"]
            or after_sql["queue"]["completed_inbox"] != EXPECTED_COUNTS["outbox"]
            or after["redis"]["stream_sha256"] != before["redis"]["stream_sha256"]
            or after["redis"]["publication_receipts_sha256"]
            != before["redis"]["publication_receipts_sha256"]
            or _stream_id_key(after["redis"]["last_delivered_id"])
            < _stream_id_key(before["redis"]["last_delivered_id"])
            or after["redis"]["last_delivered_id"] != after["redis"]["stream_last_id"]
            or after["redis"]["pending_deliveries"] != 0
            or after["redis"]["stream_entries"] != before["redis"]["stream_entries"]
            or after["redis"]["publication_receipts"]
            != before["redis"]["publication_receipts"]
        ):
            raise epoch.EpochError("R5_DRAIN_PRESERVATION_CONFLICT")
        return {
            "state": "PASS_EXACT_R5_INBOX_RECOVERY",
            "before_sha256": digest(before),
            "after_sha256": digest(after),
            "completed_message_ids": sorted(TARGET_IDS),
            "completed_inbox_increment": len(TARGETS),
            "published_messages": 0,
            "stream_entries_added": 0,
            "publication_receipts_added": 0,
            "pending_deliveries": 0,
            "redis_transport": transport_metrics,
            "audit_history_preserved": True,
            "outbox_and_sequences_preserved": True,
            "trading_started": False,
        }
    finally:
        stop.set()
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if checker is not None:
            await checker.close()


async def dispatch_r5(mode: str, config: dict, output: Path) -> dict:
    validate_config(mode, config)
    if mode == "r5-state":
        return await observe(config)
    if mode == "r5-verify-restore":
        return await verify_restore(config)
    return await drain(config, output)
