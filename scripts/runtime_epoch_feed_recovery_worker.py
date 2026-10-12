"""Exact R6 recovery for four admitted unpublished CLOSED_BAR messages.

This worker is intentionally separate from the frozen R5 worker. It accepts
only the four pinned unpublished rows, publishes them once through the normal
dispatcher, and consumes only those four IDs. It never resets Redis state.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_read_recovery_worker as r5
    from scripts import runtime_epoch_worker as epoch
else:
    import runtime_epoch_read_recovery_worker as r5
    import runtime_epoch_worker as epoch

OWNER = "69893dc7b7c647f49967387e7efca9fb"
BASE_AUDIT_ROWS = 339_618
BASE_OUTBOX_ROWS = 5_795
BASE_INBOX_ROWS = 5_791
CONSUMER_SERVICE = "kairos-epoch-consumer-" + OWNER[:12]
RESTORE_HOST = "kairos-epoch-" + OWNER[:12] + "-restore-transport06"
RESTORE_DATABASE = "kairos_recovery_" + OWNER[:12] + "_epochrestore"
TARGETS = (
    {
        "outbox_id": 5805,
        "message_id": "1ead8a5bb5d11c46e17f793dfb59e492d110b7bf51c69e9b994cba1757d0cfca",
        "payload_sha256": "c765a31c0bc11bf7713f5f6204f67a060c10c8c6f35238acd12ed300cfece221",
    },
    {
        "outbox_id": 5806,
        "message_id": "4a9d06ec9584c74865ab0d92981dc4e1a586f3a9aa1837c620575469083e98a2",
        "payload_sha256": "64bfb1f4db53db14701600d730846426f2fe2d57000ab96a440bf3c0a783a625",
    },
    {
        "outbox_id": 5807,
        "message_id": "16858d249a388c0d54b14bc687d7b62d64b68556a17f9ed86aee3031ff752fe2",
        "payload_sha256": "ab4b1a23f11373b4d83c658d6919f3a05fe2e0260cc7a3f03b1c9e8c46ebd751",
    },
    {
        "outbox_id": 5808,
        "message_id": "82113d6dfcea025dda8258446281117d314b56f71d43bde8acdbb5c43ca51a8d",
        "payload_sha256": "55efec9603ecf4e2c3619a480f872a1f8f12da150f8aedb32aadddc3f5ea4e9b",
    },
)
TARGET_BY_ID = {row["message_id"]: row for row in TARGETS}
TARGET_IDS = frozenset(TARGET_BY_ID)
TARGET_OUTBOX_IDS = frozenset(row["outbox_id"] for row in TARGETS)
TARGET_SQL = ",".join(f"${i}" for i in range(1, len(TARGETS) + 1))


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def bounded_live_batch_end(seed: dict, target_end_exclusive_ms: int) -> int:
    """Choose forward progress whose aggregate five-symbol append is <=100."""
    anchors = seed.get("anchors") if isinstance(seed, dict) else None
    if (
        not isinstance(anchors, dict)
        or set(anchors) != set(epoch.SYMBOLS)
        or type(target_end_exclusive_ms) is not int
        or target_end_exclusive_ms <= 0
        or target_end_exclusive_ms % epoch.MINUTE
    ):
        raise epoch.EpochError("R6_BOUNDED_LIVE_SEED_REQUIRED")
    starts = []
    for row in anchors.values():
        if (
            not isinstance(row, dict)
            or type(row.get("last_close_time_ms")) is not int
            or row["last_close_time_ms"] < 0
            or (row["last_close_time_ms"] + 1) % epoch.MINUTE
        ):
            raise epoch.EpochError("R6_BOUNDED_LIVE_ANCHORS_REQUIRED")
        starts.append(row["last_close_time_ms"] + 1)
    earliest = min(starts)
    end = min(
        target_end_exclusive_ms,
        earliest + (epoch.MAX_PENDING // len(epoch.SYMBOLS)) * epoch.MINUTE,
    )
    appended = sum(max(0, (end - start) // epoch.MINUTE) for start in starts)
    while appended > epoch.MAX_PENDING:
        end -= epoch.MINUTE
        appended = sum(max(0, (end - start) // epoch.MINUTE) for start in starts)
    if not 0 < appended <= epoch.MAX_PENDING:
        raise epoch.EpochError("R6_LIVE_BATCH_BOUND_REQUIRED")
    return end


def validate_exact_pending_rows(rows: list[dict]) -> None:
    """No subset/superset or changed payload may be admitted as R6 work."""
    if len(rows) != len(TARGETS):
        raise epoch.EpochError("R6_EXACT_UNPUBLISHED_SET_REQUIRED")
    actual = {
        row.get("id"): (row.get("message_id"), row.get("payload_sha256"))
        for row in rows
    }
    expected = {
        target["outbox_id"]: (target["message_id"], target["payload_sha256"])
        for target in TARGETS
    }
    if actual != expected:
        raise epoch.EpochError("R6_EXACT_UNPUBLISHED_SET_REQUIRED")


def validate_config(mode: str, config: dict) -> None:
    restore = mode == "r6-verify-restore"
    fields = set(r5._state_fields() if restore else r5._common_fields())
    if mode == "r6-drain":
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
        mode not in {"r6-state", "r6-verify-restore", "r6-drain"}
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
        raise epoch.EpochError("EXACT_R6_PRIVATE_CONFIG_REQUIRED")
    if mode == "r6-drain":
        validate_expected_state(config["expected_state"], include_redis=True)
    if restore:
        if (
            config["restore_host"] != RESTORE_HOST
            or config["restore_database"] != RESTORE_DATABASE
            or not isinstance(config["expected_seed"], dict)
        ):
            raise epoch.EpochError("EXACT_R6_DISPOSABLE_RESTORE_REQUIRED")
        validate_expected_state(config["expected_seed"], include_redis=True)


def validate_expected_state(value: dict, *, include_redis: bool) -> dict:
    """Validate the full R6 state envelope and exact four pending rows."""
    expected = dict(value)
    if (
        expected.get("owner") != OWNER
        or expected.get("mode") != "r6-state"
        or expected.get("new_epoch_database") != "kairos_epoch_" + OWNER[:12]
    ):
        raise epoch.EpochError("EXACT_R6_SIGNED_STATE_BINDING_REQUIRED")
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
        or expected.get("state") != "PASS_R6_STATE"
        or expected.get("matched_public_tables")
        != len(epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES)
        or expected.get("trading_started") is not False
        or not isinstance(expected.get("tables"), dict)
        or set(expected["tables"]) != set(epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES)
        or not isinstance(expected.get("sequences"), dict)
        or not isinstance(expected.get("anchors"), dict)
        or not isinstance(expected.get("queue"), dict)
        or not isinstance(expected.get("preserved_queue_prefixes"), dict)
        or set(expected.get("preserved_queue_prefixes", {}))
        != {"message_outbox", "message_inbox"}
        or expected.get("original_prefix")
        != {
            "rows": epoch.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": epoch.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": epoch.ORIGINAL_PREFIX_LAST_OPEN_MS,
        }
    ):
        raise epoch.EpochError("EXACT_R6_FULL_STATE_REQUIRED")
    tables = expected["tables"]
    if any(
        not isinstance(row, dict)
        or type(row.get("count")) is not int
        or row["count"] < 0
        or re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))) is None
        for row in tables.values()
    ):
        raise epoch.EpochError("EXACT_R6_TABLE_DIGESTS_REQUIRED")
    queue = expected["queue"]
    if (
        tables["event_audit"]["count"] < BASE_AUDIT_ROWS
        or tables["message_outbox"]["count"] != BASE_OUTBOX_ROWS
        or tables["message_inbox"]["count"] not in {BASE_INBOX_ROWS, BASE_OUTBOX_ROWS}
        or queue.get("outbox_rows") != tables["message_outbox"]["count"]
        or queue.get("inbox_rows") != tables["message_inbox"]["count"]
        or queue.get("trading_rows") != 0
        or queue.get("unresolved_inbox") != 0
        or queue.get("pending_outbox") not in {0, len(TARGETS)}
        or queue.get("missing_inbox_message_ids") not in (sorted(TARGET_IDS), [])
    ):
        raise epoch.EpochError("EXACT_R6_QUEUE_BASELINE_REQUIRED")
    for field in (
        "outbox_rows",
        "inbox_rows",
        "completed_inbox",
        "pending_outbox",
        "unresolved_inbox",
        "trading_rows",
    ):
        if type(queue.get(field)) is not int or queue[field] < 0:
            raise epoch.EpochError("EXACT_R6_QUEUE_COUNTERS_REQUIRED")
    epoch.validate_history_snapshot(
        tables["event_audit"]["count"],
        expected["anchors"],
        {"anchors": expected["anchors"]},
    )
    before_drain = queue["pending_outbox"] == len(TARGETS)
    prefixes = expected["preserved_queue_prefixes"]
    if any(
        not isinstance(prefixes.get(table), dict)
        or set(prefixes[table]) != {"n", "sha"}
        or type(prefixes[table]["n"]) is not int
        or prefixes[table]["n"]
        != (
            BASE_OUTBOX_ROWS - len(TARGETS)
            if table == "message_outbox"
            else BASE_INBOX_ROWS
        )
        or re.fullmatch(r"[0-9a-f]{64}", str(prefixes[table]["sha"])) is None
        for table in ("message_outbox", "message_inbox")
    ):
        raise epoch.EpochError("R6_PRESERVED_QUEUE_PREFIX_REQUIRED")
    if before_drain != (queue["missing_inbox_message_ids"] == sorted(TARGET_IDS)):
        raise epoch.EpochError("R6_EXACT_PENDING_INBOX_SET_REQUIRED")
    if before_drain:
        if (
            tables["event_audit"]["count"] != BASE_AUDIT_ROWS
            or tables["message_outbox"]["count"] != BASE_OUTBOX_ROWS
            or tables["message_inbox"]["count"] != BASE_INBOX_ROWS
            or queue.get("completed_inbox") != BASE_INBOX_ROWS
        ):
            raise epoch.EpochError("R6_FROZEN_PRESTATE_COUNTS_REQUIRED")
    elif (
        queue.get("pending_outbox") != 0
        or queue.get("missing_inbox_message_ids") != []
        or queue.get("completed_inbox") != queue.get("outbox_rows")
    ):
        raise epoch.EpochError("R6_EXACT_DRAIN_POSTSTATE_REQUIRED")
    if include_redis:
        redis = expected.get("redis")
        required = {
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
            or set(redis) != required
            or type(redis.get("stream_entries")) is not int
            or type(redis.get("publication_receipts")) is not int
            or type(redis.get("pending_deliveries")) is not int
            or redis.get("consumer_group") != "bars"
            or redis.get("trading_started") is not False
            or redis.get("pending_deliveries") != 0
            or redis.get("pending_target_message_ids") != []
            or redis.get("publication_receipts")
            != queue["outbox_rows"] - queue["pending_outbox"]
            or redis.get("stream_entries") != redis.get("publication_receipts") + 1
            or any(
                re.fullmatch(r"[0-9a-f]{64}", str(redis.get(key, ""))) is None
                for key in (
                    "publication_receipts_sha256",
                    "publication_message_ids_sha256",
                    "stream_sha256",
                )
            )
        ):
            raise epoch.EpochError("EXACT_R6_REDIS_STATE_REQUIRED")
    return expected


def _payload(row: dict):
    value = row["payload"]
    return json.loads(value) if isinstance(value, str) else value


def validate_drain_transition(before: dict, after: dict) -> None:
    """Only target publication/inbox completion and corresponding Redis adds may change."""
    if (
        after["queue"]["pending_outbox"] != 0
        or after["queue"]["missing_inbox_message_ids"]
        or after["queue"]["unresolved_inbox"] != 0
        or after["queue"]["trading_rows"] != 0
        or after["queue"]["completed_inbox"] != BASE_OUTBOX_ROWS
        or after["tables"]["event_audit"] != before["tables"]["event_audit"]
        or after["tables"]["message_outbox"]["count"]
        != before["tables"]["message_outbox"]["count"]
        or after["tables"]["message_inbox"]["count"]
        != before["tables"]["message_inbox"]["count"] + len(TARGETS)
        or any(
            after["tables"][name] != before["tables"][name]
            for name in before["tables"]
            if name not in {"event_audit", "message_outbox", "message_inbox"}
        )
        or after["sequences"] != before["sequences"]
        or after["anchors"] != before["anchors"]
        or after["original_prefix"] != before["original_prefix"]
        or after["preserved_queue_prefixes"] != before["preserved_queue_prefixes"]
        or after["redis"]["pending_deliveries"] != 0
        or after["redis"]["pending_target_message_ids"]
        or after["redis"]["publication_receipts"]
        != before["redis"]["publication_receipts"] + len(TARGETS)
        or after["redis"]["stream_entries"]
        != before["redis"]["stream_entries"] + len(TARGETS)
        or after["redis"]["trading_started"] is not False
    ):
        raise epoch.EpochError("R6_EXACT_DRAIN_PRESERVATION_CONFLICT")


async def _sql_snapshot(
    config: dict, *, connection=None, database=None, check_workers=True
):
    from controlled_runtime_worker import Budget, _table_digest
    from kairos_core.contracts import ClosedBarEventV1
    from kairos_persistence.runtime import canonical_payload

    owns = connection is None
    if owns:
        connection = await epoch.connect(config, "kairos")
    try:
        target_database = database or config["database"]
        if await connection.fetchval("SELECT current_database()") != target_database:
            raise epoch.EpochError("R6_DATABASE_IDENTITY_CONFLICT")
        await epoch.verify_schema(connection)
        if check_workers:
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
                raise epoch.EpochError("R6_NONTRADING_TABLE_NOT_EMPTY")
            epoch.validate_boot_database_identity(tables)
            history = await epoch.boot_history_snapshot(connection)
            if (
                tables["event_audit"] != history["audit"]
                or tables["event_audit"]["count"] < BASE_AUDIT_ROWS
            ):
                raise epoch.EpochError("R6_AUDIT_HISTORY_CONFLICT")
            outbox = await connection.fetch(
                "SELECT id,message_id,topic,payload,payload_sha256,producer,published_at,publish_attempts,last_error,lease_owner,lease_until,dead_lettered_at,reconciliation_state FROM message_outbox ORDER BY id"
            )
            inbox = await connection.fetch(
                "SELECT consumer,message_id,topic,payload_sha256,status FROM message_inbox ORDER BY consumer,message_id"
            )
            if (
                len(outbox) != tables["message_outbox"]["count"]
                or len(inbox) != tables["message_inbox"]["count"]
            ):
                raise epoch.EpochError("R6_QUEUE_TABLE_DIGEST_CONFLICT")
            inbox_by_id = {}
            for row in inbox:
                if (
                    row["consumer"] != CONSUMER_SERVICE + ":bars"
                    or row["topic"] != epoch.TOPIC
                    or row["status"] != "COMPLETED"
                    or row["message_id"] in inbox_by_id
                ):
                    raise epoch.EpochError("R6_INBOX_IDENTITY_CONFLICT")
                inbox_by_id[row["message_id"]] = row
            pending_rows = []
            durable = {}
            missing = set()
            completed_ids = set(inbox_by_id)
            outbox_ids = set()
            for row in outbox:
                payload = _payload(row)
                event = ClosedBarEventV1.model_validate(payload)
                encoded, payload_hash = canonical_payload(payload)
                target = TARGET_BY_ID.get(row["message_id"])
                if (
                    row["id"] in outbox_ids
                    or row["topic"] != epoch.TOPIC
                    or row["producer"] != epoch.SOURCE
                    or payload_hash != row["payload_sha256"]
                    or event.message_id != row["message_id"]
                    or event.source != epoch.SOURCE
                    or event.symbol not in epoch.SYMBOLS
                    or row["last_error"] is not None
                    or row["lease_owner"] is not None
                    or row["lease_until"] is not None
                    or row["dead_lettered_at"] is not None
                    or row["reconciliation_state"] != "NONE"
                ):
                    raise epoch.EpochError("R6_OUTBOX_IDENTITY_OR_STATE_CONFLICT")
                outbox_ids.add(row["id"])
                inbox_row = inbox_by_id.pop(row["message_id"], None)
                if row["published_at"] is None:
                    if (
                        target is None
                        or row["id"] != target["outbox_id"]
                        or payload_hash != target["payload_sha256"]
                        or type(row["publish_attempts"]) is not int
                        or row["publish_attempts"] != 0
                        or inbox_row is not None
                    ):
                        raise epoch.EpochError("R6_UNADMITTED_UNPUBLISHED_ROW")
                    pending_rows.append(row)
                    missing.add(row["message_id"])
                else:
                    if (
                        type(row["publish_attempts"]) is not int
                        or row["publish_attempts"] != 1
                        or inbox_row is None
                        or inbox_row["payload_sha256"] != payload_hash
                    ):
                        raise epoch.EpochError("R6_PUBLISHED_MESSAGE_NOT_COMPLETED")
                    durable[row["message_id"]] = (payload_hash, encoded)
                if target and (
                    row["id"] != target["outbox_id"]
                    or payload_hash != target["payload_sha256"]
                ):
                    raise epoch.EpochError("R6_TARGET_ROW_CONFLICT")
            if inbox_by_id or {row["id"] for row in pending_rows} not in (
                set(TARGET_OUTBOX_IDS),
                set(),
            ):
                raise epoch.EpochError("R6_EXACT_PENDING_OUTBOX_SET_REQUIRED")
            if len(pending_rows) not in (0, len(TARGETS)):
                raise epoch.EpochError("R6_PARTIAL_PENDING_SET_REJECTED")
            if pending_rows:
                validate_exact_pending_rows(pending_rows)
            if await connection.fetchval(
                "SELECT count(*) FROM message_outbox o WHERE NOT EXISTS(SELECT 1 FROM event_audit a WHERE a.message_id=o.message_id AND a.topic=o.topic AND a.source=o.producer AND a.payload=o.payload)"
            ):
                raise epoch.EpochError("R6_AUDIT_OUTBOX_IDENTITY_CONFLICT")
            sequences = {}
            for row in await connection.fetch(
                "SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename"
            ):
                name = row["sequencename"]
                if re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name) is None:
                    raise epoch.EpochError("R6_SEQUENCE_IDENTITY_REJECTED")
                sequences[name] = dict(
                    await connection.fetchrow(
                        f'SELECT last_value,is_called FROM public."{name}"'
                    )
                )
            preserved = {}
            for table in ("message_outbox", "message_inbox"):
                row = await connection.fetchrow(
                    f"SELECT count(*) n,encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex') sha FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') row_sha FROM {table} t WHERE message_id NOT IN ({TARGET_SQL})) r",
                    *(target["message_id"] for target in TARGETS),
                )
                preserved[table] = dict(row)
            state = {
                "state": "PASS_R6_STATE",
                "matched_public_tables": len(tables),
                "tables": tables,
                "sequences": sequences,
                "anchors": history["anchors"],
                "original_prefix": history["original_prefix"],
                "queue": {
                    "outbox_rows": len(outbox),
                    "inbox_rows": len(inbox),
                    "completed_inbox": len(inbox),
                    "pending_outbox": len(pending_rows),
                    "unresolved_inbox": 0,
                    "trading_rows": 0,
                    "missing_inbox_message_ids": sorted(missing),
                },
                "preserved_queue_prefixes": preserved,
                "trading_started": False,
            }
            return state, durable, completed_ids, pending_rows
    finally:
        if owns:
            await connection.close()


async def state_snapshot(
    config: dict, *, connection=None, database=None, check_workers=True
):
    state, durable, completed, pending_rows = await _sql_snapshot(
        config, connection=connection, database=database, check_workers=check_workers
    )
    state["redis"] = await r5._redis_snapshot(config, durable, completed, set())
    if pending_rows:
        import redis.asyncio as aioredis

        client = aioredis.Redis(
            host=config["redis_host"],
            username="kairos_epoch_producer",
            password=config["redis_producer_password"],
            decode_responses=True,
            socket_timeout=15,
        )
        try:
            for row in pending_rows:
                if await client.hget(
                    "kairos.runtime." + OWNER + ".publication", row["message_id"]
                ):
                    raise epoch.EpochError("R6_UNPUBLISHED_TARGET_HAS_RECEIPT")
        finally:
            await client.aclose()
    return state, durable, pending_rows


async def observe(config: dict) -> dict:
    state, _durable, _pending = await state_snapshot(config)
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
        source, _, _, _ = await _sql_snapshot(config, connection=original)
        clone, _, _, _ = await _sql_snapshot(
            config, connection=restored, database=config["restore_database"]
        )
        expected = validate_expected_state(config["expected_seed"], include_redis=True)
        expected.pop("redis", None)
        for key in ("owner", "mode", "new_epoch_database"):
            expected.pop(key, None)
        if source != expected or clone != source:
            raise epoch.EpochError("R6_FULL_RESTORE_STATE_CONFLICT")
        return {
            **source,
            "state": "PASS_R6_ISOLATED_RESTORE",
            "source_clone_sql_equal": True,
            "trading_started": False,
        }
    finally:
        await original.close()
        await restored.close()


class _AckTrackingTransport:
    def __init__(self, transport, stop):
        self.transport = transport
        self.stop = stop
        self.acked: set[str] = set()

    async def subscribe(self, *args, **kwargs):
        async for item in self.transport.subscribe(*args, **kwargs):
            yield item

    async def ack(self, topic, envelope, *, group=None):
        await self.transport.ack(topic, envelope, group=group)
        message_id = envelope.payload.get("message_id")
        if message_id in TARGET_IDS:
            self.acked.add(message_id)
            if self.acked == TARGET_IDS:
                self.stop.set()

    async def close(self):
        await self.transport.close()


async def _consume_exact(config: dict, stop: asyncio.Event) -> dict:
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
                or event.message_id not in TARGET_IDS
                or payload_hash != target["payload_sha256"]
                or envelope.topic != epoch.TOPIC
            ):
                raise epoch.EpochError("R6_UNEXPECTED_DELIVERY_REJECTED")
            await bus.ack(epoch.TOPIC, envelope, group="bars")
    finally:
        await bus.close()
    return {**telemetry, "target_ack_message_ids": sorted(transport.acked)}


async def drain(config: dict, output: Path) -> dict:
    import asyncpg
    import redis.asyncio as aioredis

    before, _durable, pending = await state_snapshot(config)
    expected = validate_expected_state(config["expected_state"], include_redis=True)
    if before != expected:
        raise epoch.EpochError("R6_FULL_PRESTATE_CHANGED")
    if {row["id"] for row in pending} != set(TARGET_OUTBOX_IDS):
        raise epoch.EpochError("R6_EXACT_UNPUBLISHED_SET_REQUIRED")

    # Lock every runtime writer role before rechecking. The normal flush function
    # then publishes only the four proven rows while the writer/supervisor stay fenced.
    fence = await epoch.connect(config, "kairos")
    acquired = []
    pool = producer = None
    try:
        for key in epoch.BOOT_ADVISORY_LOCKS:
            if key == 7716101100001:  # epoch.flush owns the dispatcher lock itself
                continue
            if not await fence.fetchval("SELECT pg_try_advisory_lock($1)", key):
                raise epoch.EpochError("R6_RUNTIME_WORKER_LOCK_CONFLICT")
            acquired.append(key)
        locked_before, _d, locked_pending = await state_snapshot(
            config, connection=fence, check_workers=False
        )
        locked_expected = dict(expected)
        for key in ("owner", "mode", "new_epoch_database"):
            locked_expected.pop(key, None)
        if locked_before != locked_expected or {
            row["id"] for row in locked_pending
        } != set(TARGET_OUTBOX_IDS):
            raise epoch.EpochError("R6_LOCKED_PRESTATE_CONFLICT")
        pool = await asyncpg.create_pool(
            epoch.dsn(config, "kairos_epoch_producer"),
            min_size=1,
            max_size=2,
            command_timeout=30,
        )
        producer = aioredis.Redis(
            host=config["redis_host"],
            username="kairos_epoch_producer",
            password=config["redis_producer_password"],
            decode_responses=True,
            socket_timeout=15,
        )
        published = await epoch.flush(config, pool, producer)
        if published != len(TARGETS):
            raise epoch.EpochError("R6_EXACT_PUBLICATION_COUNT_REQUIRED")
    finally:
        if producer is not None:
            await producer.aclose()
        if pool is not None:
            await pool.close()
        for key in reversed(acquired):
            await fence.fetchval("SELECT pg_advisory_unlock($1)", key)
        await fence.close()

    stop = asyncio.Event()
    task = asyncio.create_task(_consume_exact(config, stop))
    deadline = time.monotonic() + 90
    try:
        while not task.done():
            if time.monotonic() >= deadline:
                raise epoch.EpochError("R6_EXACT_COMPLETION_DEADLINE")
            await asyncio.sleep(0.2)
        metrics = await task
        if set(metrics.get("target_ack_message_ids", [])) != TARGET_IDS:
            raise epoch.EpochError("R6_TRANSPORT_ACK_SET_INCOMPLETE")
    finally:
        stop.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    after, _durable, pending_after = await state_snapshot(config)
    if pending_after:
        raise epoch.EpochError("R6_EXACT_DRAIN_PRESERVATION_CONFLICT")
    validate_drain_transition(before, after)
    return {
        "state": "PASS_EXACT_R6_PUBLICATION_AND_DRAIN",
        "before_sha256": digest(before),
        "after_sha256": digest(after),
        "published_message_ids": sorted(TARGET_IDS),
        "completed_message_ids": sorted(TARGET_IDS),
        "completed_inbox_increment": len(TARGETS),
        "published_messages": len(TARGETS),
        "stream_entries_added": len(TARGETS),
        "publication_receipts_added": len(TARGETS),
        "pending_deliveries": 0,
        "redis_transport": metrics,
        "audit_history_preserved": True,
        "outbox_and_sequences_preserved": True,
        "trading_started": False,
    }


async def dispatch_r6(mode: str, config: dict, output: Path) -> dict:
    validate_config(mode, config)
    if mode == "r6-state":
        return await observe(config)
    if mode == "r6-verify-restore":
        return await verify_restore(config)
    return await drain(config, output)
