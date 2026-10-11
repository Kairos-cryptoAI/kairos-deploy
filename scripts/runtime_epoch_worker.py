"""Isolated CLOSED_BAR epoch: no strategy, risk, execution, or paid provider.

Historical bars enter audit only. Fresh bars use a bounded transactional outbox
and a Redis atomic receipt ledger, so a crash after acceptance is replay-safe.
Consumer credentials cannot enqueue output. Old clusters are never addressed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

TOPIC = "kairos.market.closed_bar.v1"
SYMBOLS = ("BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT")
MINUTE = 60_000
MAX_BARS = 150_000
MAX_PENDING = 100
FINALITY_MS = 5_000
MAX_STATUS_BYTES = 32_768
SOURCE = "kairos-quant-scouts"
SOURCE_DUMP_SHA256 = "2408db1335dc856122750e4604f14a436184f54a7f4ffab22bc35eb69747a7bc"
DB_ROLES = ("kairos_epoch_history", "kairos_epoch_producer", "kairos_epoch_consumer")
MODES = ("prepare", "seed", "catchup", "verify-restore", "qualify", "serve")
PUBLICATION_LUA = """
local prior=redis.call('HGET',KEYS[2],ARGV[1])
if prior then
 local p=cjson.decode(prior)
 if p[1]~=ARGV[2] then return redis.error_reply('EPOCH_IDENTITY_CONFLICT') end
 local row=redis.call('XRANGE',KEYS[1],p[2],p[2])
 if #row~=1 then return redis.error_reply('EPOCH_RECEIPT_WITHOUT_STREAM') end
 if #row[1][2]~=2 or row[1][2][1]~='data' or row[1][2][2]~=ARGV[3] then
  return redis.error_reply('EPOCH_STREAM_PAYLOAD_CONFLICT')
 end
 return p[2]
end
local id=redis.call('XADD',KEYS[1],'*','data',ARGV[3])
redis.call('HSET',KEYS[2],ARGV[1],cjson.encode({ARGV[2],id}))
return id
""".strip()


class EpochError(RuntimeError):
    """Safe error: no credentials, database payload, or driver text."""


def validate_config(value: dict, mode: str) -> None:
    if mode not in MODES or not isinstance(value, dict):
        raise EpochError("EPOCH_MODE_CONFIG_REQUIRED")
    owner = value.get("owner", "")
    if not re.fullmatch(r"[0-9a-f]{32}", owner):
        raise EpochError("EPOCH_OWNER_REQUIRED")
    if value.get("database") != "kairos_epoch_" + owner[:12]:
        raise EpochError("NEW_EPOCH_DATABASE_REQUIRED")
    for key in ("pg_host", "redis_host"):
        if not re.fullmatch(
            r"kairos-epoch-" + owner[:12] + r"-[a-z]+", value.get(key, "")
        ):
            raise EpochError("OWNED_EPOCH_HOST_REQUIRED")
    for key, item in value.items():
        if key.endswith("password") and not re.fullmatch(r"[0-9a-f]{64}", item):
            raise EpochError("NEW_PRIVATE_CREDENTIAL_REQUIRED")
    if mode in {"qualify", "serve"}:
        if any(
            k in value
            for k in (
                "admin_password",
                "history_password",
                "source_password",
                "source_admin_password",
            )
        ):
            raise EpochError("RUNTIME_ADMIN_CREDENTIAL_REJECTED")
        if any(
            not value.get(k)
            for k in (
                "producer_password",
                "consumer_password",
                "redis_producer_password",
                "redis_consumer_password",
            )
        ):
            raise EpochError("SEPARATE_RUNTIME_CREDENTIALS_REQUIRED")
    if mode == "catchup":
        end = value.get("end_exclusive_ms")
        now = int(time.time() * 1000)
        if type(end) is not int or end % MINUTE or end > now - FINALITY_MS:
            raise EpochError("FIXED_FINALITY_SAFE_DEADLINE_REQUIRED")
        if value.get("maximum_bars") != MAX_BARS:
            raise EpochError("EXACT_GLOBAL_HISTORY_CAP_REQUIRED")
    if mode == "seed" and (
        value.get("source_dump_sha256") != SOURCE_DUMP_SHA256
        or value.get("seed_expectation") != {"accepted_dump_sha256": SOURCE_DUMP_SHA256}
    ):
        raise EpochError("PINNED_SOURCE_DUMP_PROVENANCE_REQUIRED")


def write_status(path: Path, value: dict, *, immutable: bool = False) -> None:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if len(encoded) > MAX_STATUS_BYTES:
        raise EpochError("STATUS_BOUND_EXCEEDED")
    path.parent.mkdir(parents=True, exist_ok=True)
    if immutable:
        with path.open("xb") as stream:
            stream.write(encoded)
    else:
        temporary = path.with_suffix(".new")
        with temporary.open("wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)


def dsn(config: dict, role: str) -> str:
    key = {
        "kairos": "admin_password",
        "kairos_epoch_history": "history_password",
        "kairos_epoch_producer": "producer_password",
        "kairos_epoch_consumer": "consumer_password",
    }[role]
    return f"postgresql://{role}:{quote(config[key], safe='')}@{config['pg_host']}:5432/{config['database']}"


async def connect(config: dict, role: str):
    import asyncpg

    return await asyncpg.connect(dsn(config, role), timeout=15, command_timeout=30)


async def verify_schema(connection) -> None:
    from kairos_persistence.database import Database, MigrationProfile

    actual = tuple(
        r["version"]
        for r in await connection.fetch(
            "SELECT version FROM schema_migrations ORDER BY version"
        )
    )
    expected = Database.migration_names(MigrationProfile.CONTROLLED_RUNTIME)
    if actual != expected:
        raise EpochError("EXACT_CONTROLLED_SCHEMA_REQUIRED")


async def source_connection(config: dict, *, admin: bool = False):
    import asyncpg

    if (
        config.get("source_database")
        != "kairos_recovery_" + config["owner"][:12] + "_epoch"
    ):
        raise EpochError("OWNED_RESTORED_SOURCE_REQUIRED")
    if config.get("source_host") != "kairos-epoch-" + config["owner"][:12] + "-source":
        raise EpochError("OWNED_SOURCE_HOST_REQUIRED")
    role = "kairos" if admin else "kairos_epoch_source"
    password = config["source_admin_password" if admin else "source_password"]
    return await asyncpg.connect(
        f"postgresql://{role}:{password}@{config['source_host']}:5432/{config['source_database']}",
        timeout=15,
        command_timeout=120,
    )


async def create_role(connection, name: str, password: str) -> None:
    if name not in (*DB_ROLES, "kairos_epoch_source") or not re.fullmatch(
        r"[0-9a-f]{64}", password
    ):
        raise EpochError("EXACT_NONTRADING_ROLE_REQUIRED")
    await connection.execute(
        f"CREATE ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}'"
    )


async def prepare(config: dict) -> dict:
    from kairos_persistence.config import PersistenceSettings
    from kairos_persistence.database import Database, MigrationProfile

    settings = PersistenceSettings(
        database_url=dsn(config, "kairos"), pool_min_size=1, pool_max_size=2
    )
    database = Database(settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME)
    await database.connect()
    try:
        async with database.pool.acquire() as connection:
            if await connection.fetchval(
                "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
            ):
                raise EpochError("EMPTY_NEW_DATABASE_REQUIRED")
        await database.migrate()
        async with database.pool.acquire() as connection:
            await verify_schema(connection)
            async with connection.transaction():
                await connection.execute(
                    "REVOKE ALL ON SCHEMA public FROM PUBLIC; REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC; REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC; REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;"
                )
                for role, key in zip(
                    DB_ROLES,
                    ("history_password", "producer_password", "consumer_password"),
                    strict=True,
                ):
                    await create_role(connection, role, config[key])
                    await connection.execute(
                        f"GRANT CONNECT ON DATABASE {config['database']} TO {role}; GRANT USAGE ON SCHEMA public TO {role}; GRANT SELECT ON schema_migrations TO {role}; GRANT SELECT,INSERT ON event_audit TO {role}; GRANT SELECT ON message_outbox TO {role}"
                    )
                await connection.execute(
                    "GRANT INSERT,UPDATE ON message_outbox TO kairos_epoch_producer; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO kairos_epoch_producer; GRANT SELECT,INSERT,UPDATE ON message_inbox TO kairos_epoch_consumer; GRANT SELECT ON execution_orders,execution_effects TO kairos_epoch_consumer"
                )
    finally:
        await database.close()
    source = await source_connection(config, admin=True)
    try:
        await verify_schema(source)
        await create_role(source, "kairos_epoch_source", config["source_password"])
        await source.execute(
            f"GRANT CONNECT ON DATABASE {config['source_database']} TO kairos_epoch_source; GRANT USAGE ON SCHEMA public TO kairos_epoch_source; GRANT SELECT ON schema_migrations,event_audit,message_outbox TO kairos_epoch_source; ALTER ROLE kairos_epoch_source SET default_transaction_read_only=on"
        )
    finally:
        await source.close()
    return {
        "state": "PREPARED_EMPTY_NONTRADING_EPOCH",
        "schema_verified": True,
        "roles": list(DB_ROLES),
    }


async def seed(config: dict) -> dict:
    from runtime_epoch_history_seed import (
        SOURCE_EXPORT_SQL,
        Anchor,
        SeedLimits,
        SourceIdentity,
        TargetIdentity,
        measure_history,
        seed_history,
    )

    source = await source_connection(config)
    target = await connect(config, "kairos_epoch_history")
    try:
        await verify_schema(source)
        await verify_schema(target)
        last = int(datetime(2026, 9, 19, 15, 43, tzinfo=UTC).timestamp() * 1000)
        expected_anchors = {
            s: Anchor(
                34632 if s == "XRPUSDT" else 34633,
                last - ((34632 if s == "XRPUSDT" else 34633) - 1) * MINUTE,
                last,
                last + MINUTE - 1,
            )
            for s in SYMBOLS
        }
        async with source.transaction(isolation="repeatable_read", readonly=True):
            if await source.fetchval("SHOW transaction_read_only") != "on":
                raise EpochError("READONLY_SOURCE_REQUIRED")

            async def rows():
                async for row in source.cursor(
                    SOURCE_EXPORT_SQL, TOPIC, SOURCE, prefetch=500
                ):
                    yield dict(row)

            limits = SeedLimits(maximum_seconds=600)
            expectation = await measure_history(rows(), expected_anchors, limits=limits)
            receipt = await seed_history(
                rows(),
                target,
                source=SourceIdentity(
                    config["source_database"],
                    "accepted-backup-2408db1335dc",
                    True,
                    True,
                ),
                target_identity=TargetIdentity(
                    config["database"], config["owner"], True, True
                ),
                expected=expectation,
                limits=limits,
            )
        return {"state": "VERIFIED_HISTORY_SEEDED_AUDIT_ONLY", **asdict(receipt)}
    finally:
        await source.close()
        await target.close()


async def verify_restore(config: dict) -> dict:
    import asyncpg
    from controlled_runtime_worker import Budget, _table_digest

    if (
        config.get("restore_host")
        != "kairos-epoch-" + config["owner"][:12] + "-restore"
        or config.get("restore_database")
        != "kairos_recovery_" + config["owner"][:12] + "_epochrestore"
    ):
        raise EpochError("OWNED_EPOCH_RESTORE_REQUIRED")
    original = await connect(config, "kairos")
    restored = await asyncpg.connect(
        f"postgresql://kairos:{config['restore_admin_password']}@{config['restore_host']}:5432/{config['restore_database']}",
        timeout=15,
        command_timeout=120,
    )

    async def snapshot(connection):
        await verify_schema(connection)
        result = {}
        async with connection.transaction(isolation="repeatable_read", readonly=True):
            tables = [
                r["relname"]
                for r in await connection.fetch(
                    "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition ORDER BY c.relname"
                )
            ]
            if len(tables) != 39:
                raise EpochError("EXACT_EPOCH_TABLE_INVENTORY_REQUIRED")
            budget = Budget()
            for table in tables:
                result[table] = await _table_digest(connection, table, budget)
            for table in (
                "message_outbox",
                "message_inbox",
                "execution_orders",
                "execution_effects",
            ):
                if result[table]["count"] != 0:
                    raise EpochError("AUDIT_ONLY_BACKUP_REQUIRED")
            sequences = {}
            for row in await connection.fetch(
                "SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename"
            ):
                name = row["sequencename"]
                if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name):
                    raise EpochError("SEQUENCE_IDENTITY_REJECTED")
                sequences[name] = dict(
                    await connection.fetchrow(
                        f'SELECT last_value,is_called FROM public."{name}"'
                    )
                )
        return {"tables": result, "sequences": sequences}

    try:
        first, second = await asyncio.gather(snapshot(original), snapshot(restored))
        if first != second:
            raise EpochError("EPOCH_RESTORE_FULL_HISTORY_CONFLICT")
        return {
            "state": "PASS_ISOLATED_EPOCH_RESTORE",
            "matched_public_tables": 39,
            **first,
        }
    finally:
        await original.close()
        await restored.close()


async def anchors(pool) -> dict:
    from kairos_core.contracts import ClosedBarEventV1

    result = {}
    async with pool.acquire() as connection:
        for symbol in SYMBOLS:
            checks = await connection.fetchrow(
                """WITH b AS (SELECT (payload->>'open_time_ms')::bigint t FROM event_audit WHERE topic=$1 AND source=$2 AND payload->>'symbol'=$3) SELECT count(*) n,count(DISTINCT t) u,min(t) lo,max(t) hi FROM b""",
                TOPIC,
                SOURCE,
                symbol,
            )
            if (
                not checks["n"]
                or checks["n"] != checks["u"]
                or checks["hi"] - checks["lo"] != (checks["n"] - 1) * MINUTE
            ):
                raise EpochError("FIVE_UNIQUE_CONTIGUOUS_CHAINS_REQUIRED")
            raw = await connection.fetchval(
                "SELECT payload FROM event_audit WHERE topic=$1 AND source=$2 AND payload->>'symbol'=$3 ORDER BY (payload->>'open_time_ms')::bigint DESC LIMIT 1",
                TOPIC,
                SOURCE,
                symbol,
            )
            result[symbol] = ClosedBarEventV1.model_validate(
                json.loads(raw) if isinstance(raw, str) else raw
            )
    return result


def required_bars(values: dict, end: int) -> int:
    intervals = [end - e.close_time_ms - 1 for e in values.values()]
    if set(values) != set(SYMBOLS) or any(n < 0 or n % MINUTE for n in intervals):
        raise EpochError("FIXED_CATCHUP_INTERVAL_REQUIRED")
    return sum(n // MINUTE for n in intervals)


class EpochWriter:
    def __init__(self, pool):
        from kairos_persistence.repository import AuditRepository

        self.pool = pool
        self.repository = AuditRepository(pool)

    async def append(self, event, *, publish: bool):
        from kairos_persistence.runtime import canonical_payload

        payload = event.to_payload()
        encoded, digest = canonical_payload(payload)
        async with self.pool.acquire() as connection, connection.transaction():
            rows = await connection.fetch(
                "SELECT topic,payload FROM event_audit WHERE message_id=$1",
                event.message_id,
            )
            if rows:
                self.repository._require_matching_audit_identity(
                    rows,
                    message_id=event.message_id,
                    topic=TOPIC,
                    canonical_json=encoded,
                )
            elif not await self.repository.append_payload(
                TOPIC, payload, connection=connection
            ):
                rows = await connection.fetch(
                    "SELECT topic,payload FROM event_audit WHERE message_id=$1",
                    event.message_id,
                )
                self.repository._require_matching_audit_identity(
                    rows,
                    message_id=event.message_id,
                    topic=TOPIC,
                    canonical_json=encoded,
                )
            if publish:
                await self.repository.enqueue_outbox(
                    connection, event.message_id, TOPIC, encoded, digest, SOURCE
                )


async def recover(config: dict, *, publish: bool, status_path: Path) -> dict:
    import aiohttp
    import asyncpg
    from kairos_quant.long_gap_recovery import RecoveryStatus, recover_symbol

    role = "kairos_epoch_producer" if publish else "kairos_epoch_history"
    pool = await asyncpg.create_pool(
        dsn(config, role), min_size=1, max_size=6, command_timeout=30
    )
    end = config["end_exclusive_ms"]
    totals = {}
    progress_by_symbol = {}
    try:
        async with pool.acquire() as connection:
            await verify_schema(connection)
            lock = await connection.fetchval(
                "SELECT pg_try_advisory_lock(4907627681104115019)"
            )
            if not lock:
                raise EpochError("EPOCH_WRITER_ALREADY_RUNNING")
            values = await anchors(pool)
            required = required_bars(values, end)
            if required > (MAX_PENDING if publish else MAX_BARS):
                raise EpochError("EPOCH_INTERVAL_EXCEEDS_FIXED_CAP")
            writer = EpochWriter(pool)
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:

                async def fetch(symbol, start, finish):
                    async with session.get(
                        "https://fapi.binance.com/fapi/v1/klines",
                        params={
                            "symbol": symbol,
                            "interval": "1m",
                            "startTime": start,
                            "endTime": finish - 1,
                            "limit": (finish - start) // MINUTE,
                        },
                        allow_redirects=False,
                    ) as response:
                        if (
                            response.status != 200
                            or response.content_length
                            and response.content_length > 2_000_000
                        ):
                            raise EpochError("OFFICIAL_CLOSED_BAR_FETCH_FAILED")
                        chunks = []
                        size = 0
                        async for chunk in response.content.iter_chunked(65536):
                            size += len(chunk)
                            if size > 2_000_000:
                                raise EpochError("REST_RESPONSE_BOUND_EXCEEDED")
                            chunks.append(chunk)
                        return json.loads(b"".join(chunks))

                async def one(symbol):
                    def report(item):
                        if item.get("state") == "PROGRESS":
                            progress_by_symbol[symbol] = {
                                "appended_bars": item.get("appended_bars"),
                                "through_exclusive_ms": item.get(
                                    "through_exclusive_ms"
                                ),
                            }
                            write_status(
                                status_path,
                                {
                                    "state": "CATCHUP_PROGRESS",
                                    "owner": config["owner"],
                                    "symbols": dict(progress_by_symbol),
                                    "deadline_ms": end,
                                    "observed_at_utc": datetime.now(UTC).isoformat(),
                                },
                            )

                    state = RecoveryStatus(report)

                    async def append(event):
                        await writer.append(event, publish=publish)

                    async def pause():
                        await asyncio.sleep(5)

                    count = await recover_symbol(
                        values[symbol],
                        end_exclusive=end,
                        fetch=fetch,
                        publish=append,
                        pause=pause,
                        progress=lambda _item: None,
                        status=state,
                    )
                    totals[symbol] = count
                    write_status(
                        status_path,
                        {
                            "state": "CATCHUP_PROGRESS",
                            "owner": config["owner"],
                            "completed_symbols": dict(totals),
                            "deadline_ms": end,
                            "observed_at_utc": datetime.now(UTC).isoformat(),
                        },
                    )

                await asyncio.gather(*(one(s) for s in SYMBOLS))
            if sum(totals.values()) != required:
                raise EpochError("EXACT_APPEND_COUNT_REQUIRED")
            if not publish and await connection.fetchval(
                "SELECT count(*) FROM message_outbox"
            ):
                raise EpochError("HISTORY_CREATED_OUTBOX_REJECTED")
            await connection.execute("SELECT pg_advisory_unlock(4907627681104115019)")
        return {
            "state": "CURRENT_BARS_APPENDED"
            if publish
            else "AUDIT_ONLY_CATCHUP_COMPLETE",
            "appended": totals,
            "through_exclusive_ms": end,
            "maximum_bars": MAX_PENDING if publish else MAX_BARS,
        }
    finally:
        await pool.close()


async def flush(config: dict, pool, redis) -> int:
    from kairos_persistence.runtime import canonical_payload

    count = 0
    async with pool.acquire() as connection:
        if not await connection.fetchval("SELECT pg_try_advisory_lock(7716101100001)"):
            raise EpochError("EPOCH_DISPATCHER_ALREADY_RUNNING")
        try:
            records = await connection.fetch(
                "SELECT id,message_id,topic,payload,payload_sha256,producer,reconciliation_state,dead_lettered_at FROM message_outbox WHERE published_at IS NULL ORDER BY id LIMIT $1",
                MAX_PENDING + 1,
            )
            if len(records) > MAX_PENDING:
                raise EpochError("NEW_EPOCH_PENDING_CAP_EXCEEDED")
            for row in records:
                if (
                    row["topic"] != TOPIC
                    or row["producer"] != SOURCE
                    or row["reconciliation_state"] != "NONE"
                    or row["dead_lettered_at"] is not None
                ):
                    raise EpochError("NON_BAR_OUTBOX_REJECTED")
                payload = (
                    json.loads(row["payload"])
                    if isinstance(row["payload"], str)
                    else row["payload"]
                )
                encoded, digest = canonical_payload(payload)
                if (
                    digest != row["payload_sha256"]
                    or payload.get("message_id") != row["message_id"]
                ):
                    raise EpochError("OUTBOX_HASH_CONFLICT")
                receipt = await redis.eval(
                    PUBLICATION_LUA,
                    2,
                    TOPIC,
                    "kairos.runtime." + config["owner"] + ".publication",
                    row["message_id"],
                    digest,
                    encoded,
                )
                if not re.fullmatch(r"[0-9]+-[0-9]+", receipt):
                    raise EpochError("POSITIVE_REDIS_RECEIPT_REQUIRED")
                await connection.execute(
                    "UPDATE message_outbox SET published_at=now(),publish_attempts=publish_attempts+1,last_error=NULL WHERE id=$1 AND published_at IS NULL",
                    row["id"],
                )
                count += 1
        finally:
            await connection.execute("SELECT pg_advisory_unlock(7716101100001)")
    return count


async def consume(config: dict, stop: asyncio.Event) -> None:
    from kairos_core.bus.redis_streams import RedisStreamsBus
    from kairos_core.contracts import ClosedBarEventV1
    from kairos_persistence.config import PersistenceSettings
    from kairos_persistence.database import Database, MigrationProfile
    from kairos_persistence.runtime import DurableMessageBus

    url = f"redis://kairos_epoch_consumer:{config['redis_consumer_password']}@{config['redis_host']}:6379/0"
    transport = RedisStreamsBus(url)
    settings = PersistenceSettings(
        database_url=dsn(config, "kairos_epoch_consumer"),
        pool_min_size=1,
        pool_max_size=2,
    )
    database = Database(settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME)
    bus = DurableMessageBus(
        transport,
        service_name="kairos-epoch-consumer-" + config["owner"][:12],
        settings=settings,
        database=database,
        consumer_only=True,
        verify_schema_only=True,
        required_migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
    )
    try:
        async for envelope in bus.subscribe(TOPIC, group="bars"):
            event = ClosedBarEventV1.model_validate(envelope.payload)
            if (
                event.symbol not in SYMBOLS
                or event.source != SOURCE
                or event.close_time_ms > int(time.time() * 1000) - FINALITY_MS
            ):
                raise EpochError("FRESH_CONSUMER_CONTRACT_REJECTED")
            await bus.ack(TOPIC, envelope, group="bars")
            if stop.is_set():
                break
    finally:
        await bus.close()


async def health(config: dict, pool) -> dict:
    async with pool.acquire() as connection:
        data = dict(
            await connection.fetchrow(
                """SELECT (SELECT count(*) FROM message_outbox WHERE published_at IS NULL) pending,(SELECT count(*) FROM message_inbox WHERE status<>'COMPLETED') unresolved,(SELECT count(*) FROM message_inbox WHERE status='COMPLETED') completed,(SELECT count(*) FROM execution_orders)+(SELECT count(*) FROM execution_effects) trading_rows"""
            )
        )
        watermarks = await anchors(pool)
        data["watermarks_ms"] = {s: e.close_time_ms + 1 for s, e in watermarks.items()}
    if data["trading_rows"] or data["pending"] > MAX_PENDING:
        raise EpochError("NONTRADING_HEALTH_BOUNDARY_FAILED")
    return data


async def verify_duplicate_delivery(
    config: dict, pool, producer, consumer, task
) -> dict:
    from kairos_persistence.runtime import canonical_payload
    from redis.exceptions import ResponseError

    async with pool.acquire() as connection:
        row = await connection.fetchrow(
            "SELECT message_id,payload,payload_sha256 FROM message_outbox WHERE published_at IS NOT NULL ORDER BY id DESC LIMIT 1"
        )
    if row is None:
        raise EpochError("FRESH_PUBLICATION_REQUIRED_FOR_QUALIFICATION")
    payload = (
        json.loads(row["payload"])
        if isinstance(row["payload"], str)
        else row["payload"]
    )
    encoded, digest = canonical_payload(payload)
    if digest != row["payload_sha256"]:
        raise EpochError("QUALIFICATION_PAYLOAD_CONFLICT")
    ledger = "kairos.runtime." + config["owner"] + ".publication"
    length = await producer.xlen(TOPIC)
    first = await producer.eval(
        PUBLICATION_LUA, 2, TOPIC, ledger, row["message_id"], digest, encoded
    )
    second = await producer.eval(
        PUBLICATION_LUA, 2, TOPIC, ledger, row["message_id"], digest, encoded
    )
    if first != second or await producer.xlen(TOPIC) != length:
        raise EpochError("IDEMPOTENT_REDIS_ACCEPTANCE_FAILED")
    try:
        await producer.eval(
            PUBLICATION_LUA,
            2,
            TOPIC,
            ledger,
            row["message_id"],
            "0" * 64 if digest != "0" * 64 else "1" * 64,
            encoded,
        )
    except ResponseError as exc:
        if "EPOCH_IDENTITY_CONFLICT" not in str(exc):
            raise EpochError("IDENTITY_CONFLICT_NOT_ENFORCED") from None
    else:
        raise EpochError("IDENTITY_CONFLICT_ACCEPTED")
    checker = await connect(config, "kairos_epoch_consumer")
    try:
        before = await checker.fetchval(
            "SELECT count(*) FROM message_inbox WHERE status='COMPLETED'"
        )
        duplicate = await producer.xadd(TOPIC, {"data": encoded})
        deadline = time.monotonic() + 30
        while True:
            if task.done():
                await task
                raise EpochError("DUPLICATE_CONSUMER_STOPPED")
            groups = await producer.xinfo_groups(TOPIC)
            bars = next((g for g in groups if g["name"] == "bars"), None)
            if (
                bars
                and tuple(map(int, bars["last-delivered-id"].split("-")))
                >= tuple(map(int, duplicate.split("-")))
                and not await consumer.xpending_range(
                    TOPIC, "bars", duplicate, duplicate, 1
                )
            ):
                break
            if time.monotonic() > deadline:
                raise EpochError("DUPLICATE_ACK_DEADLINE")
            await asyncio.sleep(0.25)
        after = await checker.fetchval(
            "SELECT count(*) FROM message_inbox WHERE status='COMPLETED'"
        )
        if before != after:
            raise EpochError("DUPLICATE_CREATED_EXTRA_DURABLE_EFFECT")
    finally:
        await checker.close()
    return {
        "redis_acceptance_replay_same_id": True,
        "hash_conflict_refused": True,
        "duplicate_delivery_acked_without_new_inbox": True,
    }


async def runtime(config: dict, output: Path, *, qualification: bool) -> dict:
    import asyncpg
    import redis.asyncio as aioredis
    from redis.exceptions import NoPermissionError

    pool = await asyncpg.create_pool(
        dsn(config, "kairos_epoch_producer"), min_size=1, max_size=2, command_timeout=30
    )
    producer = aioredis.Redis(
        host=config["redis_host"],
        username="kairos_epoch_producer",
        password=config["redis_producer_password"],
        decode_responses=True,
        socket_timeout=15,
    )
    consumer_probe = aioredis.Redis(
        host=config["redis_host"],
        username="kairos_epoch_consumer",
        password=config["redis_consumer_password"],
        decode_responses=True,
        socket_timeout=15,
    )
    stop = asyncio.Event()
    task = None
    supervisor = None
    qualification_proofs = {}
    try:
        supervisor = await connect(config, "kairos_epoch_producer")
        if not await supervisor.fetchval("SELECT pg_try_advisory_lock(7716101100002)"):
            raise EpochError("EPOCH_SUPERVISOR_ALREADY_RUNNING")
        async with pool.acquire() as connection:
            await verify_schema(connection)
        await consumer_probe.ping()
        try:
            await consumer_probe.xadd(TOPIC, {"data": "must-not-be-written"})
        except NoPermissionError:
            pass
        else:
            raise EpochError("CONSUMER_XADD_PERMISSION_REJECTED")
        consumer_sql = await connect(config, "kairos_epoch_consumer")
        try:
            try:
                await consumer_sql.execute(
                    "UPDATE message_outbox SET published_at=now() WHERE false"
                )
            except asyncpg.InsufficientPrivilegeError:
                pass
            else:
                raise EpochError("CONSUMER_OUTBOX_PERMISSION_REJECTED")
        finally:
            await consumer_sql.close()
        task = asyncio.create_task(consume(config, stop))
        cycles = 0
        while True:
            if task.done():
                await task
                raise EpochError("CONSUMER_STOPPED")
            end = ((int(time.time() * 1000) - FINALITY_MS) // MINUTE) * MINUTE
            await flush(config, pool, producer)
            current = {**config, "end_exclusive_ms": end}
            await recover(current, publish=True, status_path=output / "progress.json")
            sent = await flush(config, pool, producer)
            deadline = time.monotonic() + 30
            while True:
                if task.done():
                    await task
                    raise EpochError("CONSUMER_STOPPED")
                # Producer cannot inspect inbox or orders: use dedicated consumer
                # read connection; both identities still lack execution writes.
                checker = await connect(config, "kairos_epoch_consumer")
                try:
                    pending = await checker.fetchval(
                        "SELECT count(*) FROM message_outbox WHERE published_at IS NULL"
                    )
                    unresolved = await checker.fetchval(
                        "SELECT count(*) FROM message_inbox WHERE status<>'COMPLETED'"
                    )
                    completed = await checker.fetchval(
                        "SELECT count(*) FROM message_inbox WHERE status='COMPLETED'"
                    )
                    uncompleted = await checker.fetchval(
                        """SELECT count(*) FROM message_outbox o WHERE o.published_at IS NOT NULL AND NOT EXISTS (SELECT 1 FROM message_inbox i WHERE i.consumer=$1 AND i.message_id=o.message_id AND i.topic=o.topic AND i.payload_sha256=o.payload_sha256 AND i.status='COMPLETED')""",
                        "kairos-epoch-consumer-" + config["owner"][:12] + ":bars",
                    )
                    if await checker.fetchval(
                        "SELECT (SELECT count(*) FROM execution_orders)+(SELECT count(*) FROM execution_effects)"
                    ):
                        raise EpochError("TRADING_ROW_IN_NONTRADING_EPOCH")
                finally:
                    await checker.close()
                if pending == 0 and unresolved == 0 and uncompleted == 0:
                    break
                if time.monotonic() > deadline:
                    raise EpochError("CONSUMER_COMPLETION_DEADLINE")
                await asyncio.sleep(0.25)
            watermarks = await anchors(pool)
            if qualification and completed > 0 and not qualification_proofs:
                qualification_proofs = await verify_duplicate_delivery(
                    config, pool, producer, consumer_probe, task
                )
            report = {
                "state": "RUNNING_NONTRADING",
                "owner": config["owner"],
                "cycles": cycles + 1,
                "watermarks_ms": {
                    s: e.close_time_ms + 1 for s, e in watermarks.items()
                },
                "pending_outbox": pending,
                "unresolved_inbox": unresolved,
                "completed_inbox": completed,
                "uncompleted_publications": uncompleted,
                "new_publications": sent,
                "observed_at_utc": datetime.now(UTC).isoformat(),
                "PAPER_QUALIFIED": False,
                "ALPHA_READY": False,
                "LIVE_READY": False,
                "STRATEGY_POLICY": "REJECT_ALL",
                "qualification_proofs": qualification_proofs,
            }
            write_status(output / "status.json", report)
            cycles += 1
            if qualification and completed > 0 and cycles >= 2:
                return {**report, "state": "NONTRADING_RUNTIME_QUALIFIED"}
            await asyncio.sleep(10)
    finally:
        stop.set()
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await producer.aclose()
        await consumer_probe.aclose()
        if supervisor:
            await supervisor.close()
        await pool.close()


async def dispatch(mode: str, config: dict, output: Path) -> dict:
    validate_config(config, mode)
    if mode == "prepare":
        return await prepare(config)
    if mode == "seed":
        return await seed(config)
    if mode == "catchup":
        return await recover(
            config, publish=False, status_path=output / "progress.json"
        )
    if mode == "verify-restore":
        return await verify_restore(config)
    return await runtime(config, output, qualification=mode == "qualify")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.config.is_symlink() or args.config.stat().st_size > 32_768:
            raise EpochError("PRIVATE_CONFIG_BOUNDARY_REJECTED")
        config = json.loads(args.config.read_bytes())
        result = asyncio.run(dispatch(args.mode, config, args.output))
        result = {
            **result,
            "owner": config["owner"],
            "mode": args.mode,
            "new_epoch_database": config["database"],
        }
        write_status(args.output / (args.mode + ".json"), result, immutable=True)
        return 0
    except Exception as exc:  # noqa: BLE001 - fail closed, no driver data disclosure
        reason = (
            str(exc)
            if isinstance(exc, EpochError)
            else "operation failed; private diagnostic withheld"
        )
        write_status(
            args.output / "status.json",
            {
                "state": "FAILED_CLOSED",
                "mode": args.mode,
                "error_type": type(exc).__name__,
                "reason": reason,
                "observed_at_utc": datetime.now(UTC).isoformat(),
                "trading_started": False,
            },
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
