"""Isolated CLOSED_BAR epoch: no strategy, risk, execution, or paid provider.

Historical bars enter audit only. Fresh bars use a bounded transactional outbox
and a Redis atomic receipt ledger, so a crash after acceptance is replay-safe.
Consumer credentials cannot enqueue output. Old clusters are never addressed.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import json
import os
import re
import signal
import sys
import time
from builtins import ExceptionGroup
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

TOPIC = "kairos.market.closed_bar.v1"
SYMBOLS = ("BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT")
MINUTE = 60_000
MAX_BARS = 150_000
MAX_PENDING = 100
RECOVERY_PAGE_SIZE = 200
FINALITY_MS = 5_000
MAX_STATUS_BYTES = 32_768
FETCH_ATTEMPTS = 3
FETCH_RETRY_SECONDS = (2, 4)
SOURCE_WAIT_SECONDS = (5, 15, 30, 60)
SOURCE_HEARTBEAT_SECONDS = 5
MAX_UNPUBLISHED_CONFIRMATION_RETRIES = 2  # Three complete rounds including the first.
RUNTIME_REDIS_BLOCK_MS = 1_000
RUNTIME_REDIS_COMMAND_SECONDS = 6.0
RUNTIME_REDIS_RECOVERY_SECONDS = 22.0
RUNTIME_REDIS_ATTEMPTS = 3
RUNTIME_REDIS_BACKOFF_SECONDS = (0.25, 0.5)
ORIGINAL_PREFIX_ROWS = 173_164
ORIGINAL_PREFIX_LAST_OPEN_MS = 1_789_832_580_000
ORIGINAL_PREFIX_TABLE_SHA256 = (
    "f23b4060feae703c568b0204f4b3ff8932fe2813b20f578bc0a0d983e5600499"
)
SOURCE = "kairos-quant-scouts"
SOURCE_DUMP_SHA256 = "2408db1335dc856122750e4604f14a436184f54a7f4ffab22bc35eb69747a7bc"
DB_ROLES = ("kairos_epoch_history", "kairos_epoch_producer", "kairos_epoch_consumer")
# Fresh CONTROLLED_RUNTIME at the pinned Persistence source: its 31 migration
# tables plus schema_migrations. Legacy primary extras must never be admitted.
CONTROLLED_RUNTIME_PUBLIC_TABLES = (
    "account_equity_state",
    "account_snapshots",
    "campaign_source_budgets",
    "event_audit",
    "execution_effect_events",
    "execution_effects",
    "execution_mutation_budget_scopes",
    "execution_mutation_reservations",
    "execution_orders",
    "execution_recovery_state",
    "execution_runtime_health",
    "execution_trade_events",
    "execution_trades",
    "message_inbox",
    "message_outbox",
    "operator_control_admissions",
    "operator_control_commands",
    "operator_control_dispatch_claims",
    "operator_controls",
    "paper_canary_arms",
    "paper_canary_attempts",
    "paper_canary_database_identity",
    "paper_canary_dispatch_claims",
    "paper_canary_sessions",
    "paper_readonly_receipts",
    "paper_readonly_runs",
    "paper_readonly_samples",
    "position_snapshots",
    "public_execution_events",
    "schema_migrations",
    "source_cursors",
    "source_usage_reservations",
)
MODES = (
    "prepare",
    "seed",
    "catchup",
    "verify-restore",
    "boot-state",
    "incident-state",
    "incident-drain",
    "incident-verify-restore",
    "r5-state",
    "r5-verify-restore",
    "r5-drain",
    "r6-state",
    "r6-verify-restore",
    "r6-drain",
    "r7-state",
    "r7-verify-restore",
    "r7-drain",
    "boot-verify-restore",
    "boot-catchup",
    "boot-redis-state",
    "boot-redis-clone",
    "rotate-history",
    "history-state",
    "qualify",
    "serve",
)
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


def safe_unpublished_confirmation(
    observations: list[tuple[str, int, int, object]],
    *,
    symbol: str,
    anchor,
    end_exclusive: int,
    parse_page,
) -> bool:
    """Allow another full confirmation only for mutable, unpublished rows."""
    if len(observations) != 2:
        return False
    first_request, second_request = observations
    if (
        first_request[:3] != second_request[:3]
        or first_request[0] != symbol
        or first_request[1] != anchor.open_time_ms
        or first_request[2]
        != min(end_exclusive, first_request[1] + RECOVERY_PAGE_SIZE * MINUTE)
    ):
        return False
    try:
        first_page = parse_page(
            first_request[3],
            symbol=symbol,
            start=first_request[1],
            end=first_request[2],
        )
        second_page = parse_page(
            second_request[3],
            symbol=symbol,
            start=second_request[1],
            end=second_request[2],
        )
        if len(first_page) < 2 or len(first_page) != len(second_page):
            return False
        if (
            first_page[0].canonical_bar_bytes() != anchor.canonical_bar_bytes()
            or second_page[0].canonical_bar_bytes() != anchor.canonical_bar_bytes()
        ):
            return False
        return tuple(event.canonical_bar_bytes() for event in first_page[1:]) != tuple(
            event.canonical_bar_bytes() for event in second_page[1:]
        )
    except Exception:  # noqa: BLE001 - malformed evidence can never authorize a retry.
        return False


def validate_config(value: dict, mode: str) -> None:
    if mode in {"r7-state", "r7-verify-restore", "r7-drain"}:
        if __package__:
            from scripts.runtime_epoch_r7_read_profile import (
                validate_config as validate_r7,
            )
        else:
            from runtime_epoch_r7_read_profile import validate_config as validate_r7
        validate_r7(mode, value)
        return
    if mode in {"r6-state", "r6-verify-restore", "r6-drain"}:
        if __package__:
            from scripts.runtime_epoch_feed_recovery_worker import (
                validate_config as validate_r6,
            )
        else:
            from runtime_epoch_feed_recovery_worker import (
                validate_config as validate_r6,
            )
        validate_r6(mode, value)
        return
    if mode in {"r5-state", "r5-verify-restore", "r5-drain"}:
        if __package__:
            from scripts.runtime_epoch_read_recovery_worker import (
                validate_config as validate_r5,
            )
        else:
            from runtime_epoch_read_recovery_worker import (
                validate_config as validate_r5,
            )
        validate_r5(mode, value)
        return
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
    if mode in {
        "boot-state",
        "boot-verify-restore",
        "boot-catchup",
        "boot-redis-state",
        "boot-redis-clone",
    } and (
        value.get("pg_host") != "kairos-epoch-" + owner[:12] + "-pg"
        or value.get("redis_host")
        != "kairos-epoch-"
        + owner[:12]
        + ("-redisclone" if mode == "boot-redis-clone" else "-redis")
    ):
        raise EpochError("EXACT_OWNED_BOOT_EPOCH_HOSTS_REQUIRED")
    if mode == "history-state" and set(value) != {
        "owner",
        "database",
        "pg_host",
        "redis_host",
        "admin_password",
    }:
        raise EpochError("EXACT_READONLY_HISTORY_STATE_CONFIG_REQUIRED")
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
    if mode == "boot-state" and set(value) != {
        "owner",
        "database",
        "pg_host",
        "redis_host",
        "admin_password",
    }:
        raise EpochError("EXACT_READONLY_BOOT_STATE_CONFIG_REQUIRED")
    if mode == "boot-verify-restore":
        if (
            set(value)
            != {
                "owner",
                "database",
                "pg_host",
                "redis_host",
                "admin_password",
                "restore_host",
                "restore_database",
                "restore_admin_password",
                "expected_seed",
            }
            or (
                value.get("restore_host")
                not in {
                    "kairos-epoch-" + owner[:12] + "-restore",
                    *(
                        {"kairos-epoch-69893dc7b7c6-restore-incident03"}
                        if owner == "69893dc7b7c647f49967387e7efca9fb"
                        else set()
                    ),
                    *(
                        {"kairos-epoch-69893dc7b7c6-restore-transport03"}
                        if owner == "69893dc7b7c647f49967387e7efca9fb"
                        else set()
                    ),
                    *(
                        {"kairos-epoch-69893dc7b7c6-restore-transport04"}
                        if owner == "69893dc7b7c647f49967387e7efca9fb"
                        else set()
                    ),
                    *(
                        {"kairos-epoch-69893dc7b7c6-restore-transport05"}
                        if owner == "69893dc7b7c647f49967387e7efca9fb"
                        else set()
                    ),
                    *(
                        {"kairos-epoch-69893dc7b7c6-restore-transport06"}
                        if owner == "69893dc7b7c647f49967387e7efca9fb"
                        else set()
                    ),
                    *(
                        {"kairos-epoch-69893dc7b7c6-restore-transport07"}
                        | {"kairos-epoch-69893dc7b7c6-restore-transport08"}
                        if owner == "69893dc7b7c647f49967387e7efca9fb"
                        else set()
                    ),
                }
                and not is_reviewed_boot_restore_host(owner, value.get("restore_host"))
            )
            or value.get("restore_database")
            != "kairos_recovery_" + owner[:12] + "_epochrestore"
        ):
            raise EpochError("EXACT_OWNED_BOOT_RESTORE_CONFIG_REQUIRED")
        validate_boot_seed(value["expected_seed"], owner, value["database"])
    if mode == "boot-catchup":
        end = value.get("end_exclusive_ms")
        now = int(time.time() * 1000)
        if (
            type(end) is not int
            or end % MINUTE
            or end > now - FINALITY_MS
            or value.get("maximum_bars") != MAX_BARS
            or set(value)
            != {
                "owner",
                "database",
                "pg_host",
                "redis_host",
                "history_password",
                "end_exclusive_ms",
                "maximum_bars",
                "expected_seed",
            }
        ):
            raise EpochError("EXACT_FIXED_BOOT_CATCHUP_CONFIG_REQUIRED")
        validate_boot_seed(value["expected_seed"], owner, value["database"])
    if mode in {"boot-redis-state", "boot-redis-clone"} and set(value) != {
        "owner",
        "database",
        "pg_host",
        "redis_host",
        "producer_password",
        "consumer_password",
        "redis_producer_password",
        "redis_consumer_password",
    }:
        raise EpochError("EXACT_READONLY_BOOT_REDIS_CONFIG_REQUIRED")
    if mode == "seed" and (
        value.get("source_dump_sha256") != SOURCE_DUMP_SHA256
        or value.get("seed_expectation") != {"accepted_dump_sha256": SOURCE_DUMP_SHA256}
    ):
        raise EpochError("PINNED_SOURCE_DUMP_PROVENANCE_REQUIRED")
    if mode == "rotate-history" and (
        set(value)
        != {
            "owner",
            "database",
            "pg_host",
            "redis_host",
            "admin_password",
            "history_password",
        }
        or value["pg_host"] != "kairos-epoch-" + owner[:12] + "-pg"
        or value["admin_password"] == value["history_password"]
    ):
        raise EpochError("EXACT_NEW_EPOCH_HISTORY_ROTATION_REQUIRED")


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


def is_reviewed_boot_restore_host(owner: object, host: object) -> bool:
    """Fresh clone names for reviewed operations on the one admitted epoch.

    This admits no resource by itself: the operator must still prove absence,
    ownership, mounts and an exact independently restored database snapshot.
    Retained failed clones therefore never need to be removed or overwritten.
    """
    return (
        owner == "69893dc7b7c647f49967387e7efca9fb"
        and isinstance(host, str)
        and re.fullmatch(
            r"kairos-epoch-69893dc7b7c6-restore-reviewed-[0-9a-f]{8}", host
        )
        is not None
    )


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


async def rotate_history(config: dict) -> dict:
    """Replace only the isolated history credential; no data or queue writes.

    The secret is passed only through the privately mounted config and database
    protocol, never a CLI argument, stdout, status, or diagnostic message.
    """
    admin = await connect(config, "kairos")
    try:
        await verify_schema(admin)
        await admin.execute(
            "ALTER ROLE kairos_epoch_history PASSWORD '"
            + config["history_password"]
            + "'"
        )
    finally:
        await admin.close()
    history = await connect(config, "kairos_epoch_history")
    try:
        await verify_schema(history)
        identity = await history.fetchrow(
            "SELECT current_user AS role,current_database() AS database"
        )
        if dict(identity) != {
            "role": "kairos_epoch_history",
            "database": config["database"],
        }:
            raise EpochError("ROTATED_HISTORY_IDENTITY_NOT_VERIFIED")
    finally:
        await history.close()
    return {
        "state": "HISTORY_CREDENTIAL_ROTATED",
        "role": "kairos_epoch_history",
        "credential_rotated": True,
        "queue_mutations": False,
        "trading_started": False,
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


def validate_history_snapshot(
    audit_count: int, actual: dict, expected_seed: dict
) -> None:
    """Bind a restored snapshot to exact seeded/catch-up five-symbol chains."""
    expected = expected_seed.get("anchors") if isinstance(expected_seed, dict) else None
    if not isinstance(expected, dict) or set(expected) != set(SYMBOLS):
        raise EpochError("EXPECTED_FIVE_SYMBOL_HISTORY_REQUIRED")
    if set(actual) != set(SYMBOLS) or type(audit_count) is not int:
        raise EpochError("EXACT_EXPECTED_HISTORY_SNAPSHOT_REQUIRED")
    total = 0
    for symbol in SYMBOLS:
        anchor = expected[symbol]
        if (
            not isinstance(anchor, dict)
            or set(anchor)
            != {
                "count",
                "first_open_time_ms",
                "last_open_time_ms",
                "last_close_time_ms",
            }
            or any(type(value) is not int for value in anchor.values())
            or anchor["count"] <= 0
            or anchor["first_open_time_ms"] < 0
            or anchor["first_open_time_ms"] % MINUTE
            or anchor["last_open_time_ms"] - anchor["first_open_time_ms"]
            != (anchor["count"] - 1) * MINUTE
            or anchor["last_close_time_ms"] != anchor["last_open_time_ms"] + MINUTE - 1
            or actual[symbol] != anchor
        ):
            raise EpochError("EXACT_EXPECTED_HISTORY_SNAPSHOT_REQUIRED")
        total += anchor["count"]
    if audit_count != total:
        raise EpochError("EXTRA_OR_MISSING_EPOCH_AUDIT_HISTORY")


def validate_epoch_table_inventory(tables: list[str]) -> None:
    if tuple(tables) != CONTROLLED_RUNTIME_PUBLIC_TABLES:
        raise EpochError("EXACT_EPOCH_TABLE_INVENTORY_REQUIRED")


BOOT_ALLOWED_NONEMPTY_TABLES = frozenset(
    {
        "schema_migrations",
        "event_audit",
        "message_outbox",
        "message_inbox",
        "paper_canary_database_identity",
    }
)
# Migration 014 provisions one identity row, not canary/trading admission.
# Pin its full digest from the accepted continuation-05 verified restore
# (receipt SHA-256 9e5b66868c4e01d1b047d3603eba6fc9673419e838da34e1bd54d579fa70ec4b).
BOOT_DATABASE_IDENTITY = {
    "count": 1,
    "sha256": "ba22f0bf5a60970ce0553e4c307106244912c7764e0f355a1955be65898e6e38",
}
BOOT_ADVISORY_LOCKS = (
    4907627681104115019,  # history/current-bar writer
    7716101100001,  # outbox dispatcher
    7716101100002,  # epoch supervisor
)


def validate_boot_database_identity(tables: dict) -> None:
    if tables.get("paper_canary_database_identity") != BOOT_DATABASE_IDENTITY:
        raise EpochError("BOOT_MIGRATION_DATABASE_IDENTITY_CONFLICT")


def validate_boot_seed(value: dict, owner: str, database: str) -> None:
    """Require the byte-for-byte boot-state result, not a partial expectation."""
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "state",
            "matched_public_tables",
            "tables",
            "sequences",
            "anchors",
            "original_prefix",
            "queue",
            "trading_started",
        }
        or value.get("state") != "PASS_BOOT_STATE"
        or value.get("matched_public_tables") != len(CONTROLLED_RUNTIME_PUBLIC_TABLES)
        or value.get("trading_started") is not False
        or set(value.get("tables", {})) != set(CONTROLLED_RUNTIME_PUBLIC_TABLES)
        or not isinstance(value.get("sequences"), dict)
        or not isinstance(value.get("queue"), dict)
        or not isinstance(value.get("anchors"), dict)
        or not isinstance(value.get("original_prefix"), dict)
    ):
        raise EpochError("EXACT_BOOT_STATE_EXPECTATION_REQUIRED")
    if any(
        not isinstance(row, dict)
        or type(row.get("count")) is not int
        or row["count"] < 0
        or re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))) is None
        for row in value["tables"].values()
    ):
        raise EpochError("EXACT_BOOT_STATE_EXPECTATION_REQUIRED")
    if any(
        value["tables"][table]["count"] != 0
        for table in CONTROLLED_RUNTIME_PUBLIC_TABLES
        if table not in BOOT_ALLOWED_NONEMPTY_TABLES
    ):
        raise EpochError("BOOT_STATE_NON_AUDIT_TABLE_NOT_EMPTY")
    validate_boot_database_identity(value["tables"])
    if (
        value["original_prefix"]
        != {
            "rows": ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": ORIGINAL_PREFIX_LAST_OPEN_MS,
        }
        or value["queue"].get("outbox_rows") != value["queue"].get("inbox_rows")
        or value["queue"].get("completed_inbox") != value["queue"].get("inbox_rows")
        or value["queue"].get("pending_outbox") != 0
        or value["queue"].get("unresolved_inbox") != 0
        or value["queue"].get("trading_rows") != 0
        or value["queue"].get("outbox_rows")
        != value["tables"]["message_outbox"]["count"]
        or value["queue"].get("inbox_rows") != value["tables"]["message_inbox"]["count"]
        or any(
            type(value["queue"].get(key)) is not int or value["queue"][key] < 0
            for key in (
                "outbox_rows",
                "inbox_rows",
                "completed_inbox",
                "pending_outbox",
                "unresolved_inbox",
                "trading_rows",
            )
        )
    ):
        raise EpochError("EXACT_BOOT_STATE_EXPECTATION_REQUIRED")
    validate_history_snapshot(
        value["tables"]["event_audit"]["count"],
        value["anchors"],
        {"anchors": value["anchors"]},
    )


async def validate_no_epoch_workers(connection) -> None:
    """Prove the writer, dispatcher, and supervisor session locks are all free."""
    acquired = []
    try:
        for key in BOOT_ADVISORY_LOCKS:
            if not await connection.fetchval("SELECT pg_try_advisory_lock($1)", key):
                raise EpochError("EPOCH_WORKER_LOCK_STILL_HELD")
            acquired.append(key)
    finally:
        for key in reversed(acquired):
            await connection.fetchval("SELECT pg_advisory_unlock($1)", key)


async def boot_queue_state(connection, owner: str) -> dict:
    """Validate and summarize the exact already-published, completed bar queues."""
    from kairos_core.contracts import ClosedBarEventV1
    from kairos_persistence.runtime import canonical_payload

    outbox = await connection.fetch(
        """SELECT id,message_id,topic,payload,payload_sha256,producer,published_at,
                  publish_attempts,last_error,lease_owner,lease_until,
                  dead_lettered_at,reconciliation_state
             FROM message_outbox ORDER BY id"""
    )
    inbox = await connection.fetch(
        """SELECT consumer,message_id,topic,status,payload_sha256
             FROM message_inbox ORDER BY consumer,message_id"""
    )
    consumer_name = "kairos-epoch-consumer-" + owner[:12] + ":bars"
    if len(outbox) != len(inbox):
        raise EpochError("BOOT_QUEUE_ORPHAN_OR_UNRESOLVED_ROW")
    inbox_by_id = {}
    for row in inbox:
        if (
            row["consumer"] != consumer_name
            or row["status"] != "COMPLETED"
            or not row["payload_sha256"]
            or not re.fullmatch(r"[0-9a-f]{64}", row["payload_sha256"])
            or row["message_id"] in inbox_by_id
        ):
            raise EpochError("BOOT_QUEUE_INBOX_NOT_EXACTLY_COMPLETED")
        inbox_by_id[row["message_id"]] = row
    for row in outbox:
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        _encoded, digest = canonical_payload(payload)
        event = ClosedBarEventV1.model_validate(payload)
        inbox_row = inbox_by_id.pop(row["message_id"], None)
        if (
            row["topic"] != TOPIC
            or row["producer"] != SOURCE
            or row["published_at"] is None
            or row["publish_attempts"] < 1
            or row["last_error"] is not None
            or row["lease_owner"] is not None
            or row["lease_until"] is not None
            or row["dead_lettered_at"] is not None
            or row["reconciliation_state"] != "NONE"
            or digest != row["payload_sha256"]
            or event.message_id != row["message_id"]
            or event.source != SOURCE
            or event.symbol not in SYMBOLS
            or inbox_row is None
            or inbox_row["topic"] != row["topic"]
            or inbox_row["payload_sha256"] != digest
        ):
            raise EpochError("BOOT_QUEUE_IDENTITY_OR_STATE_CONFLICT")
    if inbox_by_id:
        raise EpochError("BOOT_QUEUE_ORPHAN_OR_UNRESOLVED_ROW")
    if await connection.fetchval(
        """SELECT count(*) FROM message_outbox o WHERE NOT EXISTS
             (SELECT 1 FROM event_audit a WHERE a.message_id=o.message_id
                AND a.topic=o.topic AND a.source=o.producer AND a.payload=o.payload)"""
    ):
        raise EpochError("BOOT_QUEUE_AUDIT_IDENTITY_MISMATCH")
    return {
        "outbox_rows": len(outbox),
        "inbox_rows": len(inbox),
        "completed_inbox": len(inbox),
        "pending_outbox": 0,
        "unresolved_inbox": 0,
        "trading_rows": 0,
    }


def validate_boot_stream_rows(
    stream_rows: list, durable: dict, receipt_ids: set[str]
) -> None:
    """Allow the single exact duplicate delivery written by prior qualification."""
    allowed_payloads = {encoded for _digest, encoded in durable.values()}
    stream_ids = {stream_id for stream_id, _fields in stream_rows}
    if (
        len(stream_rows) != len(durable) + 1
        or len(stream_ids) != len(stream_rows)
        or not receipt_ids.issubset(stream_ids)
        or any(
            set(fields) != {"data"} or fields["data"] not in allowed_payloads
            for _stream_id, fields in stream_rows
        )
    ):
        raise EpochError("BOOT_REDIS_UNOWNED_STREAM_ENTRY")


async def boot_history_snapshot(connection) -> dict:
    """History-role projection used around data-only recovery (no inbox grant)."""
    from controlled_runtime_worker import Budget, _table_digest

    audit = await _table_digest(connection, "event_audit", Budget())
    outbox = await _table_digest(connection, "message_outbox", Budget())
    prefix = await connection.fetchrow(
        """SELECT count(*) n,encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex') digest
             FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') row_sha
                     FROM event_audit t WHERE (payload->>'open_time_ms')::bigint <= $1) r""",
        ORIGINAL_PREFIX_LAST_OPEN_MS,
    )
    history = {}
    for symbol in SYMBOLS:
        row = await connection.fetchrow(
            """SELECT count(*) n,count(DISTINCT (payload->>'open_time_ms')::bigint) u,
                      min((payload->>'open_time_ms')::bigint) lo,
                      max((payload->>'open_time_ms')::bigint) hi
                 FROM event_audit WHERE topic=$1 AND source=$2 AND payload->>'symbol'=$3""",
            TOPIC,
            SOURCE,
            symbol,
        )
        if not row["n"] or row["n"] != row["u"]:
            raise EpochError("BOOT_HISTORY_UNIQUE_CHAIN_REQUIRED")
        history[symbol] = {
            "count": row["n"],
            "first_open_time_ms": row["lo"],
            "last_open_time_ms": row["hi"],
            "last_close_time_ms": row["hi"] + MINUTE - 1,
        }
    validate_history_snapshot(audit["count"], history, {"anchors": history})
    original_prefix = {
        "rows": prefix["n"],
        "audit_table_sha256": prefix["digest"],
        "last_open_time_ms": ORIGINAL_PREFIX_LAST_OPEN_MS,
    }
    if original_prefix != {
        "rows": ORIGINAL_PREFIX_ROWS,
        "audit_table_sha256": ORIGINAL_PREFIX_TABLE_SHA256,
        "last_open_time_ms": ORIGINAL_PREFIX_LAST_OPEN_MS,
    }:
        raise EpochError("BOOT_ORIGINAL_PREFIX_CONFLICT")
    return {
        "audit": audit,
        "outbox": outbox,
        "anchors": history,
        "original_prefix": original_prefix,
    }


async def boot_state_snapshot(connection, owner: str) -> dict:
    """Full read-only state proof for safe restart/restore admission."""
    from controlled_runtime_worker import Budget, _table_digest

    await verify_schema(connection)
    await validate_no_epoch_workers(connection)
    async with connection.transaction(isolation="repeatable_read", readonly=True):
        tables = [
            row["relname"]
            for row in await connection.fetch(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition ORDER BY c.relname"
            )
        ]
        validate_epoch_table_inventory(tables)
        budget = Budget()
        table_digests = {
            table: await _table_digest(connection, table, budget) for table in tables
        }
        if any(
            table_digests[table]["count"] != 0
            for table in tables
            if table not in BOOT_ALLOWED_NONEMPTY_TABLES
        ):
            raise EpochError("BOOT_STATE_NON_AUDIT_TABLE_NOT_EMPTY")
        validate_boot_database_identity(table_digests)
        queue = await boot_queue_state(connection, owner)
        history = await boot_history_snapshot(connection)
        if table_digests["event_audit"] != history["audit"]:
            raise EpochError("BOOT_AUDIT_SNAPSHOT_CONFLICT")
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
        result = {
            "state": "PASS_BOOT_STATE",
            "matched_public_tables": len(tables),
            "tables": table_digests,
            "sequences": sequences,
            "anchors": history["anchors"],
            "original_prefix": history["original_prefix"],
            "queue": queue,
            "trading_started": False,
        }
        validate_boot_seed(result, owner, "kairos_epoch_" + owner[:12])
        return result


async def validate_boot_audit_prefix(connection, expected: dict) -> None:
    """Prove every pre-reboot audit row, not only the original seed, survived."""
    row = await connection.fetchrow(
        """SELECT count(*) n,
                  encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex') digest
             FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') row_sha
                     FROM event_audit t
                     JOIN unnest($3::text[],$4::bigint[]) AS cutoffs(symbol,last_open)
                       ON t.payload->>'symbol'=cutoffs.symbol
                    WHERE t.topic=$1 AND t.source=$2
                      AND (t.payload->>'open_time_ms')::bigint<=cutoffs.last_open) r""",
        TOPIC,
        SOURCE,
        list(SYMBOLS),
        [expected["anchors"][s]["last_open_time_ms"] for s in SYMBOLS],
    )
    if {"count": row["n"], "sha256": row["digest"]} != expected["tables"][
        "event_audit"
    ]:
        raise EpochError("BOOT_PREEXISTING_AUDIT_PREFIX_CONFLICT")


def validate_expected_audit_digest(expected_seed: dict, audit: dict) -> None:
    if "audit_table_sha256" in expected_seed and (
        re.fullmatch(r"[0-9a-f]{64}", str(expected_seed["audit_table_sha256"])) is None
        or audit.get("sha256") != expected_seed["audit_table_sha256"]
    ):
        raise EpochError("EXPECTED_FULL_AUDIT_DIGEST_CONFLICT")


def validate_history_state(value: dict) -> None:
    prefix = value.get("original_prefix")
    if (
        value.get("matched_public_tables") != len(CONTROLLED_RUNTIME_PUBLIC_TABLES)
        or prefix
        != {
            "rows": ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": ORIGINAL_PREFIX_LAST_OPEN_MS,
        }
        or type(value.get("rows")) is not int
        or not ORIGINAL_PREFIX_ROWS <= value["rows"] <= 1_000_000
        or re.fullmatch(r"[0-9a-f]{64}", str(value.get("audit_table_sha256", "")))
        is None
        or any(
            type(value.get(k)) is not int or value[k] != 0
            for k in ("outbox_rows", "inbox_rows", "orders_rows", "effects_rows")
        )
        or value.get("trading_started") is not False
    ):
        raise EpochError("VERIFIED_AUDIT_ONLY_HISTORY_STATE_REQUIRED")
    history = value.get("anchors")
    validate_history_snapshot(
        value["rows"], history, {"rows": value["rows"], "anchors": history}
    )
    for symbol, anchor in history.items():
        first = 1_787_754_720_000 if symbol == "XRPUSDT" else 1_787_754_660_000
        if (
            anchor["first_open_time_ms"] != first
            or anchor["last_open_time_ms"] < ORIGINAL_PREFIX_LAST_OPEN_MS
        ):
            raise EpochError("ORIGINAL_HISTORY_PREFIX_BOUNDARY_REQUIRED")


async def history_state(config: dict) -> dict:
    """Read only the owned epoch and prove the immutable original row prefix."""
    from controlled_runtime_worker import Budget, _table_digest

    connection = await connect(config, "kairos")
    try:
        async with connection.transaction(isolation="repeatable_read", readonly=True):
            await verify_schema(connection)
            tables = [
                r["relname"]
                for r in await connection.fetch(
                    "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition ORDER BY c.relname"
                )
            ]
            validate_epoch_table_inventory(tables)
            audit = await _table_digest(connection, "event_audit", Budget())
            prefix = await connection.fetchrow(
                """SELECT count(*) n,encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex') digest FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') row_sha FROM event_audit t WHERE (payload->>'open_time_ms')::bigint <= $1) r""",
                ORIGINAL_PREFIX_LAST_OPEN_MS,
            )
            history = {}
            for symbol in SYMBOLS:
                row = await connection.fetchrow(
                    """SELECT count(*) n,count(DISTINCT (payload->>'open_time_ms')::bigint) u,min((payload->>'open_time_ms')::bigint) lo,max((payload->>'open_time_ms')::bigint) hi FROM event_audit WHERE topic=$1 AND source=$2 AND payload->>'symbol'=$3""",
                    TOPIC,
                    SOURCE,
                    symbol,
                )
                if not row["n"] or row["n"] != row["u"]:
                    raise EpochError("HISTORY_STATE_UNIQUE_CHAIN_REQUIRED")
                history[symbol] = {
                    "count": row["n"],
                    "first_open_time_ms": row["lo"],
                    "last_open_time_ms": row["hi"],
                    "last_close_time_ms": row["hi"] + MINUTE - 1,
                }
            result = {
                "state": "VERIFIED_AUDIT_ONLY_HISTORY_STATE",
                "rows": audit["count"],
                "audit_table_sha256": audit["sha256"],
                "anchors": history,
                "matched_public_tables": len(tables),
                "original_prefix": {
                    "rows": prefix["n"],
                    "audit_table_sha256": prefix["digest"],
                    "last_open_time_ms": ORIGINAL_PREFIX_LAST_OPEN_MS,
                },
                "trading_started": False,
            }
            for key, table in (
                ("outbox_rows", "message_outbox"),
                ("inbox_rows", "message_inbox"),
                ("orders_rows", "execution_orders"),
                ("effects_rows", "execution_effects"),
            ):
                result[key] = await connection.fetchval(
                    f'SELECT count(*) FROM public."{table}"'
                )
            validate_history_state(result)
            return result
    finally:
        await connection.close()


async def boot_state(config: dict) -> dict:
    connection = await connect(config, "kairos")
    try:
        return await boot_state_snapshot(connection, config["owner"])
    finally:
        await connection.close()


async def boot_verify_restore(config: dict) -> dict:
    import asyncpg

    original = await connect(config, "kairos")
    restored = await asyncpg.connect(
        f"postgresql://kairos:{config['restore_admin_password']}@{config['restore_host']}:5432/{config['restore_database']}",
        timeout=15,
        command_timeout=120,
    )
    try:
        first, second = await asyncio.gather(
            boot_state_snapshot(original, config["owner"]),
            boot_state_snapshot(restored, config["owner"]),
        )
        if first != config["expected_seed"] or second != first:
            raise EpochError("EPOCH_BOOT_RESTORE_FULL_STATE_CONFLICT")
        return {
            "state": "PASS_BOOT_ISOLATED_RESTORE",
            "matched_public_tables": len(CONTROLLED_RUNTIME_PUBLIC_TABLES),
            "tables": first["tables"],
            "sequences": first["sequences"],
            "anchors": first["anchors"],
            "original_prefix": first["original_prefix"],
            "queue": first["queue"],
            "trading_started": False,
        }
    finally:
        await original.close()
        await restored.close()


async def verify_redis_default_disabled(config: dict, *, clone: bool = False) -> dict:
    """Refuse anonymous/default authentication; never write to an admitted epoch."""
    import redis.asyncio as aioredis
    from redis.exceptions import AuthenticationError

    client = aioredis.Redis(
        host=config["redis_host"],
        decode_responses=True,
        socket_timeout=15,
    )
    try:
        probes = [("PING",), ("AUTH", "default", "")]
        if clone:
            # Only the disposable clone receives this denial probe. Even a
            # successful probe fails qualification and never reaches serving.
            probes.append(("XADD", TOPIC, "*", "data", "qualification-denied"))
        for probe in probes:
            try:
                await client.execute_command(*probe)
            except AuthenticationError:
                continue
            raise EpochError("BOOT_REDIS_DEFAULT_OR_ANONYMOUS_ACCESS_ALLOWED")
        return {
            "anonymous_ping_refused": True,
            "default_auth_refused": True,
            "anonymous_write_refused_on_clone": clone,
        }
    finally:
        await client.aclose()


async def boot_redis_state(config: dict, *, clone: bool = False) -> dict:
    """Read-only Redis/data-plane proof before any new serving process starts."""
    import redis.asyncio as aioredis
    from kairos_core.contracts import ClosedBarEventV1
    from kairos_persistence.runtime import canonical_payload

    producer_sql = await connect(config, "kairos_epoch_producer")
    consumer_sql = await connect(config, "kairos_epoch_consumer")
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
    try:
        auth_proofs = await verify_redis_default_disabled(config, clone=clone)
        if await producer.ping() is not True or await consumer.ping() is not True:
            raise EpochError("BOOT_REDIS_SEPARATE_ROLE_AUTH_REQUIRED")
        await verify_schema(producer_sql)
        await verify_schema(consumer_sql)
        outbox = await producer_sql.fetch(
            """SELECT message_id,topic,payload,payload_sha256,producer,published_at,
                      publish_attempts,last_error,lease_owner,lease_until,
                      dead_lettered_at,reconciliation_state
                 FROM message_outbox ORDER BY id"""
        )
        inbox = await consumer_sql.fetch(
            "SELECT consumer,message_id,topic,status,payload_sha256 FROM message_inbox ORDER BY consumer,message_id"
        )
        durable = {}
        for row in outbox:
            payload = row["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            encoded, digest = canonical_payload(payload)
            event = ClosedBarEventV1.model_validate(payload)
            if (
                row["topic"] != TOPIC
                or row["producer"] != SOURCE
                or row["published_at"] is None
                or row["publish_attempts"] < 1
                or row["last_error"] is not None
                or row["lease_owner"] is not None
                or row["lease_until"] is not None
                or row["dead_lettered_at"] is not None
                or row["reconciliation_state"] != "NONE"
                or digest != row["payload_sha256"]
                or event.message_id != row["message_id"]
                or event.source != SOURCE
                or event.symbol not in SYMBOLS
            ):
                raise EpochError("BOOT_QUEUE_IDENTITY_OR_STATE_CONFLICT")
            durable[row["message_id"]] = (digest, encoded)
        consumer_name = "kairos-epoch-consumer-" + config["owner"][:12] + ":bars"
        if len(inbox) != len(durable):
            raise EpochError("BOOT_QUEUE_ORPHAN_OR_UNRESOLVED_ROW")
        inbox_by_id = {}
        for row in inbox:
            if (
                row["consumer"] != consumer_name
                or row["topic"] != TOPIC
                or row["status"] != "COMPLETED"
                or row["message_id"] not in durable
                or row["payload_sha256"] != durable[row["message_id"]][0]
                or row["message_id"] in inbox_by_id
            ):
                raise EpochError("BOOT_QUEUE_INBOX_NOT_EXACTLY_COMPLETED")
            inbox_by_id[row["message_id"]] = True
        ledger = "kairos.runtime." + config["owner"] + ".publication"
        expected_stream_ids = set()
        for message_id, (digest, encoded) in durable.items():
            receipt = await producer.hget(ledger, message_id)
            if not receipt:
                raise EpochError("BOOT_REDIS_PUBLICATION_RECEIPT_MISSING")
            value = json.loads(receipt)
            if (
                not isinstance(value, list)
                or len(value) != 2
                or value[0] != digest
                or not re.fullmatch(r"[0-9]+-[0-9]+", str(value[1]))
            ):
                raise EpochError("BOOT_REDIS_PUBLICATION_RECEIPT_CONFLICT")
            receipt_rows = await producer.xrange(TOPIC, min=value[1], max=value[1])
            if len(receipt_rows) != 1 or receipt_rows[0][1] != {"data": encoded}:
                raise EpochError("BOOT_REDIS_STREAM_RECEIPT_CONFLICT")
            expected_stream_ids.add(value[1])
        stream_rows = await producer.xrange(TOPIC, min="-", max="+")
        validate_boot_stream_rows(stream_rows, durable, expected_stream_ids)
        groups = await producer.xinfo_groups(TOPIC)
        bars_group = next(
            (group for group in groups if group.get("name") == "bars"), None
        )
        pending = await consumer.xpending(TOPIC, "bars") if bars_group else None
        if (
            len(groups) != 1
            or bars_group is None
            or not pending
            or pending.get("pending") != 0
            or bars_group.get("last-delivered-id") != stream_rows[-1][0]
            or not expected_stream_ids.issubset(
                {stream_id for stream_id, _ in stream_rows}
            )
        ):
            raise EpochError("BOOT_REDIS_CONSUMER_GROUP_NOT_CAUGHT_UP")
        return {
            "state": "PASS_BOOT_REDIS_STATE",
            "outbox_rows": len(outbox),
            "completed_inbox": len(inbox),
            "stream_entries": len(stream_rows),
            "publication_receipts": len(expected_stream_ids),
            "publication_message_ids_sha256": hashlib.sha256(
                json.dumps(sorted(durable), separators=(",", ":")).encode()
            ).hexdigest(),
            "consumer_groups": 1,
            "pending_deliveries": 0,
            "auth_proofs": auth_proofs,
            "trading_started": False,
        }
    finally:
        await producer.aclose()
        await consumer.aclose()
        await producer_sql.close()
        await consumer_sql.close()


async def boot_catchup(config: dict, output: Path) -> dict:
    result = await recover(
        config,
        publish=False,
        status_path=output / "progress.json",
        boot_expected=config["expected_seed"],
    )
    if result.get("state") != "AUDIT_ONLY_CATCHUP_COMPLETE":
        raise EpochError("BOOT_AUDIT_ONLY_CATCHUP_REQUIRED")
    return result


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
            validate_epoch_table_inventory(tables)
            budget = Budget()
            for table in tables:
                result[table] = await _table_digest(connection, table, budget)
            validate_expected_audit_digest(
                config["expected_seed"], result["event_audit"]
            )
            for table in (
                "message_outbox",
                "message_inbox",
                "execution_orders",
                "execution_effects",
            ):
                if result[table]["count"] != 0:
                    raise EpochError("AUDIT_ONLY_BACKUP_REQUIRED")
            history = {}
            for symbol in SYMBOLS:
                chain = await connection.fetchrow(
                    """SELECT count(*) n,count(DISTINCT (payload->>'open_time_ms')::bigint) u,min((payload->>'open_time_ms')::bigint) lo,max((payload->>'open_time_ms')::bigint) hi FROM event_audit WHERE topic=$1 AND source=$2 AND payload->>'symbol'=$3""",
                    TOPIC,
                    SOURCE,
                    symbol,
                )
                if not chain["n"] or chain["n"] != chain["u"]:
                    raise EpochError("RESTORED_HISTORY_UNIQUE_CHAIN_REQUIRED")
                history[symbol] = {
                    "count": chain["n"],
                    "first_open_time_ms": chain["lo"],
                    "last_open_time_ms": chain["hi"],
                    "last_close_time_ms": chain["hi"] + MINUTE - 1,
                }
            validate_history_snapshot(
                result["event_audit"]["count"], history, config.get("expected_seed")
            )
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
        return {"tables": result, "sequences": sequences, "anchors": history}

    try:
        first, second = await asyncio.gather(snapshot(original), snapshot(restored))
        if first != second:
            raise EpochError("EPOCH_RESTORE_FULL_HISTORY_CONFLICT")
        return {
            "state": "PASS_ISOLATED_EPOCH_RESTORE",
            "matched_public_tables": len(CONTROLLED_RUNTIME_PUBLIC_TABLES),
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


def bounded_runtime_end(values: dict, target: int) -> int:
    """Catch up an outage in <=100-bar batches, never relabel a lag as fresh."""
    if set(values) != set(SYMBOLS) or type(target) is not int or target % MINUTE:
        raise EpochError("FIXED_CATCHUP_INTERVAL_REQUIRED")
    latest = max(e.close_time_ms + 1 for e in values.values())
    if latest > target:
        raise EpochError("FINALITY_CLOCK_REGRESSION")
    baseline = required_bars(values, latest)
    if baseline > MAX_PENDING:
        raise EpochError("RUNTIME_WATERMARK_SKEW_EXCEEDS_PENDING_CAP")
    capacity_minutes = (MAX_PENDING - baseline) // len(SYMBOLS)
    end = min(target, latest + capacity_minutes * MINUTE)
    if required_bars(values, end) > MAX_PENDING:
        raise EpochError("EPOCH_INTERVAL_EXCEEDS_FIXED_CAP")
    return end


def source_wait_reason(error: BaseException) -> str | None:
    """Only admitted public-GET transport failures can defer.

    Mixed exception groups stay fatal rather than degrading to one source error.
    """
    if isinstance(error, ExceptionGroup):
        reasons = [source_wait_reason(child) for child in error.exceptions]
        if (
            reasons
            and reasons[0] is not None
            and all(reason == reasons[0] for reason in reasons)
        ):
            return reasons[0]
        return None
    if (
        isinstance(error, EpochError)
        and str(error) == "OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT"
    ):
        return "OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT"
    if (
        isinstance(error, EpochError)
        and str(error) == "OFFICIAL_CLOSED_BAR_FETCH_DNS_FAILURE"
    ):
        return "OFFICIAL_CLOSED_BAR_FETCH_DNS_FAILURE"
    return None


class SourceCircuit:
    """Finite per-round retry budget and capped, cancellable outage backoff."""

    def __init__(self):
        self.timeouts = 0
        self.dns_failures = 0
        self.recoveries = 0
        self.consecutive = 0
        self.consecutive_timeouts = 0
        self.consecutive_dns_failures = 0

    def failed(self, error: BaseException) -> str:
        reason = source_wait_reason(error)
        if reason is None:
            raise error
        self.consecutive += 1
        if reason == "OFFICIAL_CLOSED_BAR_FETCH_DNS_FAILURE":
            self.dns_failures += 1
            self.consecutive_dns_failures += 1
            self.consecutive_timeouts = 0
        else:
            self.timeouts += 1
            self.consecutive_timeouts += 1
            self.consecutive_dns_failures = 0
        return reason

    def succeeded(self) -> None:
        if self.consecutive:
            self.recoveries += 1
        self.consecutive = 0
        self.consecutive_timeouts = 0
        self.consecutive_dns_failures = 0

    def snapshot(self) -> dict:
        result = {
            "timeout_rounds": self.timeouts,
            "recoveries": self.recoveries,
            "consecutive_timeout_rounds": self.consecutive_timeouts,
        }
        if self.dns_failures:
            result["dns_failure_rounds"] = self.dns_failures
            result["consecutive_dns_failure_rounds"] = self.consecutive_dns_failures
        return result

    async def wait(self, requested, consumer, heartbeat) -> None:
        delay = SOURCE_WAIT_SECONDS[
            min(max(self.consecutive - 1, 0), len(SOURCE_WAIT_SECONDS) - 1)
        ]
        deadline = time.monotonic() + delay
        while time.monotonic() < deadline and not requested.is_set():
            if consumer.done():
                await consumer
                raise EpochError("CONSUMER_STOPPED")
            heartbeat()
            try:
                await asyncio.wait_for(
                    requested.wait(),
                    timeout=min(
                        SOURCE_HEARTBEAT_SECONDS,
                        max(0.001, deadline - time.monotonic()),
                    ),
                )
            except TimeoutError:
                pass


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


async def fetch_closed_bar_page(session, symbol: str, start: int, finish: int):
    """Retry only bounded timeout/DNS failures at the public GET boundary."""
    for attempt in range(FETCH_ATTEMPTS):
        try:
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
        except TimeoutError:
            if attempt + 1 == FETCH_ATTEMPTS:
                raise EpochError("OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT") from None
            await asyncio.sleep(FETCH_RETRY_SECONDS[attempt])
        except Exception as error:
            try:
                from aiohttp.client_exceptions import ClientConnectorDNSError
            except ImportError:
                ClientConnectorDNSError = None
            if ClientConnectorDNSError is None or not isinstance(
                error, ClientConnectorDNSError
            ):
                raise
            if attempt + 1 == FETCH_ATTEMPTS:
                raise EpochError("OFFICIAL_CLOSED_BAR_FETCH_DNS_FAILURE") from None
            await asyncio.sleep(FETCH_RETRY_SECONDS[attempt])
    raise EpochError("OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT")


async def recover(
    config: dict,
    *,
    publish: bool,
    status_path: Path,
    boot_expected: dict | None = None,
    failure_suffix: str = "",
) -> dict:
    import aiohttp
    import asyncpg

    recovery = importlib.import_module("kairos_quant.long_gap_recovery")
    RecoveryStatus = recovery.RecoveryStatus
    recover_symbol = recovery.recover_symbol

    role = "kairos_epoch_producer" if publish else "kairos_epoch_history"
    pool = await asyncpg.create_pool(
        dsn(config, role), min_size=1, max_size=6, command_timeout=30
    )
    end = config["end_exclusive_ms"]
    totals = {}
    progress_by_symbol = {}
    deferred_confirmation_rounds = {}
    try:
        async with pool.acquire() as connection:
            await verify_schema(connection)
            lock = await connection.fetchval(
                "SELECT pg_try_advisory_lock(4907627681104115019)"
            )
            if not lock:
                raise EpochError("EPOCH_WRITER_ALREADY_RUNNING")
            boot_before = None
            if boot_expected is not None:
                boot_before = await boot_history_snapshot(connection)
                if (
                    boot_before["audit"] != boot_expected["tables"]["event_audit"]
                    or boot_before["outbox"]
                    != boot_expected["tables"]["message_outbox"]
                    or boot_before["anchors"] != boot_expected["anchors"]
                    or boot_before["original_prefix"]
                    != boot_expected["original_prefix"]
                ):
                    raise EpochError("BOOT_CATCHUP_PRESTATE_CONFLICT")
            values = await anchors(pool)
            required = required_bars(values, end)
            if required > (MAX_PENDING if publish else MAX_BARS):
                raise EpochError("EPOCH_INTERVAL_EXCEEDS_FIXED_CAP")
            writer = EpochWriter(pool)
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:

                async def fetch(symbol, start, finish):
                    return await fetch_closed_bar_page(session, symbol, start, finish)

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

                    async def recover_with_confirmation_retries():
                        deferred = 0
                        while True:
                            observations = []

                            async def observed_fetch(
                                requested_symbol,
                                start,
                                finish,
                                _observations=observations,
                            ):
                                raw = await fetch(requested_symbol, start, finish)
                                _observations.append(
                                    (requested_symbol, start, finish, raw)
                                )
                                if len(_observations) > 2:
                                    del _observations[0]
                                return raw

                            try:
                                return await recover_symbol(
                                    values[symbol],
                                    end_exclusive=end,
                                    fetch=observed_fetch,
                                    publish=append,
                                    page_size=RECOVERY_PAGE_SIZE,
                                    pause=pause,
                                    progress=lambda _item: None,
                                    status=state,
                                )
                            except BaseException as exc:
                                if isinstance(exc, asyncio.CancelledError):
                                    raise
                                if (
                                    deferred >= MAX_UNPUBLISHED_CONFIRMATION_RETRIES
                                    or getattr(state, "phase", None)
                                    != "CONFIRMATION_COMPARE"
                                    or getattr(state, "total_appended_bars", None) != 0
                                    or not isinstance(
                                        exc,
                                        getattr(recovery, "RecoveryError", ()),
                                    )
                                    or not safe_unpublished_confirmation(
                                        observations,
                                        symbol=symbol,
                                        anchor=values[symbol],
                                        end_exclusive=end,
                                        parse_page=recovery.parse_page,
                                    )
                                ):
                                    raise
                                deferred += 1
                                deferred_confirmation_rounds[symbol] = deferred
                                progress_by_symbol[symbol] = {
                                    "deferred_confirmation_rounds": deferred,
                                }
                                write_status(
                                    status_path,
                                    {
                                        "state": "CATCHUP_PROGRESS",
                                        "owner": config["owner"],
                                        "symbols": dict(progress_by_symbol),
                                        "deadline_ms": end,
                                        "observed_at_utc": datetime.now(
                                            UTC
                                        ).isoformat(),
                                    },
                                )

                    try:
                        count = await recover_with_confirmation_retries()
                    except asyncio.CancelledError as exc:
                        write_status(
                            status_path.parent
                            / ("failure-" + symbol + failure_suffix + ".json"),
                            {
                                "state": "FAILED_CLOSED",
                                "symbol": symbol,
                                "phase": getattr(state, "phase", "UNOBSERVED"),
                                "error_type": type(exc).__name__,
                                "appended_bars": getattr(
                                    state, "total_appended_bars", None
                                ),
                                "deferred_confirmation_rounds": deferred_confirmation_rounds.get(
                                    symbol, 0
                                ),
                                "publish_outcome_unknown": getattr(state, "phase", None)
                                == "DURABLE_PUBLISH",
                                "trading_started": False,
                            },
                            immutable=True,
                        )
                        raise
                    except Exception as exc:
                        write_status(
                            status_path.parent
                            / ("failure-" + symbol + failure_suffix + ".json"),
                            {
                                "state": "FAILED_CLOSED",
                                "symbol": symbol,
                                "phase": getattr(state, "phase", "UNOBSERVED"),
                                "error_type": type(exc).__name__,
                                "appended_bars": getattr(
                                    state, "total_appended_bars", None
                                ),
                                "deferred_confirmation_rounds": deferred_confirmation_rounds.get(
                                    symbol, 0
                                ),
                                "publish_outcome_unknown": getattr(state, "phase", None)
                                == "DURABLE_PUBLISH",
                                "trading_started": False,
                            },
                            immutable=True,
                        )
                        raise
                    totals[symbol] = count
                    progress_by_symbol[symbol] = {
                        "appended_bars": count,
                        "deferred_confirmation_rounds": deferred_confirmation_rounds.get(
                            symbol, 0
                        ),
                    }
                    write_status(
                        status_path,
                        {
                            "state": "CATCHUP_PROGRESS",
                            "owner": config["owner"],
                            "completed_symbols": dict(totals),
                            "deferred_confirmation_rounds": dict(
                                deferred_confirmation_rounds
                            ),
                            "deadline_ms": end,
                            "observed_at_utc": datetime.now(UTC).isoformat(),
                        },
                    )

                try:
                    async with asyncio.TaskGroup() as group:
                        for symbol in SYMBOLS:
                            group.create_task(one(symbol))
                except ExceptionGroup as errors:
                    # TaskGroup cancels and awaits siblings before returning. Keep
                    # the original operational exception as the top-level reason;
                    # per-symbol immutable failure receipts retain sibling outcomes.
                    # Never let the first timeout hide a sibling integrity/DB
                    # failure when the serving circuit decides whether to wait.
                    original = errors
                    leaves = []
                    pending_errors = [errors]
                    while pending_errors:
                        item = pending_errors.pop()
                        if isinstance(item, ExceptionGroup):
                            pending_errors.extend(item.exceptions)
                        else:
                            leaves.append(item)
                    leaf_reasons = [source_wait_reason(error) for error in leaves]
                    admitted_reasons = {
                        reason for reason in leaf_reasons if reason is not None
                    }
                    if admitted_reasons and (
                        any(reason is None for reason in leaf_reasons)
                        or len(admitted_reasons) != 1
                    ):
                        raise
                    while isinstance(original, ExceptionGroup):
                        original = original.exceptions[0]
                    raise original
            if sum(totals.values()) != required:
                raise EpochError("EXACT_APPEND_COUNT_REQUIRED")
            if (
                not publish
                and boot_expected is None
                and await connection.fetchval("SELECT count(*) FROM message_outbox")
            ):
                raise EpochError("HISTORY_CREATED_OUTBOX_REJECTED")
            if boot_expected is not None:
                boot_after = await boot_history_snapshot(connection)
                await validate_boot_audit_prefix(connection, boot_expected)
                expected_counts = {
                    symbol: boot_before["anchors"][symbol]["count"] + totals[symbol]
                    for symbol in SYMBOLS
                }
                if (
                    boot_after["outbox"] != boot_before["outbox"]
                    or boot_after["original_prefix"] != boot_before["original_prefix"]
                    or boot_after["audit"]["count"]
                    != boot_before["audit"]["count"] + sum(totals.values())
                    or any(
                        boot_after["anchors"][symbol]["count"]
                        != expected_counts[symbol]
                        or boot_after["anchors"][symbol]["first_open_time_ms"]
                        != boot_before["anchors"][symbol]["first_open_time_ms"]
                        or boot_after["anchors"][symbol]["last_open_time_ms"]
                        != end - MINUTE
                        for symbol in SYMBOLS
                    )
                ):
                    raise EpochError("BOOT_CATCHUP_POSTSTATE_CONFLICT")
            await connection.execute("SELECT pg_advisory_unlock(4907627681104115019)")
        return {
            "state": "CURRENT_BARS_APPENDED"
            if publish
            else "AUDIT_ONLY_CATCHUP_COMPLETE",
            "appended": totals,
            "deferred_confirmation_rounds": dict(deferred_confirmation_rounds),
            "through_exclusive_ms": end,
            "maximum_bars": MAX_PENDING if publish else MAX_BARS,
            **(
                {
                    "pre_catchup_audit_rows": boot_before["audit"]["count"],
                    "post_catchup_audit_rows": boot_after["audit"]["count"],
                    "outbox_preserved": True,
                    "original_prefix_preserved": True,
                    "pre_catchup_prefix_preserved": True,
                }
                if boot_expected is not None
                else {}
            ),
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


def redis_transport_failure(error: BaseException) -> bool:
    """Only connectivity failures are recoverable; auth/protocol errors are not."""
    from redis.exceptions import AuthenticationError, ConnectionError
    from redis.exceptions import TimeoutError as RedisTimeoutError

    return not isinstance(error, AuthenticationError) and isinstance(
        error, (ConnectionError, RedisTimeoutError, TimeoutError)
    )


async def redis_retry_pause(stop: asyncio.Event, seconds: float) -> None:
    if stop.is_set():
        raise asyncio.CancelledError
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return
    raise asyncio.CancelledError


async def runtime_redis_call(operation, stop: asyncio.Event, telemetry: dict):
    """Bounded replay for idempotent operations only (never a new stream read)."""
    for attempt in range(RUNTIME_REDIS_ATTEMPTS):
        if stop.is_set():
            raise asyncio.CancelledError
        try:
            async with asyncio.timeout(RUNTIME_REDIS_COMMAND_SECONDS):
                result = await operation()
            if attempt:
                telemetry["recoveries"] += 1
            return result
        except Exception as error:
            if not redis_transport_failure(error):
                raise
            telemetry["transport_failures"] += 1
            if attempt == RUNTIME_REDIS_ATTEMPTS - 1:
                raise EpochError("REDIS_TRANSPORT_RETRY_EXHAUSTED") from error
            await redis_retry_pause(stop, RUNTIME_REDIS_BACKOFF_SECONDS[attempt])
    raise AssertionError("unreachable bounded Redis retry")


def create_runtime_transport(url: str, stop: asyncio.Event, telemetry: dict):
    """Epoch-only recovery: keep identity, drain own PEL before another `>`.

    Frozen Core and other runtimes are unchanged. A timed-out XREADGROUP may
    already have assigned entries to this consumer. Hidden redis-py retries
    are disabled; replay goes through the durable inbox, not a cursor reset.
    """
    from kairos_core.bus.base import BusEnvelope
    from kairos_core.bus.redis_streams import RedisStreamsBus
    from redis import asyncio as aioredis
    from redis.asyncio.retry import Retry
    from redis.backoff import NoBackoff

    for key in ("transport_failures", "recoveries", "pending_replays"):
        telemetry.setdefault(key, 0)

    class EpochRedisTransport(RedisStreamsBus):
        def __init__(self):
            # Do not create the Core default client (with implicit retries).
            self._redis = aioredis.from_url(
                url,
                decode_responses=True,
                socket_connect_timeout=3.0,
                socket_timeout=RUNTIME_REDIS_COMMAND_SECONDS,
                retry=Retry(NoBackoff(), 0),
                retry_on_error=[],
            )
            self._maxlen = 10_000
            self._groups_ready = set()
            self._reclaim_cursors = {}
            import socket

            self._instance_id = f"{socket.gethostname()}-{os.getpid()}"

        async def subscribe(
            self,
            topic,
            *,
            group=None,
            consumer=None,
            block_ms=RUNTIME_REDIS_BLOCK_MS,
            reclaim_idle_ms=180_000,
            reclaim_every_s=30.0,
        ):
            if (
                topic != TOPIC
                or group not in {None, "bars"}
                or block_ms != RUNTIME_REDIS_BLOCK_MS
            ):
                raise EpochError("FIXED_NONTRADING_REDIS_SUBSCRIPTION_REQUIRED")
            group = group or "bars"
            consumer = f"{consumer or 'consumer'}-{self._instance_id}"
            await runtime_redis_call(
                lambda: self._ensure_group(topic, group), stop, telemetry
            )
            last_reclaim = 0.0
            replay_pending = False
            failures = 0
            recovery_deadline = None
            recovery_pending = False
            while not stop.is_set():
                try:
                    remaining = RUNTIME_REDIS_COMMAND_SECONDS
                    if recovery_deadline is not None:
                        remaining = min(remaining, recovery_deadline - time.monotonic())
                        if remaining <= 0:
                            raise EpochError("REDIS_RECOVERY_DEADLINE_EXCEEDED")
                    async with asyncio.timeout(remaining):
                        if replay_pending:
                            response = await self._redis.xreadgroup(
                                group, consumer, {topic: "0"}, count=16
                            )
                            # A successful PEL read ends the Redis-I/O outage,
                            # but drain completion still waits for an empty PEL
                            # and a successful new-message read below.
                            failures, recovery_deadline = 0, None
                            recovery_pending = True
                            replay_rows = [
                                row for _stream, rows in response or [] for row in rows
                            ]
                        else:
                            replay_rows = []
                            now = time.monotonic()
                            if now - last_reclaim >= reclaim_every_s:
                                reclaimed = await self._reclaim_stale(
                                    topic, group, consumer, min_idle_ms=reclaim_idle_ms
                                )
                                last_reclaim = now
                            else:
                                reclaimed = []
                            # Preserve stale-owner claim semantics from frozen Core.
                            response = None
                    if replay_pending:
                        if not replay_rows:
                            replay_pending = False
                            continue
                        for message_id, fields in replay_rows:
                            if not fields or set(fields) != {"data"}:
                                raise EpochError("RUNTIME_PENDING_PAYLOAD_MISSING")
                            telemetry["pending_replays"] += 1
                            yield BusEnvelope(
                                id=message_id,
                                topic=topic,
                                payload=json.loads(fields["data"]),
                                attempt=2,
                                meta={"group": group, "reclaimed": True},
                            )
                        continue
                    for message_id, fields, attempt in reclaimed:
                        if not fields or set(fields) != {"data"}:
                            raise EpochError("RUNTIME_PENDING_PAYLOAD_MISSING")
                        yield BusEnvelope(
                            id=message_id,
                            topic=topic,
                            payload=json.loads(fields["data"]),
                            attempt=attempt,
                            meta={"group": group, "reclaimed": True},
                        )
                    remaining = RUNTIME_REDIS_COMMAND_SECONDS
                    if recovery_deadline is not None:
                        remaining = min(remaining, recovery_deadline - time.monotonic())
                        if remaining <= 0:
                            raise EpochError("REDIS_RECOVERY_DEADLINE_EXCEEDED")
                    async with asyncio.timeout(remaining):
                        response = await self._redis.xreadgroup(
                            group, consumer, {topic: ">"}, count=16, block=block_ms
                        )
                    if recovery_pending:
                        telemetry["recoveries"] += 1
                    recovery_pending = False
                    failures, recovery_deadline = 0, None
                    for _stream, rows in response or []:
                        for message_id, fields in rows:
                            if not fields or set(fields) != {"data"}:
                                raise EpochError("RUNTIME_STREAM_PAYLOAD_MISSING")
                            yield BusEnvelope(
                                id=message_id,
                                topic=topic,
                                payload=json.loads(fields["data"]),
                                meta={"group": group},
                            )
                except Exception as error:
                    if not redis_transport_failure(error):
                        raise
                    failures += 1
                    telemetry["transport_failures"] += 1
                    if failures >= RUNTIME_REDIS_ATTEMPTS:
                        raise EpochError("REDIS_TRANSPORT_RETRY_EXHAUSTED") from error
                    if recovery_deadline is None:
                        recovery_deadline = (
                            time.monotonic()
                            + RUNTIME_REDIS_RECOVERY_SECONDS
                            - RUNTIME_REDIS_COMMAND_SECONDS
                        )
                    replay_pending = True
                    await redis_retry_pause(
                        stop, RUNTIME_REDIS_BACKOFF_SECONDS[failures - 1]
                    )

        async def ack(self, topic, envelope, *, group=None):
            if topic != TOPIC or (group or envelope.meta.get("group")) != "bars":
                raise EpochError("FIXED_NONTRADING_REDIS_ACK_REQUIRED")
            await runtime_redis_call(
                lambda: self._redis.xack(topic, "bars", envelope.id), stop, telemetry
            )

    return EpochRedisTransport()


async def consume(
    config: dict, stop: asyncio.Event, telemetry: dict | None = None
) -> None:
    from kairos_core.contracts import ClosedBarEventV1
    from kairos_persistence.config import PersistenceSettings
    from kairos_persistence.database import Database, MigrationProfile
    from kairos_persistence.runtime import DurableMessageBus

    url = f"redis://kairos_epoch_consumer:{config['redis_consumer_password']}@{config['redis_host']}:6379/0"
    transport = create_runtime_transport(
        url, stop, telemetry if telemetry is not None else {}
    )
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


async def close_runtime_resources(
    *,
    stop,
    task,
    producer,
    consumer_probe,
    supervisor,
    pool,
    output: Path,
    primary_error,
) -> None:
    """Close every owned resource without replacing the operational failure."""
    stop.set()
    if task:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    failures = []
    for resource in (producer, consumer_probe, supervisor, pool):
        if resource is None:
            continue
        try:
            closer = getattr(resource, "aclose", None) or resource.close
            await closer()
        except (Exception, asyncio.CancelledError) as error:  # noqa: BLE001 - close every owner resource; diagnostics contain no driver text.
            failures.append(error)
    if failures:
        write_status(
            output / "cleanup-failure.json",
            {
                "state": "FAILED_CLOSED",
                "failure_locations": [failure_locations(e) for e in failures],
                "primary_failure_preserved": primary_error is not None,
                "trading_started": False,
            },
            immutable=True,
        )
        if primary_error is None:
            raise failures[0]


def install_runtime_shutdown(loop, requested: asyncio.Event) -> tuple:
    """SIGTERM requests a fully drained cycle; it does not cancel an inbox commit."""
    installed = []
    if os.name != "nt":
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, requested.set)
            installed.append(signum)
    return tuple(installed)


async def runtime_idle(requested: asyncio.Event) -> None:
    try:
        await asyncio.wait_for(requested.wait(), timeout=10)
    except TimeoutError:
        pass


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
    redis_telemetry = {"transport_failures": 0, "recoveries": 0, "pending_replays": 0}
    source_circuit = SourceCircuit()
    shutdown_requested = asyncio.Event()
    loop = asyncio.get_running_loop()
    signals = (
        install_runtime_shutdown(loop, shutdown_requested) if not qualification else ()
    )
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
        task = asyncio.create_task(consume(config, stop, redis_telemetry))
        cycles = 0
        while True:
            if task.done():
                await task
                raise EpochError("CONSUMER_STOPPED")
            target = ((int(time.time() * 1000) - FINALITY_MS) // MINUTE) * MINUTE
            await flush(config, pool, producer)
            end = bounded_runtime_end(await anchors(pool), target)
            current = {**config, "end_exclusive_ms": end}
            waiting_reason = None
            try:
                await recover(
                    current,
                    publish=True,
                    status_path=output / "progress.json",
                    failure_suffix="-" + str(time.time_ns()),
                )
            except Exception as source_error:
                if qualification:
                    raise
                waiting_reason = source_circuit.failed(source_error)
            else:
                source_circuit.succeeded()
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
            current_target = (
                (int(time.time() * 1000) - FINALITY_MS) // MINUTE
            ) * MINUTE
            source_fresh = waiting_reason is None and all(
                event.close_time_ms + 1 >= current_target
                for event in watermarks.values()
            )
            if qualification and completed > 0 and not qualification_proofs:
                qualification_proofs = await verify_duplicate_delivery(
                    config, pool, producer, consumer_probe, task
                )
            report = {
                "state": (
                    "WAITING_SOURCE_NONTRADING"
                    if waiting_reason
                    else "CATCHING_UP_NONTRADING"
                    if not source_fresh
                    else "RUNNING_NONTRADING"
                ),
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
                "redis_transport": dict(redis_telemetry),
                "source_transport": source_circuit.snapshot(),
                "source_wait_reason": waiting_reason,
                "finalized_target_ms": current_target,
                "batch_end_exclusive_ms": end,
                "source_fresh": source_fresh,
                "trading_started": False,
            }
            write_status(output / "status.json", report)
            cycles += 1
            if (
                qualification
                and completed > 0
                and cycles >= 2
                and report["source_fresh"]
            ):
                return {**report, "state": "NONTRADING_RUNTIME_QUALIFIED"}
            if shutdown_requested.is_set():
                return {
                    **report,
                    "state": "STOPPED_NONTRADING",
                    "graceful_shutdown": True,
                }
            if waiting_reason:

                def heartbeat(_report=report):
                    _report["observed_at_utc"] = datetime.now(UTC).isoformat()
                    write_status(output / "status.json", _report)

                await source_circuit.wait(shutdown_requested, task, heartbeat)
                if shutdown_requested.is_set():
                    return {
                        **report,
                        "state": "STOPPED_NONTRADING",
                        "graceful_shutdown": True,
                    }
            elif not source_fresh:
                # Every bounded batch is flushed and fully consumed first.
                await asyncio.sleep(0)
            else:
                await runtime_idle(shutdown_requested)
    finally:
        for signum in signals:
            loop.remove_signal_handler(signum)
        await close_runtime_resources(
            stop=stop,
            task=task,
            producer=producer,
            consumer_probe=consumer_probe,
            supervisor=supervisor,
            pool=pool,
            output=output,
            primary_error=sys.exc_info()[1],
        )


async def dispatch(mode: str, config: dict, output: Path) -> dict:
    validate_config(config, mode)
    if mode in {"r7-state", "r7-verify-restore", "r7-drain"}:
        if __package__:
            from scripts.runtime_epoch_r7_read_profile import dispatch_r7
        else:
            from runtime_epoch_r7_read_profile import dispatch_r7
        return await dispatch_r7(mode, config, output)
    if mode in {"r6-state", "r6-verify-restore", "r6-drain"}:
        if __package__:
            from scripts.runtime_epoch_feed_recovery_worker import dispatch_r6
        else:
            from runtime_epoch_feed_recovery_worker import dispatch_r6
        return await dispatch_r6(mode, config, output)
    if mode in {"r5-state", "r5-verify-restore", "r5-drain"}:
        if __package__:
            from scripts.runtime_epoch_read_recovery_worker import dispatch_r5
        else:
            from runtime_epoch_read_recovery_worker import dispatch_r5
        return await dispatch_r5(mode, config, output)
    if mode in {"incident-state", "incident-drain", "incident-verify-restore"}:
        if __package__:
            from scripts.runtime_epoch_incident_worker import dispatch_incident
        else:
            from runtime_epoch_incident_worker import dispatch_incident

        return await dispatch_incident(mode, config, output)
    if mode == "prepare":
        return await prepare(config)
    if mode == "seed":
        return await seed(config)
    if mode == "rotate-history":
        return await rotate_history(config)
    if mode == "history-state":
        return await history_state(config)
    if mode == "boot-state":
        return await boot_state(config)
    if mode == "boot-verify-restore":
        return await boot_verify_restore(config)
    if mode == "boot-catchup":
        return await boot_catchup(config, output)
    if mode == "boot-redis-state":
        return await boot_redis_state(config)
    if mode == "boot-redis-clone":
        return await boot_redis_state(config, clone=True)
    if mode == "catchup":
        return await recover(
            config, publish=False, status_path=output / "progress.json"
        )
    if mode == "verify-restore":
        return await verify_restore(config)
    return await runtime(config, output, qualification=mode == "qualify")


def failure_locations(error: BaseException) -> list[dict]:
    """Bounded public code locations only: no paths, locals, or driver text."""
    result = []
    seen = set()
    for _ in range(3):
        if id(error) in seen:
            break
        seen.add(id(error))
        locations = []
        trace = error.__traceback__
        while trace is not None:
            module = str(trace.tb_frame.f_globals.get("__name__", ""))
            function = trace.tb_frame.f_code.co_name
            if (
                (
                    module
                    in {
                        "__main__",
                        "runtime_epoch_worker",
                        "scripts.runtime_epoch_worker",
                        "runtime_epoch_read_recovery_worker",
                        "scripts.runtime_epoch_read_recovery_worker",
                        "runtime_epoch_feed_recovery_worker",
                        "scripts.runtime_epoch_feed_recovery_worker",
                    }
                    or module.startswith(("asyncio.", "asyncpg.", "aiohttp.", "redis."))
                )
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,95}", module)
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,95}", function)
            ):
                locations.append(
                    {"module": module, "function": function, "line": trace.tb_lineno}
                )
            trace = trace.tb_next
        result.append({"error_type": type(error).__name__, "locations": locations[-8:]})
        previous = error.__cause__ or error.__context__
        if previous is None:
            break
        error = previous
    return result


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
        filename = (
            "serve-stop-" + str(time.time_ns()) + "-" + str(os.getpid()) + ".json"
            if args.mode == "serve" and result.get("graceful_shutdown") is True
            else args.mode + ".json"
        )
        write_status(args.output / filename, result, immutable=True)
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
                "failure_locations": failure_locations(exc),
                "observed_at_utc": datetime.now(UTC).isoformat(),
                "trading_started": False,
            },
        )
        return 1


if __name__ == "__main__":
    sys.modules.setdefault("runtime_epoch_worker", sys.modules[__name__])
    raise SystemExit(main())
