"""Exercise offline recovery against an explicitly named disposable database.

The harness prepares its disposable target before opening the recovery writer.
The writer itself must observe the already-present 001--012 profile and never
run a migration or start a Redis/outbox dispatcher.
"""

import asyncio
import json
import re
import sys
from importlib.resources import files
from urllib.parse import urlsplit, urlunsplit

from kairos_core.topics import Topics
from kairos_persistence import Database, OfflineDurableWriter
from kairos_persistence.config import PersistenceSettings

from kairos_quant.long_gap_recovery import (
    MINUTE,
    RECOVERY_SCHEMA_VERSIONS,
    SOURCE,
    load_anchor,
    parse_page,
    recover_symbol,
)


async def prepare_disposable_profile(
    database: Database,
    *,
    expected_database_name: str,
) -> None:
    """Create only the verified historical schema in a fresh disposable DB."""
    await database.connect()
    try:
        async with database.pool.acquire() as connection:
            actual_database_name = await connection.fetchval("SELECT current_database()")
            if actual_database_name != expected_database_name:
                raise ValueError("integration target identity differs from the explicit disposable database")
            existing_tables = await connection.fetchval(
                "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'"
            )
            if existing_tables:
                raise ValueError("integration target must be a fresh disposable database")
            await connection.execute(
                """CREATE TABLE schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )"""
            )
            migrations = files("kairos_persistence").joinpath("migrations")
            for version in RECOVERY_SCHEMA_VERSIONS:
                async with connection.transaction():
                    await connection.execute(migrations.joinpath(version).read_text(encoding="utf-8"))
                    await connection.execute("INSERT INTO schema_migrations(version) VALUES ($1)", version)
    finally:
        await database.close()


async def run(database_name: str) -> None:
    if not re.fullmatch(r"kairos_gap_drill_[0-9a-f]{12}", database_name):
        raise ValueError("an explicitly isolated disposable database is required")
    original = urlsplit(PersistenceSettings().database_url)
    settings = PersistenceSettings(database_url=urlunsplit(original._replace(path="/" + database_name)))
    await prepare_disposable_profile(Database(settings), expected_database_name=database_name)
    first = OfflineDurableWriter(
        service_name=SOURCE,
        expected_database_name=database_name,
        expected_schema_versions=RECOVERY_SCHEMA_VERSIONS,
        settings=settings,
    )
    second = OfflineDurableWriter(
        service_name=SOURCE,
        expected_database_name=database_name,
        expected_schema_versions=RECOVERY_SCHEMA_VERSIONS,
        settings=settings,
    )

    async def fetch(symbol: str, start: int, end: int) -> list[list[object]]:
        del symbol
        return [
            [t, "100", "102", "99", "101", "20", t + 59999, "2000", 1, "10", "1000"]
            for t in range(start, end, MINUTE)
        ]

    async def pause() -> None:
        return None

    try:
        await first.start()
        assert not hasattr(first, "transport")
        try:
            await second.start()
        except RuntimeError as exc:
            assert "already running" in str(exc)
        else:
            raise AssertionError("second offline writer acquired a held maintenance lease")

        event = parse_page(await fetch("BTCUSDT", 0, MINUTE), symbol="BTCUSDT", start=0, end=MINUTE)[0]
        assert await first.append(Topics.CLOSED_BAR, event) is True

        async def failed_append(bar):
            assert await first.append(Topics.CLOSED_BAR, bar) is True
            if bar.open_time_ms == 3 * MINUTE:
                raise RuntimeError("simulated lost ACK after durable commit")

        try:
            await recover_symbol(
                event,
                end_exclusive=10 * MINUTE,
                fetch=fetch,
                publish=failed_append,
                page_size=4,
                pause=pause,
                progress=lambda _: None,
            )
        except RuntimeError as exc:
            assert "lost ACK" in str(exc)
        else:
            raise AssertionError("fault injection did not execute")
        await first.close()

        await second.start()
        anchor = await load_anchor(second, "BTCUSDT")
        assert anchor.open_time_ms == 3 * MINUTE

        async def append_and_replay_duplicate(bar):
            assert await second.append(Topics.CLOSED_BAR, bar) is True
            assert await second.append(Topics.CLOSED_BAR, bar) is False

        await recover_symbol(
            anchor,
            end_exclusive=10 * MINUTE,
            fetch=fetch,
            publish=append_and_replay_duplicate,
            page_size=4,
            pause=pause,
            progress=lambda _: None,
        )
        last = await load_anchor(second, "BTCUSDT")
        assert last.close_time_ms + 1 == 10 * MINUTE
        pool = second.repository.pool
        audit = await pool.fetchval("SELECT count(*) FROM event_audit")
        outbox = await pool.fetchval("SELECT count(*) FROM message_outbox")
        versions = tuple(
            row["version"]
            for row in await pool.fetch("SELECT version FROM schema_migrations ORDER BY version")
        )
        assert audit == outbox == 10
        assert versions == RECOVERY_SCHEMA_VERSIONS
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "database": database_name,
                    "audit_rows": audit,
                    "outbox_rows": outbox,
                    "lost_ack_restart": True,
                    "duplicate_rows": 0,
                    "exclusive_offline_writer": True,
                    "schema_profile": "001-012",
                    "transport_dispatcher_started": False,
                }
            ),
            flush=True,
        )
    finally:
        await first.close()
        await second.close()


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
