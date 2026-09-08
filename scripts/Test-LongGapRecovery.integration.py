"""Exercise recovery against an explicitly named disposable Timescale database."""

import asyncio
import json
import re
import sys
from urllib.parse import urlsplit, urlunsplit

from kairos_core.bus import InMemoryBus
from kairos_core.topics import Topics
from kairos_persistence import DurableMessageBus
from kairos_persistence.config import PersistenceSettings
from kairos_quant.long_gap_recovery import (
    MINUTE,
    SOURCE,
    load_anchor,
    parse_page,
    recover_symbol,
)
from kairos_quant.producer_lease import producer_lease


async def run(database_name):
    if not re.fullmatch(r"kairos_gap_drill_[0-9a-f]{12}", database_name):
        raise ValueError("an explicitly isolated disposable database is required")
    original = urlsplit(PersistenceSettings().database_url)
    settings = PersistenceSettings(
        database_url=urlunsplit(original._replace(path="/" + database_name))
    )
    first = DurableMessageBus(InMemoryBus(), service_name=SOURCE, settings=settings)
    second = DurableMessageBus(InMemoryBus(), service_name=SOURCE, settings=settings)

    async def fetch(symbol, start, end):
        return [
            [t, "100", "102", "99", "101", "20", t + 59999, "2000", 1, "10", "1000"]
            for t in range(start, end, MINUTE)
        ]

    async def pause():
        return None

    try:
        async with producer_lease(first):
            try:
                async with producer_lease(second):
                    raise AssertionError("second producer acquired the held lease")
            except RuntimeError as exc:
                assert "already running" in str(exc)
            event = parse_page(
                await fetch("BTCUSDT", 0, MINUTE), symbol="BTCUSDT", start=0, end=MINUTE
            )[0]
            await first.publish(Topics.CLOSED_BAR, event)

            async def failed_publish(bar):
                await first.publish(Topics.CLOSED_BAR, bar)
                if bar.open_time_ms == 3 * MINUTE:
                    raise RuntimeError("simulated lost ACK after durable commit")

            try:
                await recover_symbol(
                    event,
                    end_exclusive=10 * MINUTE,
                    fetch=fetch,
                    publish=failed_publish,
                    page_size=4,
                    pause=pause,
                    progress=lambda _: None,
                )
            except RuntimeError as exc:
                assert "lost ACK" in str(exc)
            else:
                raise AssertionError("fault injection did not execute")
        await first.close()
        async with producer_lease(second):
            anchor = await load_anchor(second, "BTCUSDT")
            assert anchor.open_time_ms == 3 * MINUTE

            async def publish(bar):
                await second.publish(Topics.CLOSED_BAR, bar)
                await second.publish(
                    Topics.CLOSED_BAR, bar
                )  # duplicate transport delivery

            await recover_symbol(
                anchor,
                end_exclusive=10 * MINUTE,
                fetch=fetch,
                publish=publish,
                page_size=4,
                pause=pause,
                progress=lambda _: None,
            )
            last = await load_anchor(second, "BTCUSDT")
            assert last.close_time_ms + 1 == 10 * MINUTE
            pool = second.repository.pool
            audit = await pool.fetchval("SELECT count(*) FROM event_audit")
            outbox = await pool.fetchval("SELECT count(*) FROM message_outbox")
            assert audit == outbox == 10
            print(
                json.dumps(
                    {
                        "result": "PASS",
                        "database": database_name,
                        "audit_rows": audit,
                        "outbox_rows": outbox,
                        "lost_ack_restart": True,
                        "duplicate_rows": 0,
                        "exclusive_producer": True,
                    }
                ),
                flush=True,
            )
    finally:
        await first.close()
        await second.close()


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1]))
