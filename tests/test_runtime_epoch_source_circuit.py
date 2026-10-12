"""Offline outage/backoff contracts; no HTTP, database, or trading authority."""

import asyncio
import copy
import sys
import types
import unittest
from builtins import ExceptionGroup
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import runtime_epoch_worker as worker


class SourceCircuitTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_runtime_waits_then_recovers_without_new_consumer_or_fake_freshness(
        self,
    ):
        """Run the actual supervisor loop; only boundary IO is synthetic."""

        class Forbidden(Exception):
            pass

        class Connection:
            async def fetchval(self, sql, *_args):
                if "pg_try_advisory_lock" in sql:
                    return True
                return (
                    10
                    if sql
                    == "SELECT count(*) FROM message_inbox WHERE status='COMPLETED'"
                    else 0
                )

            async def execute(self, sql):
                if sql.startswith("UPDATE"):
                    raise Forbidden()

            async def close(self):
                pass

        class Pool:
            @asynccontextmanager
            async def acquire(self):
                yield Connection()

            async def close(self):
                pass

        class Redis:
            async def ping(self):
                return True

            async def xadd(self, *_a, **_k):
                raise Forbidden()

            async def aclose(self):
                pass

        asyncpg = types.ModuleType("asyncpg")
        asyncpg.create_pool = mock.AsyncMock(return_value=Pool())
        asyncpg.InsufficientPrivilegeError = Forbidden
        redis = types.ModuleType("redis")
        redis_async = types.ModuleType("redis.asyncio")
        redis_errors = types.ModuleType("redis.exceptions")
        redis.asyncio = redis_async
        redis_async.Redis = lambda **_k: Redis()
        redis_errors.NoPermissionError = Forbidden
        captured_shutdown, reports, consumed = [], [], []
        target = 60000 * 100
        bars = self.bars([target - 60000] * 5)
        recovered = 0

        def install(_loop, requested):
            captured_shutdown.append(requested)
            return ()

        async def recover(config, **_kwargs):
            nonlocal recovered
            await asyncio.sleep(0)  # The real HTTP/SQL boundary also yields.
            recovered += 1
            if recovered == 1:
                raise worker.EpochError("OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT")
            for bar in bars.values():
                bar.close_time_ms = config["end_exclusive_ms"] - 1
            captured_shutdown[0].set()

        async def consume(*_args):
            consumed.append("start")
            try:
                await asyncio.Event().wait()
            finally:
                consumed.append("closed")

        config = {
            "owner": "a" * 32,
            "redis_host": "isolated",
            "redis_producer_password": "synthetic",
            "redis_consumer_password": "synthetic",
        }
        with (
            mock.patch.dict(
                sys.modules,
                {
                    "asyncpg": asyncpg,
                    "redis": redis,
                    "redis.asyncio": redis_async,
                    "redis.exceptions": redis_errors,
                },
            ),
            mock.patch.object(worker, "dsn", return_value="synthetic"),
            mock.patch.object(
                worker,
                "connect",
                new=mock.AsyncMock(side_effect=lambda *_a: Connection()),
            ),
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
            mock.patch.object(worker, "anchors", new=mock.AsyncMock(return_value=bars)),
            mock.patch.object(worker, "recover", side_effect=recover),
            mock.patch.object(worker, "consume", side_effect=consume),
            mock.patch.object(
                worker, "flush", new=mock.AsyncMock(return_value=0)
            ) as flush,
            mock.patch.object(worker, "install_runtime_shutdown", side_effect=install),
            mock.patch.object(
                worker.SourceCircuit, "wait", new=mock.AsyncMock()
            ) as wait,
            mock.patch.object(worker.time, "time", return_value=(target + 5000) / 1000),
            mock.patch.object(
                worker,
                "write_status",
                side_effect=lambda _p, value: reports.append(copy.deepcopy(value)),
            ),
        ):
            result = await worker.runtime(config, Path("unused"), qualification=False)
        self.assertEqual(
            [r["state"] for r in reports],
            ["WAITING_SOURCE_NONTRADING", "RUNNING_NONTRADING"],
        )
        self.assertFalse(reports[0]["source_fresh"])
        self.assertTrue(reports[1]["source_fresh"])
        self.assertEqual(reports[1]["source_transport"]["recoveries"], 1)
        self.assertEqual(result["state"], "STOPPED_NONTRADING")
        self.assertEqual(consumed, ["start", "closed"])
        self.assertEqual(flush.await_count, 4)
        wait.assert_awaited_once()

    @staticmethod
    def bars(starts):
        return {
            s: SimpleNamespace(close_time_ms=t - 1)
            for s, t in zip(worker.SYMBOLS, starts, strict=True)
        }

    def test_long_gap_is_caught_up_in_fixed_cap_batches(self):
        starts = [60000] * 5
        target = 60000 * 201
        batches = 0
        while min(starts) < target:
            bars = self.bars(starts)
            end = worker.bounded_runtime_end(bars, target)
            self.assertGreater(end, min(starts))
            self.assertLessEqual(worker.required_bars(bars, end), 100)
            starts = [end] * 5
            batches += 1
        self.assertEqual(batches, 10)
        self.assertEqual(worker.MAX_PENDING, 100)

    def test_partial_symbol_append_uses_actual_anchors_not_old_endpoint(self):
        starts = [60000, 120000, 120000, 120000, 120000]
        bars = self.bars(starts)
        end = worker.bounded_runtime_end(bars, 60000 * 201)
        self.assertGreaterEqual(end, max(starts))
        self.assertLessEqual(worker.required_bars(bars, end), 100)

    def test_unexpected_watermark_skew_and_future_data_fail_closed(self):
        with self.assertRaisesRegex(worker.EpochError, "SKEW_EXCEEDS_PENDING_CAP"):
            worker.bounded_runtime_end(
                self.bars([60000] * 4 + [60000 * 101]), 60000 * 201
            )
        with self.assertRaisesRegex(worker.EpochError, "FINALITY_CLOCK_REGRESSION"):
            worker.bounded_runtime_end(self.bars([120000] * 5), 60000)

    def test_only_complete_timeout_groups_can_defer(self):
        timeout = worker.EpochError("OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT")
        self.assertIsNotNone(
            worker.source_wait_reason(ExceptionGroup("synthetic", [timeout, timeout]))
        )
        for error in (
            worker.EpochError("OFFICIAL_CLOSED_BAR_FETCH_FAILED"),
            worker.EpochError("PAYLOAD_CONFLICT"),
            ExceptionGroup("mixed", [timeout, worker.EpochError("DB_INTEGRITY")]),
            RuntimeError("private driver value"),
        ):
            self.assertIsNone(worker.source_wait_reason(error))
            with self.assertRaises(type(error)):
                worker.SourceCircuit().failed(error)

    def test_timeout_then_success_counts_recovery_without_raising_caps(self):
        circuit = worker.SourceCircuit()
        for _ in range(10):
            circuit.failed(worker.EpochError("OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT"))
        self.assertEqual(circuit.snapshot()["timeout_rounds"], 10)
        circuit.succeeded()
        circuit.succeeded()
        self.assertEqual(
            circuit.snapshot(),
            {"timeout_rounds": 10, "recoveries": 1, "consecutive_timeout_rounds": 0},
        )

    async def test_cancelled_outage_wait_stops_without_more_requests(self):
        circuit = worker.SourceCircuit()
        circuit.failed(worker.EpochError("OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT"))
        requested = asyncio.Event()
        consumer = asyncio.create_task(asyncio.Event().wait())
        events = []

        def heartbeat():
            events.append("waiting")
            requested.set()

        try:
            await asyncio.wait_for(
                circuit.wait(requested, consumer, heartbeat), timeout=0.2
            )
        finally:
            consumer.cancel()
            await asyncio.gather(consumer, return_exceptions=True)
        self.assertEqual(events, ["waiting"])

    async def test_consumer_failure_is_never_hidden_by_source_outage(self):
        circuit = worker.SourceCircuit()
        circuit.failed(worker.EpochError("OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT"))

        async def fail():
            raise worker.EpochError("CONSUMER_INTEGRITY")

        consumer = asyncio.create_task(fail())
        await asyncio.sleep(0)
        with self.assertRaisesRegex(worker.EpochError, "CONSUMER_INTEGRITY"):
            await circuit.wait(
                asyncio.Event(),
                consumer,
                lambda: self.fail("no fake healthy heartbeat"),
            )

    async def test_backoff_is_capped_and_emits_waiting_heartbeats(self):
        circuit = worker.SourceCircuit()
        circuit.consecutive = 100
        requested = asyncio.Event()
        consumer = asyncio.create_task(asyncio.Event().wait())
        beats = []

        def heartbeat():
            beats.append("WAITING_SOURCE_NONTRADING")
            requested.set()

        with mock.patch.object(worker, "SOURCE_WAIT_SECONDS", (0.01, 0.02, 0.03, 0.04)):
            try:
                await circuit.wait(requested, consumer, heartbeat)
            finally:
                consumer.cancel()
                await asyncio.gather(consumer, return_exceptions=True)
        self.assertEqual(beats, ["WAITING_SOURCE_NONTRADING"])


if __name__ == "__main__":
    unittest.main()
