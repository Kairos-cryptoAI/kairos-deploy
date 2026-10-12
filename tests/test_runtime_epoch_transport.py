"""Fault injection for the epoch-only Redis reader; no network or DB writes."""

import asyncio
import json
import sys
import types
import unittest
from unittest import mock

from scripts import runtime_epoch_worker as worker


class ConnectionError(Exception):
    pass


class AuthenticationError(ConnectionError):
    pass


class ResponseError(Exception):
    pass


class NoPermissionError(ResponseError):
    pass


class RedisTimeoutError(Exception):
    pass


def fake_modules():
    """The Deploy Windows/CI suite is stdlib-only; native wheels are tested separately."""
    names = (
        "redis",
        "redis.asyncio",
        "redis.exceptions",
        "redis.backoff",
        "redis.asyncio.retry",
        "kairos_core",
        "kairos_core.bus",
        "kairos_core.bus.base",
        "kairos_core.bus.redis_streams",
    )
    modules = {name: types.ModuleType(name) for name in names}
    modules["redis"].asyncio = modules["redis.asyncio"]
    for name in (
        "ConnectionError",
        "AuthenticationError",
        "ResponseError",
        "NoPermissionError",
        "RedisTimeoutError",
    ):
        setattr(
            modules["redis.exceptions"],
            "TimeoutError" if name == "RedisTimeoutError" else name,
            globals()[name],
        )
    modules["redis.backoff"].NoBackoff = lambda: None

    class Retry:
        def __init__(self, _backoff, retries):
            self.retries = retries

        def get_retries(self):
            return self.retries

    class CoreBus:
        async def _ensure_group(self, topic, group):
            if (topic, group) in self._groups_ready:
                return
            try:
                await self._redis.xgroup_create(topic, group, id="0", mkstream=True)
            except ResponseError as error:
                if "BUSYGROUP" not in str(error):
                    raise
            self._groups_ready.add((topic, group))

        async def close(self):
            await self._redis.aclose()

    modules["redis.asyncio.retry"].Retry = Retry
    modules["kairos_core.bus.redis_streams"].RedisStreamsBus = CoreBus
    modules["kairos_core.bus.base"].BusEnvelope = types.SimpleNamespace
    return modules


class FakeRedis:
    def __init__(self):
        self.reads = []
        self.pending = {}
        self.failures = []
        self.lost_reply = False
        self.ack_lost = False
        self.acks = []
        self.closed = False

    async def xgroup_create(self, *_args, **_kwargs):
        raise ResponseError("BUSYGROUP")

    async def xreadgroup(self, group, consumer, streams, **_kwargs):
        cursor = streams[worker.TOPIC]
        self.reads.append((group, consumer, cursor))
        if self.failures:
            raise self.failures.pop(0)
        if cursor == "0":
            return [(worker.TOPIC, list(self.pending.items()))]
        if self.lost_reply:
            self.lost_reply = False
            self.pending["1-0"] = {"data": json.dumps({"message_id": "one"})}
            raise RedisTimeoutError("private-driver-data")
        await asyncio.sleep(0)
        return []

    async def xack(self, _topic, _group, message_id):
        self.acks.append(message_id)
        self.pending.pop(message_id, None)
        if self.ack_lost:
            self.ack_lost = False
            raise RedisTimeoutError("private-driver-data")
        return 1

    async def aclose(self):
        self.closed = True


class EpochTransportTests(unittest.IsolatedAsyncioTestCase):
    def make_transport(self, fake, stop, telemetry):
        modules = fake_modules()
        constructor = mock.Mock(return_value=fake)
        modules["redis.asyncio"].from_url = constructor
        self.enterContext(mock.patch.dict(sys.modules, modules))
        transport = worker.create_runtime_transport("redis://unused/0", stop, telemetry)
        options = constructor.call_args.kwargs
        self.assertEqual(options["socket_timeout"], 6.0)
        self.assertEqual(options["socket_connect_timeout"], 3.0)
        self.assertEqual(options["retry"].get_retries(), 0)
        self.assertEqual(options["retry_on_error"], [])
        transport._reclaim_stale = mock.AsyncMock(return_value=[])
        return transport

    async def test_lost_new_read_reply_drains_same_consumer_before_next_new_read(self):
        fake, stop, telemetry = FakeRedis(), asyncio.Event(), {}
        fake.lost_reply = True
        transport = self.make_transport(fake, stop, telemetry)
        stream = transport.subscribe(worker.TOPIC, group="bars")
        with mock.patch.object(worker, "RUNTIME_REDIS_BACKOFF_SECONDS", (0, 0)):
            envelope = await anext(stream)
            self.assertEqual(envelope.id, "1-0")
            self.assertEqual([row[2] for row in fake.reads], [">", "0"])
            self.assertEqual(len({row[:2] for row in fake.reads}), 1)
            await transport.ack(worker.TOPIC, envelope, group="bars")
            next_read = asyncio.create_task(anext(stream))
            for _ in range(20):
                await asyncio.sleep(0)
                if telemetry["recoveries"]:
                    break
            self.assertEqual([row[2] for row in fake.reads[:4]], [">", "0", "0", ">"])
            self.assertEqual(telemetry["transport_failures"], 1)
            self.assertEqual(telemetry["pending_replays"], 1)
            self.assertEqual(telemetry["recoveries"], 1)
            next_read.cancel()
            await asyncio.gather(next_read, return_exceptions=True)
        await stream.aclose()
        await transport.close()
        self.assertTrue(fake.closed)
        self.assertFalse(fake.pending)
        self.assertEqual(fake.acks, ["1-0"])

    async def test_transport_exhaustion_is_bounded_and_never_acknowledges(self):
        fake, stop, telemetry = FakeRedis(), asyncio.Event(), {}
        fake.failures = [ConnectionError("private") for _ in range(3)]
        transport = self.make_transport(fake, stop, telemetry)
        with (
            mock.patch.object(worker, "RUNTIME_REDIS_BACKOFF_SECONDS", (0, 0)),
            self.assertRaisesRegex(
                worker.EpochError, "REDIS_TRANSPORT_RETRY_EXHAUSTED"
            ),
        ):
            await anext(transport.subscribe(worker.TOPIC, group="bars"))
        self.assertEqual(len(fake.reads), 3)
        self.assertEqual(fake.acks, [])
        self.assertEqual(telemetry["transport_failures"], 3)

    async def test_auth_permission_protocol_errors_are_not_retried(self):
        for error in (
            AuthenticationError(),
            NoPermissionError(),
            ResponseError("NOGROUP"),
        ):
            with self.subTest(kind=type(error).__name__):
                fake, stop, telemetry = FakeRedis(), asyncio.Event(), {}
                fake.failures = [error]
                transport = self.make_transport(fake, stop, telemetry)
                with self.assertRaises(type(error)):
                    await anext(transport.subscribe(worker.TOPIC, group="bars"))
                self.assertEqual(len(fake.reads), 1)
                self.assertEqual(telemetry["transport_failures"], 0)

    async def test_lost_ack_reply_is_idempotently_retried(self):
        fake, stop, telemetry = FakeRedis(), asyncio.Event(), {}
        fake.lost_reply, fake.ack_lost = True, True
        transport = self.make_transport(fake, stop, telemetry)
        with mock.patch.object(worker, "RUNTIME_REDIS_BACKOFF_SECONDS", (0, 0)):
            stream = transport.subscribe(worker.TOPIC, group="bars")
            envelope = await anext(stream)
            await transport.ack(worker.TOPIC, envelope, group="bars")
            await stream.aclose()
        self.assertEqual(fake.acks, ["1-0", "1-0"])
        self.assertFalse(fake.pending)

    async def test_stop_interrupts_retry_and_cancellation_is_not_recovered(self):
        fake, stop, telemetry = FakeRedis(), asyncio.Event(), {}
        fake.failures = [RedisTimeoutError()]
        transport = self.make_transport(fake, stop, telemetry)
        task = asyncio.create_task(
            anext(transport.subscribe(worker.TOPIC, group="bars"))
        )
        for _ in range(20):
            await asyncio.sleep(0)
            if telemetry["transport_failures"]:
                break
        stop.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(len(fake.reads), 1)
        self.assertFalse(fake.acks)

    async def test_non_bar_and_deleted_pending_payload_fail_closed(self):
        fake, stop, telemetry = FakeRedis(), asyncio.Event(), {}
        transport = self.make_transport(fake, stop, telemetry)
        with self.assertRaisesRegex(worker.EpochError, "FIXED_NONTRADING"):
            await anext(transport.subscribe("orders", group="bars"))
        fake.failures = [RedisTimeoutError()]
        fake.pending["1-0"] = {}
        with (
            mock.patch.object(worker, "RUNTIME_REDIS_BACKOFF_SECONDS", (0, 0)),
            self.assertRaisesRegex(
                worker.EpochError, "RUNTIME_PENDING_PAYLOAD_MISSING"
            ),
        ):
            await anext(transport.subscribe(worker.TOPIC, group="bars"))
        self.assertFalse(fake.acks)

    def test_bounded_attempts_fit_existing_completion_deadline(self):
        self.assertLess(
            worker.RUNTIME_REDIS_COMMAND_SECONDS * worker.RUNTIME_REDIS_ATTEMPTS
            + sum(worker.RUNTIME_REDIS_BACKOFF_SECONDS),
            30,
        )
        self.assertLess(worker.RUNTIME_REDIS_RECOVERY_SECONDS, 30)

    async def test_shutdown_requests_stop_without_cancelling_consumer_commit(self):
        loop, requested = mock.Mock(), asyncio.Event()
        with mock.patch.object(worker.os, "name", "posix"):
            signals = worker.install_runtime_shutdown(loop, requested)
        self.assertEqual(len(signals), 2)
        self.assertFalse(requested.is_set())
        loop.add_signal_handler.call_args_list[0].args[1]()
        self.assertTrue(requested.is_set())
        await asyncio.wait_for(worker.runtime_idle(requested), timeout=0.1)


if __name__ == "__main__":
    unittest.main()
