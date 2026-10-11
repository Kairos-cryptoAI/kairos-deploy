"""Offline unit contracts for the isolated non-trading epoch worker."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import runtime_epoch_worker as worker

OWNER = "0123456789abcdef0123456789abcdef"
DB = "kairos_epoch_0123456789ab"


def _catchup_config(**changes):
    end = (int(time.time() * 1000) // worker.MINUTE - 1) * worker.MINUTE
    value = {
        "owner": OWNER,
        "database": DB,
        "pg_host": "kairos-epoch-0123456789ab-pg",
        "redis_host": "kairos-epoch-0123456789ab-redis",
        "end_exclusive_ms": end,
        "maximum_bars": worker.MAX_BARS,
        "history_password": "a" * 64,
    }
    value.update(changes)
    return value


class WorkerConfigTests(unittest.TestCase):
    @staticmethod
    def _seed_config(**changes):
        value = {
            "owner": OWNER,
            "database": DB,
            "pg_host": "kairos-epoch-0123456789ab-pg",
            "redis_host": "kairos-epoch-0123456789ab-redis",
            "source_host": "kairos-epoch-0123456789ab-source",
            "source_database": "kairos_recovery_0123456789ab_epoch",
            "source_password": "a" * 64,
            "history_password": "b" * 64,
            "source_dump_sha256": worker.SOURCE_DUMP_SHA256,
            "seed_expectation": {"accepted_dump_sha256": worker.SOURCE_DUMP_SHA256},
        }
        value.update(changes)
        return value

    def test_seed_accepts_exact_pinned_dump_provenance(self):
        worker.validate_config(self._seed_config(), "seed")

    def test_seed_rejects_missing_or_tampered_dump_provenance_before_connect(self):
        valid = self._seed_config()
        invalid_configs = (
            {key: value for key, value in valid.items() if key != "source_dump_sha256"},
            {key: value for key, value in valid.items() if key != "seed_expectation"},
            {**valid, "source_dump_sha256": "0" * 64},
            {
                **valid,
                "seed_expectation": {"accepted_dump_sha256": "0" * 64},
            },
            {
                **valid,
                "seed_expectation": {
                    "accepted_dump_sha256": worker.SOURCE_DUMP_SHA256,
                    "unexpected": True,
                },
            },
        )
        for config in invalid_configs:
            with (
                self.subTest(config=config),
                mock.patch.object(
                    worker, "source_connection", new=mock.AsyncMock()
                ) as connect_source,
                self.assertRaisesRegex(
                    worker.EpochError, "PINNED_SOURCE_DUMP_PROVENANCE_REQUIRED"
                ),
            ):
                asyncio.run(worker.dispatch("seed", config, Path("unused")))
            connect_source.assert_not_awaited()

    def test_catchup_requires_owned_epoch_boundary_and_exact_cap(self):
        worker.validate_config(_catchup_config(), "catchup")
        for changes in (
            {"database": "kairos"},
            {"owner": "f" * 32},
            {"pg_host": "kairos-paper-gate-postgres-1"},
            {"maximum_bars": worker.MAX_BARS - 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(worker.EpochError):
                worker.validate_config(_catchup_config(**changes), "catchup")

    def test_catchup_requires_minute_aligned_finality_safe_deadline(self):
        config = _catchup_config()
        config["end_exclusive_ms"] = (
            int(time.time() * 1000) // worker.MINUTE + 1
        ) * worker.MINUTE
        with self.assertRaisesRegex(
            worker.EpochError, "FIXED_FINALITY_SAFE_DEADLINE_REQUIRED"
        ):
            worker.validate_config(config, "catchup")
        config = _catchup_config()
        config["end_exclusive_ms"] += 1
        with self.assertRaises(worker.EpochError):
            worker.validate_config(config, "catchup")

    def test_runtime_modes_reject_admin_and_old_source_credentials(self):
        common = {
            "owner": OWNER,
            "database": DB,
            "pg_host": "kairos-epoch-0123456789ab-pg",
            "redis_host": "kairos-epoch-0123456789ab-redis",
            "producer_password": "a" * 64,
            "consumer_password": "b" * 64,
            "redis_producer_password": "c" * 64,
            "redis_consumer_password": "d" * 64,
        }
        worker.validate_config(common, "qualify")
        with self.assertRaisesRegex(
            worker.EpochError, "RUNTIME_ADMIN_CREDENTIAL_REJECTED"
        ):
            worker.validate_config({**common, "admin_password": "e" * 64}, "qualify")
        with self.assertRaisesRegex(
            worker.EpochError, "RUNTIME_ADMIN_CREDENTIAL_REJECTED"
        ):
            worker.validate_config({**common, "source_password": "e" * 64}, "serve")

    def test_controller_generated_hex_password_is_accepted(self):
        # The controller's `secrets.token_hex(32)` is exactly 64 lowercase hex.
        config = _catchup_config(history_password="ab" * 32)
        worker.validate_config(config, "catchup")
        with self.assertRaisesRegex(
            worker.EpochError, "NEW_PRIVATE_CREDENTIAL_REQUIRED"
        ):
            worker.validate_config(
                _catchup_config(history_password="Ab_-" + "9x" * 30), "catchup"
            )

    def test_bar_count_math_is_exact_for_all_five_symbols(self):
        events = {
            symbol: types.SimpleNamespace(close_time_ms=999_999)
            for symbol in worker.SYMBOLS
        }
        self.assertEqual(worker.required_bars(events, 1_000_000 + worker.MINUTE), 5)
        with self.assertRaisesRegex(
            worker.EpochError, "FIXED_CATCHUP_INTERVAL_REQUIRED"
        ):
            worker.required_bars({"BTCUSDT": next(iter(events.values()))}, 1_060_000)
        with self.assertRaises(worker.EpochError):
            worker.required_bars(events, 1_000_001)


class _FakeTransaction:
    def __init__(self, connection):
        self.connection = connection
        self.before_audit = 0
        self.before_outbox = 0

    async def __aenter__(self):
        self.before_audit = self.connection.audit_count
        self.before_outbox = len(self.connection.outbox)
        return self

    async def __aexit__(self, exc_type, _exc, _tb):
        if exc_type is not None:
            self.connection.audit_count = self.before_audit
            del self.connection.outbox[self.before_outbox :]
        return False


class _FakeConnection:
    def __init__(self):
        self.audit_count = 0
        self.outbox = []

    def transaction(self):
        return _FakeTransaction(self)

    async def fetch(self, query, *_args):
        if "FROM event_audit" in query:
            return []
        raise AssertionError("unexpected query")


class _PoolAcquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_args):
        return False


class _FakePool:
    def __init__(self, connection=None):
        self.connection = connection or _FakeConnection()
        self.closed = False

    def acquire(self):
        return _PoolAcquire(self.connection)

    async def close(self):
        self.closed = True


class _FakeEvent:
    message_id = "fixture-message-id"

    def to_payload(self):
        return {"message_id": self.message_id, "value": 42}


class WriterTests(unittest.TestCase):
    def _modules(self, *, fail_outbox=False):
        connection = _FakeConnection()
        pool = _FakePool(connection)
        calls = []

        class FakeAuditRepository:
            def __init__(self, _pool):
                pass

            @staticmethod
            def _require_matching_audit_identity(
                rows, *, message_id, topic, canonical_json
            ):
                if rows:
                    raise AssertionError("unexpected pre-existing audit row in fixture")

            async def append_payload(self, topic, payload, *, connection):
                encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                digest = hashlib.sha256(encoded.encode()).hexdigest()
                calls.append(("audit", topic, payload, encoded, digest))
                connection.audit_count += 1
                return True

            async def enqueue_outbox(
                self, connection, message_id, topic, encoded, digest, producer
            ):
                calls.append(("outbox", message_id, topic, encoded, digest, producer))
                if fail_outbox:
                    raise RuntimeError("simulated outbox failure")
                connection.outbox.append(message_id)

        repository_module = types.ModuleType("kairos_persistence.repository")
        repository_module.AuditRepository = FakeAuditRepository
        runtime_module = types.ModuleType("kairos_persistence.runtime")

        def canonical_payload(payload):
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            return encoded, hashlib.sha256(encoded.encode()).hexdigest()

        runtime_module.canonical_payload = canonical_payload
        package_module = types.ModuleType("kairos_persistence")
        package_module.__path__ = []
        return (
            pool,
            calls,
            {
                "kairos_persistence": package_module,
                "kairos_persistence.repository": repository_module,
                "kairos_persistence.runtime": runtime_module,
            },
        )

    def test_audit_only_writer_never_enqueues_outbox(self):
        pool, calls, modules = self._modules()
        with mock.patch.dict(sys.modules, modules):
            writer = worker.EpochWriter(pool)
            asyncio.run(writer.append(_FakeEvent(), publish=False))
        self.assertEqual(pool.connection.audit_count, 1)
        self.assertEqual(pool.connection.outbox, [])
        self.assertEqual([call[0] for call in calls], ["audit"])

    def test_current_publication_writes_audit_and_outbox_in_same_transaction(self):
        pool, calls, modules = self._modules()
        with mock.patch.dict(sys.modules, modules):
            writer = worker.EpochWriter(pool)
            asyncio.run(writer.append(_FakeEvent(), publish=True))
        self.assertEqual(pool.connection.audit_count, 1)
        self.assertEqual(pool.connection.outbox, ["fixture-message-id"])
        self.assertEqual([call[0] for call in calls], ["audit", "outbox"])

    def test_outbox_failure_rolls_back_the_paired_audit_insert(self):
        pool, _calls, modules = self._modules(fail_outbox=True)
        with mock.patch.dict(sys.modules, modules):
            writer = worker.EpochWriter(pool)
            with self.assertRaisesRegex(RuntimeError, "simulated outbox failure"):
                asyncio.run(writer.append(_FakeEvent(), publish=True))
        self.assertEqual(pool.connection.audit_count, 0)
        self.assertEqual(pool.connection.outbox, [])


class _FakeOutboxConnection:
    def __init__(self, rows):
        self.rows = rows
        self.published_updates = []
        self.unlocked = False

    async def fetchval(self, query, *_args):
        if "pg_try_advisory_lock" in query:
            return True
        if "count(*) FROM message_outbox" in query:
            return 0
        raise AssertionError("unexpected fetchval")

    async def fetch(self, query, *args):
        if "FROM message_outbox" not in query:
            raise AssertionError("unexpected query")
        return self.rows[: args[0]]

    async def execute(self, query, *args):
        if "pg_advisory_unlock" in query:
            self.unlocked = True
            return "SELECT 1"
        if "UPDATE message_outbox" in query:
            self.published_updates.append(args[0])
            return "UPDATE 1"
        raise AssertionError("unexpected mutation")


class _FakeRedis:
    def __init__(self):
        self.ledger = {}
        self.stream = {}
        self.sequence = 0
        self.lua_calls = []

    async def eval(
        self, script, numkeys, stream_key, ledger_key, message_id, digest, encoded
    ):
        self.lua_calls.append(
            (script, numkeys, stream_key, ledger_key, message_id, digest, encoded)
        )
        prior = self.ledger.get(message_id)
        if prior is not None:
            if prior[0] != digest:
                raise RuntimeError("EPOCH_IDENTITY_CONFLICT")
            if prior[1] not in self.stream:
                raise RuntimeError("EPOCH_RECEIPT_WITHOUT_STREAM")
            if self.stream[prior[1]] != encoded:
                raise RuntimeError("EPOCH_STREAM_PAYLOAD_CONFLICT")
            # Mirrors the Lua duplicate path; the worker's script is separately
            # asserted below to bind the stream data as well as the digest.
            return prior[1]
        self.sequence += 1
        stream_id = f"{self.sequence}-0"
        self.stream[stream_id] = encoded
        self.ledger[message_id] = (digest, stream_id)
        return stream_id


class PublicationTests(unittest.TestCase):
    @staticmethod
    def _row(payload):
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        return {
            "id": 1,
            "message_id": payload["message_id"],
            "topic": worker.TOPIC,
            "payload": payload,
            "payload_sha256": digest,
            "producer": worker.SOURCE,
            "reconciliation_state": "NONE",
            "dead_lettered_at": None,
        }

    def _run_flush(self, row, redis, connection=None):
        fake_connection = connection or _FakeOutboxConnection([row])
        pool = _FakePool(fake_connection)
        package_module = types.ModuleType("kairos_persistence")
        package_module.__path__ = []
        runtime_module = types.ModuleType("kairos_persistence.runtime")

        def canonical_payload(payload):
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            return encoded, hashlib.sha256(encoded.encode()).hexdigest()

        runtime_module.canonical_payload = canonical_payload
        with mock.patch.dict(
            sys.modules,
            {
                "kairos_persistence": package_module,
                "kairos_persistence.runtime": runtime_module,
            },
        ):
            count = asyncio.run(worker.flush({"owner": OWNER}, pool, redis))
        return count, fake_connection

    def test_lua_binds_identity_conflicts_and_missing_stream_fail_closed(self):
        self.assertIn("p[1]~=ARGV[2]", worker.PUBLICATION_LUA)
        self.assertIn("EPOCH_IDENTITY_CONFLICT", worker.PUBLICATION_LUA)
        self.assertIn("EPOCH_RECEIPT_WITHOUT_STREAM", worker.PUBLICATION_LUA)
        self.assertIn("XRANGE", worker.PUBLICATION_LUA)
        self.assertIn("XADD", worker.PUBLICATION_LUA)
        self.assertIn("HSET", worker.PUBLICATION_LUA)
        self.assertRegex(worker.PUBLICATION_LUA, r"row\[[^]]+\].*ARGV\[3\]")

    def test_same_message_and_payload_returns_same_receipt_without_reappend(self):
        payload = {"message_id": "m1", "symbol": "BTCUSDT"}
        row = self._row(payload)
        redis = _FakeRedis()
        _first, _ = self._run_flush(row, redis)
        second_count, second_connection = self._run_flush(row, redis)
        self.assertEqual(second_count, 1)
        self.assertEqual(len(redis.stream), 1)
        self.assertEqual(len(redis.ledger), 1)
        self.assertEqual(second_connection.published_updates, [1])

    def test_digest_conflict_and_receipt_without_stream_are_not_positive_receipts(self):
        payload = {"message_id": "m1", "symbol": "BTCUSDT"}
        row = self._row(payload)
        redis = _FakeRedis()
        self._run_flush(row, redis)
        conflicting = self._row({**payload, "symbol": "ETHUSDT"})
        conflicting["id"] = 2
        conflicting["message_id"] = "m1"
        # Change the stored content identity while keeping the logical ID.
        changed_payload = {**conflicting["payload"], "message_id": "m1", "extra": True}
        conflicting["payload"] = changed_payload
        conflicting["payload_sha256"] = hashlib.sha256(
            json.dumps(changed_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        conflicting["topic"] = worker.TOPIC
        conflicting["producer"] = worker.SOURCE
        with self.assertRaisesRegex(RuntimeError, "EPOCH_IDENTITY_CONFLICT"):
            self._run_flush(conflicting, redis)
        del redis.stream[redis.ledger["m1"][1]]
        with self.assertRaisesRegex(RuntimeError, "EPOCH_RECEIPT_WITHOUT_STREAM"):
            self._run_flush(row, redis)
        redis.stream[redis.ledger["m1"][1]] = "foreign payload"
        with self.assertRaisesRegex(RuntimeError, "EPOCH_STREAM_PAYLOAD_CONFLICT"):
            self._run_flush(row, redis)


class FailureHandlingTests(unittest.TestCase):
    def test_unknown_driver_error_is_not_leaked_to_status_file(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            output = Path(directory) / "output"
            config.write_text("{}", encoding="utf-8")

            async def fail(_mode, _config, _output):
                raise RuntimeError("postgres password=private-value")

            with mock.patch.object(worker, "dispatch", side_effect=fail):
                code = worker.main(
                    [
                        "--mode",
                        "prepare",
                        "--config",
                        str(config),
                        "--output",
                        str(output),
                    ]
                )
            report = json.loads((output / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 1)
            self.assertEqual(report["state"], "FAILED_CLOSED")
            self.assertEqual(
                report["reason"], "operation failed; private diagnostic withheld"
            )
            self.assertNotIn("private-value", json.dumps(report))

    def test_recovery_failure_propagates_and_closes_pool(self):
        pool = _FakePool(_FakeOutboxConnection([]))
        asyncpg = types.ModuleType("asyncpg")

        async def create_pool(*_args, **_kwargs):
            return pool

        asyncpg.create_pool = create_pool
        aiohttp = types.ModuleType("aiohttp")

        class _ClientSession:
            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        aiohttp.ClientSession = _ClientSession
        aiohttp.ClientTimeout = lambda **_kwargs: object()
        quant = types.ModuleType("kairos_quant")
        recovery = types.ModuleType("kairos_quant.long_gap_recovery")
        recovery.RecoveryStatus = lambda emit: types.SimpleNamespace(emit=emit)

        async def fail_recover(*_args, **_kwargs):
            raise worker.EpochError("OFFICIAL_CLOSED_BAR_FETCH_FAILED")

        recovery.recover_symbol = fail_recover
        end = (int(time.time() * 1000) // worker.MINUTE - 1) * worker.MINUTE
        current = _catchup_config(end_exclusive_ms=end, maximum_bars=worker.MAX_BARS)
        status = Path("unused-progress.json")
        anchor_map = {
            symbol: types.SimpleNamespace(close_time_ms=end - worker.MINUTE - 1)
            for symbol in worker.SYMBOLS
        }
        with (
            mock.patch.dict(
                sys.modules,
                {
                    "asyncpg": asyncpg,
                    "aiohttp": aiohttp,
                    "kairos_quant": quant,
                    "kairos_quant.long_gap_recovery": recovery,
                    **self._writer_modules(),
                },
            ),
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
            mock.patch.object(
                worker, "anchors", new=mock.AsyncMock(return_value=anchor_map)
            ),
            mock.patch.object(worker, "required_bars", return_value=5),
            self.assertRaisesRegex(
                worker.EpochError, "OFFICIAL_CLOSED_BAR_FETCH_FAILED"
            ),
        ):
            asyncio.run(worker.recover(current, publish=False, status_path=status))
        self.assertTrue(pool.closed)

    def _run_chunked_recovery(self, chunks, *, content_length=None):
        pool = _FakePool(_FakeOutboxConnection([]))
        fetched = []
        chunk_sizes = []
        self._observed_chunk_sizes = chunk_sizes
        asyncpg = types.ModuleType("asyncpg")

        async def create_pool(*_args, **_kwargs):
            return pool

        asyncpg.create_pool = create_pool

        class Content:
            def __init__(self, values):
                self.values = values

            async def iter_chunked(self, size):
                chunk_sizes.append(size)
                for value in self.values:
                    yield value

        class Response:
            status = 200

            def __init__(self, values):
                self.content = Content(values)
                self.content_length = content_length

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class Session:
            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def get(self, url, *, params, allow_redirects):
                self.last_request = (url, params, allow_redirects)
                return Response(chunks)

        aiohttp = types.ModuleType("aiohttp")
        aiohttp.ClientSession = Session
        aiohttp.ClientTimeout = lambda **_kwargs: object()
        quant = types.ModuleType("kairos_quant")
        recovery = types.ModuleType("kairos_quant.long_gap_recovery")
        recovery.RecoveryStatus = lambda emit: types.SimpleNamespace(emit=emit)

        async def fake_recover(anchor, *, end_exclusive, fetch, **_kwargs):
            result = await fetch("BTCUSDT", 0, worker.MINUTE)
            fetched.append(result)
            return 1

        recovery.recover_symbol = fake_recover
        end = (int(time.time() * 1000) // worker.MINUTE - 1) * worker.MINUTE
        config = _catchup_config(end_exclusive_ms=end)
        anchors = {
            symbol: types.SimpleNamespace(close_time_ms=end - worker.MINUTE - 1)
            for symbol in worker.SYMBOLS
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                sys.modules,
                {
                    "asyncpg": asyncpg,
                    "aiohttp": aiohttp,
                    "kairos_quant": quant,
                    "kairos_quant.long_gap_recovery": recovery,
                    **self._writer_modules(),
                },
            ),
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
            mock.patch.object(
                worker, "anchors", new=mock.AsyncMock(return_value=anchors)
            ),
            mock.patch.object(
                worker, "required_bars", return_value=len(worker.SYMBOLS)
            ),
        ):
            result = asyncio.run(
                worker.recover(
                    config, publish=False, status_path=Path(directory) / "progress.json"
                )
            )
        self.assertEqual(result["state"], "AUDIT_ONLY_CATCHUP_COMPLETE")
        self.assertTrue(pool.closed)
        return fetched, chunk_sizes

    def test_recovery_reads_chunked_http_body_and_parses_complete_json(self):
        body = b'{"ok":true,"bars":[1,2]}'
        fetched, chunk_sizes = self._run_chunked_recovery(
            [body[:7], body[7:15], body[15:]], content_length=len(body)
        )
        self.assertEqual(fetched, [{"ok": True, "bars": [1, 2]}] * len(worker.SYMBOLS))
        self.assertEqual(chunk_sizes, [65536] * len(worker.SYMBOLS))

    def test_recovery_rejects_chunked_http_body_over_two_megabytes(self):
        chunks = [b"x" * 65536 for _ in range(40)]
        with self.assertRaisesRegex(worker.EpochError, "REST_RESPONSE_BOUND_EXCEEDED"):
            self._run_chunked_recovery(chunks)
        self.assertTrue(self._observed_chunk_sizes)
        self.assertTrue(all(size == 65536 for size in self._observed_chunk_sizes))

    @staticmethod
    def _writer_modules():
        package = types.ModuleType("kairos_persistence")
        package.__path__ = []
        repo_module = types.ModuleType("kairos_persistence.repository")
        repo_module.AuditRepository = type(
            "AuditRepository", (), {"__init__": lambda self, _pool: None}
        )
        runtime_module = types.ModuleType("kairos_persistence.runtime")
        runtime_module.canonical_payload = lambda value: (json.dumps(value), "0" * 64)
        return {
            "kairos_persistence": package,
            "kairos_persistence.repository": repo_module,
            "kairos_persistence.runtime": runtime_module,
        }


if __name__ == "__main__":
    unittest.main()
