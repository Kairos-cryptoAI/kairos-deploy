"""Fail-closed boot/restart proofs for the isolated non-trading epoch worker."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import runtime_epoch_worker as worker

OWNER = "0123456789abcdef0123456789abcdef"
DB = "kairos_epoch_0123456789ab"


def boot_seed() -> dict:
    counts = {
        "BTCUSDT": 35_429,
        "ETHUSDT": 35_429,
        "SOLUSDT": 35_429,
        "BNBUSDT": 34_633,
        "XRPUSDT": 35_428,
    }
    anchors = {}
    for symbol, count in counts.items():
        first = 1_787_754_720_000 if symbol == "XRPUSDT" else 1_787_754_660_000
        last = first + (count - 1) * worker.MINUTE
        anchors[symbol] = {
            "count": count,
            "first_open_time_ms": first,
            "last_open_time_ms": last,
            "last_close_time_ms": last + worker.MINUTE - 1,
        }
    table_rows = {
        name: {"count": 0, "sha256": "a" * 64}
        for name in worker.CONTROLLED_RUNTIME_PUBLIC_TABLES
    }
    table_rows["schema_migrations"]["count"] = 30
    table_rows["event_audit"]["count"] = sum(counts.values())
    table_rows["event_audit"]["sha256"] = "b" * 64
    table_rows["message_outbox"]["count"] = 2_220
    table_rows["message_inbox"]["count"] = 2_220
    table_rows["paper_canary_database_identity"] = {
        "count": 1,
        "sha256": "ba22f0bf5a60970ce0553e4c307106244912c7764e0f355a1955be65898e6e38",
    }
    return {
        "state": "PASS_BOOT_STATE",
        "matched_public_tables": 32,
        "tables": table_rows,
        "sequences": {"message_outbox_id_seq": {"last_value": 2220, "is_called": True}},
        "anchors": anchors,
        "original_prefix": {
            "rows": worker.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": worker.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": worker.ORIGINAL_PREFIX_LAST_OPEN_MS,
        },
        "queue": {
            "outbox_rows": 2_220,
            "inbox_rows": 2_220,
            "completed_inbox": 2_220,
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "trading_rows": 0,
        },
        "trading_started": False,
    }


def base(**changes) -> dict:
    value = {
        "owner": OWNER,
        "database": DB,
        "pg_host": "kairos-epoch-0123456789ab-pg",
        "redis_host": "kairos-epoch-0123456789ab-redis",
    }
    value.update(changes)
    return value


class BootConfigTests(unittest.TestCase):
    def test_boot_state_and_restore_configs_are_exact_and_read_only(self):
        worker.validate_config(base(admin_password="a" * 64), "boot-state")
        for bad in (
            base(admin_password="a" * 64, producer_password="b" * 64),
            base(admin_password="a" * 64, expected_seed=boot_seed()),
            base(admin_password="a" * 64, pg_host="kairos-epoch-0123456789ab-source"),
        ):
            with self.subTest(bad=bad), self.assertRaises(worker.EpochError):
                worker.validate_config(bad, "boot-state")

        expected = boot_seed()
        restore = base(
            admin_password="a" * 64,
            restore_host="kairos-epoch-0123456789ab-restore",
            restore_database="kairos_recovery_0123456789ab_epochrestore",
            restore_admin_password="b" * 64,
            expected_seed=expected,
        )
        worker.validate_config(restore, "boot-verify-restore")
        restore["expected_seed"] = {**expected, "unexpected": True}
        with self.assertRaisesRegex(worker.EpochError, "EXACT_BOOT_STATE_EXPECTATION"):
            worker.validate_config(restore, "boot-verify-restore")

    def test_boot_catchup_requires_exact_seed_and_bounded_fixed_deadline(self):
        end = (int(time.time() * 1000) // worker.MINUTE - 1) * worker.MINUTE
        valid = base(
            history_password="a" * 64,
            end_exclusive_ms=end,
            maximum_bars=worker.MAX_BARS,
            expected_seed=boot_seed(),
        )
        worker.validate_config(valid, "boot-catchup")
        for bad in (
            {**valid, "maximum_bars": worker.MAX_BARS - 1},
            {**valid, "expected_seed": {}},
            {**valid, "admin_password": "b" * 64},
            {**valid, "end_exclusive_ms": end + 1},
        ):
            with self.subTest(bad=bad), self.assertRaises(worker.EpochError):
                worker.validate_config(bad, "boot-catchup")

    def test_boot_redis_state_requires_only_separate_runtime_identities(self):
        config = base(
            producer_password="a" * 64,
            consumer_password="b" * 64,
            redis_producer_password="c" * 64,
            redis_consumer_password="d" * 64,
        )
        worker.validate_config(config, "boot-redis-state")
        with self.assertRaises(worker.EpochError):
            worker.validate_config(
                {**config, "admin_password": "e" * 64}, "boot-redis-state"
            )
        with self.assertRaisesRegex(worker.EpochError, "EXACT_OWNED_BOOT_EPOCH_HOSTS"):
            worker.validate_config(
                {**config, "redis_host": "kairos-epoch-0123456789ab-source"},
                "boot-redis-state",
            )

    def test_clone_proof_requires_exact_disposable_host_and_no_admin(self):
        config = base(
            producer_password="a" * 64,
            consumer_password="b" * 64,
            redis_producer_password="c" * 64,
            redis_consumer_password="d" * 64,
            redis_host="kairos-epoch-0123456789ab-redisclone",
        )
        worker.validate_config(config, "boot-redis-clone")
        for change in (
            {"redis_host": "kairos-epoch-0123456789ab-redis"},
            {"pg_host": "kairos-epoch-0123456789ab-source"},
            {"admin_password": "e" * 64},
        ):
            with self.subTest(change=change), self.assertRaises(worker.EpochError):
                worker.validate_config({**config, **change}, "boot-redis-clone")


class BootSeedGuardTests(unittest.TestCase):
    def test_only_the_exact_previously_restored_migration_identity_is_admitted(self):
        accepted = boot_seed()
        worker.validate_boot_seed(accepted, OWNER, DB)
        for changed in (
            {"count": 0, "sha256": "a" * 64},
            {**worker.BOOT_DATABASE_IDENTITY, "count": 2},
            {**worker.BOOT_DATABASE_IDENTITY, "sha256": "0" * 64},
        ):
            value = copy.deepcopy(accepted)
            value["tables"]["paper_canary_database_identity"] = changed
            with (
                self.subTest(changed=changed),
                self.assertRaisesRegex(
                    worker.EpochError, "BOOT_MIGRATION_DATABASE_IDENTITY_CONFLICT"
                ),
            ):
                worker.validate_boot_seed(value, OWNER, DB)
        for table in ("paper_canary_sessions", "paper_canary_arms", "execution_orders"):
            value = copy.deepcopy(accepted)
            value["tables"][table]["count"] = 1
            with (
                self.subTest(table=table),
                self.assertRaisesRegex(
                    worker.EpochError, "BOOT_STATE_NON_AUDIT_TABLE_NOT_EMPTY"
                ),
            ):
                worker.validate_boot_seed(value, OWNER, DB)

    def test_all_preexisting_audit_rows_remain_hash_bound_after_catchup(self):
        expected = boot_seed()
        connection = mock.AsyncMock()
        connection.fetchrow.return_value = {
            "n": expected["tables"]["event_audit"]["count"],
            "digest": expected["tables"]["event_audit"]["sha256"],
        }
        asyncio.run(worker.validate_boot_audit_prefix(connection, expected))
        args = connection.fetchrow.call_args.args
        self.assertIn("unnest($3::text[],$4::bigint[])", args[0])
        self.assertEqual(args[3], list(worker.SYMBOLS))
        self.assertEqual(
            args[4],
            [expected["anchors"][s]["last_open_time_ms"] for s in worker.SYMBOLS],
        )
        connection.fetchrow.return_value["digest"] = "0" * 64
        with self.assertRaisesRegex(
            worker.EpochError, "BOOT_PREEXISTING_AUDIT_PREFIX_CONFLICT"
        ):
            asyncio.run(worker.validate_boot_audit_prefix(connection, expected))

    def test_seed_accepts_completed_queues_without_pin_to_a_specific_count(self):
        state = boot_seed()
        state["queue"]["outbox_rows"] += 5
        state["queue"]["inbox_rows"] += 5
        state["queue"]["completed_inbox"] += 5
        state["tables"]["message_outbox"]["count"] += 5
        state["tables"]["message_inbox"]["count"] += 5
        worker.validate_boot_seed(state, OWNER, DB)

    def test_seed_rejects_trading_rows_nonempty_tables_and_queue_drift(self):
        mutations = []
        state = boot_seed()
        state["tables"]["execution_orders"]["count"] = 1
        mutations.append(state)
        state = boot_seed()
        state["queue"]["pending_outbox"] = 1
        mutations.append(state)
        state = boot_seed()
        state["tables"]["message_inbox"]["count"] -= 1
        mutations.append(state)
        state = boot_seed()
        state["original_prefix"]["audit_table_sha256"] = "0" * 64
        mutations.append(state)
        state = boot_seed()
        del state["anchors"]["BNBUSDT"]
        mutations.append(state)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(worker.EpochError):
                worker.validate_boot_seed(value, OWNER, DB)

    def test_worker_locks_are_probed_and_always_released(self):
        class Connection:
            def __init__(self, held=None):
                self.held = held
                self.probes = []
                self.releases = []

            async def fetchval(self, query, key):
                if "try_advisory_lock" in query:
                    self.probes.append(key)
                    return key != self.held
                self.releases.append(key)
                return True

        clean = Connection()
        asyncio.run(worker.validate_no_epoch_workers(clean))
        self.assertEqual(clean.probes, list(worker.BOOT_ADVISORY_LOCKS))
        self.assertEqual(clean.releases, list(reversed(worker.BOOT_ADVISORY_LOCKS)))
        held = Connection(worker.BOOT_ADVISORY_LOCKS[1])
        with self.assertRaisesRegex(worker.EpochError, "EPOCH_WORKER_LOCK_STILL_HELD"):
            asyncio.run(worker.validate_no_epoch_workers(held))
        self.assertEqual(held.releases, [worker.BOOT_ADVISORY_LOCKS[0]])

    def test_redis_stream_allows_one_exact_qualification_duplicate_only(self):
        durable = {
            "bar-1": ("a" * 64, '{"message_id":"bar-1"}'),
            "bar-2": ("b" * 64, '{"message_id":"bar-2"}'),
        }
        rows = [
            ("1-0", {"data": durable["bar-1"][1]}),
            ("2-0", {"data": durable["bar-2"][1]}),
            ("3-0", {"data": durable["bar-2"][1]}),
        ]
        worker.validate_boot_stream_rows(rows, durable, {"1-0", "2-0"})
        invalid = (
            rows[:-1],
            rows + [("4-0", {"data": "unowned"})],
            rows[:-1] + [("3-0", {"data": "forged", "other": "field"})],
            rows[1:],
        )
        for value in invalid:
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(
                    worker.EpochError, "BOOT_REDIS_UNOWNED_STREAM_ENTRY"
                ),
            ):
                worker.validate_boot_stream_rows(value, durable, {"1-0", "2-0"})

    def test_existing_queue_requires_published_hash_bound_rows_and_completed_inbox(
        self,
    ):
        payload = {"message_id": "bar-1", "source": worker.SOURCE, "symbol": "BTCUSDT"}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        outbox_row = {
            "id": 1,
            "message_id": "bar-1",
            "topic": worker.TOPIC,
            "payload": payload,
            "payload_sha256": digest,
            "producer": worker.SOURCE,
            "published_at": "published",
            "publish_attempts": 1,
            "last_error": None,
            "lease_owner": None,
            "lease_until": None,
            "dead_lettered_at": None,
            "reconciliation_state": "NONE",
        }
        inbox_row = {
            "consumer": "kairos-epoch-consumer-0123456789ab:bars",
            "message_id": "bar-1",
            "topic": worker.TOPIC,
            "status": "COMPLETED",
            "payload_sha256": digest,
        }

        class Connection:
            def __init__(self):
                self.outbox = [outbox_row]
                self.inbox = [inbox_row]
                self.audit_orphans = 0

            async def fetch(self, query):
                return self.outbox if "FROM message_outbox" in query else self.inbox

            async def fetchval(self, _query):
                return self.audit_orphans

        core = types.ModuleType("kairos_core")
        core.__path__ = []
        contracts = types.ModuleType("kairos_core.contracts")
        contracts.ClosedBarEventV1 = type(
            "ClosedBarEventV1",
            (),
            {
                "model_validate": staticmethod(
                    lambda value: types.SimpleNamespace(**value)
                )
            },
        )
        persistence = types.ModuleType("kairos_persistence")
        persistence.__path__ = []
        runtime = types.ModuleType("kairos_persistence.runtime")
        runtime.canonical_payload = lambda value: (
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )
        connection = Connection()
        with mock.patch.dict(
            sys.modules,
            {
                "kairos_core": core,
                "kairos_core.contracts": contracts,
                "kairos_persistence": persistence,
                "kairos_persistence.runtime": runtime,
            },
        ):
            result = asyncio.run(worker.boot_queue_state(connection, OWNER))
            self.assertEqual(result["outbox_rows"], 1)
            connection.outbox = [{**outbox_row, "lease_owner": "stale"}]
            with self.assertRaisesRegex(worker.EpochError, "BOOT_QUEUE_IDENTITY"):
                asyncio.run(worker.boot_queue_state(connection, OWNER))
            connection.outbox = [outbox_row]
            connection.audit_orphans = 1
            with self.assertRaisesRegex(worker.EpochError, "BOOT_QUEUE_AUDIT_IDENTITY"):
                asyncio.run(worker.boot_queue_state(connection, OWNER))


class RedisInterfaceProofTests(unittest.TestCase):
    """Exercise the actual coroutine/driver interface, not only pure validators."""

    def fixture(self):
        payload = {"message_id": "bar-1", "source": worker.SOURCE, "symbol": "BTCUSDT"}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        outbox = {
            "message_id": "bar-1",
            "topic": worker.TOPIC,
            "payload": payload,
            "payload_sha256": digest,
            "producer": worker.SOURCE,
            "published_at": "published",
            "publish_attempts": 1,
            "last_error": None,
            "lease_owner": None,
            "lease_until": None,
            "dead_lettered_at": None,
            "reconciliation_state": "NONE",
        }
        inbox = {
            "consumer": "kairos-epoch-consumer-0123456789ab:bars",
            "message_id": "bar-1",
            "topic": worker.TOPIC,
            "status": "COMPLETED",
            "payload_sha256": digest,
        }
        state = types.SimpleNamespace(
            outbox=[outbox],
            inbox=[inbox],
            receipt=json.dumps([digest, "1-0"]),
            rows=[("1-0", {"data": encoded}), ("2-0", {"data": encoded})],
            groups=[{"name": "bars", "last-delivered-id": "2-0"}],
            pending={"pending": 0},
            clients=[],
            anonymous_allowed=False,
            role_authenticated=True,
            commands=[],
        )
        producer_sql, consumer_sql = mock.AsyncMock(), mock.AsyncMock()
        producer_sql.fetch.return_value = state.outbox
        consumer_sql.fetch.return_value = state.inbox

        class AuthenticationError(Exception):
            pass

        class Redis:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.closed = False
                state.clients.append(self)

            async def ping(self):
                return state.role_authenticated

            async def execute_command(self, *command):
                state.commands.append(command)
                if state.anonymous_allowed:
                    return True
                raise AuthenticationError("withheld")

            async def hget(self, key, field):
                if (
                    key != "kairos.runtime." + OWNER + ".publication"
                    or field != "bar-1"
                ):
                    raise AssertionError("unexpected ledger identity")
                return state.receipt

            async def xrange(self, name, **bounds):
                if name != worker.TOPIC:
                    raise AssertionError("unexpected stream")
                return state.rows[:1] if bounds["min"] != "-" else state.rows

            async def xinfo_groups(self, name):
                if name != worker.TOPIC:
                    raise AssertionError("unexpected groups")
                return state.groups

            async def xpending(self, name, group):
                if (name, group) != (worker.TOPIC, "bars"):
                    raise AssertionError("unexpected pending scope")
                return state.pending

            async def aclose(self):
                self.closed = True

        core = types.ModuleType("kairos_core")
        core.__path__ = []
        contracts = types.ModuleType("kairos_core.contracts")
        contracts.ClosedBarEventV1 = types.SimpleNamespace(
            model_validate=lambda value: types.SimpleNamespace(**value)
        )
        persistence = types.ModuleType("kairos_persistence")
        persistence.__path__ = []
        runtime = types.ModuleType("kairos_persistence.runtime")
        runtime.canonical_payload = lambda value: (
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )
        redis = types.ModuleType("redis")
        redis.__path__ = []
        redis_async = types.ModuleType("redis.asyncio")
        redis_async.Redis = Redis
        redis.asyncio = redis_async
        exceptions = types.ModuleType("redis.exceptions")
        exceptions.AuthenticationError = AuthenticationError
        config = base(
            producer_password="a" * 64,
            consumer_password="b" * 64,
            redis_producer_password="c" * 64,
            redis_consumer_password="d" * 64,
        )
        modules = {
            "kairos_core": core,
            "kairos_core.contracts": contracts,
            "kairos_persistence": persistence,
            "kairos_persistence.runtime": runtime,
            "redis": redis,
            "redis.asyncio": redis_async,
            "redis.exceptions": exceptions,
        }
        return state, producer_sql, consumer_sql, config, modules

    def run_proof(self, fixture, *, clone=False):
        _state, producer_sql, consumer_sql, config, modules = fixture
        with (
            mock.patch.dict(sys.modules, modules),
            mock.patch.object(
                worker,
                "connect",
                new=mock.AsyncMock(side_effect=[producer_sql, consumer_sql]),
            ),
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
        ):
            return asyncio.run(worker.boot_redis_state(config, clone=clone))

    def test_actual_readonly_proof_matches_receipts_stream_groups_and_closes(self):
        fixture = self.fixture()
        result = self.run_proof(fixture)
        self.assertEqual(result["state"], "PASS_BOOT_REDIS_STATE")
        self.assertEqual(result["publication_receipts"], 1)
        self.assertEqual(result["stream_entries"], 2)
        self.assertEqual(
            result["publication_message_ids_sha256"],
            hashlib.sha256(b'["bar-1"]').hexdigest(),
        )
        self.assertEqual(fixture[0].commands, [("PING",), ("AUTH", "default", "")])
        self.assertTrue(all(client.closed for client in fixture[0].clients))
        fixture[1].close.assert_awaited_once()
        fixture[2].close.assert_awaited_once()

    def test_only_disposable_clone_receives_anonymous_write_denial_probe(self):
        fixture = self.fixture()
        result = self.run_proof(fixture, clone=True)
        self.assertTrue(result["auth_proofs"]["anonymous_write_refused_on_clone"])
        self.assertEqual(fixture[0].commands[-1][0], "XADD")

    def test_missing_aof_transaction_effects_fail_before_any_serving(self):
        fixture = self.fixture()
        fixture[0].receipt = None
        with self.assertRaisesRegex(worker.EpochError, "PUBLICATION_RECEIPT_MISSING"):
            self.run_proof(fixture)
        self.assertTrue(all(client.closed for client in fixture[0].clients))

    def test_conflict_pending_unknown_group_or_auth_fail_closed(self):
        changes = (
            ("receipt", '["forged","1-0"]'),
            ("pending", {"pending": 1}),
            ("groups", [{"name": "wrong", "last-delivered-id": "2-0"}]),
            ("anonymous_allowed", True),
            ("role_authenticated", False),
        )
        for name, value in changes:
            fixture = self.fixture()
            setattr(fixture[0], name, value)
            with self.subTest(name=name), self.assertRaises(worker.EpochError):
                self.run_proof(fixture)
            self.assertTrue(all(client.closed for client in fixture[0].clients))


class BootDispatchTests(unittest.TestCase):
    def test_boot_verify_restore_requires_both_full_snapshots_to_equal_seed(self):
        expected = boot_seed()
        config = base(
            admin_password="a" * 64,
            restore_host="kairos-epoch-0123456789ab-restore",
            restore_database="kairos_recovery_0123456789ab_epochrestore",
            restore_admin_password="b" * 64,
            expected_seed=expected,
        )
        original = mock.AsyncMock()
        restored = mock.AsyncMock()
        asyncpg = types.ModuleType("asyncpg")
        asyncpg.connect = mock.AsyncMock(return_value=restored)
        with (
            mock.patch.dict(sys.modules, {"asyncpg": asyncpg}),
            mock.patch.object(
                worker, "connect", new=mock.AsyncMock(return_value=original)
            ),
            mock.patch.object(
                worker,
                "boot_state_snapshot",
                new=mock.AsyncMock(return_value=copy.deepcopy(expected)),
            ) as snapshot,
        ):
            result = asyncio.run(worker.boot_verify_restore(config))
        self.assertEqual(snapshot.await_count, 2)
        self.assertEqual(result["state"], "PASS_BOOT_ISOLATED_RESTORE")
        original.close.assert_awaited_once()
        restored.close.assert_awaited_once()

    def test_boot_catchup_calls_existing_audit_only_recovery_with_seed_guard(self):
        expected = boot_seed()
        config = {
            **base(
                history_password="a" * 64,
                end_exclusive_ms=(int(time.time() * 1000) // worker.MINUTE - 1)
                * worker.MINUTE,
                maximum_bars=worker.MAX_BARS,
                expected_seed=expected,
            )
        }
        with mock.patch.object(
            worker,
            "recover",
            new=mock.AsyncMock(return_value={"state": "AUDIT_ONLY_CATCHUP_COMPLETE"}),
        ) as recover:
            result = asyncio.run(worker.boot_catchup(config, Path("unused")))
        recover.assert_awaited_once_with(
            config,
            publish=False,
            status_path=Path("unused") / "progress.json",
            boot_expected=expected,
        )
        self.assertEqual(result["state"], "AUDIT_ONLY_CATCHUP_COMPLETE")


if __name__ == "__main__":
    unittest.main()
