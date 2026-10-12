"""Offline safety tests for exact R5 inbox recovery admission."""

from __future__ import annotations

import asyncio
import json
import sys
import types
import unittest
from unittest import mock

from scripts import runtime_epoch_read_recovery_worker as r5


def config(**changes):
    value = {
        "owner": r5.OWNER,
        "database": "kairos_epoch_" + r5.OWNER[:12],
        "pg_host": "kairos-epoch-" + r5.OWNER[:12] + "-pg",
        "redis_host": "kairos-epoch-" + r5.OWNER[:12] + "-redis",
        **{
            key: "a" * 64
            for key in (
                "admin_password",
                "producer_password",
                "consumer_password",
                "redis_producer_password",
                "redis_consumer_password",
            )
        },
    }
    value.update(changes)
    return value


def state_fixture():
    tables = {
        name: {"count": 0, "sha256": "0" * 64}
        for name in r5.epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES
    }
    tables["event_audit"]["count"] = r5.EXPECTED_COUNTS["audit"]
    tables["message_outbox"]["count"] = r5.EXPECTED_COUNTS["outbox"]
    tables["message_inbox"]["count"] = r5.EXPECTED_COUNTS["inbox"]
    tables["paper_canary_database_identity"] = dict(r5.epoch.BOOT_DATABASE_IDENTITY)
    counts = [67_286, 67_286, 67_286, 67_286, 67_285]
    anchors = {}
    for symbol, count in zip(r5.epoch.SYMBOLS, counts, strict=True):
        first = 1_780_000_020_000
        last = first + (count - 1) * r5.epoch.MINUTE
        anchors[symbol] = {
            "count": count,
            "first_open_time_ms": first,
            "last_open_time_ms": last,
            "last_close_time_ms": last + r5.epoch.MINUTE - 1,
        }
    return {
        "owner": r5.OWNER,
        "mode": "r5-state",
        "new_epoch_database": "kairos_epoch_" + r5.OWNER[:12],
        "state": "PASS_R5_STATE",
        "matched_public_tables": len(tables),
        "tables": tables,
        "sequences": {},
        "anchors": anchors,
        "original_prefix": {
            "rows": r5.epoch.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": r5.epoch.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": r5.epoch.ORIGINAL_PREFIX_LAST_OPEN_MS,
        },
        "queue": {
            "outbox_rows": r5.EXPECTED_COUNTS["outbox"],
            "inbox_rows": r5.EXPECTED_COUNTS["inbox"],
            "completed_inbox": r5.EXPECTED_COUNTS["inbox"],
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "trading_rows": 0,
            "missing_inbox_message_ids": sorted(r5.TARGET_IDS),
        },
        "preserved_queue_prefixes": {
            "message_outbox": {"n": 5331, "sha": "1" * 64},
            "message_inbox": {"n": 5331, "sha": "2" * 64},
        },
        "trading_started": False,
        "redis": {
            "stream_entries": 5337,
            "publication_receipts": 5336,
            "publication_receipts_sha256": "3" * 64,
            "publication_message_ids_sha256": "4" * 64,
            "stream_sha256": "5" * 64,
            "stream_last_id": "6000-0",
            "consumer_group": "bars",
            "last_delivered_id": "5900-0",
            "pending_deliveries": 5,
            "pending_target_message_ids": sorted(r5.TARGET_IDS),
            "trading_started": False,
        },
    }


def core_and_persistence_modules():
    core = types.ModuleType("kairos_core.contracts")
    core.ClosedBarEventV1 = types.SimpleNamespace(
        model_validate=lambda payload: types.SimpleNamespace(**payload)
    )
    persistence = types.ModuleType("kairos_persistence.runtime")

    def canonical_payload(payload):
        return payload["encoded"], payload["test_hash"]

    persistence.canonical_payload = canonical_payload
    return core, persistence


def queue_fixture():
    outbox = []
    inbox = []
    for index in range(r5.EXPECTED_COUNTS["inbox"]):
        message_id = f"ordinary-{index}"
        payload = {
            "message_id": message_id,
            "source": r5.epoch.SOURCE,
            "symbol": "BTCUSDT",
            "open_time_ms": 1_791_791_760_000,
            "encoded": f"payload-{message_id}",
            "test_hash": f"hash-{message_id}",
        }
        outbox.append(
            {
                "id": index + 1,
                "message_id": message_id,
                "topic": r5.epoch.TOPIC,
                "payload": payload,
                "payload_sha256": payload["test_hash"],
                "producer": r5.epoch.SOURCE,
                "published_at": "published",
                "publish_attempts": 1,
                "last_error": None,
                "lease_owner": None,
                "lease_until": None,
                "dead_lettered_at": None,
                "reconciliation_state": "NONE",
            }
        )
        inbox.append(
            {
                "consumer": r5.CONSUMER_SERVICE + ":bars",
                "message_id": message_id,
                "topic": r5.epoch.TOPIC,
                "payload_sha256": payload["test_hash"],
                "status": "COMPLETED",
            }
        )
    for target in r5.TARGETS:
        payload = {
            "message_id": target["message_id"],
            "source": r5.epoch.SOURCE,
            "symbol": target["symbol"],
            "open_time_ms": target["open_time_ms"],
            "encoded": f"payload-{target['message_id']}",
            "test_hash": target["payload_sha256"],
        }
        outbox.append(
            {
                "id": target["outbox_id"],
                "message_id": target["message_id"],
                "topic": r5.epoch.TOPIC,
                "payload": payload,
                "payload_sha256": target["payload_sha256"],
                "producer": r5.epoch.SOURCE,
                "published_at": "published",
                "publish_attempts": 1,
                "last_error": None,
                "lease_owner": None,
                "lease_until": None,
                "dead_lettered_at": None,
                "reconciliation_state": "NONE",
            }
        )
    return outbox, inbox


class ConfigTests(unittest.TestCase):
    def test_exact_mode_configs_and_restore_sql_only_fields(self):
        r5.validate_config("r5-state", config())
        r5.validate_config("r5-drain", config(expected_state=state_fixture()))
        r5.validate_config(
            "r5-verify-restore",
            {
                **{
                    key: config()[key]
                    for key in (
                        "owner",
                        "database",
                        "pg_host",
                        "redis_host",
                        "admin_password",
                    )
                },
                "restore_host": r5.RESTORE_HOST,
                "restore_database": r5.RESTORE_DATABASE,
                "restore_admin_password": "b" * 64,
                "expected_seed": state_fixture(),
            },
        )

    def test_restore_rejects_runtime_credentials_and_wrong_clone_before_io(self):
        value = {
            **{
                key: config()[key]
                for key in (
                    "owner",
                    "database",
                    "pg_host",
                    "redis_host",
                    "admin_password",
                )
            },
            "restore_host": r5.RESTORE_HOST,
            "restore_database": r5.RESTORE_DATABASE,
            "restore_admin_password": "b" * 64,
            "expected_seed": state_fixture(),
        }
        for change in (
            {"producer_password": "a" * 64},
            {"restore_host": "kairos-paper-gate-timescaledb-1"},
            {"restore_database": "kairos"},
        ):
            with self.subTest(change=change), self.assertRaises(r5.epoch.EpochError):
                r5.validate_config("r5-verify-restore", {**value, **change})

    def test_unsupported_mode_and_foreign_epoch_rejected(self):
        for mode, changes in (
            ("replay", {}),
            ("r5-drain", {"owner": "f" * 32, "expected_state": {}}),
            ("r5-state", {"database": "kairos"}),
            ("r5-state", {"trading_started": True}),
        ):
            with (
                self.subTest(mode=mode, changes=changes),
                self.assertRaises(r5.epoch.EpochError),
            ):
                r5.validate_config(mode, config(**changes))


class QueueAdmissionTests(unittest.TestCase):
    def test_only_exact_five_target_inbox_gaps_are_admitted(self):
        outbox, inbox = queue_fixture()
        core, persistence = core_and_persistence_modules()
        with mock.patch.dict(
            sys.modules,
            {"kairos_core.contracts": core, "kairos_persistence.runtime": persistence},
        ):
            queue, durable, completed = r5.validate_queue(outbox, inbox)
        self.assertEqual(queue["missing_inbox_message_ids"], sorted(r5.TARGET_IDS))
        self.assertEqual(queue["outbox_rows"], 5336)
        self.assertEqual(queue["inbox_rows"], 5331)
        self.assertEqual(len(durable), 5336)
        self.assertEqual(len(completed), 5331)

    def test_state_accepts_exact_prestate_or_fully_completed_poststate_only(self):
        outbox, inbox = queue_fixture()
        for row in outbox[-len(r5.TARGETS) :]:
            inbox.append(
                {
                    "consumer": r5.CONSUMER_SERVICE + ":bars",
                    "message_id": row["message_id"],
                    "topic": r5.epoch.TOPIC,
                    "payload_sha256": row["payload_sha256"],
                    "status": "COMPLETED",
                }
            )
        core, persistence = core_and_persistence_modules()
        with mock.patch.dict(
            sys.modules,
            {"kairos_core.contracts": core, "kairos_persistence.runtime": persistence},
        ):
            queue, _durable, completed = r5.validate_queue(outbox, inbox)
            self.assertEqual(queue["missing_inbox_message_ids"], [])
            self.assertEqual(queue["completed_inbox"], r5.EXPECTED_COUNTS["outbox"])
            self.assertEqual(len(completed), r5.EXPECTED_COUNTS["outbox"])
            with self.assertRaises(r5.epoch.EpochError):
                r5.validate_queue(outbox, inbox[:-1])

    def test_extra_gap_or_target_identity_change_fails_closed(self):
        outbox, inbox = queue_fixture()
        core, persistence = core_and_persistence_modules()
        with mock.patch.dict(
            sys.modules,
            {"kairos_core.contracts": core, "kairos_persistence.runtime": persistence},
        ):
            changed = [dict(row) for row in inbox]
            changed[-1]["message_id"] = "orphan"
            with self.assertRaisesRegex(r5.epoch.EpochError, "UNEXPECTED_INBOX_GAP"):
                r5.validate_queue(outbox, changed)
            bad = [dict(row) for row in outbox]
            bad[-1]["payload_sha256"] = "0" * 64
            with self.assertRaisesRegex(r5.epoch.EpochError, "OUTBOX_IDENTITY"):
                r5.validate_queue(bad, inbox)


class RedisSnapshotTests(unittest.TestCase):
    def _fake_clients(
        self,
        *,
        pending_count=3,
        omit_pending=(),
        extra_pending=False,
        last_delivered="102-0",
    ):
        durable = {}
        stream = []
        receipts = {}
        for index, target in enumerate(r5.TARGETS):
            stream_id = f"{100 + index}-0"
            encoded = f"payload-{target['message_id']}"
            durable[target["message_id"]] = (target["payload_sha256"], encoded)
            receipts[target["message_id"]] = json.dumps(
                [target["payload_sha256"], stream_id]
            )
            stream.append((stream_id, {"data": encoded}))
        stream.append(("105-0", {"data": stream[0][1]["data"]}))
        pending = [
            {"message_id": f"{100 + index}-0", "consumer": "consumer-host-123"}
            for index in range(pending_count)
            if index not in omit_pending
        ]
        if extra_pending:
            pending.append({"message_id": "999-0", "consumer": "consumer-host-123"})

        class FakeRedis:
            def __init__(self, *, username, **_kwargs):
                self.username = username

            async def hget(self, _key, message_id):
                return receipts.get(message_id)

            async def hgetall(self, _key):
                return dict(receipts)

            async def xrange(self, _topic, min="-", max="+"):
                if min == max:
                    return [row for row in stream if row[0] == min]
                return list(stream)

            async def xinfo_groups(self, _topic):
                return [{"name": "bars", "last-delivered-id": last_delivered}]

            async def xpending(self, _topic, _group):
                return {"pending": len(pending)}

            async def xpending_range(self, *_args, **_kwargs):
                return list(pending)

            async def aclose(self):
                return None

        redis_async = types.ModuleType("redis.asyncio")
        redis_async.Redis = FakeRedis
        redis_package = types.ModuleType("redis")
        redis_package.__path__ = []
        redis_package.asyncio = redis_async
        return durable, {"redis": redis_package, "redis.asyncio": redis_async}

    def test_partial_target_pending_and_old_cursor_are_accepted(self):
        durable, redis_modules = self._fake_clients(pending_count=3)
        with mock.patch.dict(sys.modules, redis_modules):
            result = asyncio.run(
                r5._redis_snapshot(config(), durable, set(), set(r5.TARGET_IDS))
            )
        self.assertEqual(result["pending_deliveries"], 3)
        self.assertEqual(
            result["pending_target_message_ids"],
            sorted(target["message_id"] for target in r5.TARGETS[:3]),
        )
        self.assertEqual(result["last_delivered_id"], "102-0")

    def test_missing_target_pel_and_foreign_pel_are_rejected(self):
        durable, redis_modules = self._fake_clients(pending_count=3, omit_pending={1})
        with (
            mock.patch.dict(sys.modules, redis_modules),
            self.assertRaises(r5.epoch.EpochError),
        ):
            asyncio.run(
                r5._redis_snapshot(config(), durable, set(), set(r5.TARGET_IDS))
            )
        durable, redis_modules = self._fake_clients(pending_count=3, extra_pending=True)
        with (
            mock.patch.dict(sys.modules, redis_modules),
            self.assertRaises(r5.epoch.EpochError),
        ):
            asyncio.run(
                r5._redis_snapshot(config(), durable, set(), set(r5.TARGET_IDS))
            )

    def test_completed_target_duplicates_and_clean_poststate_are_valid(self):
        durable, redis_modules = self._fake_clients(pending_count=3)
        completed = {target["message_id"] for target in r5.TARGETS[:2]}
        missing = r5.TARGET_IDS - completed
        with mock.patch.dict(sys.modules, redis_modules):
            result = asyncio.run(
                r5._redis_snapshot(config(), durable, completed, missing)
            )
        self.assertEqual(
            result["pending_target_message_ids"],
            sorted(target["message_id"] for target in r5.TARGETS[:3]),
        )

        durable, redis_modules = self._fake_clients(
            pending_count=0, last_delivered="105-0"
        )
        with mock.patch.dict(sys.modules, redis_modules):
            result = asyncio.run(
                r5._redis_snapshot(config(), durable, r5.TARGET_IDS, set())
            )
        self.assertEqual(result["pending_deliveries"], 0)


class ExactConsumerTests(unittest.TestCase):
    def test_consumer_acks_only_fixed_targets_and_uses_owned_transport_factory(self):
        calls = {"factory": [], "acks": [], "closed": 0}
        stop = asyncio.Event()
        completed = set()

        class FakeTransport:
            async def ack(self, topic, envelope, *, group=None):
                calls["acks"].append((topic, envelope.payload["message_id"], group))
                calls.setdefault("stop_during_ack", []).append(stop.is_set())

            async def close(self):
                calls["closed"] += 1

        transport = FakeTransport()

        class Settings:
            def __init__(self, **_kwargs):
                pass

        class Database:
            def __init__(self, *_args, **_kwargs):
                pass

            async def close(self):
                return None

        class MigrationProfile:
            CONTROLLED_RUNTIME = object()

        class FakeBus:
            def __init__(self, passed_transport, **kwargs):
                self.transport = passed_transport
                self.kwargs = kwargs

            async def subscribe(self, _topic, *, group):
                self.group = group
                for target in r5.TARGETS:
                    yield types.SimpleNamespace(
                        topic=r5.epoch.TOPIC,
                        id="unused",
                        payload={
                            "message_id": target["message_id"],
                            "source": r5.epoch.SOURCE,
                            "symbol": target["symbol"],
                            "open_time_ms": target["open_time_ms"],
                            "encoded": f"payload-{target['message_id']}",
                            "test_hash": target["payload_sha256"],
                        },
                    )

            async def ack(self, topic, envelope, *, group):
                await self.transport.ack(topic, envelope, group=group)

            async def close(self):
                await self.transport.close()

        core = types.ModuleType("kairos_core.contracts")
        core.ClosedBarEventV1 = types.SimpleNamespace(
            model_validate=lambda payload: types.SimpleNamespace(**payload)
        )
        persistence_config = types.ModuleType("kairos_persistence.config")
        persistence_config.PersistenceSettings = Settings
        persistence_database = types.ModuleType("kairos_persistence.database")
        persistence_database.Database = Database
        persistence_database.MigrationProfile = MigrationProfile
        persistence_runtime = types.ModuleType("kairos_persistence.runtime")
        persistence_runtime.DurableMessageBus = FakeBus
        persistence_runtime.canonical_payload = core_and_persistence_modules()[
            1
        ].canonical_payload

        def factory(url, event, telemetry):
            calls["factory"].append((url, event, dict(telemetry)))
            return transport

        with (
            mock.patch.object(
                r5.epoch, "create_runtime_transport", factory, create=True
            ),
            mock.patch.dict(
                sys.modules,
                {
                    "kairos_core.contracts": core,
                    "kairos_persistence.config": persistence_config,
                    "kairos_persistence.database": persistence_database,
                    "kairos_persistence.runtime": persistence_runtime,
                },
            ),
        ):
            metrics = asyncio.run(r5._consume_exact(config(), stop, completed))
        self.assertEqual(completed, r5.TARGET_IDS)
        self.assertEqual(len(calls["acks"]), len(r5.TARGETS))
        self.assertEqual(calls["closed"], 1)
        self.assertTrue(stop.is_set())
        self.assertEqual(calls["stop_during_ack"], [False] * len(r5.TARGETS))
        self.assertEqual(set(metrics["target_ack_message_ids"]), r5.TARGET_IDS)
        self.assertFalse(hasattr(transport, "publish"))
        self.assertIs(calls["factory"][0][1], stop)
        self.assertEqual(
            calls["factory"][0][2],
            {"transport_failures": 0, "recoveries": 0, "pending_replays": 0},
        )

    def test_drain_accepts_only_five_inbox_delta_and_preserves_stream_history(self):
        before = state_fixture()
        for key in ("owner", "mode", "new_epoch_database"):
            before.pop(key)
        after = json.loads(json.dumps(before))
        after["queue"].update(
            {
                "inbox_rows": r5.EXPECTED_COUNTS["outbox"],
                "completed_inbox": r5.EXPECTED_COUNTS["outbox"],
                "missing_inbox_message_ids": [],
            }
        )
        after["tables"]["message_inbox"].update(
            {"count": r5.EXPECTED_COUNTS["outbox"], "sha256": "6" * 64}
        )
        after["redis"].update(
            {
                "pending_deliveries": 0,
                "pending_target_message_ids": [],
                "last_delivered_id": "6000-0",
            }
        )
        completions = []

        async def consume(config_value, stop, completed):
            del config_value
            completions.append(stop)
            completed.update(r5.TARGET_IDS)
            return {"target_ack_message_ids": sorted(r5.TARGET_IDS)}

        class Checker:
            async def fetch(self, *_args):
                return [
                    {
                        "message_id": target["message_id"],
                        "payload_sha256": target["payload_sha256"],
                        "status": "COMPLETED",
                    }
                    for target in r5.TARGETS
                ]

            async def close(self):
                return None

        with (
            mock.patch.object(
                r5, "state_snapshot", side_effect=[(before, {}), (after, {})]
            ),
            mock.patch.object(r5, "_consume_exact", side_effect=consume),
            mock.patch.object(
                r5.epoch, "connect", new=mock.AsyncMock(return_value=Checker())
            ),
        ):
            result = asyncio.run(
                r5.drain(config(expected_state=state_fixture()), output=None)
            )
        self.assertEqual(result["completed_inbox_increment"], 5)
        self.assertEqual(result["published_messages"], 0)
        self.assertEqual(result["stream_entries_added"], 0)
        self.assertTrue(result["audit_history_preserved"])
        self.assertEqual(len(completions), 1)

    def test_drain_rejects_audit_or_stream_mutation(self):
        before = state_fixture()
        for key in ("owner", "mode", "new_epoch_database"):
            before.pop(key)
        after = json.loads(json.dumps(before))
        after["queue"].update(
            {
                "inbox_rows": r5.EXPECTED_COUNTS["outbox"],
                "completed_inbox": r5.EXPECTED_COUNTS["outbox"],
                "missing_inbox_message_ids": [],
            }
        )
        after["tables"]["message_inbox"].update(
            {"count": r5.EXPECTED_COUNTS["outbox"], "sha256": "6" * 64}
        )
        after["tables"]["event_audit"]["sha256"] = "7" * 64
        after["redis"].update(
            {
                "pending_deliveries": 0,
                "pending_target_message_ids": [],
                "last_delivered_id": "6000-0",
            }
        )

        async def consume(_config, _stop, completed):
            completed.update(r5.TARGET_IDS)
            return {"target_ack_message_ids": sorted(r5.TARGET_IDS)}

        class Checker:
            async def fetch(self, *_args):
                return [
                    {
                        "message_id": target["message_id"],
                        "payload_sha256": target["payload_sha256"],
                        "status": "COMPLETED",
                    }
                    for target in r5.TARGETS
                ]

            async def close(self):
                return None

        with (
            mock.patch.object(
                r5, "state_snapshot", side_effect=[(before, {}), (after, {})]
            ),
            mock.patch.object(r5, "_consume_exact", side_effect=consume),
            mock.patch.object(
                r5.epoch, "connect", new=mock.AsyncMock(return_value=Checker())
            ),
            self.assertRaisesRegex(r5.epoch.EpochError, "PRESERVATION_CONFLICT"),
        ):
            asyncio.run(r5.drain(config(expected_state=state_fixture()), output=None))


if __name__ == "__main__":
    unittest.main()
