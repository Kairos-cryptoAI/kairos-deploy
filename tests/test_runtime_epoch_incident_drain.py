"""Offline orchestration tests for the exact incident drain boundary."""

from __future__ import annotations

import asyncio
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from scripts import runtime_epoch_incident_worker as incident

RECEIPT = "1791769980000-0"
ENCODED = '{"message_id":"' + incident.MESSAGE_ID + '"}'


def config(expected_state):
    return {
        "owner": incident.OWNER,
        "database": "kairos_epoch_" + incident.OWNER[:12],
        "pg_host": "kairos-epoch-" + incident.OWNER[:12] + "-pg",
        "redis_host": "kairos-epoch-" + incident.OWNER[:12] + "-redis",
        "admin_password": "a" * 64,
        "producer_password": "b" * 64,
        "consumer_password": "c" * 64,
        "redis_producer_password": "d" * 64,
        "redis_consumer_password": "e" * 64,
        "expected_state": expected_state,
    }


def state(*, pending=True):
    return {
        "state": "PASS_INCIDENT_STATE",
        "tables": {
            "event_audit": {"count": 334355, "sha256": "a" * 64},
            "message_outbox": {"count": 4546, "sha256": "b" * 64},
            "message_inbox": {
                "count": 4545 if pending else 4546,
                "sha256": "c" * 64,
            },
            "schema_migrations": {"count": 31, "sha256": "d" * 64},
        },
        "sequences": {"outbox_id_seq": {"last_value": 4559, "is_called": True}},
        "preserved_queue_prefixes": {
            "message_outbox": {"n": 4545, "sha": "e" * 64},
            "message_inbox": {"n": 4544, "sha": "f" * 64},
        },
        "trading_started": False,
    }


class FakeTransaction:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        self.connection.events.append("transaction-enter")
        return self

    async def __aexit__(self, exc_type, _exc, _tb):
        self.connection.events.append("transaction-exit")
        if exc_type is None and self.connection.commit_error:
            raise RuntimeError("commit outcome unknown")
        return False


class FakeConnection:
    def __init__(
        self, *, update_error=None, commit_error=False, events=None, label="db"
    ):
        self.update_error = update_error
        self.commit_error = commit_error
        self.events = events if events is not None else []
        self.label = label
        self.updates = []
        self.closed = False
        self.lock_attempts = []

    def transaction(self):
        return FakeTransaction(self)

    async def fetchval(self, query, *args):
        if "pg_try_advisory_lock" in query:
            self.lock_attempts.append(args[0])
            self.events.append("lock")
            return True
        if "pg_advisory_unlock" in query:
            self.events.append("unlock")
            return True
        if query.startswith("UPDATE message_outbox"):
            self.events.append("sql-ack")
            self.updates.append((query, args))
            if self.update_error:
                raise self.update_error
            return incident.OUTBOX_ID
        raise AssertionError("unexpected SQL fetchval: " + query)

    async def fetchrow(self, query, *args):
        self.events.append("pending-row-lock")
        self.select_args = args
        return {
            "message_id": incident.MESSAGE_ID,
            "payload": {"message_id": incident.MESSAGE_ID},
            "payload_sha256": incident.PAYLOAD_SHA256,
        }

    async def close(self):
        self.events.append(self.label + "-close")
        self.closed = True

    def is_closed(self):
        return self.closed


class FakeRedisProducer:
    def __init__(self, events, *, eval_error=None, receipt=RECEIPT):
        self.events = events
        self.eval_error = eval_error
        self.receipt = receipt
        self.eval_calls = []
        self.closed = False

    async def eval(self, *args):
        self.events.append("redis-eval")
        self.eval_calls.append(args)
        if self.eval_error:
            raise self.eval_error
        return self.receipt

    async def xinfo_groups(self, _topic):
        return [
            {
                "name": "bars",
                "pending": 0,
                "last-delivered-id": self.receipt,
            }
        ]

    async def aclose(self):
        self.events.append("redis-close")
        self.closed = True


class IncidentDrainTests(unittest.TestCase):
    def _run(
        self,
        *,
        eval_error=None,
        update_error=None,
        commit_error=False,
        mismatch=False,
        consumer_timeout=False,
    ):
        events = []
        producer_db = FakeConnection(
            update_error=update_error, commit_error=commit_error, events=events
        )
        checker = FakeConnection(events=events, label="checker")
        producer = FakeRedisProducer(events, eval_error=eval_error)
        consumer_finalized = {"value": False}
        snapshot_calls = []
        before_state = state(pending=True)
        after_state = state(pending=False)
        redis_before = {
            "stream_entries": 4546,
            "published_receipts": 4545,
            "pending_deliveries": 0,
        }
        redis_after = {
            "stream_entries": 4547,
            "published_receipts": 4546,
            "pending_deliveries": 0,
        }

        async def connect(_config, role):
            if role == "kairos_epoch_producer":
                return producer_db
            if role == "kairos_epoch_consumer":
                return checker
            raise AssertionError(role)

        async def snapshot(_config, *, allow_pending, workers_stopped=True):
            snapshot_calls.append(allow_pending)
            events.append("snapshot-before" if allow_pending else "snapshot-after")
            return (before_state if allow_pending else after_state), (
                {}
                if allow_pending
                else {incident.MESSAGE_ID: (incident.PAYLOAD_SHA256, ENCODED)}
            )

        async def redis_snapshot(_config, _published, *, allow_pending):
            events.append(
                "redis-snapshot-before" if allow_pending else "redis-snapshot-after"
            )
            return redis_before if allow_pending else redis_after

        async def consume(_config, stop):
            events.append("consumer-start")
            try:
                await stop.wait()
            finally:
                consumer_finalized["value"] = True
                events.append("consumer-finalized")

        async def check_completed(*_args):
            await asyncio.sleep(0)
            return 0 if consumer_timeout else 1

        checker.fetchval = check_completed
        expected = {**before_state, "redis": redis_before}
        if mismatch:
            expected["tables"] = {**expected["tables"], "message_outbox": {"count": -1}}
        expected.update(
            {
                "owner": incident.OWNER,
                "mode": "incident-state",
                "new_epoch_database": "kairos_epoch_" + incident.OWNER[:12],
            }
        )

        class RedisModule:
            def __init__(self, **_kwargs):
                return None

        redis_module = types.ModuleType("redis")
        redis_module.__path__ = []
        redis_asyncio = types.ModuleType("redis.asyncio")
        redis_asyncio.Redis = lambda **_kwargs: producer
        persistence_runtime = types.ModuleType("kairos_persistence.runtime")
        persistence_runtime.canonical_payload = lambda _payload: (
            ENCODED,
            incident.PAYLOAD_SHA256,
        )

        failure = None
        result = None
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                sys.modules,
                {
                    "redis": redis_module,
                    "redis.asyncio": redis_asyncio,
                    "kairos_persistence.runtime": persistence_runtime,
                },
            ),
            mock.patch.object(incident.epoch, "connect", new=connect),
            mock.patch.object(incident, "incident_snapshot", new=snapshot),
            mock.patch.object(incident, "redis_snapshot", new=redis_snapshot),
            mock.patch.object(incident, "validate_redis_drain_preservation"),
            mock.patch.object(incident.epoch, "consume", new=consume),
            mock.patch.object(
                incident,
                "time",
                types.SimpleNamespace(
                    monotonic=mock.Mock(side_effect=[0, 31])
                    if consumer_timeout
                    else lambda: 0
                ),
            ),
        ):
            output = Path(directory) / "output"
            output.mkdir()
            try:
                result = asyncio.run(incident.drain_incident(config(expected), output))
            except Exception as exc:  # noqa: BLE001 - inspect the sanitized offline failure boundary.
                failure = exc
        return {
            "events": events,
            "producer_db": producer_db,
            "checker": checker,
            "producer": producer,
            "consumer_finalized": consumer_finalized["value"],
            "snapshot_calls": snapshot_calls,
            "result": result,
            "failure": failure,
        }

    def test_single_eval_exact_ack_and_consumer_completion(self):
        observed = self._run()
        self.assertIsNone(observed["failure"])
        self.assertEqual(observed["producer"].eval_calls.__len__(), 1)
        args = observed["producer"].eval_calls[0]
        self.assertEqual(
            args[:3], (incident.epoch.PUBLICATION_LUA, 2, incident.epoch.TOPIC)
        )
        self.assertEqual(args[3], "kairos.runtime." + incident.OWNER + ".publication")
        self.assertEqual(
            args[4:], (incident.MESSAGE_ID, incident.PAYLOAD_SHA256, ENCODED)
        )
        self.assertEqual(len(observed["producer_db"].updates), 1)
        query, sql_args = observed["producer_db"].updates[0]
        self.assertIn("published_at IS NULL AND publish_attempts=0", query)
        self.assertEqual(
            sql_args, (incident.OUTBOX_ID, incident.MESSAGE_ID, incident.PAYLOAD_SHA256)
        )
        self.assertIn("consumer-start", observed["events"])
        self.assertIn("snapshot-after", observed["events"])
        self.assertEqual(observed["snapshot_calls"], [True, False])
        self.assertEqual(observed["result"]["published_messages"], 1)
        self.assertEqual(observed["result"]["completed_inbox_increment"], 1)
        self.assertTrue(observed["consumer_finalized"])
        self.assertLess(
            observed["events"].index("consumer-finalized"),
            observed["events"].index("redis-close"),
        )
        self.assertLess(
            observed["events"].index("consumer-finalized"),
            observed["events"].index("db-close"),
        )

    def test_redis_eval_unknown_is_not_retried_or_sql_acked(self):
        observed = self._run(eval_error=OSError("redis response lost"))
        self.assertIsInstance(observed["failure"], OSError)
        self.assertEqual(len(observed["producer"].eval_calls), 1)
        self.assertEqual(observed["producer_db"].updates, [])
        self.assertNotIn("consumer-start", observed["events"])
        self.assertTrue(observed["producer"].closed)
        self.assertTrue(observed["producer_db"].closed)

    def test_sql_ack_and_commit_failures_do_not_retry_publication(self):
        for changes, update_count in (
            ({"update_error": RuntimeError("ack outcome unknown")}, 1),
            ({"commit_error": True}, 1),
        ):
            with self.subTest(changes=changes):
                observed = self._run(**changes)
                self.assertIsInstance(observed["failure"], Exception)
                self.assertEqual(len(observed["producer"].eval_calls), 1)
                self.assertEqual(len(observed["producer_db"].updates), update_count)
                self.assertNotIn("consumer-start", observed["events"])
                self.assertTrue(observed["producer"].closed)
                self.assertTrue(observed["producer_db"].closed)

    def test_prestate_conflict_fails_before_publication_or_sql_update(self):
        observed = self._run(mismatch=True)
        self.assertIsInstance(observed["failure"], incident.epoch.EpochError)
        self.assertEqual(str(observed["failure"]), "INCIDENT_FULL_PRESTATE_CHANGED")
        self.assertEqual(observed["producer"].eval_calls, [])
        self.assertEqual(observed["producer_db"].updates, [])
        self.assertNotIn("pending-row-lock", observed["events"])

    def test_consumer_timeout_cancels_and_awaits_before_resource_close(self):
        observed = self._run(consumer_timeout=True)
        self.assertIsInstance(observed["failure"], incident.epoch.EpochError)
        self.assertEqual(str(observed["failure"]), "INCIDENT_COMPLETION_DEADLINE")
        self.assertEqual(len(observed["producer"].eval_calls), 1)
        self.assertEqual(len(observed["producer_db"].updates), 1)
        self.assertTrue(observed["consumer_finalized"])
        self.assertLess(
            observed["events"].index("consumer-finalized"),
            observed["events"].index("redis-close"),
        )
        self.assertLess(
            observed["events"].index("consumer-finalized"),
            observed["events"].index("db-close"),
        )


if __name__ == "__main__":
    unittest.main()
