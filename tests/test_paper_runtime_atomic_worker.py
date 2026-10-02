"""One-connection/savepoint orchestration MODEL, never an actual DDL proof."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from test_paper_runtime_atomic_contract import contract, history, intent, plan, plan_document
import paper_runtime_atomic_worker as worker


class Transaction:
    def __init__(self, connection, *, readonly=False):
        self.connection = connection
        self.readonly = readonly
        self.baseline = None
        self.outer = False

    async def start(self):
        self.outer = not self.connection.depth
        self.baseline = copy.deepcopy(self.connection.state)
        self.connection.depth += 1
        self.connection.events.append("BEGIN_READONLY" if self.readonly else ("BEGIN" if self.outer else "SAVEPOINT"))

    async def commit(self):
        self.connection.depth -= 1
        self.connection.events.append("COMMIT" if self.outer else "RELEASE_SAVEPOINT")
        if self.outer and self.connection.lose_commit_response:
            raise OSError("synthetic lost response; must not be logged")

    async def rollback(self):
        self.connection.state = self.baseline
        self.connection.depth -= 1
        self.connection.events.append("ROLLBACK" if self.outer else "ROLLBACK_SAVEPOINT")

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, error_type, error, traceback):
        await (self.rollback() if error_type else self.commit())


class Connection:
    def __init__(self):
        document = plan_document()
        row = {**document["identity"], "payload": {"synthetic": True}, "lease_owner": "synthetic-owner", "lease_until": document["lease_until_utc"], "last_error": "synthetic historical error", "published_at": None, "dead_lettered_at": None, "available_at": document["lease_until_utc"], "created_at": document["lease_until_utc"]}
        self.state = {"history": history(), "target": row, "other_error": "unchanged", "other_reconciliation": "NONE"}
        self.depth = 0
        self.events = []
        self.name = "kairos_paper_atomic_0123456789ab"
        self.backend_pid = 1234
        self.other_clients = 0
        self.lose_commit_response = False
        self.quarantine_calls = 0
        self.migration_fault = None
        self.rejection = False

    def transaction(self, **kwargs):
        return Transaction(self, readonly=kwargs.get("readonly", False))

    def is_in_transaction(self):
        return self.depth > 0

    async def execute(self, query, *args):
        self.events.append("SQL:" + query)

    async def fetchval(self, query, *args):
        if query == "SELECT current_database()":
            return self.name
        if query == "SELECT pg_backend_pid()":
            return self.backend_pid
        if "pg_stat_activity" in query:
            return self.other_clients
        if "reconciliation_state IS DISTINCT" in query:
            return int(self.state["other_reconciliation"] != "NONE")
        raise AssertionError("unexpected synthetic query")

    async def fetchrow(self, query, *args):
        if "to_jsonb(t)::text" in query:
            return {"row": json.dumps(self.state["target"])}
        raise AssertionError("unexpected synthetic row query")

    async def fetch(self, query, *args):
        if "pg_class" in query:
            return [{"relname": name} for name in (contract.RUNTIME_TABLES if len(self.state["history"]["migrations"]) > 12 else contract.LEGACY_TABLES)]
        if "schema_migrations" in query:
            return [{"version": name} for name in self.state["history"]["migrations"]]
        raise AssertionError("unexpected synthetic rows query")


class Database:
    def __init__(self, pool, name):
        self.pool = pool

    async def migrate(self):
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                for name in contract.CATALOG.RUNTIME_SUFFIX:
                    connection.state["history"]["migrations"].append(name)
                    if connection.migration_fault == "after_migration_" + name[:3]:
                        raise ValueError("synthetic DDL stage fault")
                connection.state["history"] = history(True)


class Repository:
    def __init__(self, pool):
        self.pool = pool

    @staticmethod
    def _quarantine_evidence(reason, lease):
        return contract.canonical({"expired_lease_owner_sha256": hashlib.sha256(lease.owner.encode()).hexdigest(), "expired_lease_until": lease.until.astimezone(UTC).isoformat(timespec="microseconds"), "reason": reason}).decode()

    async def quarantine_expired_outbox_exact(self, identity, *, expired_lease, reconciliation_id, reason):
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                connection._pool.connection.quarantine_calls += 1
                if connection.rejection:
                    return SimpleNamespace(state=SimpleNamespace(value="REJECTED"))
                now = datetime.now(UTC).isoformat()
                connection.state["target"].update(lease_owner=None, lease_until=None, last_error=self._quarantine_evidence(reason, expired_lease), reconciliation_state="PUBLISH_OUTCOME_UNKNOWN", reconciliation_id=reconciliation_id, reconciliation_started_at=now, reconciliation_outcome_at=now)
                return SimpleNamespace(state=SimpleNamespace(value="QUARANTINED"))


PRIMITIVES = SimpleNamespace(database=Database, repository=Repository, identity=lambda **kwargs: SimpleNamespace(**kwargs), lease=lambda **kwargs: SimpleNamespace(**kwargs))


async def model_history(connection, *, runtime, original_row=None):
    result = copy.deepcopy(connection.state["history"])
    if original_row is not None:
        result = history()
        if connection.state["other_error"] != "unchanged":
            result["tables"]["message_outbox"]["row_digest_sha256"] = "d" * 64
    return result


class WorkerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.connection = Connection()
        document = plan_document()
        document["lease_until_utc"] = self.connection.state["target"]["lease_until"]
        self.plan = contract.AtomicPlan.from_document(document, now=datetime.now(UTC))
        self.intents = []

    def sink(self, prepared):
        self.intents.append(copy.deepcopy(prepared))
        self.connection.events.append("INTENT_FSYNC_ACK")
        return contract.digest(prepared)

    async def run_atomic(self, **kwargs):
        with mock.patch.object(worker, "_history", side_effect=model_history), mock.patch.object(worker.snapshot, "_roles", return_value={"sufficient_for_reviewed_next_step": True}):
            return await worker.atomic_upgrade_and_quarantine(self.connection, self.plan, kwargs.pop("intent_sink", self.sink), _primitives=PRIMITIVES, **kwargs)

    async def test_one_physical_connection_outer_commit_and_two_nested_savepoints(self):
        result = await self.run_atomic()
        self.assertEqual(result["quarantine_calls"], 1)
        self.assertEqual(self.connection.quarantine_calls, 1)
        self.assertEqual(result["bound_acquisitions"], 2)
        self.assertEqual(self.connection.events.count("BEGIN"), 1)
        self.assertEqual(self.connection.events.count("SAVEPOINT"), 2)
        self.assertEqual(self.connection.events.count("RELEASE_SAVEPOINT"), 2)
        self.assertEqual(self.connection.events.count("COMMIT"), 1)
        self.assertLess(self.connection.events.index("INTENT_FSYNC_ACK"), self.connection.events.index("COMMIT"))
        self.assertEqual(result["intent"]["backend_pid"], 1234)
        self.assertFalse(result["consumer_restart_permitted"])

    async def test_primary_simulator_foreign_database_rejected_before_transaction(self):
        for name in ("kairos", "kairos_sim", "kairos_paper_snapshot_0123456789ab", "kairos_paper_atomic_NOTHEX", "kairos_paper_atomic_0123456789ab_extra"):
            self.connection.name = name
            with self.subTest(name=name), self.assertRaises(contract.AtomicError):
                await self.run_atomic()
            self.assertFalse(self.connection.events)

    async def test_each_migration_fault_rolls_back_everything_in_model(self):
        for name in contract.CATALOG.RUNTIME_SUFFIX:
            self.connection = Connection()
            document = self.plan.document
            document["lease_until_utc"] = self.connection.state["target"]["lease_until"]
            self.plan = contract.AtomicPlan.from_document(document, now=datetime.now(UTC))
            before = copy.deepcopy(self.connection.state)
            self.connection.migration_fault = "after_migration_" + name[:3]
            with self.subTest(migration=name), self.assertRaises(contract.AtomicError):
                await self.run_atomic()
            self.assertEqual(self.connection.state, before)
            self.assertEqual(self.connection.events[-1], "ROLLBACK")
            self.assertNotIn("COMMIT", self.connection.events)

    async def test_late_faults_rejected_quarantine_and_sink_failure_roll_back_both(self):
        for stage in ("after_migrations", "after_quarantine", "before_commit", "quarantine_rejected", "sink_rejected"):
            self.connection = Connection()
            document = self.plan.document
            document["lease_until_utc"] = self.connection.state["target"]["lease_until"]
            self.plan = contract.AtomicPlan.from_document(document, now=datetime.now(UTC))
            before = copy.deepcopy(self.connection.state)
            self.connection.rejection = stage == "quarantine_rejected"
            def fault(actual):
                if actual == stage:
                    raise ValueError("synthetic late fault")
            with self.subTest(stage=stage), self.assertRaises(contract.AtomicError):
                await self.run_atomic(_fault=fault, intent_sink=(lambda _: "bad") if stage == "sink_rejected" else self.sink)
            self.assertEqual(self.connection.state, before)
            self.assertNotIn("COMMIT", self.connection.events)

    async def test_other_outbox_row_error_is_not_masked_by_exact_row_projection(self):
        def fault(stage):
            if stage == "after_quarantine":
                self.connection.state["other_error"] = "forbidden mutation"
        with self.assertRaises(contract.AtomicError):
            await self.run_atomic(_fault=fault)
        self.assertEqual(self.connection.state["other_error"], "unchanged")

    async def test_target_payload_attempts_ack_and_other_reconciliation_mutations_reject(self):
        for mutate in (lambda c: c.state["target"].update(payload={"changed": True}), lambda c: c.state["target"].update(publish_attempts=2), lambda c: c.state["target"].update(published_at="synthetic ACK"), lambda c: c.state.update(other_reconciliation="PUBLISH_OUTCOME_UNKNOWN")):
            self.connection = Connection()
            document = self.plan.document
            document["lease_until_utc"] = self.connection.state["target"]["lease_until"]
            self.plan = contract.AtomicPlan.from_document(document, now=datetime.now(UTC))
            def fault(stage):
                if stage == "after_quarantine":
                    mutate(self.connection)
            with self.subTest(mutate=mutate), self.assertRaises(contract.AtomicError):
                await self.run_atomic(_fault=fault)
            self.assertNotIn("COMMIT", self.connection.events)

    async def test_commit_response_loss_never_reruns_quarantine(self):
        self.connection.lose_commit_response = True
        with self.assertRaises(worker.OutcomeUnknown) as observed:
            await self.run_atomic()
        self.assertEqual(self.connection.quarantine_calls, 1)
        self.assertEqual(self.connection.events.count("COMMIT"), 1)
        self.assertNotIn("ROLLBACK", self.connection.events)
        self.assertEqual(contract.classify_readonly_outcome(self.plan, observed.exception.intent, self.connection.state["history"]), "COMMITTED_EXACT")

    async def test_stale_plan_clients_and_missing_role_stop_without_commit(self):
        self.connection.other_clients = 1
        with self.assertRaises(contract.AtomicError):
            await self.run_atomic()
        self.assertNotIn("COMMIT", self.connection.events)

    async def test_bound_pool_requires_outer_transaction_and_has_no_release_route(self):
        pool = worker.ConnectionBoundPool(self.connection)
        with self.assertRaises(contract.AtomicError):
            async with pool.acquire():
                pass
        self.assertFalse(hasattr(pool, "release"))
        self.assertFalse(hasattr(pool, "close"))

    async def test_readonly_inspection_uses_readonly_transaction_and_never_write_api(self):
        prepared = intent(self.plan)
        with mock.patch.object(worker, "_history", return_value=history(True)):
            self.connection.state["history"] = history(True)
            state = await worker.inspect_unknown_readonly(self.connection, self.plan, prepared)
        self.assertEqual(state, "COMMITTED_EXACT")
        self.assertEqual(self.connection.quarantine_calls, 0)
        self.assertIn("BEGIN_READONLY", self.connection.events)
        self.assertFalse(any("UPDATE" in event or "INSERT" in event or "LOCK TABLE" in event for event in self.connection.events))


class IntentTests(unittest.TestCase):
    def test_durable_intent_is_create_only_fsynced_and_read_back(self):
        prepared = intent(plan())
        with tempfile.TemporaryDirectory(prefix="atomic-intent-unit-") as directory:
            # Hosted Windows TEMP may use a short-name alias. The admitted
            # fixture supplies the canonical directory, just like the native
            # controller; do not relax the worker's non-canonical-path guard.
            path = Path(directory).resolve(strict=True) / ("atomic-precommit-" + contract.digest(prepared) + ".json")
            self.assertEqual(worker.persist_precommit_intent(path, prepared), contract.digest(prepared))
            self.assertEqual(path.read_bytes(), contract.canonical(prepared))
            with self.assertRaises(contract.AtomicError):
                worker.persist_precommit_intent(path, prepared)
            self.assertEqual(path.read_bytes(), contract.canonical(prepared))

    def test_intent_fsync_failure_cannot_acknowledge_commit(self):
        prepared = intent(plan())
        with tempfile.TemporaryDirectory(prefix="atomic-intent-unit-") as directory, mock.patch.object(worker.os, "fsync", side_effect=OSError("synthetic failure")):
            path = Path(directory).resolve(strict=True) / ("atomic-precommit-" + contract.digest(prepared) + ".json")
            with self.assertRaises(contract.AtomicError):
                worker.persist_precommit_intent(path, prepared)

    def test_noncanonical_parent_still_rejects_before_file_creation(self):
        prepared = intent(plan())
        with tempfile.TemporaryDirectory(prefix="atomic-intent-unit-") as directory:
            root = Path(directory).resolve(strict=True)
            child = root / "child"
            child.mkdir()
            filename = "atomic-precommit-" + contract.digest(prepared) + ".json"
            path = child / ".." / filename
            with self.assertRaisesRegex(contract.AtomicError, "precommit intent directory differs"):
                worker.persist_precommit_intent(path, prepared)
            self.assertFalse((root / filename).exists())


if __name__ == "__main__":
    unittest.main()
