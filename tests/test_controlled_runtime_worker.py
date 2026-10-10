from __future__ import annotations

import hashlib
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from scripts import controlled_runtime_worker as worker


def _plan(*, primary_authorized: bool = False) -> dict:
    tables = [f"legacy_{index:02d}" for index in range(27)]
    accepted = [
        {"table": table, "count": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        for table in tables
    ]
    sequences = {"legacy_id_seq": "1|f"}
    schema_sha = "a" * 64
    history = {
        "tables": accepted,
        "sequences": sequences,
        "migrations": list(worker.LEGACY_MIGRATIONS),
        "schema_fingerprint_sha256": schema_sha,
    }
    owner = "0123456789ab" + "c" * 20
    return {
        "schema_version": 1,
        "kind": "controlled-runtime-transition-v1",
        "owner": owner,
        "reconciliation_id": "controlled-runtime-" + owner,
        "reason": worker.EXACT_REASON,
        "legacy_snapshot_sha256": worker._digest(history),
        "legacy_schema_fingerprint_sha256": schema_sha,
        "expected_legacy_tables": tables,
        "accepted_legacy_tables": accepted,
        "accepted_legacy_sequences": sequences,
        "accepted_migrations": list(worker.LEGACY_MIGRATIONS),
        "package_revisions": {
            "kairos-core": "6937eb4773fc00afaf5ba4e020b28b689f48e377",
            "kairos-persistence": "f" * 40,
        },
        "primary_authorized": primary_authorized,
        "role_provision_authorized": True,
    }


class WorkerPlanTests(unittest.TestCase):
    def test_exact_clone_plan_passes_and_primary_needs_second_gate(self) -> None:
        plan = _plan()
        worker.validate_plan(
            plan, database="kairos_recovery_0123456789ab_current", primary=False
        )
        with self.assertRaises(worker.WorkerError):
            worker.validate_plan(plan, database="kairos", primary=False)
        with self.assertRaises(worker.WorkerError):
            worker.validate_plan(plan, database="kairos", primary=True)

    def test_wrong_owner_namespace_and_unreviewed_role_creation_fail(self) -> None:
        plan = _plan()
        with self.assertRaises(worker.WorkerError):
            worker.validate_plan(
                plan, database="kairos_recovery_deadbeefdead_current", primary=False
            )
        plan["role_provision_authorized"] = False
        with self.assertRaises(worker.WorkerError):
            worker.validate_plan(
                plan, database="kairos_recovery_0123456789ab_current", primary=False
            )

    def test_primary_bit_is_the_only_clone_to_primary_plan_binding_change(self) -> None:
        clone = _plan(primary_authorized=False)
        primary = _plan(primary_authorized=True)
        worker.validate_plan(primary, database="kairos", primary=True)
        self.assertNotEqual(worker._digest(clone), worker._digest(primary))
        self.assertEqual(
            worker._plan_binding_sha256(clone), worker._plan_binding_sha256(primary)
        )

    def test_manifest_must_have_exact_offline_package_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(
                json.dumps({"schema_version": 1, "packages": []}), encoding="utf-8"
            )
            with self.assertRaises(worker.WorkerError):
                worker.verify_wheel_manifest(path, _plan())

    def test_runtime_snapshot_requires_all_twelve_new_relations_and_identity_singleton(
        self,
    ) -> None:
        good = {
            name: {"count": 1 if name == "paper_canary_database_identity" else 0}
            for name in worker.NEW_TABLES
        }
        worker._check_new_relations({"tables": good})
        missing = dict(good)
        missing.pop("operator_control_commands")
        with self.assertRaises(worker.WorkerError):
            worker._check_new_relations({"tables": missing})
        duplicate_identity = dict(good)
        duplicate_identity["paper_canary_database_identity"] = {"count": 2}
        with self.assertRaises(worker.WorkerError):
            worker._check_new_relations({"tables": duplicate_identity})

    def test_fault_checkpoint_error_identifies_the_exact_requested_stage(self) -> None:
        checkpoint = worker.FaultCheckpointError("after_migration_013")
        self.assertIsInstance(checkpoint, worker.WorkerError)
        self.assertEqual(checkpoint.stage, "after_migration_013")

    def test_permission_negative_probe_never_treats_syntax_or_constraint_errors_as_denials(
        self,
    ) -> None:
        class InsufficientPrivilegeError(Exception):
            pass

        privilege = InsufficientPrivilegeError()
        privilege.sqlstate = "42501"
        syntax = RuntimeError("undefined column")
        syntax.sqlstate = "42703"
        self.assertTrue(worker._is_insufficient_privilege(privilege))
        self.assertFalse(worker._is_insufficient_privilege(syntax))

    def test_private_artifacts_are_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve(strict=True)
            if os.name != "nt":
                directory.chmod(0o700)
            safe = worker._safe_directory(directory)
            target = safe / "native-test.json"
            digest = worker._write_private_json(target, safe, {"z": 1, "a": "two"})
            self.assertEqual(target.read_text(encoding="utf-8"), '{"a":"two","z":1}\n')
            self.assertEqual(digest, hashlib.sha256(target.read_bytes()).hexdigest())
            with self.assertRaises(worker.WorkerError):
                worker._write_private_json(target, safe, {"replacement": True})


class _FakeTransaction:
    def __init__(self, connection, **_kwargs):
        self.connection = connection

    async def start(self):
        self.connection.depth += 1

    async def commit(self):
        self.connection.depth -= 1

    async def rollback(self):
        self.connection.depth = max(0, self.connection.depth - 1)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if exc_type:
            await self.rollback()
        else:
            await self.commit()


class _FakeConnection:
    def __init__(self):
        self.depth = 0
        self.queries = []

    def is_in_transaction(self):
        return self.depth > 0

    def transaction(self, **kwargs):
        return _FakeTransaction(self, **kwargs)

    async def fetchval(self, query, *_args):
        self.queries.append(query)
        if "pg_backend_pid" in query:
            return 4242
        return None

    async def execute(self, query, *_args):
        self.queries.append(query)
        return "OK"


class BoundPoolTests(unittest.IsolatedAsyncioTestCase):
    async def test_bound_pool_requires_outer_transaction_and_preserves_connection(
        self,
    ) -> None:
        connection = _FakeConnection()
        pool = worker.ConnectionBoundPool(connection)
        with self.assertRaises(worker.WorkerError):
            async with pool.acquire():
                pass
        async with connection.transaction():
            async with pool.acquire() as bound:
                await bound.execute("UPDATE sample SET value=1")
                async with bound.transaction():
                    await bound.execute("UPDATE sample SET value=2")
            self.assertTrue(connection.is_in_transaction())
            self.assertEqual(pool.acquisitions, 1)
            self.assertEqual(pool.savepoints, 1)
        self.assertFalse(connection.is_in_transaction())
        self.assertEqual(connection.queries.count("UPDATE sample SET value=2"), 1)


class RestoredPrimaryVerificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_verifies_exact_history_without_claiming_restored_role_permissions(
        self,
    ) -> None:
        plan = _plan()
        original = {
            "id": "row-1",
            "producer": "p",
            "message_id": "m",
            "topic": "t",
            "payload_sha256": "b" * 64,
            "publish_attempts": 2,
            "lease_owner": "private-owner",
            "lease_until": "2026-10-01T00:00:00Z",
            "last_error": None,
            "reconciliation_state": None,
            "reconciliation_id": None,
            "reconciliation_started_at": None,
            "reconciliation_outcome_at": None,
        }
        after = dict(original)
        after.update(
            {
                "lease_owner": None,
                "lease_until": None,
                "reconciliation_state": "PUBLISH_OUTCOME_UNKNOWN",
                "reconciliation_id": plan["reconciliation_id"],
                "reconciliation_started_at": "2026-10-10T00:00:00+00:00",
                "reconciliation_outcome_at": "2026-10-10T00:00:00+00:00",
                "last_error": json.dumps(
                    {
                        "expired_lease_owner_sha256": hashlib.sha256(
                            b"private-owner"
                        ).hexdigest(),
                        "expired_lease_until": "2026-10-01T00:00:00.000000+00:00",
                        "reason": plan["reason"],
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            }
        )
        history = {
            "tables": {
                name: {"count": 1 if name == "paper_canary_database_identity" else 0}
                for name in worker.NEW_TABLES
            },
            "schema_fingerprint_sha256": "c" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve(strict=True)
            if os.name != "nt":
                directory.chmod(0o700)
            manifest_sha = "d" * 64
            receipt = {
                "kind": "controlled-runtime-native-apply-v1",
                "plan_binding_sha256": worker._plan_binding_sha256(plan),
                "wheel_manifest_sha256": manifest_sha,
                "state": "COMMITTED_ACKNOWLEDGED",
                "runtime_history_sha256": worker._digest(history),
                "private_target": original,
            }
            worker._write_private_json(
                directory / "native-apply.json", directory, receipt
            )
            connection = _FakeConnection()
            with (
                mock.patch.object(
                    worker, "_history", new=mock.AsyncMock(return_value=history)
                ),
                mock.patch.object(
                    worker, "_quarantined_row", new=mock.AsyncMock(return_value=after)
                ),
                mock.patch.object(worker, "_check_new_relations") as check_relations,
            ):
                checked, target = await worker._verify_restored_primary(
                    connection, plan, directory, manifest_sha256=manifest_sha
                )
            self.assertEqual(checked, history)
            self.assertEqual(target, original)
            check_relations.assert_called_once_with(history)
            self.assertIn("SET LOCAL TIME ZONE 'UTC'", connection.queries)
            self.assertFalse(
                any("kairos_runtime" in query for query in connection.queries)
            )

    async def test_refuses_mismatched_restored_history(self) -> None:
        plan = _plan()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve(strict=True)
            if os.name != "nt":
                directory.chmod(0o700)
            worker._write_private_json(
                directory / "native-apply.json", directory, {"kind": "wrong"}
            )
            with (
                mock.patch.object(
                    worker, "_history", new=mock.AsyncMock(return_value={"tables": {}})
                ),
                mock.patch.object(worker, "_check_new_relations"),
                mock.patch.object(
                    worker, "_quarantined_row", new=mock.AsyncMock(return_value={})
                ),
                self.assertRaises(worker.WorkerError),
            ):
                await worker._verify_restored_primary(
                    _FakeConnection(), plan, directory, manifest_sha256="e" * 64
                )

    async def test_fault_observer_runs_after_exact_migration_marker(self) -> None:
        connection = _FakeConnection()
        seen = []

        def fault(stage):
            seen.append(stage)
            raise worker.WorkerError("injected")

        pool = worker.ConnectionBoundPool(connection, fault)
        async with connection.transaction(), pool.acquire() as bound:
            with self.assertRaises(worker.WorkerError):
                await bound.execute(
                    "INSERT INTO schema_migrations(version) VALUES ($1)",
                    "013_campaign_source_budgets.sql",
                )
        self.assertEqual(seen, ["after_migration_013"])

    async def test_full_table_digest_uses_accepted_sorted_sql_hash(self) -> None:
        class DigestConnection:
            query = ""

            async def fetchval(self, query, table):
                self.query = query
                return json.dumps(
                    {"table": table, "count": 3, "bytes": 30, "sha256": "a" * 64}
                )

        connection = DigestConnection()
        budget = worker.Budget()
        result = await worker._table_digest(connection, "message_outbox", budget)
        self.assertEqual(result, {"count": 3, "sha256": "a" * 64})
        self.assertIn("sha256(convert_to(to_jsonb(t)::text,'UTF8'))", connection.query)
        self.assertIn("json_build_object('table',$1::text", connection.query)
        self.assertIn("string_agg(row_sha,'' ORDER BY row_sha)", connection.query)
        self.assertEqual((budget.rows, budget.bytes), (3, 30))

    async def test_permission_probe_requires_actual_runtime_session_and_denies_five_paths(
        self,
    ) -> None:
        module = types.ModuleType("kairos_persistence")
        module.__path__ = []
        operator = types.ModuleType("kairos_persistence.operator_control")

        class Repository:
            def __init__(self, _pool):
                pass

            async def verify_runtime_access(self):
                return None

        operator.OperatorControlRepository = Repository
        old_parent = __import__("sys").modules.get("kairos_persistence")
        old_module = __import__("sys").modules.get(
            "kairos_persistence.operator_control"
        )
        __import__("sys").modules["kairos_persistence"] = module
        __import__("sys").modules["kairos_persistence.operator_control"] = operator

        class RuntimeConnection(_FakeConnection):
            async def fetchrow(self, _query):
                return {"role": "kairos_runtime", "session_role": "kairos_runtime"}

            async def execute(self, query, *_args):
                self.queries.append(query)
                if query.startswith(
                    (
                        "INSERT INTO public.operator_controls",
                        "UPDATE public.operator_controls",
                        "ALTER TABLE public.operator_controls",
                        "SET ROLE kairos_operator",
                        "CREATE TABLE public.kairos_forbidden_probe",
                    )
                ):

                    class InsufficientPrivilegeError(PermissionError):
                        sqlstate = "42501"

                    raise InsufficientPrivilegeError("expected deny")
                return "OK"

        connection = RuntimeConnection()
        try:
            result = await worker._verify_permissions(connection)
        finally:
            if old_parent is None:
                __import__("sys").modules.pop("kairos_persistence", None)
            else:
                __import__("sys").modules["kairos_persistence"] = old_parent
            if old_module is None:
                __import__("sys").modules.pop(
                    "kairos_persistence.operator_control", None
                )
            else:
                __import__("sys").modules["kairos_persistence.operator_control"] = (
                    old_module
                )
        self.assertEqual(result["forbidden_capabilities_rejected"], 5)
        self.assertFalse(
            any(
                query in {"SET ROLE kairos_runtime", "RESET ROLE"}
                for query in connection.queries
            )
        )


if __name__ == "__main__":
    unittest.main()
