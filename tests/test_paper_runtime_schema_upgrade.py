"""Provider/Docker/database-free adversarial PAPER read-only preflight tests."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, filename: str):
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


controller = _load("paper_readonly_controller_unit", "paper_runtime_schema_upgrade.py")
worker = _load("paper_readonly_worker_unit", "paper_runtime_snapshot_worker.py")


def snapshot(primary: bool = True) -> dict:
    role = {"role": "kairos", "session_role": "kairos", "superuser": True, "bypass_rls": True, "schema_usage": True, "schema_create": True, "uuid_execute": True, "actual_ddl_executed": False, "sufficient_for_reviewed_next_step": True, "table_capabilities": {table: {"readable": True, "updatable": True, "owner_capable": True, "row_security": False} for table in controller.TABLES}} if primary else None
    return {"schema_version": 1, "kind": "kairos.paper-readonly-snapshot.v1", "primary_mutations": 0, "forbidden_network_calls": 0, "loopback_database_connections": 1, "other_application_clients": 0, "target_role": role, "history": {"database": "kairos", "migrations": list(controller.CATALOG.LEGACY_MIGRATIONS), "schema_fingerprint_sha256": controller.CATALOG.EXPECTED_LEGACY_FINGERPRINT, "tables": {table: {"count": 12 if table == "schema_migrations" else 0, "row_digest_sha256": "a" * 64} for table in controller.TABLES}, "public_sequences": {"message_outbox_id_seq": {"last_value": 1, "is_called": False}}, "public_execution_events_max_sequence": 0}}


def inspection() -> dict:
    return {"Id": "1" * 64, "Name": "/" + controller.SOURCE_CONTAINER, "Image": "sha256:" + "2" * 64, "State": {"Running": True}, "HostConfig": {"Privileged": False, "PortBindings": {}}, "Config": {"Labels": {"com.docker.compose.project": controller.SOURCE_PROJECT, "com.docker.compose.service": "timescaledb"}}, "Mounts": [{"Destination": "/var/lib/postgresql/data", "Type": "volume", "Name": controller.SOURCE_VOLUME, "RW": True}], "NetworkSettings": {"Networks": {controller.SOURCE_NETWORK: {"NetworkID": "3" * 64}}}}


class ControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="paper-readonly-unit-")
        self.directory = Path(self.temporary.name).resolve(strict=True)
        self.dump = self.directory / "kairos-paper-gate-20261002T170608Z.dump"
        self.dump.write_bytes(b"synthetic immutable backup")
        self.manifest_path = self.directory / (self.dump.name + ".json")
        self.manifest_path.write_text("{}", encoding="utf-8")
        self.inputs = types.SimpleNamespace(staging_directory=self.directory, dump_path=self.dump, manifest={"sha256": controller._sha(self.dump), "bytes": self.dump.stat().st_size, "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "checkpoints": {**{table: 0 for table in controller.CATALOG.CHECKPOINT_TABLES}, "public_execution_events_max_sequence": 0}, "timescaledb_bgw_owners": ["kairos"]}, manifest_sha256="b" * 64, recovery_sha256="c" * 64, inspection_sha256="d" * 64, inspection_signature_sha256="e" * 64, expectation_sha256="f" * 64)
        self.args = argparse.Namespace(confirmation=controller.CONFIRMATION, manifest_path=str(self.manifest_path), clone_receipt_path="accepted.json", clone_signature_path="accepted.json.asc")
        self.manifest_path.write_text(json.dumps({**self.inputs.manifest, "file": self.dump.name}), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self, restored=None, after=None):
        with mock.patch.object(controller.CATALOG, "BACKUP_ROOT", self.directory), mock.patch.object(controller.CATALOG, "_verify_inputs", return_value=self.inputs) as verified, mock.patch.object(controller.CATALOG, "_snapshot_file", side_effect=lambda source, destination, label: destination), mock.patch.object(controller.CATALOG, "_cleanup_evidence_stage") as cleanup, mock.patch.object(controller, "_verify_clone_receipt", return_value="a" * 64), mock.patch.object(controller, "_runner_identity"), mock.patch.object(controller, "_source_identity", return_value={"container_id": "1" * 64}), mock.patch.object(controller, "_snapshot", side_effect=[snapshot(), after or snapshot()]), mock.patch.object(controller, "_restore_snapshot", return_value=restored or snapshot(False)), mock.patch.object(controller, "_sha", side_effect=lambda path: "e" * 64 if path.name.endswith(".asc") else hashlib.sha256(path.read_bytes()).hexdigest()):
            try:
                return controller.run(self.args)
            finally:
                cleanup.assert_called_once_with(self.directory)
                self.assertEqual(verified.call_args.args[0].confirmation, "CLONE_ONLY_LEGACY_OUTBOX_QUARANTINE_REHEARSAL")

    def test_full_history_success_never_authorizes_apply_or_restart(self):
        receipt = self._run()
        self.assertEqual(receipt["result"], "PASS_READ_ONLY_PRIMARY_AND_CLONE")
        self.assertFalse(receipt["primary_apply_implemented"])
        self.assertFalse(receipt["consumer_restart_permitted"])
        self.assertEqual(receipt["primary_mutations"], 0)
        self.assertEqual(receipt["source_snapshot"]["history"], receipt["restored_snapshot"]["history"])

    def test_archive_bound_is_enforced_before_evidence_copy_or_docker(self):
        self.manifest_path.write_text(json.dumps({"file": self.dump.name, "bytes": controller.MAX_DUMP_BYTES + 1}), encoding="utf-8")
        with mock.patch.object(controller.CATALOG, "BACKUP_ROOT", self.directory), mock.patch.object(controller.CATALOG, "_verify_inputs") as copied, mock.patch.object(controller, "_docker") as docker, self.assertRaises(controller.PreflightError):
            controller.run(self.args)
        copied.assert_not_called()
        docker.assert_not_called()

    def test_same_count_mutated_row_sequence_or_original_migration_is_rejected(self):
        changes = (
            lambda value: value["history"]["tables"]["event_audit"].update(row_digest_sha256="b" * 64),
            lambda value: value["history"]["public_sequences"]["message_outbox_id_seq"].update(is_called=True),
            lambda value: value["history"]["tables"]["schema_migrations"].update(row_digest_sha256="b" * 64),
        )
        for mutate in changes:
            changed = snapshot(False)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(controller.PreflightError):
                self._run(restored=changed)

    def test_source_change_during_clone_restore_is_rejected(self):
        changed = snapshot()
        changed["history"]["tables"]["market_snapshots"]["row_digest_sha256"] = "b" * 64
        with self.assertRaises(controller.PreflightError):
            self._run(after=changed)

    def test_fixed_paper_identity_rejects_foreign_or_active_runtime(self):
        value = inspection()
        self.assertEqual(controller._identity(value, [value], value["Image"])["volume"], "kairos-paper-gate_paper-ts-data")
        mutations = (
            lambda item: item.update(Name="/kairos-shadow-gate-timescaledb-1"),
            lambda item: item["Config"]["Labels"].update({"com.docker.compose.project": "kairos"}),
            lambda item: item["Mounts"][0].update(Name="kairos-paper-gate_ts-data"),
            lambda item: item["HostConfig"].update(Privileged=True),
            lambda item: item["HostConfig"].update(PortBindings={"5432/tcp": [{}]}),
            lambda item: item["NetworkSettings"].update(Networks={"kairos-paper-gate_data": {"NetworkID": "3" * 64}}),
            lambda item: item["Mounts"].append({"Destination": "/other", "Type": "bind", "RW": False}),
        )
        for mutate in mutations:
            altered = copy.deepcopy(value)
            mutate(altered)
            with self.subTest(mutate=mutate), self.assertRaises(controller.PreflightError):
                controller._identity(altered, [], value["Image"])
        foreign = {"Id": "9" * 64, "Config": {"Labels": {"com.docker.compose.project": controller.SOURCE_PROJECT, "com.docker.compose.service": "quant-scouts"}}}
        with self.assertRaises(controller.PreflightError):
            controller._identity(value, [foreign], value["Image"])
        for foreign in ({"Id": "9" * 64, "NetworkSettings": {"Networks": {controller.SOURCE_NETWORK: {}}}}, {"Id": "9" * 64, "Mounts": [{"Name": controller.SOURCE_VOLUME}]}):
            with self.assertRaises(controller.PreflightError):
                controller._identity(value, [foreign], value["Image"])

    def test_missing_role_privileges_raw_data_and_wrong_snapshot_are_rejected(self):
        self.assertEqual(controller._validate_snapshot(snapshot(), primary=True), snapshot())
        mutations = (
            lambda value: value.update(raw_payload="sensitive"),
            lambda value: value.update(schema_version=True),
            lambda value: value.update(primary_mutations=True),
            lambda value: value.update(other_application_clients=1),
            lambda value: value["history"]["migrations"].append("017_simulator_journal.sql"),
            lambda value: value["target_role"].update(actual_ddl_executed=True),
            lambda value: value["target_role"].update(schema_create=False),
            lambda value: value["target_role"]["table_capabilities"]["message_outbox"].update(owner_capable=False),
            lambda value: value["target_role"]["table_capabilities"]["market_snapshots"].update(row_security=True),
            lambda value: value["history"]["tables"]["event_audit"].update(raw_row="private"),
        )
        for mutate in mutations:
            altered = snapshot()
            mutate(altered)
            with self.subTest(mutate=mutate), self.assertRaises(controller.PreflightError):
                controller._validate_snapshot(altered, primary=True)
        with self.assertRaises(controller.PreflightError):
            controller._validate_snapshot(snapshot(), primary=False)

    def test_all_bootstrap_tables_and_schema_migrations_are_hashed(self):
        self.assertTrue(controller.BOOTSTRAP_TABLES.issubset(controller.TABLES))
        self.assertIn("schema_migrations", controller.TABLES)
        self.assertEqual(set(controller.TABLES), controller.CATALOG.CHECKPOINT_TABLES | controller.BOOTSTRAP_TABLES | {"schema_migrations"})

    def test_snapshot_worker_has_only_fixed_credential_mount_and_loopback_namespace(self):
        secret = self.directory / "persistence_database_url"
        secret.write_text("never read by host", encoding="utf-8")
        with mock.patch.object(controller, "SOURCE_SECRET", secret), mock.patch.object(controller, "_docker", return_value=json.dumps(snapshot())) as docker:
            controller._snapshot(controller.SOURCE_CONTAINER, "kairos", primary=True)
        args = docker.call_args.args[0]
        self.assertIn("container:" + controller.SOURCE_CONTAINER, args)
        self.assertIn(controller.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, args)
        self.assertEqual(sum("type=bind" in value for value in args), 2)
        self.assertTrue(all(value.endswith(",readonly") for value in args if "type=bind" in value))
        self.assertNotIn("never read by host", repr(docker.call_args))
        self.assertNotIn("--publish", args)
        self.assertNotIn("--env-file", args)
        self.assertNotIn("source_usage", " ".join(args))

    def test_clone_restore_is_generated_network_none_without_primary_mounts(self):
        completed = subprocess.CompletedProcess([], 0, stdout="kairos_paper_snapshot_" + "a" * 12 + "\n", stderr="")
        with mock.patch.object(controller.uuid, "uuid4", return_value=types.SimpleNamespace(hex="a" * 32)), mock.patch.object(controller, "_docker", return_value="") as docker, mock.patch.object(controller.subprocess, "run", return_value=completed) as process, mock.patch.object(controller.time, "sleep"), mock.patch.object(controller.CATALOG, "_ensure_timescaledb_job_owners") as owners, mock.patch.object(controller, "_snapshot", return_value=snapshot(False)), mock.patch.object(controller, "_cleanup_clone") as cleanup:
            controller._restore_snapshot(self.inputs)
        create = docker.call_args_list[0].args[0]
        self.assertIn("--network=none", create)
        self.assertEqual([item for item in create if item.startswith("--memory=")], ["--memory=3g"])
        self.assertEqual([item for item in create if item.startswith("--cpus=")], ["--cpus=1"])
        self.assertEqual([item for item in create if item.startswith("--pids-limit=")], ["--pids-limit=256"])
        self.assertEqual([create[index + 1] for index, item in enumerate(create) if item == "--tmpfs"], ["/var/lib/postgresql/data:rw,nosuid,nodev,size=2g", "/tmp:rw,nosuid,nodev,size=128m"])
        self.assertEqual(create[create.index(controller.CATALOG.EXPECTED_TIMESCALE_IMAGE) + 1:], ["postgres", "-c", "shared_buffers=64MB", "-c", "work_mem=4MB", "-c", "max_connections=20", "-c", "max_worker_processes=8", "-c", "timescaledb.max_background_workers=4"])
        self.assertFalse(any(item.split("=", 1)[0] in {"--mount", "--volume", "--volumes-from", "-v", "--publish", "--publish-all", "-p", "-P", "--privileged"} for item in create))
        self.assertNotIn(controller.SOURCE_VOLUME, repr(docker.call_args_list))
        restore = [call for call in process.call_args_list if "pg_restore" in call.args[0]]
        self.assertEqual(len(restore), 1)
        self.assertIn("--no-owner", restore[0].args[0])
        self.assertEqual(restore[0].kwargs["timeout"], 300)
        owners.assert_called_once_with("kairos-paper-snapshot-clone-" + "a" * 12, "kairos_paper_snapshot", self.inputs.manifest["timescaledb_bgw_owners"])
        cleanup.assert_called_once_with("kairos-paper-snapshot-clone-" + "a" * 12, "a" * 12)

    def test_clone_restore_failure_never_retries_or_expands_resources(self):
        def process(arguments, **kwargs):
            if "pg_restore" in arguments:
                return subprocess.CompletedProcess(arguments, 1, stdout="", stderr=b"raw restore details withheld")
            return subprocess.CompletedProcess(arguments, 0, stdout="kairos_paper_snapshot_" + "a" * 12 + "\n", stderr="")
        with mock.patch.object(controller.uuid, "uuid4", return_value=types.SimpleNamespace(hex="a" * 32)), mock.patch.object(controller, "_docker", return_value="") as docker, mock.patch.object(controller.subprocess, "run", side_effect=process) as operations, mock.patch.object(controller.time, "sleep"), mock.patch.object(controller.CATALOG, "_ensure_timescaledb_job_owners"), mock.patch.object(controller, "_snapshot") as restored, mock.patch.object(controller, "_cleanup_clone") as cleanup, self.assertRaisesRegex(controller.PreflightError, "raw output withheld"):
            controller._restore_snapshot(self.inputs)
        self.assertEqual(sum(call.args[0][0] == "create" for call in docker.call_args_list), 1)
        self.assertEqual(sum("pg_restore" in call.args[0] for call in operations.call_args_list), 1)
        restored.assert_not_called()
        cleanup.assert_called_once_with("kairos-paper-snapshot-clone-" + "a" * 12, "a" * 12)

    def test_foreign_cleanup_is_refused_before_remove(self):
        with mock.patch.object(controller, "_docker", return_value=json.dumps([inspection()])) as docker, self.assertRaises(controller.PreflightError):
            controller._cleanup_clone("kairos-paper-snapshot-clone-" + "a" * 12, "a" * 12)
        self.assertEqual(docker.call_count, 1)

    def test_no_primary_apply_interface_or_persistence_mutation_call_exists(self):
        text = (ROOT / "scripts" / "paper_runtime_schema_upgrade.py").read_text(encoding="utf-8")
        tree = ast.parse(text)
        self.assertFalse(any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and "apply" in node.name for node in ast.walk(tree)))
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in {"migrate", "quarantine_expired_outbox_exact", "claim_outbox", "publish"} for node in ast.walk(tree)))
        self.assertNotIn('"--apply"', text)
        self.assertNotIn("shadow_runtime_schema_upgrade", text)

    def test_preexisting_receipt_is_not_overwritten_or_deleted(self):
        output = self.directory / "paper-runtime-readonly-preflight-20261002T190000Z.json"
        output.write_bytes(b"immutable prior evidence")
        with mock.patch.object(controller.CATALOG, "BACKUP_ROOT", self.directory), self.assertRaises(controller.PreflightError):
            controller._write_receipt({}, self.manifest_path, str(output))
        self.assertEqual(output.read_bytes(), b"immutable prior evidence")

    def test_failed_signature_write_does_not_delete_a_racing_foreign_artifact(self):
        output = self.directory / "paper-runtime-readonly-preflight-20261002T190000Z.json"
        signature = output.with_suffix(".json.asc")
        original = controller.CATALOG._write_new_file
        def racing(path, content, label):
            if path == signature:
                signature.write_bytes(b"foreign race evidence")
            return original(path, content, label)
        with mock.patch.object(controller.CATALOG, "BACKUP_ROOT", self.directory), mock.patch.object(controller.CATALOG, "_detached_signature", return_value=b"signed"), mock.patch.object(controller.CATALOG, "_write_new_file", side_effect=racing), self.assertRaises(controller.CATALOG.RehearsalError):
            controller._write_receipt({}, self.manifest_path, str(output))
        self.assertFalse(output.exists())
        self.assertEqual(signature.read_bytes(), b"foreign race evidence")

    def test_clone_receipt_signature_freshness_and_backup_binding_are_required(self):
        catalog = controller.CATALOG
        receipt = {"schema_version": 1, "classification": "CLONE_ONLY_LEGACY_OUTBOX_QUARANTINE_REHEARSAL", "result": "PASS_CLONE_ONLY", "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "source_backup": {"sha256": self.inputs.manifest["sha256"], "bytes": self.inputs.manifest["bytes"], "manifest_sha256": self.inputs.manifest_sha256, "recovery_receipt_sha256": self.inputs.recovery_sha256, "legacy_inspection_receipt_sha256": self.inputs.inspection_sha256, "legacy_inspection_signature_sha256": self.inputs.inspection_signature_sha256, "expectation_sha256": self.inputs.expectation_sha256, "legacy_schema_fingerprint_sha256": catalog.EXPECTED_LEGACY_FINGERPRINT}, "migration_runner": {"persistence_repository": catalog.EXPECTED_PERSISTENCE_REPOSITORY, "persistence_revision": catalog.EXPECTED_PERSISTENCE_REVISION, "image_digest": catalog.EXPECTED_MIGRATION_RUNNER_IMAGE, "repository_module_sha256": catalog.EXPECTED_PERSISTENCE_REPOSITORY_SHA256, "exact_runtime_profile": list(catalog.TARGET_MIGRATIONS), "excluded_simulator_migration": "017_simulator_journal.sql"}, "original_migration": {"authorized": False, "original_quarantine_authorized": False, "required_next_gate": "SEPARATE_TARGET_ROLE_AND_PRIMARY_MIGRATION_REVIEW"}, "readiness": {"paper_qualified": False, "alpha_ready": False, "live_ready": False, "strategy_policy": "REJECT_ALL"}, "clone": {"network_mode": "none", "original_runtime_contacted": False, "redis_contacted": False, "publisher_contacted": False, "simulator_relations_present": False, "forbidden_network_calls": 0, "first_runtime_schema_fingerprint_sha256": "a" * 64, "second_runtime_schema_fingerprint_sha256": "a" * 64}, "restore_drill": {"passed": True, "schema_fingerprint_sha256": "a" * 64}, "quarantine": {}, "assertions": ["synthetic receipt only"]}
        path = self.directory / "accepted.json"
        def save():
            unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
            receipt["receipt_sha256"] = controller.CATALOG._sha256_json(unsigned)
            path.write_text(json.dumps(receipt), encoding="utf-8")
        save()
        with mock.patch.object(controller.CATALOG, "_verify_signature") as verify, mock.patch.object(controller.CATALOG, "_verify_worker_result"):
            controller._verify_clone_receipt(path, self.directory / "signature.asc", self.inputs)
            verify.assert_called_once()
            del receipt["clone"]["first_runtime_schema_fingerprint_sha256"]
            del receipt["clone"]["second_runtime_schema_fingerprint_sha256"]
            del receipt["restore_drill"]["schema_fingerprint_sha256"]
            save()
            with self.assertRaises(controller.PreflightError):
                controller._verify_clone_receipt(path, self.directory / "signature.asc", self.inputs)
            receipt["clone"].update(first_runtime_schema_fingerprint_sha256="a" * 64, second_runtime_schema_fingerprint_sha256="a" * 64)
            receipt["restore_drill"]["schema_fingerprint_sha256"] = "a" * 64
            receipt["source_backup"]["sha256"] = "0" * 64
            save()
            with self.assertRaises(controller.PreflightError):
                controller._verify_clone_receipt(path, self.directory / "signature.asc", self.inputs)
            receipt["source_backup"]["sha256"] = self.inputs.manifest["sha256"]
            receipt["created_at_utc"] = (datetime.now(UTC) - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
            save()
            with self.assertRaises(controller.PreflightError):
                controller._verify_clone_receipt(path, self.directory / "signature.asc", self.inputs)


class WorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_role_query_requires_owner_capability_not_a_fake_alter_privilege(self):
        class Connection:
            def __init__(self):
                self.queries = []
                self.owner = True
            async def fetchrow(self, query, *args):
                self.queries.append(query)
                if not args:
                    return {"role": "kairos", "session_role": "kairos", "superuser": False, "bypass_rls": False, "schema_usage": True, "schema_create": True, "uuid_execute": True}
                return {"readable": True, "updatable": True, "owner_capable": self.owner, "row_security": False}
        connection = Connection()
        role = await worker._roles(connection, controller.TABLES)
        self.assertTrue(role["sufficient_for_reviewed_next_step"])
        self.assertFalse(role["actual_ddl_executed"])
        self.assertIn("pg_has_role", " ".join(connection.queries))
        self.assertNotIn("'ALTER'", " ".join(connection.queries))
        connection.owner = False
        role = await worker._roles(connection, controller.TABLES)
        self.assertFalse(role["sufficient_for_reviewed_next_step"])

    async def test_unexpected_client_or_table_inventory_stops_before_streaming(self):
        connection = mock.Mock()
        connection.fetch = mock.AsyncMock(side_effect=[[{"relname": table} for table in controller.TABLES], [{"version": name} for name in controller.CATALOG.LEGACY_MIGRATIONS]])
        connection.fetchval = mock.AsyncMock(side_effect=["synthetic catalog", 1])
        config = controller._worker_config("clone", "kairos_paper_snapshot_" + "a" * 12)
        config["legacy_fingerprint"] = hashlib.sha256(b"synthetic catalog").hexdigest()
        with self.assertRaises(worker.SnapshotError):
            await worker._snapshot(connection, config)
        connection.cursor.assert_not_called()
        connection.fetch = mock.AsyncMock(return_value=[{"relname": "unexpected_table"}])
        with self.assertRaises(worker.SnapshotError):
            await worker._snapshot(connection, config)

    def test_worker_byte_identity_is_checked_before_any_package_import(self):
        with mock.patch.object(worker, "files") as package, self.assertRaises(worker.SnapshotError):
            worker._package({"worker_sha256": "0" * 64})
        package.assert_not_called()

    def test_secret_target_is_fixed_and_never_returned(self):
        config = {"mode": "primary", "physical_database": "kairos"}
        self.assertEqual(worker._dsn(config, "postgresql://kairos:synthetic@timescaledb:5432/kairos"), "postgresql://kairos:synthetic@127.0.0.1:5432/kairos")
        for raw in ("postgresql://kairos:synthetic@prod:5432/kairos", "postgresql://kairos:synthetic@timescaledb:5432/kairos_sim", "postgresql://other:synthetic@timescaledb:5432/kairos", "postgresql://kairos:synthetic@timescaledb:5432/kairos?option=unsafe", "postgresql://kairos:synthetic@timescaledb:5432/kairos\nsecond"):
            with self.subTest(raw=raw), self.assertRaises(worker.SnapshotError):
                worker._dsn(config, raw)
        with self.assertRaises(worker.SnapshotError):
            worker._dsn({"mode": "clone", "physical_database": "kairos"})

    async def test_table_digest_streams_with_unambiguous_framing(self):
        class Connection:
            def cursor(self, query, prefetch):
                self.query, self.prefetch = query, prefetch
                async def rows():
                    for row in ("a\nb", "c"):
                        yield {"row": row}
                return rows()
        connection = Connection()
        result = await worker._table_digest(connection, "event_audit", worker.Budget())
        expected = hashlib.sha256()
        for data in (b"a\nb", b"c"):
            expected.update(len(data).to_bytes(8, "big"))
            expected.update(data)
        self.assertEqual(result, {"count": 2, "row_digest_sha256": expected.hexdigest()})
        self.assertEqual(connection.prefetch, 16)
        self.assertIn('COLLATE "C"', connection.query)
        with self.assertRaises(worker.SnapshotError):
            await worker._table_digest(connection, 'unsafe";drop', worker.Budget())

    def test_snapshot_memory_row_and_time_bounds_fail_closed(self):
        budget = worker.Budget()
        with mock.patch.object(worker, "MAX_ROW_BYTES", 2), self.assertRaises(worker.SnapshotError):
            budget.add("three")
        budget = worker.Budget()
        with mock.patch.object(worker, "MAX_TOTAL_ROWS", 0), self.assertRaises(worker.SnapshotError):
            budget.add("one")
        budget = worker.Budget()
        with mock.patch.object(worker.time, "monotonic", return_value=budget.started + 301), self.assertRaises(worker.SnapshotError):
            budget.add("one")

    async def test_network_guard_allows_only_numeric_database_loopback(self):
        fake = mock.AsyncMock(return_value="loopback")
        with mock.patch.object(worker.asyncio.BaseEventLoop, "create_connection", fake):
            with worker.LoopbackOnly() as guard:
                loop = worker.asyncio.get_running_loop()
                self.assertEqual(await loop.create_connection(None, "127.0.0.1", 5432), "loopback")
                for host, port in (("redis", 6379), ("api.openai.com", 443), ("timescaledb", 5432), ("127.0.0.1", 80)):
                    with self.assertRaises(worker.SnapshotError):
                        await loop.create_connection(None, host, port)
            self.assertEqual(guard.connections, 1)
            self.assertEqual(guard.forbidden, 4)
            self.assertIs(worker.asyncio.BaseEventLoop.create_connection, fake)

    async def test_actual_worker_transaction_is_read_only_and_bounded(self):
        connection = mock.Mock()
        connection.fetchval = mock.AsyncMock(return_value="kairos")
        connection.execute = mock.AsyncMock()
        connection.close = mock.AsyncMock()
        transaction = mock.MagicMock()
        transaction.__aenter__ = mock.AsyncMock()
        transaction.__aexit__ = mock.AsyncMock()
        transaction_calls = []
        # Use asyncpg's real public signature rather than a permissive Mock:
        # the unsupported read_only keyword must fail this test immediately.
        def create_transaction(*, isolation, readonly):
            transaction_calls.append((isolation, readonly))
            return transaction
        connection.transaction = create_transaction
        driver = types.SimpleNamespace(connect=mock.AsyncMock(return_value=connection))
        guard = types.SimpleNamespace(connections=1, forbidden=0)
        context = mock.MagicMock()
        context.__enter__.return_value = guard
        config = {"mode": "primary", "physical_database": "kairos"}
        with mock.patch.dict(sys.modules, {"asyncpg": driver}), mock.patch.object(worker, "_package"), mock.patch.object(worker, "_dsn", return_value="synthetic internal only"), mock.patch.object(worker, "LoopbackOnly", return_value=context), mock.patch.object(worker, "_snapshot", return_value={"history": {}, "target_role": {}}):
            result = await worker._run(config)
        self.assertEqual(driver.connect.call_args.kwargs["server_settings"]["default_transaction_read_only"], "on")
        self.assertEqual(transaction_calls, [("repeatable_read", True)])
        self.assertEqual(connection.execute.call_count, 4)
        self.assertTrue(all(call.args[0].startswith("SET LOCAL ") for call in connection.execute.call_args_list))
        connection.close.assert_awaited_once()
        self.assertEqual(result["primary_mutations"], 0)

    def test_raw_driver_details_are_not_emitted(self):
        with mock.patch.object(worker, "_run", side_effect=RuntimeError("postgresql://user:SECRET@prod/private payload")), mock.patch.object(worker.sys, "stdin", types.SimpleNamespace(readline=lambda: "{}")), mock.patch("builtins.print") as printed:
            self.assertEqual(worker.main(), 2)
        output = printed.call_args.args[0]
        self.assertNotIn("SECRET", output)
        self.assertNotIn("payload", output)
        self.assertEqual(json.loads(output)["error_type"], "RuntimeError")


if __name__ == "__main__":
    unittest.main()
