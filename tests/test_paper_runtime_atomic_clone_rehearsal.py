"""Offline model, admission and native-controller boundary tests; no Docker."""

from __future__ import annotations

import argparse
import copy
import json
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from test_paper_runtime_atomic_contract import contract, history, intent, plan, plan_document, preflight
import paper_runtime_atomic_clone_rehearsal as rehearsal
import validate_paper_runtime_atomic_receipt as verifier
import paper_runtime_atomic_worker as worker


class ModelBackend:
    evidence_mode = "offline-model"

    def __init__(self, value):
        self.plan = value
        self.faults = []
        self.source_calls = 0
        self.tamper = None

    async def source_snapshot(self):
        self.source_calls += 1
        value = self.plan.document["legacy_history"]
        if self.tamper == "source" and self.source_calls == 2:
            value["tables"]["llm_calls"]["row_digest_sha256"] = "c" * 64
        return value

    async def run_fault(self, fault):
        self.faults.append(fault)
        value = self.plan.document["legacy_history"]
        if self.tamper == "rollback":
            value["tables"]["execution_effects"]["row_digest_sha256"] = "c" * 64
        return value

    async def run_success(self):
        after = history(True)
        value = {"worker": {"state": "COMMITTED_ACKNOWLEDGED", "intent": intent(self.plan, after), "history": after, "quarantine_calls": 1, "bound_acquisitions": 2, "primary_mutations": 0, "consumer_restart_permitted": False}, "restored_history": copy.deepcopy(after), "backup_after_sha256": "d" * 64, "unknown_after_commit": "COMMITTED_EXACT", "unknown_after_rollback": "ROLLED_BACK", "unknown_mixed": "INDETERMINATE", "forbidden_network_calls": 0, "publisher_calls": 0, "redis_contacted": False, "consumers_started": 0}
        if self.tamper == "restore":
            value["restored_history"]["tables"]["paper_canary_sessions"]["row_digest_sha256"] = "e" * 64
        elif self.tamper == "publisher":
            value["publisher_calls"] = 1
        return value


class ModelTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_model_is_explicitly_not_native_or_primary_authority(self):
        value = plan()
        backend = ModelBackend(value)
        receipt = await rehearsal.run_offline_model(value, backend)
        self.assertEqual(backend.faults, list(rehearsal.FAULTS))
        self.assertEqual(len(receipt["rollback_snapshots"]), 8)
        result = verifier.verify_receipt(receipt, value, now=datetime.now(UTC))
        self.assertEqual(result["result"], "VERIFIED_OFFLINE_MODEL_ONLY")
        self.assertFalse(result["actual_postgres_rollback_proven"])
        self.assertFalse(result["primary_quarantine_authorized"])

    async def test_source_rollback_restore_and_forbidden_calls_stop_model(self):
        for change in ("source", "rollback", "restore", "publisher"):
            value = plan()
            backend = ModelBackend(value)
            backend.tamper = change
            with self.subTest(change=change), self.assertRaises(contract.AtomicError):
                await rehearsal.run_offline_model(value, backend)

    async def test_real_proof_cannot_be_selected_on_fake_backend(self):
        value = plan()
        backend = ModelBackend(value)
        backend.evidence_mode = "native-postgresql-clone"
        with self.assertRaises(contract.AtomicError):
            await rehearsal.run_offline_model(value, backend)
        self.assertFalse(backend.faults)

    async def test_verifier_rejects_forged_promotion_restore_missing_fault_and_bad_intent(self):
        value = plan()
        receipt = await rehearsal.run_offline_model(value, ModelBackend(value))
        changes = (lambda d: d.update(actual_postgres_rollback_proven=True), lambda d: d.update(primary_quarantine_authorized=True), lambda d: d.update(primary_history_observed_during_rehearsal=True), lambda d: d.update(consumer_restart_permitted=True), lambda d: d.update(restored_history_sha256="0" * 64), lambda d: d["rollback_snapshots"].pop(rehearsal.FAULTS[0]), lambda d: d["worker"]["intent"].update(quarantine_calls=2), lambda d: d.update(created_at_utc=(datetime.now(UTC) - timedelta(hours=3)).isoformat()))
        for mutate in changes:
            changed = copy.deepcopy(receipt)
            mutate(changed)
            changed["receipt_sha256"] = contract.digest({k: v for k, v in changed.items() if k != "receipt_sha256"})
            with self.subTest(mutate=mutate), self.assertRaises(contract.AtomicError):
                verifier.verify_receipt(changed, value, now=datetime.now(UTC))

    async def test_native_verifier_requires_retained_host_plan_intent_and_dump(self):
        value = plan()
        receipt = await rehearsal.run_offline_model(value, ModelBackend(value))
        with tempfile.TemporaryDirectory(prefix="atomic-native-verifier-unit-") as directory:
            # Preserve the native canonical-path requirement even when the
            # hosted Windows TEMP environment contains a short-name alias.
            root = Path(directory).resolve(strict=True)
            attempt = root / "paper-runtime-atomic-attempt-0123456789ab"
            attempt.mkdir()
            (attempt / "atomic-plan.json").write_bytes(value.serialized)
            (attempt / "atomic-after.dump").write_bytes(b"synthetic runtime35 dump")
            intents = attempt / "atomic-intents"
            intents.mkdir()
            prepared = receipt["worker"]["intent"]
            intent_path = intents / ("atomic-precommit-" + contract.digest(prepared) + ".json")
            worker.persist_precommit_intent(intent_path, prepared)
            stopped = {"identity": value.document["source_identity"], "state": {"Status": "exited", "Running": False, "Paused": False, "Restarting": False, "Dead": False, "StartedAt": "synthetic", "FinishedAt": "synthetic", "ExitCode": 0}, "volume": {"Name": contract.readonly.SOURCE_VOLUME, "Driver": "local", "CreatedAt": "synthetic", "Labels": {}, "Scope": "local"}}
            receipt.update(result="PASS_NATIVE_ATOMIC_CLONE_ONLY", evidence_mode="native-postgresql-clone", actual_postgres_rollback_proven=True, primary_history_observed_during_rehearsal=False, stopped_primary_before=stopped, stopped_primary_after=copy.deepcopy(stopped), code_sha256={name: contract.readonly._sha(rehearsal.SCRIPTS / name) for name in rehearsal.CODE_FILES}, resource_bounds={"database_memory_bytes": 3 * 1024**3, "database_tmpfs_bytes": 2 * 1024**3, "database_cpus": 1, "worker_memory_bytes": 512 * 1024**2, "maximum_seconds": 300, "maximum_parallel_databases": 1}, preflight_sha256=value.document["preflight_sha256"], unknown_outcome_proof={"commit": "native injected lost response after COMMIT; fresh read-only connection", "rollback": "native fault rollback full baseline; read-only classifier", "mixed": "offline metadata-only negative classifier; no mixed DB mutation"}, retained_attempt_directory=str(attempt), backup_after_sha256=contract.readonly._sha(attempt / "atomic-after.dump"))
            receipt["worker"]["state"] = "COMMITTED_EXACT_READONLY"
            receipt["receipt_sha256"] = contract.digest({k: v for k, v in receipt.items() if k != "receipt_sha256"})
            with mock.patch.object(contract.CATALOG, "BACKUP_ROOT", root):
                verified = verifier.verify_receipt(receipt, value, now=datetime.now(UTC))
                self.assertEqual(verified["result"], "VERIFIED_UNSIGNED_NATIVE_CLONE_ONLY")
                self.assertFalse(verified["primary_quarantine_authorized"])
                # Model fixture deliberately exercises verifier branches only;
                # never persist this test receipt as real external evidence.
                intent_path.write_bytes(b"{}")
                with self.assertRaises(contract.AtomicError):
                    verifier.verify_receipt(receipt, value, now=datetime.now(UTC))


class NativeBoundaryTests(unittest.TestCase):
    def test_stopped_source_accepts_only_existing_reviewed_readonly_binds(self):
        value = plan()
        expected = value.document["source_identity"]
        source = {"Id": expected["container_id"], "Name": "/" + contract.readonly.SOURCE_CONTAINER, "Image": expected["image_id"], "State": {"Status": "exited", "Running": False, "Paused": False, "Restarting": False, "Dead": False}, "Labels": {"com.docker.compose.project": contract.readonly.SOURCE_PROJECT, "com.docker.compose.service": "timescaledb"}, "Mounts": [{"Destination": "/docker-entrypoint-initdb.d/001-kairos.sql", "Type": "bind", "RW": False}, {"Destination": "/run/secrets/paper_postgres_password", "Type": "bind", "RW": False}, {"Destination": "/var/lib/postgresql/data", "Type": "volume", "Name": contract.readonly.SOURCE_VOLUME, "RW": True}], "Networks": {contract.readonly.SOURCE_NETWORK: {"NetworkID": expected["network_id"]}}, "Privileged": False, "PortBindings": {}}
        controller = rehearsal.NativeCloneController(argparse.Namespace())
        def docker(arguments):
            return "" if arguments[0] == "ps" else json.dumps({"Name": contract.readonly.SOURCE_VOLUME, "Driver": "local", "CreatedAt": "synthetic", "Labels": {}, "Scope": "local"})
        with mock.patch.object(controller, "inspection", return_value=source), mock.patch.object(controller, "docker", side_effect=docker):
            self.assertEqual(controller.stopped_source(value)["identity"], expected)
            source["Mounts"][1]["RW"] = True
            with self.assertRaises(contract.AtomicError):
                controller.stopped_source(value)
            source["Mounts"][1]["RW"] = False
            source["Mounts"].append({"Destination": "/unexpected", "Type": "bind", "RW": False})
            with self.assertRaises(contract.AtomicError):
                controller.stopped_source(value)

    def test_total_deadline_expires_without_resource_retry(self):
        controller = rehearsal.NativeCloneController(argparse.Namespace())
        controller.deadline = time.monotonic() - 1
        with mock.patch.object(rehearsal.subprocess, "run") as runner, self.assertRaises(contract.AtomicError):
            controller.docker(["create", "not-used"])
        runner.assert_not_called()

    def test_inspection_template_never_reads_environment_or_secret_values(self):
        controller = rehearsal.NativeCloneController(argparse.Namespace())
        with mock.patch.object(controller, "docker", return_value="{}") as docker:
            controller.inspection("synthetic-container")
        command = docker.call_args.args[0]
        self.assertNotIn("Config.Env", " ".join(command))
        self.assertIn("--format", command)

    def test_worker_has_no_pull_or_primary_route_and_only_approved_mounts(self):
        controller = rehearsal.NativeCloneController(argparse.Namespace())
        container = "kairos-paper-atomic-clone-0123456789ab"
        controller.clones[container] = "0123456789ab"
        with tempfile.TemporaryDirectory(prefix="atomic-native-command-unit-") as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text("{}")
            intents = root / "intents"
            intents.mkdir()
            with mock.patch.object(controller, "docker", return_value=json.dumps({"state": "READ_ONLY_SNAPSHOT", "primary_mutations": 0, "forbidden_network_calls": 0})) as docker:
                controller.worker(container, "kairos_paper_atomic_0123456789ab", plan_path, intents)
            command = docker.call_args.args[0]
            self.assertIn("--pull=never", command)
            self.assertIn("--memory=512m", command)
            self.assertIn(contract.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, command)
            self.assertEqual(command.count("--mount"), 3)
            self.assertFalse(any("/run/secrets" in word for word in command))
            self.assertFalse(controller.workers)
            with mock.patch.object(controller, "docker") as docker, self.assertRaises(contract.AtomicError):
                controller.worker(contract.readonly.SOURCE_CONTAINER, "kairos", plan_path, intents)
            docker.assert_not_called()

    def test_cleanup_cannot_touch_another_agents_container_or_volume(self):
        controller = rehearsal.NativeCloneController(argparse.Namespace())
        container = "kairos-paper-atomic-clone-0123456789ab"
        controller.clones[container] = "0123456789ab"
        inspection = {"Name": "/" + container, "Labels": {"com.kairos.scope": "different-agent", "com.kairos.drill": "0123456789ab"}, "NetworkMode": "none", "Mounts": [], "Privileged": False, "PortBindings": {}, "Memory": 3 * 1024**3, "NanoCpus": 1_000_000_000}
        with mock.patch.object(controller, "docker", return_value="present") as docker, mock.patch.object(controller, "inspection", return_value=inspection), self.assertRaises(contract.AtomicError):
            controller.remove_clone(container)
        self.assertFalse(any(call.args[0][0] == "rm" for call in docker.call_args_list))

    def test_permanent_host_intent_and_partial_dump_survive_failure_receipt(self):
        with tempfile.TemporaryDirectory(prefix="atomic-retention-unit-") as directory:
            controller = rehearsal.NativeCloneController(argparse.Namespace())
            controller.attempt_directory = Path(directory)
            controller.phase = "POSTCOMMIT_DUMP"
            controller.observed["commit_outcome"] = "COMMITTED_EXACT"
            (Path(directory) / "atomic-plan.json").write_bytes(b"synthetic plan")
            (Path(directory) / "atomic-after.dump").write_bytes(b"synthetic partial dump")
            intents = Path(directory) / "atomic-intents"
            intents.mkdir()
            (intents / "synthetic-intent.json").write_bytes(b"synthetic intent")
            output = controller.failure_receipt(OSError("must never disclose this driver message"))
            self.assertTrue((intents / "synthetic-intent.json").exists())
            self.assertTrue((Path(directory) / "atomic-after.dump").exists())
            value = contract.read_json(output)
            self.assertEqual(value["observed"]["commit_outcome"], "COMMITTED_EXACT")
            self.assertNotIn("must never disclose", output.read_text())
            self.assertFalse(value["primary_quarantine_authorized"])
            self.assertEqual(value["result"], "FAILED_NATIVE_CLONE_NO_AUTHORIZATION")

    def test_frozen_migrate_checkpoint_is_after_real_marker_not_manual_migration(self):
        class Raw:
            def __init__(self):
                self.executed = []
            async def execute(self, query, *args):
                self.executed.append((query, args))
                return "INSERT 0 1"
        raw = Raw()
        stages = []
        bound = worker.ConnectionBoundPool(raw, stages.append)
        import asyncio
        asyncio.run(bound.view.execute("INSERT INTO schema_migrations(version) VALUES ($1)", contract.CATALOG.RUNTIME_SUFFIX[0]))
        self.assertEqual(stages, ["after_migration_013"])
        self.assertEqual(raw.executed[0][1], (contract.CATALOG.RUNTIME_SUFFIX[0],))


class AdmissionTests(unittest.TestCase):
    def test_wrong_confirmation_cannot_read_evidence_or_launch(self):
        with mock.patch.object(contract.CATALOG, "_verify_inputs") as inputs, self.assertRaises(contract.AtomicError):
            rehearsal.prepare_plan(argparse.Namespace(confirmation="APPLY_PRIMARY"))
        inputs.assert_not_called()

    def test_backup_age_is_checked_at_commit_not_only_plan_creation(self):
        document = plan_document()
        document["backup_created_at_utc"] = (datetime.now(UTC) - timedelta(hours=2, seconds=1)).isoformat()
        with self.assertRaises(contract.AtomicError):
            contract.AtomicPlan.from_document(document, now=datetime.now(UTC))


if __name__ == "__main__":
    unittest.main()
