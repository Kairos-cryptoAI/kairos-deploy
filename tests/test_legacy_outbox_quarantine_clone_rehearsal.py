from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "legacy_outbox_quarantine_clone_rehearsal.py"
RUNNER = ROOT / "scripts" / "legacy_outbox_clone_runner.py"
VALIDATOR = ROOT / "scripts" / "validate_legacy_outbox_quarantine_clone_rehearsal.py"


def _validator_module():
    specification = importlib.util.spec_from_file_location("kairos_legacy_clone_rehearsal_validator", VALIDATOR)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _controller_module():
    specification = importlib.util.spec_from_file_location("kairos_legacy_clone_rehearsal_controller", CONTROLLER)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


validator = _validator_module()


class LegacyOutboxQuarantineCloneRehearsalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = CONTROLLER.read_text(encoding="utf-8")
        self.runner = RUNNER.read_text(encoding="utf-8")
        self.runtime_controller = _controller_module()

    def test_static_contract_is_valid(self) -> None:
        self.assertEqual(validator.validate(self.controller, self.runner), [])

    def test_historical_profile_is_distinct_from_clean_preflight(self) -> None:
        self.assertIn("LEGACY_BOOTSTRAPPED_RUNTIME_001_012", self.controller)
        self.assertIn("a2fec9fe81d6af73a1e44038a0e71c21d9aaf2e3933ea8c76793d9e6f25b9adf", self.controller)
        self.assertIn("_verify_signature", self.controller)
        self.assertIn("--require-eligible", self.controller)
        self.assertIn("lease_owner_sha256", self.runner)
        self.assertNotIn("lease_owner\": owner", self.runner)

    def test_runtime_profile_excludes_simulator(self) -> None:
        suffix = validator._tuple_block(self.controller, "RUNTIME_SUFFIX")
        self.assertEqual(suffix, validator.RUNTIME_SUFFIX)
        self.assertIn("017_simulator_journal.sql", self.controller)
        self.assertIn("simulator_relations != 0", self.runner)
        self.assertIn("simulator_relations_present\": False", self.controller)

    def test_worker_uses_db_only_primitive_and_never_publisher(self) -> None:
        self.assertIn("AuditRepository", self.runner)
        self.assertIn("quarantine_expired_outbox_exact", self.runner)
        self.assertIn("LoopbackDatabaseOnlyGuard", self.runner)
        self.assertIn("forbidden_network_calls", self.runner)
        self.assertIn("loopback_database_connections", self.runner)
        self.assertIn("_assert_identity(row, identity)", self.runner)
        self.assertNotIn("FailingNoNetworkPublisher", self.runner)
        self.assertNotIn("claim_expired_outbox_exact", self.runner)
        self.assertNotIn("OfflineOutboxReconciler", self.runner)

    def test_gpg_uses_direct_argv_without_shell_or_ambient_key_retrieval(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="[GNUPG:] VALIDSIG", stderr="")
        with (
            mock.patch.object(self.runtime_controller, "_gpg_executable", return_value=Path(r"C:\Program Files\Git\usr\bin\gpg.exe")),
            mock.patch.object(self.runtime_controller.subprocess, "run", return_value=completed) as run,
        ):
            self.runtime_controller._gpg(["--batch", "--verify", "receipt.asc", "receipt.json"], "unit verification")
        command = run.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertEqual(command[0], r"C:\Program Files\Git\usr\bin\gpg.exe")
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertNotIn("shell=True", self.controller)
        self.assertNotIn("subprocess.list2cmdline", self.controller)
        self.assertNotIn("gpg.program", self.controller)
        self.assertIn("--no-auto-key-retrieve", self.controller)
        armored = "-----BEGIN PGP SIGNATURE-----\nunit\n-----END PGP SIGNATURE-----\n"
        with mock.patch.object(
            self.runtime_controller,
            "_gpg",
            return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=armored, stderr=""),
        ) as gpg:
            self.assertEqual(
                self.runtime_controller._detached_signature(Path("receipt.json")),
                armored.encode("ascii"),
            )
        self.assertIn("--output", gpg.call_args.args[0])
        self.assertEqual(gpg.call_args.args[0][gpg.call_args.args[0].index("--output") + 1], "-")

    def test_worker_result_rejects_each_immutable_identity_difference(self) -> None:
        identity = {
            "id": 7,
            "producer": "recovery",
            "message_id": "message-7",
            "topic": "execution.reported",
            "payload_sha256": "a" * 64,
            "publish_attempts": 3,
        }
        with tempfile.TemporaryDirectory() as directory:
            expectation_path = Path(directory) / "expectation.json"
            expectation_path.write_text(
                json.dumps({"schema_version": 1, "identity": identity, "reconciliation_id": "recovery-7"}),
                encoding="utf-8",
            )
            inputs = types.SimpleNamespace(expectation_path=expectation_path)
            after = {
                **identity,
                "published": False,
                "dead_lettered": False,
                "lease_owner_sha256": None,
                "lease_until_utc": None,
                "reconciliation_state": "PUBLISH_OUTCOME_UNKNOWN",
                "reconciliation_id": "recovery-7",
            }
            payload = {
                "schema_version": 1,
                "kind": "kairos.legacy-outbox-clone-quarantine-result.v1",
                "first_state": "QUARANTINED",
                "repeat_state": "ALREADY_QUARANTINED",
                "before_sha256": "b" * 64,
                "after_sha256": self.runtime_controller._sha256_json(after),
                "after": after,
                "runtime_profile": list(self.runtime_controller.TARGET_MIGRATIONS),
                "simulator_relations": 0,
                "repository_module_sha256": self.runtime_controller.EXPECTED_PERSISTENCE_REPOSITORY_SHA256,
                "forbidden_network_calls": 0,
                "loopback_database_connections": 1,
            }
            self.assertEqual(self.runtime_controller._verify_worker_result(payload, inputs), payload)
            for field in self.runtime_controller.IDENTITY_FIELDS:
                changed = copy.deepcopy(payload)
                if field in {"id", "publish_attempts"}:
                    changed["after"][field] = int(changed["after"][field]) + 1
                else:
                    changed["after"][field] = str(changed["after"][field]) + "-changed"
                changed["after_sha256"] = self.runtime_controller._sha256_json(changed["after"])
                with self.subTest(field=field), self.assertRaises(self.runtime_controller.RehearsalError):
                    self.runtime_controller._verify_worker_result(changed, inputs)

    def test_cleanup_continues_after_a_worker_label_mismatch(self) -> None:
        calls: list[tuple[str, ...]] = []

        def fake_docker(arguments, _label, *, allow_failure=False):
            values = tuple(arguments)
            calls.append(values)
            returncode = 0
            if values[:2] == ("inspect", "--format"):
                return subprocess.CompletedProcess(values, returncode, stdout="container")
            if values[:3] == ("volume", "inspect", "--format"):
                return subprocess.CompletedProcess(values, returncode, stdout="volume")
            return subprocess.CompletedProcess(values, returncode, stdout="")

        def labels(name: str):
            drill = "mismatch" if name == "worker" else "suffix"
            return {"com.kairos.scope": self.runtime_controller.CLONE_SCOPE, "com.kairos.drill": drill}

        with (
            mock.patch.object(self.runtime_controller, "_docker", side_effect=fake_docker),
            mock.patch.object(self.runtime_controller, "_container_labels", side_effect=labels),
            mock.patch.object(self.runtime_controller, "_volume_labels", return_value={"com.kairos.scope": self.runtime_controller.CLONE_SCOPE, "com.kairos.drill": "suffix"}),
        ):
            with self.assertRaises(self.runtime_controller.RehearsalError):
                self.runtime_controller._cleanup(("worker", "probe", "clone"), "data", "stage", "suffix")
        removals = [values for values in calls if values[:2] == ("rm", "-f") or values[:2] == ("volume", "rm")]
        self.assertNotIn(("rm", "-f", "worker"), removals)
        self.assertIn(("rm", "-f", "probe"), removals)
        self.assertIn(("rm", "-f", "clone"), removals)
        self.assertIn(("volume", "rm", "stage"), removals)
        self.assertIn(("volume", "rm", "data"), removals)

    def test_evidence_stage_cleanup_rejects_foreign_directory_and_removes_only_its_stage(self) -> None:
        self.runtime_controller.BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self.runtime_controller.BACKUP_ROOT, prefix=".legacy-outbox-quarantine-evidence-") as directory:
            stage = Path(directory)
            (stage / "frozen-evidence.json").write_text("{}", encoding="utf-8")
            self.runtime_controller._cleanup_evidence_stage(stage)
            self.assertFalse(stage.exists())
        with tempfile.TemporaryDirectory() as foreign:
            with self.assertRaises(self.runtime_controller.RehearsalError):
                self.runtime_controller._cleanup_evidence_stage(Path(foreign))

    def test_timescaledb_owner_placeholder_is_constrained_and_clone_local(self) -> None:
        docker_calls: list[tuple[str, ...]] = []

        def fake_docker(arguments, _label, *, allow_failure=False):
            values = tuple(arguments)
            docker_calls.append(values)
            return subprocess.CompletedProcess(values, 0, stdout="")

        expected_roles = ["source_owner|f|f|f|f|f|f|f"]
        with (
            mock.patch.object(self.runtime_controller, "_docker", side_effect=fake_docker),
            mock.patch.object(self.runtime_controller, "_psql", return_value=expected_roles),
        ):
            owners = self.runtime_controller._ensure_timescaledb_job_owners("clone", "clone_user", ["source_owner"])
        self.assertEqual(owners, ("source_owner",))
        self.assertTrue(any("NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS" in value for call in docker_calls for value in call))
        with self.assertRaises(self.runtime_controller.RehearsalError):
            self.runtime_controller._ensure_timescaledb_job_owners("clone", "clone_user", ["clone_user"])

    def test_receipt_collision_does_not_overwrite_existing_file(self) -> None:
        self.runtime_controller.BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self.runtime_controller.BACKUP_ROOT) as directory:
            receipt_directory = Path(directory)
            output = receipt_directory / "legacy-outbox-quarantine-clone-rehearsal-20260920T000000Z.json"
            output.write_bytes(b"existing")
            with self.assertRaises(self.runtime_controller.RehearsalError):
                self.runtime_controller._write_signed_receipt({"schema_version": 1}, receipt_directory, str(output))
            self.assertEqual(output.read_bytes(), b"existing")

    def test_tampering_is_rejected(self) -> None:
        changed = self.controller.replace("018_offline_outbox_reconciliation.sql", "018_changed.sql", 1)
        self.assertIn("legacy clone rehearsal runtime migration suffix changed", validator.validate(changed, self.runner))
        self.assertTrue(any("runtime/provider route" in error for error in validator.validate(self.controller + "\ndocker compose up\n", self.runner)))
        unpinned = self.controller.replace("EXPECTED_RUNNER_SHA256", "OTHER_RUNNER_SHA256", 1)
        self.assertIn("clone controller must pin the exact reviewed worker bytes", validator.validate(unpinned, self.runner))


if __name__ == "__main__":
    unittest.main()
