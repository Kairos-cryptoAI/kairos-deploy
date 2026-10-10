from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import SimpleNamespace
from unittest import mock

from scripts import controlled_runtime_primary as primary


def _write_json(path: Path, value) -> str:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PrimaryAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clone_root = self.root / "controlled"
        self.clone_root.mkdir()
        self.clone_dir = self.clone_root / ("run-" + "a" * 32)
        self.clone_dir.mkdir()
        self.supervisor_dir = self.clone_root / ("supervisor-" + "b" * 32)
        self.supervisor_dir.mkdir()
        self.wheelhouse = self.root / "wheelhouse"
        self.wheelhouse.mkdir()
        self.old_root = primary.current.ROOT
        primary.current.ROOT = self.clone_root
        # Host-native admission keeps its fixed Windows paths. These tests
        # exercise signed-document policy using only owned temporary fixtures.
        self.path_patch = mock.patch.object(
            primary.fresh, "safe", side_effect=lambda path: path.absolute()
        )
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        self.repo_patch = mock.patch.object(
            primary.fresh, "REPO", Path(primary.__file__).resolve().parent.parent
        )
        self.repo_patch.start()
        self.addCleanup(self.repo_patch.stop)

    def tearDown(self):
        primary.current.ROOT = self.old_root
        self.temp.cleanup()

    def _accepted(self):
        owner = "a" * 32
        revisions = {"kairos-core": "1" * 40, "kairos-persistence": "2" * 40}
        packages = []
        for name, wheel, revision in (
            (
                "kairos-core",
                "kairos_core-1.0-py3-none-any.whl",
                revisions["kairos-core"],
            ),
            (
                "kairos-persistence",
                "kairos_persistence-1.0-py3-none-any.whl",
                revisions["kairos-persistence"],
            ),
        ):
            payload = name.encode()
            (self.wheelhouse / wheel).write_bytes(payload)
            prefix = name.replace("-", "_") + "/"
            packages.append(
                {
                    "name": name,
                    "revision": revision,
                    "wheel": wheel,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "files": {prefix + "__init__.py": "c" * 64},
                }
            )
        manifest = {"schema_version": 1, "packages": packages}
        manifest_hash = _write_json(self.wheelhouse / "manifest.json", manifest)
        plan = {
            "schema_version": 1,
            "kind": primary.current.KIND,
            "owner": owner,
            "primary_authorized": False,
            "package_revisions": revisions,
            "plan_binding_sha256": "f" * 64,
        }
        inspection = {"state": "INSPECTED", "plan_binding_sha256": "f" * 64}
        rehearsal = {"result": "PASS", "plan_binding_sha256": "f" * 64}
        verification = {
            "state": "VERIFIED_HISTORY_ONLY",
            "plan_binding_sha256": "f" * 64,
        }
        for filename, value in (
            ("plan.json", plan),
            ("native-inspection.json", inspection),
            ("native-rehearsal.json", rehearsal),
            ("native-verify.json", verification),
            ("source-before.json", {"source": "unchanged"}),
            (
                "cold-fingerprint.json",
                {"files_sha256": "d" * 64, "metadata_sha256": "e" * 64, "bytes": 42},
            ),
        ):
            _write_json(self.clone_dir / filename, value)
        names = {
            "source-before.json",
            "cold-fingerprint.json",
            "plan.json",
            "native-inspection.json",
            "native-rehearsal.json",
            "native-verify.json",
        }
        artifact_hashes = {
            name: hashlib.sha256((self.clone_dir / name).read_bytes()).hexdigest()
            for name in names
        }
        clone_receipt = {
            "kind": primary.current.KIND,
            "owner": owner,
            "result": "PASS_CURRENT_CONTROLLED_CLONE",
            "cleanup_verified": True,
            "primary_mutations": 0,
            "primary_consumers_started": 0,
            "proofs": {
                "artifact_sha256": artifact_hashes,
                "current_rehearsal_sha256": artifact_hashes["native-rehearsal.json"],
                "current_restore_verify_sha256": artifact_hashes["native-verify.json"],
                "reviewed_deploy_revision": "3" * 40,
                "wheel_manifest_sha256": manifest_hash,
                "package_revisions": revisions,
            },
        }
        clone_receipt_path = self.clone_dir / "receipt.json"
        clone_sha = _write_json(clone_receipt_path, clone_receipt)
        (self.clone_dir / "receipt.json.asc").write_text("test", encoding="utf-8")
        supervisor = {
            "kind": "controlled-runtime-hidden-supervisor-v1",
            "result": "PASS",
            "child_receipt_sha256": clone_sha,
            "child_result": {"receipt": str(clone_receipt_path)},
            "cli_tree": {
                "assigned_before_resume": True,
                "tree_cleanup_verified": True,
                "active_owned_processes_after": 0,
            },
        }
        _write_json(self.supervisor_dir / "receipt.json", supervisor)
        (self.supervisor_dir / "receipt.json.asc").write_text("test", encoding="utf-8")
        return revisions

    def test_signed_acceptance_requires_exact_receipts_artifact_hashes_and_revisions(
        self,
    ):
        revisions = self._accepted()
        with mock.patch.object(primary, "_verify_signature"):
            owner, clone, plan, accepted = primary.validate_acceptance(
                self.clone_dir,
                self.supervisor_dir,
                expected_revision="3" * 40,
                wheelhouse=self.wheelhouse,
                verifier=object(),
            )
        self.assertEqual(owner, "a" * 32)
        self.assertEqual(clone["result"], "PASS_CURRENT_CONTROLLED_CLONE")
        self.assertFalse(plan["primary_authorized"])
        self.assertEqual(accepted["revisions"], revisions)

    def test_rejects_modified_artifact_even_when_receipt_mentions_old_hash(self):
        self._accepted()
        (self.clone_dir / "native-rehearsal.json").write_text("{}", encoding="utf-8")
        with (
            mock.patch.object(primary, "_verify_signature"),
            self.assertRaises(primary.fresh.Rejected),
        ):
            primary.validate_acceptance(
                self.clone_dir,
                self.supervisor_dir,
                expected_revision="3" * 40,
                wheelhouse=self.wheelhouse,
                verifier=object(),
            )

    def test_primary_admission_never_runs_by_default(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = primary.main([])
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["mode"], "PLAN_ONLY")
        self.assertEqual(report["primary_mutations"], 0)

    def test_running_primary_entrypoint_must_match_frozen_operator_manifest(self):
        running = Path(primary.__file__).resolve()
        relative = (
            running.relative_to(primary.fresh.REPO.resolve())
            .as_posix()
            .removeprefix("scripts/")
        )
        controller = type("Controller", (), {})()
        controller.operator_snapshot = self.root / "snapshot"
        controller.operator_manifest = {relative: primary.fresh.sha(running)}
        controller.proofs = {}
        with mock.patch.object(
            primary.current, "verify_operator_snapshot", return_value="a" * 64
        ):
            self.assertEqual(
                primary.verify_primary_script_snapshot(controller),
                primary.fresh.sha(running),
            )
        self.assertEqual(
            controller.proofs["primary_controller_sha256"], primary.fresh.sha(running)
        )
        controller.operator_manifest[relative] = "0" * 64
        with (
            mock.patch.object(
                primary.current, "verify_operator_snapshot", return_value="a" * 64
            ),
            self.assertRaises(primary.fresh.Rejected),
        ):
            primary.verify_primary_script_snapshot(controller)

    def test_remote_absence_checks_cover_broken_symlinks(self):
        controller = object.__new__(primary.PrimaryController)
        controller.docker = mock.Mock()
        controller._require_remote_absent("/tmp/owned.sql")
        commands = [entry.args[0] for entry in controller.docker.call_args_list]
        self.assertEqual(
            commands,
            [
                ["exec", primary.fresh.SOURCE, "test", "!", "-e", "/tmp/owned.sql"],
                ["exec", primary.fresh.SOURCE, "test", "!", "-L", "/tmp/owned.sql"],
            ],
        )

    def test_signature_verification_uses_posix_file_arguments_and_exact_signer(self):
        trusted_key = (
            Path(__file__).resolve().parents[1]
            / "tests/offline_outbox_reconciliation/trusted-signer.asc"
        )
        executable = self.root / "fixture-gpg"
        executable.write_bytes(b"not executed")
        receipt = self.root / "receipt.json"
        signature = self.root / "receipt.json.asc"
        status = self.root / "clone-gpg-verify.stdout"
        status.write_text(
            "[GNUPG:] VALIDSIG "
            + primary.SIGNER
            + " 2026-10-10 0 0 4 0 22 8 00 "
            + primary.SIGNER
            + "\n",
            encoding="utf-8",
        )
        controller = SimpleNamespace(work=self.root, process=mock.Mock())
        with (
            mock.patch.object(primary, "GPG", executable),
            mock.patch.object(primary, "TRUSTED_KEY", trusted_key),
        ):
            primary._verify_signature(controller, receipt, signature, "clone")
        calls = controller.process.call_args_list
        self.assertEqual(len(calls), 2)
        import_args, verify_args = calls[0].args[1], calls[1].args[1]
        self.assertEqual(
            import_args[1], primary._gpg_file_arg(self.root / "gpg-home-clone")
        )
        self.assertEqual(import_args[-1], primary._gpg_file_arg(trusted_key))
        self.assertEqual(
            verify_args[-2:],
            [primary._gpg_file_arg(signature), primary._gpg_file_arg(receipt)],
        )
        self.assertIn("--no-auto-key-retrieve", verify_args)
        self.assertIn("--no-autostart", import_args)
        self.assertIn("--no-autostart", verify_args)
        self.assertTrue(all("\\" not in value for value in import_args + verify_args))

        # A valid signature from any other primary fingerprint is not accepted.
        (self.root / "other-gpg-verify.stdout").write_text(
            status.read_text().replace(primary.SIGNER, "F" * 40)
        )
        with (
            mock.patch.object(primary, "GPG", executable),
            mock.patch.object(primary, "TRUSTED_KEY", trusted_key),
            self.assertRaisesRegex(primary.fresh.Rejected, "SIGNER_MISMATCH"),
        ):
            primary._verify_signature(controller, receipt, signature, "other")

    def test_gpg_file_paths_map_local_drives_and_reject_relative_or_unc(self):
        self.assertEqual(
            primary._gpg_file_arg(PureWindowsPath("D:/Kairos/receipt.json")),
            "/d/Kairos/receipt.json",
        )
        self.assertEqual(
            primary._gpg_file_arg(PurePosixPath("/tmp/receipt.json")),
            "/tmp/receipt.json",
        )
        for path in (
            PureWindowsPath("receipt.json"),
            PureWindowsPath("//server/share/receipt.json"),
        ):
            with (
                self.subTest(path=str(path)),
                self.assertRaises(primary.fresh.Rejected),
            ):
                primary._gpg_file_arg(path)


if __name__ == "__main__":
    unittest.main()
