"""Synthetic host-I/O regression checks; no runtime, GPG, task or database."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import runtime_epoch_current_boot as boot


class SignatureHostIOTests(unittest.TestCase):
    def test_pinned_public_key_is_not_subject_to_checkout_newline_conversion(self):
        attributes = (Path(__file__).resolve().parents[1] / ".gitattributes").read_text()
        self.assertIn("tests/offline_outbox_reconciliation/trusted-signer.asc -text", attributes.splitlines())

    def test_msys_resource_is_relative_and_both_processes_share_private_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_bytes(b"synthetic receipt, not evidence")
            signature = receipt.with_suffix(".asc")
            signature.write_bytes(b"synthetic signature, not evidence")
            digest = boot.epoch._sha(receipt)
            result = SimpleNamespace(returncode=0, stdout=(
                "[GNUPG:] VALIDSIG " + boot.TRUSTED_SIGNER_FINGERPRINT + " 2026-01-01\n"
            ).encode())
            with mock.patch.object(boot.subprocess, "run", return_value=result) as run:
                boot.verify_receipt_signature(receipt, signature, digest)
            self.assertEqual(run.call_count, 2)
            calls = run.call_args_list
            self.assertEqual(calls[0].kwargs["cwd"], calls[1].kwargs["cwd"])
            self.assertNotEqual(Path(calls[0].kwargs["cwd"]), receipt.parent)
            for call in calls:
                args = call.args[0]
                self.assertEqual(args[args.index("--keyring") + 1], "trusted.gpg")
                self.assertEqual(call.kwargs["env"]["GNUPGHOME"], ".")
            self.assertIn("--no-default-keyring", calls[0].args[0])
            self.assertIn("--no-auto-key-retrieve", calls[0].args[0])
            self.assertEqual(calls[1].args[0][-2:], [signature.as_posix(), receipt.as_posix()])
            with mock.patch.object(boot.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=b"[GNUPG:] VALIDSIG untrusted-signer\n"
            )), self.assertRaises(boot.CurrentBootRejected):
                boot.verify_receipt_signature(receipt, signature, digest)


class InspectionEvidenceTests(unittest.TestCase):
    def test_repeated_admission_never_reuses_native_cli_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            owner_work = Path(directory) / "owner"
            owner_work.mkdir()
            native_log = owner_work / "cli-001.stdout"
            native_log.write_bytes(b"immutable native evidence")
            receipt = owner_work / "current-runtime-receipt.json"
            receipt.write_bytes(b"{}")
            owner = "0123456789abcdef0123456789abcdef"
            digest = "a" * 64
            profile = {"wheelhouse": directory, "wheel_manifest_sha256": digest,
                       "deploy_revision": "b" * 40, "subnet": "10.254.251.96/28"}
            workdirs = []

            def controller(*args, **kwargs):
                path = kwargs["workdir"]
                self.assertNotEqual(path, owner_work)
                self.assertEqual(path.parent, owner_work)
                with (path / "cli-001.stdout").open("xb") as stream:
                    stream.write(b"separate inspection evidence")
                workdirs.append(path)
                return SimpleNamespace()

            with mock.patch.object(boot, "verify_receipt_signature"), \
                 mock.patch.object(boot, "read_bounded_json", return_value={}), \
                 mock.patch.object(boot, "validate_current_receipt", return_value=(
                     owner, profile, {"build": None, "proofs": {}}, owner_work
                 )), \
                 mock.patch.object(boot.current, "verify_clean_signed_sources"), \
                 mock.patch.object(boot.epoch, "_sha", return_value=digest), \
                 mock.patch.object(boot.epoch, "_private_directory", side_effect=lambda path: path.mkdir()), \
                 mock.patch.object(boot.current, "CurrentEpochController", side_effect=controller), \
                 mock.patch.object(boot, "database_identity_from_restore_proof", return_value={}), \
                 mock.patch.object(boot.CurrentEpochBootAdapter, "_validate_sources_and_resources", return_value={}):
                for _ in range(2):
                    boot.CurrentEpochBootAdapter(receipt, digest, receipt.with_suffix(".asc"))
            self.assertEqual(len(set(workdirs)), 2)
            self.assertEqual(native_log.read_bytes(), b"immutable native evidence")
            for path in workdirs:
                self.assertTrue((path / "inspection-binding.json").is_file())


if __name__ == "__main__":
    unittest.main()
