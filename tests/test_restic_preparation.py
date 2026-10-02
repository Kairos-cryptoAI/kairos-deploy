"""Offline CLI/inventory/native-tool contracts, not crypto execution evidence."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts import paper_runtime_schema_upgrade as paper
from scripts import restic_contract as contract
from scripts import restic_preparation as preparation
from tests.test_paper_runtime_schema_upgrade import snapshot


class PolicyTests(unittest.TestCase):
    def test_example_is_explicitly_blocked_and_never_executes_tools(self):
        policy = contract.read_json(contract.ROOT / "operations/offhost-backup.example.json")
        with patch.object(preparation, "_run") as run:
            status = contract.policy_status(policy)
        self.assertEqual(status["status"], "BLOCKED_DESTINATION_UNCONFIGURED")
        self.assertFalse(status["offhost_qualified"])
        self.assertEqual(status["readiness"], contract.READINESS)
        run.assert_not_called()
        for key, value in (("enabled", 0), ("enabled", True), ("destination", "s3:https://unselected"), ("mode", "replicate"), ("schema_version", True), ("managed_secret_reference", "guessed")):
            changed = {**policy, key: value}
            with self.subTest(key=key), self.assertRaises(contract.PreparationError):
                contract.policy_status(changed)
        with self.assertRaises(contract.PreparationError):
            contract.policy_status({**policy, "password": "must-not-enter-policy"})

    def test_lock_is_strict_and_does_not_claim_native_signature_or_installation(self):
        tool = contract.lock()
        self.assertFalse(tool["native_signature_verified"])
        self.assertFalse(tool["installed"])
        for key, value in (("platform", "linux/amd64"), ("archive_bytes", True), ("archive_sha256", "short"), ("installed", True), ("extra", "rejected")):
            changed = {**tool, key: value}
            with patch.object(contract, "read_json", return_value=changed), self.assertRaises(contract.PreparationError):
                contract.lock()


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.archive = self.root / "kairos-paper-gate-20261002T195000Z.dump"
        self.archive.write_bytes(b"synthetic custom archive fixture, not runtime data")
        self.manifest_path = self.archive.with_suffix(".dump.json")
        self.manifest = {"schema_version": 1, "created_at_utc": "2026-10-02T19:50:00Z", "compose_project": "kairos-paper-gate", "database": "kairos", "file": self.archive.name, "bytes": self.archive.stat().st_size, "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(), "checkpoints": {**{name: 0 for name in paper.CATALOG.CHECKPOINT_TABLES}, "public_execution_events_max_sequence": 0}, "timescaledb_bgw_owners": ["kairos"]}
        self.manifest_path.write_bytes(contract.canonical(self.manifest))
        self.receipt_path = self.root / "paper-runtime-readonly-preflight-20261002T195241Z.json"
        self.signature = self.receipt_path.with_suffix(".json.asc")
        self.signature.write_bytes(b"synthetic signature; verification mocked in contract tests")
        self.receipt = {"schema_version": 1, "classification": "PAPER_RUNTIME_READONLY_TARGET_ROLE_AND_RESTORE_BINDING", "result": "PASS_READ_ONLY_PRIMARY_AND_CLONE", "source_backup_sha256": self.manifest["sha256"], "source_manifest_sha256": hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(), "source_identity": {"compose_project": paper.SOURCE_PROJECT, "database": paper.SOURCE_DATABASE, "volume": paper.SOURCE_VOLUME, "network": paper.SOURCE_NETWORK}, "immutable_runner": paper.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, "readiness": dict(contract.READINESS), "primary_apply_implemented": False, "consumer_restart_permitted": False, "redis_contacted": False, "primary_mutations": 0, "consumers_started": 0, "publisher_calls": 0, "source_snapshot": snapshot(), "restored_snapshot": snapshot(False), **paper._code_identity()}
        self.save()
        self.policy = contract.read_json(contract.ROOT / "operations/offhost-backup.example.json")

    def save(self):
        self.receipt["receipt_sha256"] = hashlib.sha256(contract.canonical({k: v for k, v in self.receipt.items() if k != "receipt_sha256"})).hexdigest()
        self.receipt_path.write_bytes(contract.canonical(self.receipt))

    def prepare(self):
        with patch.object(preparation, "_signature") as signature, patch.object(paper, "_docker") as docker:
            value = preparation.prepare_inventory(self.manifest_path, self.receipt_path, self.signature, self.policy, backups=self.root, verification_homedir=self.root / "isolated-public-home")
        signature.assert_called_once_with(self.receipt_path, self.signature, signer=contract.SIGNER, homedir=self.root / "isolated-public-home")
        docker.assert_not_called()
        return value

    def test_actual_backup_and_fullhistory_contracts_create_four_file_inventory_only(self):
        inventory = self.prepare()
        self.assertEqual(len(inventory["files"]), 4)
        self.assertFalse(inventory["remote_transfer_implemented"])
        self.assertTrue(inventory["signing_required_before_transfer"])
        self.assertEqual(inventory["status"], "BLOCKED_DESTINATION_UNCONFIGURED")
        self.assertEqual(inventory["inventory_sha256"], hashlib.sha256(contract.canonical({k: v for k, v in inventory.items() if k != "inventory_sha256"})).hexdigest())
        self.assertNotIn("synthetic custom archive", json.dumps(inventory))

    def test_row_digest_sequence_checkpoint_mutation_is_rejected(self):
        mutations = [lambda r: r["restored_snapshot"]["history"]["tables"]["event_audit"].update(row_digest_sha256="b" * 64), lambda r: r["restored_snapshot"]["history"]["public_sequences"]["message_outbox_id_seq"].update(last_value=2), lambda r: r["source_snapshot"]["history"]["tables"]["event_audit"].update(count=1)]
        initial = copy.deepcopy(self.receipt)
        for mutate in mutations:
            self.receipt = copy.deepcopy(initial)
            mutate(self.receipt)
            self.save()
            with self.assertRaises(contract.PreparationError):
                self.prepare()

    def test_unbound_unsigned_drifted_or_mutating_evidence_is_rejected(self):
        original = copy.deepcopy(self.receipt)
        for key, value in (("source_manifest_sha256", "b" * 64), ("source_backup_sha256", "b" * 64), ("controller_sha256", "b" * 64), ("primary_mutations", True), ("consumer_restart_permitted", True), ("redis_contacted", True), ("immutable_runner", "guessed-image"), ("readiness", {**contract.READINESS, "live_ready": 0})):
            self.receipt = {**original, key: value}
            self.save()
            with self.subTest(key=key), self.assertRaises(contract.PreparationError):
                self.prepare()
        with patch.object(preparation, "_signature", side_effect=contract.PreparationError("SIGNATURE_IDENTITY_REJECTED")), self.assertRaises(contract.PreparationError):
            preparation.prepare_inventory(self.manifest_path, self.receipt_path, self.signature, self.policy, backups=self.root)

    def test_archive_mutation_and_sibling_prefix_do_not_enter_inventory(self):
        self.archive.write_bytes(b"different bytes")
        with self.assertRaises(contract.PreparationError):
            self.prepare()
        with self.assertRaises(contract.PreparationError):
            contract.contained(self.archive, self.root / "unrelated")


class NativeToolContractTests(unittest.TestCase):
    def test_tampered_official_bundle_is_rejected_before_import_extract_or_exec(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / contract.lock()["archive_name"]).write_bytes(b"tampered official bundle")
            with patch.object(preparation, "_run") as run, self.assertRaisesRegex(contract.PreparationError, "PUBLISHED_TOOL_HASH_MISMATCH"):
                preparation.verify_tool_bundle(bundle, root / "new", ops_root=root)
            run.assert_not_called()
            self.assertFalse((root / "new").exists())

    def test_unsigned_proof_objects_existing_targets_and_outside_workspace_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(preparation, "_private_acl"):
            root = Path(temporary).resolve()
            (root / "existing").mkdir()
            with self.assertRaisesRegex(contract.PreparationError, "EXCLUSIVELY_NEW_TARGET_REQUIRED"):
                preparation._new_directory(root / "existing", ops_root=root)
            with self.assertRaisesRegex(contract.PreparationError, "OWNED_OFFLINE_WORKSPACE_REQUIRED"):
                preparation._new_directory(root.parent / (root.name + "-sibling"), ops_root=root)

    def test_forged_tool_receipt_cannot_execute_any_candidate(self):
        with patch.object(preparation, "_run") as run, self.assertRaisesRegex(contract.PreparationError, "SIGNED_NATIVE_BUNDLE_REQUIRED"):
            preparation.local_fixture({"maintainer_signature_verified": True, "executable": "arbitrary"}, Path("arbitrary"))
        run.assert_not_called()

    def test_signature_matches_exact_primary_maintainer_not_any_valid_key(self):
        fields = "[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-07-05 1 0 4 0 1 10 00 " + contract.SIGNER
        with patch.object(preparation, "_run", return_value=fields.encode()), patch.object(preparation, "_public_verification_home"):
            preparation._signature(Path("fixture").resolve(), Path("signature").resolve(), signer=contract.SIGNER, homedir=Path("isolated-public-home").resolve())
            with self.assertRaisesRegex(contract.PreparationError, "SIGNATURE_IDENTITY_REJECTED"):
                preparation._signature(Path("fixture").resolve(), Path("signature").resolve(), signer="B" * 40, homedir=Path("isolated-public-home").resolve())

    def test_signature_without_explicit_home_never_uses_ambient_key_store(self):
        with patch.object(preparation, "_run") as run, self.assertRaisesRegex(contract.PreparationError, "EXPLICIT_PUBLIC_VERIFICATION_HOME_REQUIRED"):
            preparation._signature(Path("fixture"), Path("signature"), signer=contract.SIGNER)
        run.assert_not_called()

    def test_public_gpg_verification_cannot_start_agent_dirmngr_or_retrieve_keys(self):
        expected = ("--batch", "--no-options", "--no-autostart", "--disable-dirmngr", "--no-auto-key-retrieve", "--no-auto-check-trustdb")
        self.assertEqual(preparation.PUBLIC_GPG_OPTIONS, expected)
        valid = ("[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-07-05 1 0 4 0 1 10 00 " + contract.SIGNER).encode()
        with patch.object(preparation, "_public_verification_home"), patch.object(preparation, "_run", return_value=valid) as run:
            preparation._signature(Path("payload").resolve(), Path("signature").resolve(), signer=contract.SIGNER, homedir=Path("public-home").resolve())
        self.assertEqual(run.call_args.args[0][1:7], list(expected))
        self.assertIn("--status-fd", run.call_args.args[0])
        self.assertIn("--verify", run.call_args.args[0])

    def test_gpg_signature_operands_use_absolute_msys_paths_and_keep_spaces(self):
        fields = "[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-07-05 1 0 4 0 1 10 00 " + contract.SIGNER
        with tempfile.TemporaryDirectory(prefix="kairos gpg ") as temporary, patch.object(preparation, "_private_acl"):
            root = Path(temporary).resolve()
            home = root / "public home"
            home.mkdir()
            (home / "private-keys-v1.d").mkdir()  # empty public-import side effect allowed
            signature, payload = root / "receipt file.json.asc", root / "receipt file.json"
            with patch.object(preparation, "OPS_ROOT", root), patch.object(preparation, "_run", return_value=fields.encode()) as run:
                preparation._signature(payload, signature, signer=contract.SIGNER, homedir=home)
            arguments = run.call_args.args[0]
            self.assertEqual(arguments[arguments.index("--homedir") + 1], preparation._gpg_path(home))
            self.assertEqual(arguments[-2:], [preparation._gpg_path(signature), preparation._gpg_path(payload)])
            self.assertTrue(all("\\" not in argument for argument in arguments[arguments.index("--homedir") + 1:]))

    @unittest.skipUnless(os.name == "nt", "fixed Git/MSYS path mapping is Windows-only")
    def test_gpg_drive_paths_are_msys_absolute_before_native_execution(self):
        self.assertEqual(preparation._gpg_path(Path("D:/Kairos/public home/file.asc")), "/d/Kairos/public home/file.asc")
        self.assertEqual(preparation._gpg_path(Path("C:/Kairos/public home/file.asc")), "/c/Kairos/public home/file.asc")
        for operand in ("\\\\server\\share\\file.asc", "//server/share/file.asc", "\\\\?\\D:\\Kairos\\file.asc", "D:relative.asc", "relative.asc", "\\rooted.asc"):
            with self.subTest(operand=operand), patch.object(preparation, "_run") as run, self.assertRaisesRegex(contract.PreparationError, "MSYS_LOCAL_DRIVE_PATH_REQUIRED"):
                preparation._gpg_path(Path(operand))
            run.assert_not_called()

    def test_non_windows_gpg_operand_keeps_normal_absolute_posix_behavior(self):
        operand = Path("ordinary relative fixture.asc")
        expected = operand.resolve().as_posix()
        with patch.object(preparation.os, "name", "posix"):
            self.assertEqual(preparation._gpg_path(operand), expected)

    def test_existing_private_material_is_rejected_by_metadata_without_opening_it(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(preparation, "_private_acl"):
            root = Path(temporary).resolve()
            home = root / "home"
            private = home / "private-keys-v1.d"
            private.mkdir(parents=True)
            (private / "synthetic.key").write_bytes(b"synthetic test material, never opened")
            with patch.object(preparation, "OPS_ROOT", root), patch.object(preparation, "_run") as run, patch.object(Path, "read_bytes", side_effect=AssertionError("private value must not be opened")), self.assertRaisesRegex(contract.PreparationError, "PRIVATE_MATERIAL_IN_VERIFICATION_HOME"):
                preparation._signature(Path("fixture"), Path("signature"), signer=contract.SIGNER, homedir=home)
            run.assert_not_called()
            with patch.object(preparation, "OPS_ROOT", root), self.assertRaisesRegex(contract.PreparationError, "OWNED_PUBLIC_VERIFICATION_HOME_REQUIRED"):
                preparation._public_verification_home(root.parent)

    def test_legacy_private_keyring_is_rejected_without_opening_values(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(preparation, "_private_acl"):
            root = Path(temporary).resolve()
            home = root / "home"
            home.mkdir()
            (home / "secring.gpg").write_bytes(b"synthetic legacy private material, never opened")
            with patch.object(preparation, "OPS_ROOT", root), patch.object(Path, "read_bytes", side_effect=AssertionError("private value must not be opened")), self.assertRaisesRegex(contract.PreparationError, "PRIVATE_MATERIAL_IN_VERIFICATION_HOME"):
                preparation._public_verification_home(home)

    def test_gpg_bundle_import_is_isolated_msys_absolute_and_hash_bound(self):
        with tempfile.TemporaryDirectory(prefix="kairos gpg ") as temporary, patch.object(preparation, "_private_acl"):
            root = Path(temporary).resolve()
            bundle = root / "public bundle"
            bundle.mkdir()
            tool = contract.lock()
            archive = bundle / tool["archive_name"]
            with zipfile.ZipFile(archive, "w") as fixture:
                fixture.writestr(tool["executable_name"], b"synthetic binary; native execution mocked")
            tool = {**tool, "archive_bytes": archive.stat().st_size, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
            checksums = bundle / "SHA256SUMS"
            checksums.write_text(tool["archive_sha256"] + "  " + tool["archive_name"] + "\n", encoding="ascii")
            (bundle / "SHA256SUMS.asc").write_bytes(b"synthetic signature")
            (bundle / "maintainer.asc").write_bytes(b"synthetic public key")
            tool.update(checksums_sha256=hashlib.sha256(checksums.read_bytes()).hexdigest(), signature_sha256=hashlib.sha256((bundle / "SHA256SUMS.asc").read_bytes()).hexdigest())
            valid = ("[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-07-05 1 0 4 0 1 10 00 " + tool["maintainer_fingerprint"]).encode()
            def run(arguments, **kwargs):
                if "version" in arguments:
                    return b"restic 0.19.1 compiled with go1.25.0 on windows/amd64\n"
                return valid if "--verify" in arguments else b""
            work = root / "new verification"
            with patch.object(contract, "lock", return_value=tool), patch.object(preparation, "OPS_ROOT", root), patch.object(preparation, "_run", side_effect=run) as commands:
                receipt = preparation.verify_tool_bundle(bundle, work, ops_root=root)
            imported = commands.call_args_list[0].args[0]
            self.assertEqual(imported[1:7], list(preparation.PUBLIC_GPG_OPTIONS))
            self.assertEqual(imported[imported.index("--homedir") + 1], preparation._gpg_path(work / "verification-keyring"))
            self.assertEqual(imported[-1], preparation._gpg_path(work / "signed-inputs/maintainer.asc"))
            self.assertTrue(receipt["maintainer_signature_verified"])

    def test_tool_error_is_sanitized_bounded_no_proxy_or_ambient_provider_env(self):
        failure = subprocess.CompletedProcess([], 1, stdout=b"PRIVATE_DATA", stderr=b"SECRET_URL")
        with patch.dict(os.environ, {"RESTIC_REPOSITORY": "s3:secret", "HTTPS_PROXY": "https://secret", "AWS_SECRET_ACCESS_KEY": "secret"}), patch.object(preparation.subprocess, "run", return_value=failure) as run, self.assertRaisesRegex(contract.PreparationError, "BOUNDED_TOOL_OPERATION_FAILED") as raised:
            preparation._run(["verified-fixture", "check"], cwd=Path.cwd())
        self.assertNotIn("PRIVATE", str(raised.exception))
        self.assertNotIn("SECRET", str(raised.exception))
        self.assertFalse({"RESTIC_REPOSITORY", "HTTPS_PROXY", "AWS_SECRET_ACCESS_KEY"} & run.call_args.kwargs["env"].keys())
        self.assertEqual(run.call_args.kwargs["timeout"], 120)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_wrong_password_requires_native_decryption_category_not_any_failure(self):
        with patch.object(preparation.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"wrong password or no key found")):
            self.assertEqual(preparation._run(["fixture"], cwd=Path.cwd(), expect_failure=True), b"RESTIC_DECRYPTION_REJECTED")
        with patch.object(preparation.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"disk error")), self.assertRaisesRegex(contract.PreparationError, "AUTH_REJECTION_CATEGORY_UNPROVEN"):
            preparation._run(["fixture"], cwd=Path.cwd(), expect_failure=True)

    def test_synthetic_native_command_contract_binds_new_target_and_complete_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(preparation, "_private_acl"):
            root = Path(temporary).resolve()
            binary = root / "verified-synthetic.exe"
            binary.write_bytes(b"not executed; mocked native fixture")
            receipt = {"executable": str(binary), "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
            work = root / "new-fixture"
            full_id = "a" * 64
            calls = []
            def run(args, **kwargs):
                calls.append((args, kwargs))
                if kwargs.get("expect_failure"):
                    return b"RESTIC_DECRYPTION_REJECTED"
                for verb in ("init", "cat", "backup", "snapshots", "check", "restore"):
                    if verb not in args:
                        continue
                    if verb == "cat":
                        return json.dumps({"id": "b" * 64}).encode()
                    if verb == "backup":
                        self.assertEqual(kwargs["data"], preparation.FIXTURE_BYTES)
                        return json.dumps({"message_type": "summary", "snapshot_id": full_id}).encode()
                    if verb == "snapshots":
                        self.assertIn(full_id, args)
                        return json.dumps([{"id": full_id}]).encode()
                    if verb == "restore":
                        self.assertIn("never", args)
                        self.assertIn("--verify", args)
                        restored = Path(args[args.index("--target") + 1])
                        self.assertFalse(restored.exists())
                        restored.mkdir()
                        (restored / preparation.FIXTURE_NAME).write_bytes(preparation.FIXTURE_BYTES)
                return b"{}"
            with patch.object(preparation, "verify_tool_bundle", return_value=receipt) as verify, patch.object(preparation, "_run", side_effect=run):
                result = preparation.local_fixture(root / "bundle", work, ops_root=root)
            verify.assert_called_once_with(root / "bundle", work / "verified-tool", ops_root=root)
            self.assertEqual(result["snapshot_id"], full_id)
            self.assertFalse(result["offhost_qualified"])
            self.assertFalse(result["database_restore_proven"])
            self.assertEqual(result["fixture_sha256"], result["restored_sha256"])
            self.assertTrue(all("latest" not in args for args, _ in calls))
            self.assertTrue(all(args[args.index("--repo") + 1] == str(work / "repository") for args, _ in calls))
            with self.assertRaises(contract.PreparationError):
                preparation.local_fixture(root / "bundle", work, ops_root=root)


if __name__ == "__main__":
    unittest.main()
