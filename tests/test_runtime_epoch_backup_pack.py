"""Offline contract tests for the create-only R7 Restic pack adapter."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts import restic_contract as contract
from scripts import runtime_epoch_backup_pack as pack

SOURCE_REVISION = "a" * 40
CONTAINER_ID = "b" * 64
PROOF_SHA = "c" * 64
SNAPSHOT_ID = "d" * 64
REPOSITORY_ID = "e" * 64


def make_accepted_workdir(root: Path) -> tuple[Path, str, dict[str, bytes]]:
    work = root.resolve(strict=True) / (pack.WORK_PREFIX + uuid.uuid4().hex)
    work.mkdir()
    payloads = {
        pack.BEFORE_NAME: b"full epoch history before\n" * 4,
        pack.AFTER_NAME: b"full epoch history after\n" * 5,
    }
    for name, raw in payloads.items():
        (work / name).write_bytes(raw)
    receipt = {
        "result": "PASS_NEW_NONTRADING_GENERATION",
        "recovery_kind": "R7_REDIS_TRANSPORT_RECOVERY",
        "owner": pack.OWNER,
        "source_revision": SOURCE_REVISION,
        "prebackup_sha256": hashlib.sha256(payloads[pack.BEFORE_NAME]).hexdigest(),
        "postcatchup_backup_sha256": hashlib.sha256(payloads[pack.AFTER_NAME]).hexdigest(),
        "cold_backups": {"before": PROOF_SHA},
        "generation": {
            "name": "kairos-epoch-" + pack.OWNER[:12] + "-serve-r7",
            "container_id": CONTAINER_ID,
            "status": {
                "state": "RUNNING_NONTRADING",
                "owner": pack.OWNER,
                "trading_started": False,
            },
            "graceful_restart_proven": True,
            "stop_receipt_sha256": PROOF_SHA,
        },
        "redis_proof": {"stream_proof_sha256": PROOF_SHA},
        "final_state_sha256": PROOF_SHA,
        "completed_at_utc": "2026-10-13T09:00:00+00:00",
        "trading_started": False,
        "PAPER_QUALIFIED": False,
        "ALPHA_READY": False,
        "LIVE_READY": False,
        "STRATEGY_POLICY": "REJECT_ALL",
    }
    receipt_path = work / pack.RECEIPT_NAME
    receipt_path.write_bytes(contract.canonical(receipt) + b"\n")
    receipt_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    (work / pack.ACCEPTED_NAME).write_bytes(
        contract.canonical(
            {
                "state": "ACCEPTED",
                "owner": pack.OWNER,
                "source_revision": SOURCE_REVISION,
                "receipt_sha256": receipt_sha,
                "trading_started": False,
            }
        )
        + b"\n"
    )
    (work / pack.SIGNATURE_NAME).write_bytes(b"synthetic detached signature\n")
    return work, receipt_sha, payloads


def verifier_for(paths: list[Path] | None = None):
    def verify(receipt: Path, signature: Path, signer: str) -> None:
        if paths is not None:
            paths.extend((receipt, signature))
        assert receipt.name == pack.RECEIPT_NAME
        assert signature.name == pack.SIGNATURE_NAME
        assert signer == pack.SIGNER

    return verify


class RuntimeEpochBackupPackTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp_path = Path(temporary.name)

    def assert_pack_rejected(self, message: str, operation) -> None:
        with self.assertRaisesRegex(contract.PreparationError, message):
            operation()

    def test_plan_only_binds_only_the_three_allowlisted_files_and_writes_nothing(self) -> None:
        work, receipt_sha, _payloads = make_accepted_workdir(self.tmp_path)
        result = pack.plan_pack(
            work,
            work / pack.REPOSITORY_NAME,
            accepted_receipt_sha256=receipt_sha,
            source_revision=SOURCE_REVISION,
            verify_signature=verifier_for(),
            runtime_root=self.tmp_path,
        )

        self.assertEqual(result["mode"], "PLAN_ONLY")
        self.assertEqual(
            [Path(path).name for path in result["snapshot_inputs"]],
            [pack.BEFORE_NAME, pack.AFTER_NAME, pack.RECEIPT_NAME],
        )
        self.assertEqual(result["native_restic_calls"], 0)
        self.assertFalse(result["creates_run_claim"])
        self.assertFalse((work / pack.CLAIM_NAME).exists())
        self.assertFalse((work / pack.REPOSITORY_NAME).exists())
        self.assertEqual(
            {path.name for path in work.iterdir()},
            {
                pack.BEFORE_NAME,
                pack.AFTER_NAME,
                pack.RECEIPT_NAME,
                pack.ACCEPTED_NAME,
                pack.SIGNATURE_NAME,
            },
        )

    def test_cli_defaults_to_plan_only_and_does_not_enter_native_path(self) -> None:
        work, receipt_sha, _payloads = make_accepted_workdir(self.tmp_path)
        output = StringIO()
        with (
            patch.object(pack, "RUNTIME_ROOT", self.tmp_path),
            patch.object(pack.preparation, "_signature", lambda *_args, **_kwargs: None),
            redirect_stdout(output),
        ):
            result = pack.main(
                [
                    "--workdir",
                    str(work),
                    "--repository",
                    str(work / pack.REPOSITORY_NAME),
                    "--accepted-receipt-sha256",
                    receipt_sha,
                    "--source-revision",
                    SOURCE_REVISION,
                    "--verification-homedir",
                    str(self.tmp_path / "public-verification-home"),
                ]
            )

        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["mode"], "PLAN_ONLY")
        self.assertEqual(report["native_restic_calls"], 0)
        self.assertFalse((work / pack.CLAIM_NAME).exists())
        self.assertFalse((work / pack.REPOSITORY_NAME).exists())

    def test_receipt_hash_argument_and_accepted_record_are_mandatory(self) -> None:
        work, receipt_sha, _payloads = make_accepted_workdir(self.tmp_path)
        self.assert_pack_rejected(
            "ACCEPTED_RECEIPT_HASH_MISMATCH",
            lambda: pack.validate_accepted_inputs(
                work,
                accepted_receipt_sha256="0" * 64,
                source_revision=SOURCE_REVISION,
                verify_signature=verifier_for(),
                runtime_root=self.tmp_path,
            ),
        )

        accepted = json.loads((work / pack.ACCEPTED_NAME).read_text(encoding="utf-8"))
        accepted["source_revision"] = "f" * 40
        (work / pack.ACCEPTED_NAME).write_text(json.dumps(accepted), encoding="utf-8")
        self.assert_pack_rejected(
            "R7_ACCEPTED_RECORD_MISMATCH",
            lambda: pack.validate_accepted_inputs(
                work,
                accepted_receipt_sha256=receipt_sha,
                source_revision=SOURCE_REVISION,
                verify_signature=verifier_for(),
                runtime_root=self.tmp_path,
            ),
        )

    def test_dump_hash_must_match_signed_receipt(self) -> None:
        work, receipt_sha, _payloads = make_accepted_workdir(self.tmp_path)
        (work / pack.AFTER_NAME).write_bytes(b"changed after acceptance")
        self.assert_pack_rejected(
            "R7_FULL_DUMP_HASH_BINDING_REJECTED",
            lambda: pack.validate_accepted_inputs(
                work,
                accepted_receipt_sha256=receipt_sha,
                source_revision=SOURCE_REVISION,
                verify_signature=verifier_for(),
                runtime_root=self.tmp_path,
            ),
        )

    def test_unexpected_recovery_scope_and_linked_sources_fail_closed(self) -> None:
        work, _receipt_sha, _payloads = make_accepted_workdir(self.tmp_path)
        receipt_path = work / pack.RECEIPT_NAME
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["STRATEGY_POLICY"] = "ALLOW"
        receipt_path.write_bytes(contract.canonical(receipt) + b"\n")
        new_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        accepted = json.loads((work / pack.ACCEPTED_NAME).read_text(encoding="utf-8"))
        accepted["receipt_sha256"] = new_sha
        (work / pack.ACCEPTED_NAME).write_bytes(contract.canonical(accepted) + b"\n")
        self.assert_pack_rejected(
            "R7_ACCEPTED_SCOPE_OR_PROOF_REJECTED",
            lambda: pack.validate_accepted_inputs(
                work,
                accepted_receipt_sha256=new_sha,
                source_revision=SOURCE_REVISION,
                verify_signature=verifier_for(),
                runtime_root=self.tmp_path,
            ),
        )

        work2, receipt_sha2, _payloads2 = make_accepted_workdir(self.tmp_path)
        linked = work2 / (pack.BEFORE_NAME + ".linked")
        os.link(work2 / pack.BEFORE_NAME, linked)
        with self.assertRaises(contract.PreparationError):
            pack.validate_accepted_inputs(
                work2,
                accepted_receipt_sha256=receipt_sha2,
                source_revision=SOURCE_REVISION,
                verify_signature=verifier_for(),
                runtime_root=self.tmp_path,
            )

    def test_fake_restic_adapter_claims_once_checks_and_restores_exact_bytes(self) -> None:
        work, receipt_sha, payloads = make_accepted_workdir(self.tmp_path)
        bundle = self.tmp_path / "restic-signed-bundle"
        bundle.mkdir()
        executable = self.tmp_path / "restic-verified.exe"
        executable.write_bytes(b"synthetic fake-restic executable")
        invocations: list[list[str]] = []

        def verify_tool(_bundle: Path, destination: Path, *, ops_root: Path) -> dict[str, Any]:
            self.assertEqual(_bundle, bundle)
            self.assertEqual(ops_root, self.tmp_path)
            destination.mkdir()
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            return {"executable": str(executable), "executable_sha256": digest}

        def fake_restic(command: list[str], *, cwd: Path, data=None, expect_failure=False) -> bytes:
            # Hosted Windows runners may expose TEMP through an 8.3 alias.
            # The adapter correctly canonicalizes it before native execution.
            self.assertEqual(cwd.resolve(), work.resolve())
            self.assertIsNone(data)
            invocations.append(command)
            repo = Path(command[2])
            password_file = Path(command[4])
            self.assertTrue(password_file.exists())
            self.assertEqual(command[3], "--password-file")
            self.assertEqual(command[4], str(password_file))
            subcommand = command[7]
            args = command[8:]
            if expect_failure:
                self.assertEqual(subcommand, "cat")
                self.assertEqual(args, ["config"])
                return b"RESTIC_DECRYPTION_REJECTED"
            if subcommand == "init":
                repo.mkdir()
                return b"{}"
            if subcommand == "cat":
                return json.dumps({"id": REPOSITORY_ID}).encode("utf-8")
            if subcommand == "backup":
                self.assertEqual(
                    args[:4],
                    ["--host", "kairos-r7-accepted-runtime", "--tag", "kairos-r7-accepted-v1"],
                )
                sources = [Path(path) for path in args[4:]]
                self.assertEqual(
                    [path.name for path in sources],
                    [pack.BEFORE_NAME, pack.AFTER_NAME, pack.RECEIPT_NAME],
                )
                self.assertTrue(all(path.parent == work for path in sources))
                self.assertNotIn(pack.SIGNATURE_NAME, [path.name for path in sources])
                summary = {"message_type": "summary", "snapshot_id": SNAPSHOT_ID}
                return (json.dumps(summary) + "\n").encode()
            if subcommand == "snapshots":
                return json.dumps([{"id": args[0]}]).encode()
            if subcommand == "check":
                self.assertEqual(args, ["--read-data"])
                return b"{}"
            if subcommand == "restore":
                target = Path(args[args.index("--target") + 1])
                self.assertEqual(args[args.index("--overwrite") + 1], "never")
                target.mkdir()
                for name, content in payloads.items():
                    (target / name).write_bytes(content)
                (target / pack.RECEIPT_NAME).write_bytes((work / pack.RECEIPT_NAME).read_bytes())
                return b"{}"
            self.fail(f"unexpected fake Restic command: {subcommand}")
            return b""

        with patch.object(pack, "_private_acl", lambda _path: None):
            result = pack.create_local_pack(
                work,
                work / pack.REPOSITORY_NAME,
                bundle,
                accepted_receipt_sha256=receipt_sha,
                source_revision=SOURCE_REVISION,
                verify_signature=verifier_for(),
                tool_verifier=verify_tool,
                run_process=fake_restic,
                runtime_root=self.tmp_path,
            )

        self.assertEqual(result["status"], "PASS_LOCAL_ENCRYPTED_R7_PACK_AND_RESTORE")
        self.assertTrue(result["wrong_password_rejected"])
        self.assertTrue(result["full_authenticated_data_check"])
        self.assertEqual(
            result["restored_sha256"],
            {name: values["sha256"] for name, values in result["input_sha256"].items()},
        )
        self.assertEqual(result["network_requests"], 0)
        self.assertTrue((work / pack.CLAIM_NAME).is_file())
        self.assertTrue((work / pack.RESULT_NAME).is_file())
        self.assertTrue(all("--repo" in command and "--password-file" in command for command in invocations))
        self.assertTrue(all(not any(value.startswith("https://") for value in command) for command in invocations))
        self.assert_pack_rejected(
            "R7_RESTIC_CLAIM_ALREADY_EXISTS_NO_RETRY",
            lambda: pack.create_local_pack(
                work,
                work / "another-repository",
                bundle,
                accepted_receipt_sha256=receipt_sha,
                source_revision=SOURCE_REVISION,
                verify_signature=verifier_for(),
                tool_verifier=verify_tool,
                run_process=fake_restic,
                runtime_root=self.tmp_path,
            ),
        )
