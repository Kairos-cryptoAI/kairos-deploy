from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL_ROOT = ROOT / "tests" / "offline_outbox_reconciliation"


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


policy = load_module("kairos_offline_outbox_policy_test", TOOL_ROOT / "policy.py")
runner = load_module("kairos_offline_outbox_runner_test", TOOL_ROOT / "runner.py")


def expectation_value() -> dict[str, object]:
    return {
        "schema_version": 1,
        "identity": {
            "id": 42,
            "producer": "recovery-producer",
            "message_id": "outbox-message-42",
            "topic": "kairos.recovery.v1",
            "payload_sha256": "4ea5edbf85d6199e192a6a6c3b9c3d664d8cd3b2934a4249612fb38cfe96083b",
            "publish_attempts": 3,
        },
        "reconciliation_id": "operator-approved-recovery-42",
    }


class OfflineOutboxPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "outbox-reconciliation.sources.lock.json").read_text(encoding="utf-8"))
        self.packaged_lock = json.loads((TOOL_ROOT / "source-lock.json").read_text(encoding="utf-8"))
        self.compose = json.loads((TOOL_ROOT / "compose.fixture.json").read_text(encoding="utf-8"))

    def test_sealed_lock_signer_dockerfile_and_profile_are_accepted(self) -> None:
        self.assertEqual(self.lock, self.packaged_lock)
        self.assertEqual(policy.validate_source_lock(self.lock), [])
        self.assertEqual(policy.validate_trusted_signer(TOOL_ROOT / "trusted-signer.asc", self.lock), [])
        self.assertEqual(policy.validate_dockerfile((TOOL_ROOT / "Dockerfile").read_text(encoding="utf-8")), [])
        self.assertEqual(policy.validate_dockerignore((TOOL_ROOT / ".dockerignore").read_text(encoding="utf-8")), [])
        self.assertEqual(policy.validate_compose(self.compose), [])

    def test_normal_up_cannot_start_a_reconciliation_service(self) -> None:
        self.assertEqual(policy.normal_up_services(self.compose), set())
        for service in self.compose["services"].values():
            self.assertTrue(service["profiles"])
            self.assertEqual(service["command"][1], "inspect")
        self.assertEqual(
            policy.validate_normal_up_compose(
                {"name": policy.PROJECT, "services": {}, "x-outbox-reconciler-runtime": {"read_only": True}}
            ),
            [],
        )
        self.assertTrue(
            any(
                "must contain no offline outbox services" in error
                for error in policy.validate_normal_up_compose(
                    {"name": policy.PROJECT, "services": {"outbox-inspector": {}}}
                )
            )
        )

    def test_profile_rejects_egress_auto_restart_and_bulk_escape_hatches(self) -> None:
        broken = copy.deepcopy(self.compose)
        broken["services"]["outbox-reconciler"]["ports"] = ["443:443"]
        broken["services"]["outbox-reconciler"]["restart"] = "unless-stopped"
        broken["services"]["outbox-reconciler"]["environment"] = {"KAIROS_EVEDEX_API_KEY": "forbidden"}
        broken["services"]["outbox-reconciler"]["networks"]["egress"] = None
        errors = policy.validate_compose(broken)
        self.assertTrue(any("unsafe service option ports" in error for error in errors))
        self.assertTrue(any("automatic restart" in error for error in errors))
        self.assertTrue(any("runtime environment" in error for error in errors))
        self.assertTrue(any("network scope changed" in error for error in errors))

    def test_lock_rejects_mutable_persistence_and_unbounded_receipt(self) -> None:
        broken = copy.deepcopy(self.lock)
        broken["dependencies"]["kairos-persistence"]["revision"] = "main"
        broken["profile"]["maximum_receipt_age_seconds"] = 3_600
        errors = policy.validate_source_lock(broken)
        self.assertTrue(any("exact source pins" in error for error in errors))
        self.assertTrue(any("exact and bounded" in error for error in errors))


class OfflineOutboxRunnerTests(unittest.TestCase):
    def exact_expectation(self):
        return runner.ExactExpectation.from_json(expectation_value())

    def matching_row(self) -> dict[str, object]:
        expectation = expectation_value()["identity"]
        assert isinstance(expectation, dict)
        payload = {"message_id": "outbox-message-42", "value": 1}
        return {
            **expectation,
            "payload": json.dumps(payload, separators=(",", ":")),
            "published_at": None,
            "dead_lettered_at": None,
            "lease_expired": True,
            "available": True,
            "reconciliation_state": "NONE",
        }

    def test_expectation_is_exact_and_never_supplies_a_default_row(self) -> None:
        parser = runner.parser()
        args = parser.parse_args(["--expectation", "expectation.json", "--database-url-file", "database_url"])
        self.assertEqual(args.mode, "inspect")
        malformed = expectation_value()
        del malformed["identity"]
        with self.assertRaises(runner.ReconciliationInputError):
            runner.ExactExpectation.from_json(malformed)

    def test_inspection_receipt_is_hashed_redacted_and_freshly_bound(self) -> None:
        row = self.matching_row()
        expectation = self.exact_expectation()
        receipt = runner.build_inspection_receipt(
            expectation,
            row=row,
            audit_rows=[{"topic": row["topic"], "payload": row["payload"]}],
            has_unpublished_predecessor=False,
            inspected_at=datetime(2026, 9, 19, 12, 0, tzinfo=UTC),
        )
        rendered = runner.canonical_json(receipt)
        self.assertEqual(receipt["inspection"]["result"], "ELIGIBLE")
        self.assertNotIn('"payload"', rendered)
        self.assertNotIn("postgres://", rendered)
        self.assertNotIn("redis://", rendered)
        runner.validate_apply_receipt(
            receipt,
            expectation,
            expected_file_sha256=hashlib.sha256((rendered + "\n").encode("utf-8")).hexdigest(),
            actual_file_sha256=hashlib.sha256((rendered + "\n").encode("utf-8")).hexdigest(),
            now=datetime(2026, 9, 19, 12, 1, tzinfo=UTC),
        )

    def test_edited_or_stale_receipt_is_rejected_before_apply(self) -> None:
        row = self.matching_row()
        expectation = self.exact_expectation()
        receipt = runner.build_inspection_receipt(
            expectation,
            row=row,
            audit_rows=[{"topic": row["topic"], "payload": row["payload"]}],
            has_unpublished_predecessor=False,
            inspected_at=datetime(2026, 9, 19, 12, 0, tzinfo=UTC),
        )
        edited = copy.deepcopy(receipt)
        edited["identity"]["id"] = 43
        with self.assertRaises(runner.ReconciliationInputError):
            runner.validate_apply_receipt(
                edited,
                expectation,
                expected_file_sha256=hashlib.sha256(runner.canonical_json(receipt).encode("utf-8")).hexdigest(),
                actual_file_sha256=hashlib.sha256(runner.canonical_json(edited).encode("utf-8")).hexdigest(),
                now=datetime(2026, 9, 19, 12, 1, tzinfo=UTC),
            )
        with self.assertRaises(runner.ReconciliationInputError):
            runner.validate_apply_receipt(
                receipt,
                expectation,
                expected_file_sha256=hashlib.sha256(runner.canonical_json(receipt).encode("utf-8")).hexdigest(),
                actual_file_sha256=hashlib.sha256(runner.canonical_json(receipt).encode("utf-8")).hexdigest(),
                now=datetime(2026, 9, 19, 12, 6, tzinfo=UTC),
            )

    def test_receipt_file_hash_must_match_the_explicitly_armed_bytes(self) -> None:
        row = self.matching_row()
        expectation = self.exact_expectation()
        receipt = runner.build_inspection_receipt(
            expectation,
            row=row,
            audit_rows=[{"topic": row["topic"], "payload": row["payload"]}],
            has_unpublished_predecessor=False,
            inspected_at=datetime(2026, 9, 19, 12, 0, tzinfo=UTC),
        )
        rendered = runner.canonical_json(receipt) + "\n"
        with self.assertRaises(runner.ReconciliationInputError):
            runner.validate_apply_receipt(
                receipt,
                expectation,
                expected_file_sha256=hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                actual_file_sha256=hashlib.sha256(rendered.rstrip("\n").encode("utf-8")).hexdigest(),
                now=datetime(2026, 9, 19, 12, 1, tzinfo=UTC),
            )

    def test_unknown_publish_outcome_is_terminal_and_redacted(self) -> None:
        expectation = self.exact_expectation()

        class Result:
            identity = expectation.identity
            state = "PUBLISH_OUTCOME_UNKNOWN"
            rejection = None
            unknown_quarantined = False
            failure_kind = "database_ack_not_applied"

        payload = runner.result_payload(Result())
        self.assertEqual(payload["state"], "PUBLISH_OUTCOME_UNKNOWN")
        self.assertFalse(payload["unknown_quarantined"])
        self.assertNotIn('"payload":', runner.canonical_json(payload))
        self.assertEqual(runner._result_state_value(Result()), "PUBLISH_OUTCOME_UNKNOWN")
        self.assertEqual(runner.reconciliation_exit_code(Result()), 3)

        class Acknowledged:
            state = "PUBLISH_ACKNOWLEDGED"

        class Rejected:
            state = "CLAIM_REJECTED"

        self.assertEqual(runner.reconciliation_exit_code(Acknowledged()), 0)
        self.assertEqual(runner.reconciliation_exit_code(Rejected()), 2)
        self.assertEqual(runner.reconciliation_exit_code(object()), 3)

    def test_receipt_rejects_raw_connection_or_payload_material(self) -> None:
        with self.assertRaises(runner.ReconciliationInputError):
            runner.assert_receipt_redacted({"database_url": "postgres://not-permitted"})
        with self.assertRaises(runner.ReconciliationInputError):
            runner.assert_receipt_redacted({"payload": {"message_id": "not-permitted"}})

    def test_signature_verification_uses_only_the_pinned_public_signer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            signature = Path(directory) / "receipt.json.asc"
            receipt.write_text("{}\n", encoding="utf-8")
            signature.write_text("safe-test-signature\n", encoding="utf-8")
            completed = [
                runner.subprocess.CompletedProcess(args=["gpg"], returncode=0, stdout="", stderr=""),
                runner.subprocess.CompletedProcess(
                    args=["gpgv"],
                    returncode=0,
                    stdout="[GNUPG:] VALIDSIG 40AF365C6682B73D056A6A274DBFF6B65BE9F827 2026-09-19 0 4 0 22 8 00 40AF365C6682B73D056A6A274DBFF6B65BE9F827\n",
                    stderr="",
                ),
            ]
            with mock.patch.object(runner.subprocess, "run", side_effect=completed) as execute:
                runner.verify_receipt_signature(receipt, signature)
            import_call, verify_call = execute.call_args_list
            self.assertIn("--no-default-keyring", import_call.args[0])
            self.assertIn("--keyring", verify_call.args[0])
            self.assertIn(str(signature), verify_call.args[0])
            self.assertIn(str(receipt), verify_call.args[0])

            with (
                mock.patch.object(
                    runner.subprocess,
                    "run",
                    side_effect=[
                        runner.subprocess.CompletedProcess(args=["gpg"], returncode=0, stdout="", stderr=""),
                        runner.subprocess.CompletedProcess(args=["gpgv"], returncode=1, stdout="", stderr=""),
                    ],
                ),
                self.assertRaises(runner.ReconciliationInputError),
            ):
                runner.verify_receipt_signature(receipt, signature)


class OfflineOutboxWrapperTests(unittest.TestCase):
    def test_wrapper_is_explicit_profile_run_only_and_never_authorizes_a_row(self) -> None:
        wrapper = (ROOT / "scripts" / "Invoke-OfflineOutboxReconciliation.ps1").read_text(encoding="utf-8")
        self.assertIn('[string]$Mode = "Inspect"', wrapper)
        self.assertIn("Assert-ExactExpectation", wrapper)
        self.assertIn("-ArmApply", wrapper)
        self.assertIn("Test-DetachedReceiptSignature", wrapper)
        self.assertIn("Get-FileHash -Algorithm SHA256", wrapper)
        self.assertIn("run --rm --no-deps", wrapper)
        self.assertIsNone(re.search(r"(?<!\d)\d{6}(?!\d)", wrapper))
        self.assertNotIn("claim_outbox", wrapper)
        self.assertNotIn("docker compose up", wrapper.casefold())

    def test_runner_never_uses_the_normal_dispatcher_or_a_retry_loop(self) -> None:
        source = (TOOL_ROOT / "runner.py").read_text(encoding="utf-8")
        self.assertIn("OfflineOutboxReconciler", source)
        self.assertIn("def reconciliation_exit_code", source)
        self.assertIn("default_transaction_read_only", source)
        self.assertNotIn("claim_outbox", source)
        self.assertNotIn("while True", source)
        self.assertNotIn("_dispatch_outbox", source)
        self.assertNotIn("for attempt", source.casefold())


if __name__ == "__main__":
    unittest.main()
