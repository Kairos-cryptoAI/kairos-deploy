from __future__ import annotations

import contextlib
import copy
import csv
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import alert_delivery as delivery
from scripts import validate_alert_delivery as topology


class AlertPolicyTests(unittest.TestCase):
    @staticmethod
    def policy() -> dict:
        return {"schema_version": 1, "enabled": True, "receiver": "telegram", "profile": "paper", "source_sha256": hashlib.sha256((delivery.ROOT / "monitoring/prometheus.yml").read_bytes()).hexdigest(), "expected_bot_username": delivery.EXPECTED_BOT, "expected_chat_id": delivery.EXPECTED_CHAT, "group_wait_seconds": 5, "group_interval_seconds": 30, "repeat_interval_seconds": 300}

    def test_disabled_example_is_not_launchable(self) -> None:
        policy = json.loads((delivery.ROOT / "operations/alert-delivery.example.json").read_text())
        self.assertIn("DELIVERY_DISABLED", delivery.policy_errors(policy))
        with self.assertRaises(delivery.DeliveryError):
            delivery.render_alertmanager(policy)

    def test_only_exact_receiver_and_bound_source_are_accepted(self) -> None:
        self.assertEqual(delivery.policy_errors(self.policy()), [])
        for key, value in (("expected_chat_id", -1), ("expected_bot_username", "wrong"), ("receiver", "webhook"), ("source_sha256", "0" * 64), ("group_wait_seconds", True), ("group_interval_seconds", None), ("repeat_interval_seconds", 1)):
            with self.subTest(key=key):
                policy = self.policy()
                policy[key] = value
                self.assertTrue(delivery.policy_errors(policy))
        policy = self.policy()
        policy["bot_token"] = "synthetic-not-a-key"
        self.assertEqual(delivery.policy_errors(policy), ["INVALID_POLICY_FIELDS"])

    def test_native_config_has_only_sanitized_file_secret_receiver(self) -> None:
        rendered = delivery.render_alertmanager(self.policy())
        for text in ("bot_token_file: /run/secrets/telegram_bot_token", "send_resolved: true", "parse_mode: \"\"", "follow_redirects: false", "proxy_from_environment: false", "insecure_skip_verify: false"):
            self.assertIn(text, rendered)
        for text in ("bot_token:", ".Annotations", "inhibit_rules:", "mute_time_intervals:"):
            self.assertNotIn(text, rendered)
        self.assertNotIn("@@", rendered)

    def test_notifier_preserves_actual_baseline_and_rules(self) -> None:
        rule_hashes = [(path, hashlib.sha256(path.read_bytes()).hexdigest()) for path in (delivery.ROOT / "monitoring/alerts.yml", delivery.ROOT / "monitoring/alerts.base.yml")]
        rendered = delivery.render_prometheus(self.policy())
        baseline = (delivery.ROOT / "monitoring/prometheus.yml").read_text()
        tail = baseline.split("  scrape_interval:", 1)[1]
        self.assertIn("  scrape_interval:" + tail, rendered)
        self.assertIn("kairos_environment: paper", rendered)
        self.assertIn("kairos-ops-alertmanager:9093", rendered)
        for path, digest in rule_hashes:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_render_exclusively_new_directory_and_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch.object(delivery, "TelegramTransport") as transport:
            output = Path(temporary) / "new"
            result = delivery.render_files(self.policy(), output)
            self.assertEqual(result["status"], "PREPARED_CONFIG_ONLY")
            self.assertFalse(result["operationally_qualified"])
            with self.assertRaisesRegex(delivery.DeliveryError, "OUTPUT_MUST_BE_NEW"):
                delivery.render_files(self.policy(), output)
            transport.assert_not_called()


class QualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "ops"
        self.root.mkdir(mode=0o700)
        secrets = self.root / "secrets"
        secrets.mkdir(mode=0o700)
        self.token = secrets / "telegram_bot_token"
        self.token.write_text("123456:" + "A" * 35)
        self.token.chmod(0o600)
        # Windows ACL verification is separately exercised below; these tests
        # only use synthetic fixture contents and never operator credentials.
        self.acl = patch.object(delivery, "_private_acl")
        self.acl.start()
        self.addCleanup(self.acl.stop)
        self.transport = patch.object(delivery, "TelegramTransport")
        self.factory = self.transport.start()
        self.addCleanup(self.transport.stop)

    @staticmethod
    def replies() -> list[dict]:
        return [{"is_bot": True, "username": delivery.EXPECTED_BOT}, {"id": delivery.EXPECTED_TEST_CHAT, "type": "group", "title": "DO_NOT_DISCLOSE"}, {"message_id": 42, "chat": {"id": delivery.EXPECTED_TEST_CHAT, "title": "DO_NOT_DISCLOSE"}, "text": "ignored"}]

    def run_test(self) -> dict:
        return delivery.qualify(self.token, authorize_one_test=True, ops_root=self.root)

    def test_explicit_authorization_precedes_all_side_effects(self) -> None:
        with self.assertRaisesRegex(delivery.DeliveryError, "EXPLICIT_TEST_AUTHORIZATION_REQUIRED"):
            delivery.qualify(self.token, authorize_one_test=False, ops_root=self.root)
        self.factory.assert_not_called()
        self.assertFalse((self.root / "receipts").exists())

    def test_exactly_one_send_after_durable_reservation_and_repeat_guard(self) -> None:
        replies = iter(self.replies())

        def call(method, params):
            if method == "sendMessage":
                journals = list((self.root / "receipts").glob("*.jsonl"))
                self.assertEqual(len(journals), 1)
                records = [json.loads(line) for line in journals[0].read_text().splitlines()]
                self.assertEqual(records[-1]["stage"], "SEND_RESERVED")
                self.assertIn("QUALIFICATION TEST", params["text"])
            return next(replies)

        self.factory.return_value.call.side_effect = call
        result = self.run_test()
        self.assertEqual(result["stage"], "TRANSPORT_ACCEPTED")
        self.assertEqual(result["send_attempts"], 1)
        self.assertEqual(result["expected_chat_id"], delivery.EXPECTED_TEST_CHAT)
        self.assertEqual(result["recipient_purpose"], "qualification_test_only")
        self.assertEqual(result["http_method_counts"], {"getMe": 1, "getChat": 1, "sendMessage": 1})
        self.assertEqual(result["implementation_sha256"], hashlib.sha256(Path(delivery.__file__).read_bytes()).hexdigest())
        self.assertEqual(result["test_message_sha256"], hashlib.sha256(delivery.TEST_MESSAGE.encode("utf-8")).hexdigest())
        self.assertFalse(result["human_acknowledged"])
        self.assertFalse(result["trading_authority"])
        self.assertEqual([args[0][0] for args in self.factory.return_value.call.call_args_list], ["getMe", "getChat", "sendMessage"])
        count = self.factory.return_value.call.call_count
        with self.assertRaisesRegex(delivery.DeliveryError, "EXISTING_QUALIFICATION_REQUIRES_REVIEW"):
            self.run_test()
        self.assertEqual(self.factory.return_value.call.call_count, count)
        evidence = "".join(p.read_text() for p in (self.root / "receipts").glob("*.jsonl"))
        self.assertNotIn("DO_NOT_DISCLOSE", evidence)
        self.assertNotIn(self.token.read_text(), evidence)

    def test_test_recipient_is_distinct_from_production_and_old_journal_preserved(self) -> None:
        self.assertNotEqual(delivery.EXPECTED_TEST_CHAT, delivery.EXPECTED_CHAT)
        receipts = self.root / "receipts"
        receipts.mkdir()
        old_scope = hashlib.sha256(delivery.canonical({"bot": delivery.EXPECTED_BOT, "chat": delivery.EXPECTED_CHAT})).hexdigest()
        old_journal = receipts / ("telegram-qualification-" + old_scope + ".jsonl")
        old_evidence = b'{"stage":"PRECHECK_FAILED","send_attempts":0}\n'
        old_journal.write_bytes(old_evidence)
        self.factory.return_value.call.side_effect = self.replies()
        result = self.run_test()
        self.assertEqual(result["stage"], "TRANSPORT_ACCEPTED")
        self.assertEqual(old_journal.read_bytes(), old_evidence)
        self.assertEqual(len(list(receipts.glob("*.jsonl"))), 2)
        for call in self.factory.return_value.call.call_args_list:
            if call.args[0] in {"getChat", "sendMessage"}:
                self.assertEqual(call.args[1]["chat_id"], delivery.EXPECTED_TEST_CHAT)
        self.assertIn("chat_id: " + str(delivery.EXPECTED_CHAT), delivery.render_alertmanager(AlertPolicyTests.policy()))

    def test_wrong_sender_or_chat_never_sends(self) -> None:
        for replies in ([{"is_bot": True, "username": "wrong"}], [{"is_bot": True, "username": delivery.EXPECTED_BOT}, {"id": -1, "type": "group"}]):
            with self.subTest(replies=replies):
                self.factory.return_value.call.side_effect = replies
                result = self.run_test()
                self.assertEqual(result["stage"], "PRECHECK_FAILED")
                self.assertEqual(result["send_attempts"], 0)
                # Different fixture root, not removal of a retained guard.
                self.root = self.root.parent / (self.root.name + "-next")
                self.root.mkdir(mode=0o700)
                (self.root / "secrets").mkdir(mode=0o700)
                self.token = self.root / "secrets/telegram_bot_token"
                self.token.write_text("123456:" + "A" * 35)

    def test_ambiguous_send_and_partial_receipt_are_never_retried(self) -> None:
        self.factory.return_value.call.side_effect = self.replies()[:2] + [delivery.DeliveryError("TRANSPORT_FAILED")]
        result = self.run_test()
        self.assertEqual(result["stage"], "SEND_OUTCOME_UNKNOWN")
        self.assertEqual(result["send_attempts"], 1)
        with self.assertRaisesRegex(delivery.DeliveryError, "EXISTING_QUALIFICATION_REQUIRES_REVIEW"):
            self.run_test()

    def test_disk_failure_before_reservation_means_no_send(self) -> None:
        self.factory.return_value.call.side_effect = self.replies()
        original = os.fsync
        calls = 0

        def fail_before_send(fd):
            nonlocal calls
            calls += 1
            # Initial guard: file + POSIX directory; next record is identity.
            if calls >= (4 if os.name != "nt" else 3):
                raise OSError("SYNTHETIC_PRIVATE_DATA")
            return original(fd)

        with patch.object(delivery.os, "fsync", side_effect=fail_before_send):
            result = self.run_test()
        self.assertEqual(result["stage"], "PRECHECK_FAILED")
        self.assertNotIn("sendMessage", [args[0][0] for args in self.factory.return_value.call.call_args_list])

    def test_token_path_substitution_is_rejected_before_read(self) -> None:
        wrong = self.root / "wrong"
        wrong.write_text("not a key")
        with self.assertRaisesRegex(delivery.DeliveryError, "DEDICATED_TOKEN_FILE_REQUIRED"):
            delivery.qualify(wrong, authorize_one_test=True, ops_root=self.root)
        self.factory.assert_not_called()


class AcknowledgementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "ops"
        self.receipts = self.root / "receipts"
        self.receipts.mkdir(parents=True, mode=0o700)
        self.journal = delivery._qualification_path(self.root)
        self.entries = self.synthetic_entries()
        self.raw = b"".join(delivery.canonical(entry) + b"\n" for entry in self.entries)
        self.journal.write_bytes(self.raw)
        self.journal.chmod(0o600)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.acl = patch.object(delivery, "_private_acl")
        self.acl.start()
        self.addCleanup(self.acl.stop)

    @staticmethod
    def synthetic_entries() -> list[dict]:
        common = {"schema_version": 1, "implementation_sha256": hashlib.sha256(b"historical qualification implementation").hexdigest(), "test_message_sha256": hashlib.sha256(delivery.TEST_MESSAGE.encode("utf-8")).hexdigest(), "expected_bot_username": delivery.EXPECTED_BOT, "expected_chat_id": delivery.EXPECTED_TEST_CHAT, "recipient_purpose": "qualification_test_only", "human_acknowledged": False, "trading_authority": False}
        stages = ["PRECHECK_STARTED", "IDENTITY_VERIFIED", "SEND_RESERVED", "TRANSPORT_ACCEPTED"]
        counts = [{"getMe": 0, "getChat": 0, "sendMessage": 0}, {"getMe": 1, "getChat": 1, "sendMessage": 0}, {"getMe": 1, "getChat": 1, "sendMessage": 0}, {"getMe": 1, "getChat": 1, "sendMessage": 1}]
        entries = []
        for index, stage in enumerate(stages):
            entry = {**common, "stage": stage, "send_attempts": 1 if index >= 2 else 0, "http_method_counts": counts[index], "transport_accepted": index == 3}
            if index > 0:
                entry.update({"error_category": None, "observed_at_utc": "2026-10-10T09:00:00+00:00"})
            if index == 3:
                entry["message_id"] = 42
            entries.append(entry)
        return entries

    def attest(self) -> dict:
        return delivery.acknowledge(expected_journal_sha256=self.digest, message_id=42, confirmation=delivery.ACK_CONFIRMATION, ops_root=self.root)

    def test_success_is_local_attestation_and_readback_survives_restart(self) -> None:
        with patch.object(delivery, "TelegramTransport", side_effect=AssertionError("ack must not access Telegram")) as transport:
            result = self.attest()
            readback = delivery.read_acknowledgement(expected_journal_sha256=self.digest, message_id=42, ops_root=self.root)
        self.assertEqual(result, readback)
        self.assertNotEqual(self.entries[0]["implementation_sha256"], hashlib.sha256(Path(delivery.__file__).read_bytes()).hexdigest())
        self.assertEqual(result["basis"], "LOCAL_OPERATOR_ATTESTATION")
        self.assertFalse(result["telegram_user_authenticated"])
        self.assertFalse(result["operationally_qualified"])
        self.assertFalse(result["trading_authority"])
        self.assertEqual(self.journal.read_bytes(), self.raw)
        self.assertEqual(transport.call_count, 0)
        self.assertFalse((self.root / "secrets" / "telegram_bot_token").exists())

    def test_requires_exact_confirmation_digest_and_message_id(self) -> None:
        for kwargs, error in (({"confirmation": "yes"}, "EXPLICIT_ACKNOWLEDGEMENT_REQUIRED"), ({"expected_journal_sha256": "0" * 64}, "QUALIFICATION_JOURNAL_SHA256_MISMATCH"), ({"message_id": 43}, "MESSAGE_ID_MISMATCH"), ({"message_id": True}, "MESSAGE_ID_REQUIRED")):
            args = {"expected_journal_sha256": self.digest, "message_id": 42, "confirmation": delivery.ACK_CONFIRMATION, "ops_root": self.root}
            args.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(delivery.DeliveryError, error):
                delivery.acknowledge(**args)
        self.assertFalse(delivery._acknowledgement_path(self.root).exists())

    def test_rejects_wrong_chat_bot_flags_and_tampered_sequence(self) -> None:
        mutations = ((3, "expected_chat_id", -1), (3, "expected_bot_username", "wrong"), (3, "trading_authority", True), (3, "trading_authority", 0), (3, "human_acknowledged", True), (3, "human_acknowledged", 0), (3, "transport_accepted", False), (3, "stage", "SEND_OUTCOME_UNKNOWN"), (2, "error_category", "uncertain"), (3, "extra", "unknown"), (3, "implementation_sha256", "0" * 64))
        for index, key, value in mutations:
            with self.subTest(key=key, value=value):
                entries = self.synthetic_entries()
                entries[index][key] = value
                raw = b"".join(delivery.canonical(entry) + b"\n" for entry in entries)
                self.journal.write_bytes(raw)
                self.journal.chmod(0o600)
                digest = hashlib.sha256(raw).hexdigest()
                with self.assertRaises(delivery.DeliveryError):
                    delivery.acknowledge(expected_journal_sha256=digest, message_id=42, confirmation=delivery.ACK_CONFIRMATION, ops_root=self.root)
                self.assertFalse(delivery._acknowledgement_path(self.root).exists())

    def test_rejects_middle_record_source_fingerprint_drift(self) -> None:
        entries = self.synthetic_entries()
        entries[1]["implementation_sha256"] = "0" * 64
        raw = b"".join(delivery.canonical(entry) + b"\n" for entry in entries)
        self.journal.write_bytes(raw)
        self.journal.chmod(0o600)
        with self.assertRaisesRegex(delivery.DeliveryError, "QUALIFICATION_JOURNAL_DRIFT"):
            delivery.acknowledge(expected_journal_sha256=hashlib.sha256(raw).hexdigest(), message_id=42, confirmation=delivery.ACK_CONFIRMATION, ops_root=self.root)
        self.assertFalse(delivery._acknowledgement_path(self.root).exists())

    def test_refuses_partial_extra_duplicate_or_ambiguous_journals(self) -> None:
        cases = (b"".join(self.raw.splitlines(keepends=True)[:2]), self.raw + self.raw.splitlines(keepends=True)[-1], self.raw.replace(b"TRANSPORT_ACCEPTED", b"SEND_OUTCOME_UNKNOWN"), self.raw[:-1])
        for raw in cases:
            with self.subTest(length=len(raw)):
                self.journal.write_bytes(raw)
                self.journal.chmod(0o600)
                digest = hashlib.sha256(raw).hexdigest()
                with self.assertRaises(delivery.DeliveryError):
                    delivery.acknowledge(expected_journal_sha256=digest, message_id=42, confirmation=delivery.ACK_CONFIRMATION, ops_root=self.root)
                self.assertFalse(delivery._acknowledgement_path(self.root).exists())

    def test_existing_complete_or_partial_acknowledgement_is_never_overwritten(self) -> None:
        receipt = delivery._acknowledgement_path(self.root)
        self.attest()
        original = receipt.read_bytes()
        with self.assertRaisesRegex(delivery.DeliveryError, "EXISTING_ACKNOWLEDGEMENT_REQUIRES_REVIEW"):
            self.attest()
        self.assertEqual(receipt.read_bytes(), original)
        receipt.unlink()
        receipt.write_bytes(b'{"partial":')
        receipt.chmod(0o600)
        original = receipt.read_bytes()
        with self.assertRaisesRegex(delivery.DeliveryError, "EXISTING_ACKNOWLEDGEMENT_REQUIRES_REVIEW"):
            self.attest()
        self.assertEqual(receipt.read_bytes(), original)
        with self.assertRaisesRegex(delivery.DeliveryError, "ACKNOWLEDGEMENT_RECEIPT_INVALID"):
            delivery.read_acknowledgement(expected_journal_sha256=self.digest, message_id=42, ops_root=self.root)

    def test_journal_and_ack_reads_are_bounded_and_reparse_safe(self) -> None:
        self.journal.write_bytes(b"x" * (delivery.MAX_QUALIFICATION_JOURNAL_BYTES + 1))
        with self.assertRaisesRegex(delivery.DeliveryError, "QUALIFICATION_JOURNAL_SIZE_REJECTED"):
            self.attest()
        self.journal.unlink()
        outside = Path(self.temporary.name) / "outside.jsonl"
        outside.write_bytes(self.raw)
        try:
            self.journal.symlink_to(outside)
        except OSError:
            self.skipTest("Symlink creation unavailable on this host")
        with self.assertRaisesRegex(delivery.DeliveryError, "REPARSE_PATH_REJECTED"):
            self.attest()

    def test_readback_refuses_changed_or_missing_original_journal(self) -> None:
        result = self.attest()
        self.assertEqual(result["basis"], "LOCAL_OPERATOR_ATTESTATION")
        changed = self.raw.replace(b"TRANSPORT_ACCEPTED", b"SEND_OUTCOME_UNKNOWN")
        self.journal.write_bytes(changed)
        self.journal.chmod(0o600)
        with self.assertRaisesRegex(delivery.DeliveryError, "QUALIFICATION_JOURNAL_SHA256_MISMATCH"):
            delivery.read_acknowledgement(expected_journal_sha256=self.digest, message_id=42, ops_root=self.root)
        self.journal.unlink()
        with self.assertRaisesRegex(delivery.DeliveryError, "QUALIFICATION_JOURNAL_REQUIRED"):
            delivery.read_acknowledgement(expected_journal_sha256=self.digest, message_id=42, ops_root=self.root)

    def test_readback_rejects_bool_type_confusion_and_ack_before_terminal(self) -> None:
        result = self.attest()
        receipt_path = Path(result["receipt_path"])
        receipt = json.loads(receipt_path.read_bytes())
        receipt["trading_authority"] = 0
        receipt_path.write_bytes(delivery.canonical(receipt) + b"\n")
        receipt_path.chmod(0o600)
        with self.assertRaisesRegex(delivery.DeliveryError, "ACKNOWLEDGEMENT_RECEIPT_MISMATCH"):
            delivery.read_acknowledgement(expected_journal_sha256=self.digest, message_id=42, ops_root=self.root)
        receipt["trading_authority"] = False
        receipt["attested_at_utc"] = "2026-10-10T08:59:59+00:00"
        receipt_path.write_bytes(delivery.canonical(receipt) + b"\n")
        receipt_path.chmod(0o600)
        with self.assertRaisesRegex(delivery.DeliveryError, "ACKNOWLEDGEMENT_TIME_ORDER_REJECTED"):
            delivery.read_acknowledgement(expected_journal_sha256=self.digest, message_id=42, ops_root=self.root)

    def test_journal_observation_times_must_be_utc_and_monotonic(self) -> None:
        for index, timestamp in ((1, "2026-10-10T12:00:00+03:00"), (2, "2026-10-10T08:59:59+00:00")):
            with self.subTest(timestamp=timestamp):
                entries = self.synthetic_entries()
                entries[index]["observed_at_utc"] = timestamp
                raw = b"".join(delivery.canonical(entry) + b"\n" for entry in entries)
                self.journal.write_bytes(raw)
                self.journal.chmod(0o600)
                with self.assertRaises(delivery.DeliveryError):
                    delivery.acknowledge(expected_journal_sha256=hashlib.sha256(raw).hexdigest(), message_id=42, confirmation=delivery.ACK_CONFIRMATION, ops_root=self.root)

    def test_future_terminal_time_fails_before_exclusive_receipt_creation(self) -> None:
        entries = self.synthetic_entries()
        future = "2100-01-01T00:00:00+00:00"
        for entry in entries[1:]:
            entry["observed_at_utc"] = future
        raw = b"".join(delivery.canonical(entry) + b"\n" for entry in entries)
        self.journal.write_bytes(raw)
        self.journal.chmod(0o600)
        with self.assertRaisesRegex(delivery.DeliveryError, "ACKNOWLEDGEMENT_TIME_ORDER_REJECTED"):
            delivery.acknowledge(expected_journal_sha256=hashlib.sha256(raw).hexdigest(), message_id=42, confirmation=delivery.ACK_CONFIRMATION, ops_root=self.root)
        self.assertFalse(delivery._acknowledgement_path(self.root).exists())


class TransportTests(unittest.TestCase):
    def test_actual_acl_probe_accepts_only_restricted_synthetic_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "owned-fixture"
            root.mkdir(mode=0o700)
            token = root / "synthetic-token"
            token.write_text("synthetic-not-a-real-key")
            if os.name == "nt":
                # Exactly the reviewed owner/Admin/SYSTEM ACL, on this test's
                # newly owned directory only; no actual operator file access.
                identity = delivery.subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True, timeout=10)
                current_sid = list(csv.reader(identity.stdout.splitlines()))[0][1]
                commands = [["icacls", str(root), "/reset", "/T", "/Q"], ["icacls", str(root), "/inheritance:r", "/T", "/Q"], ["icacls", str(root), "/grant:r", "*" + current_sid + ":F", "*S-1-5-18:F", "*S-1-5-32-544:F", "/T", "/Q"], ["icacls", str(root), "/grant:r", "*" + current_sid + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/Q"]]
                try:
                    for index, command in enumerate(commands):
                        result = delivery.subprocess.run(command, capture_output=True, text=True, timeout=10)
                        if result.returncode:
                            self.skipTest("Windows ACL fixture privilege unavailable at setup stage " + str(index))
                finally:
                    # Keep this owned fixture accessible even if an ACL setup
                    # step failed; do not strand a protected temporary tree.
                    delivery.subprocess.run(commands[2], capture_output=True, text=True, timeout=10)
            else:
                token.chmod(0o600)
            delivery._private_acl(root)
            delivery._private_acl(token)
            if os.name != "nt":
                token.chmod(0o644)
                with self.assertRaisesRegex(delivery.DeliveryError, "PROTECTED_ACL_REQUIRED"):
                    delivery._private_acl(token)

    def test_reparse_path_fails_before_read_or_send(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original"
            original.mkdir()
            alias = Path(temporary) / "alias"
            try:
                alias.symlink_to(original, target_is_directory=True)
            except OSError:
                self.skipTest("Symlink creation unavailable on this host")
            with self.assertRaisesRegex(delivery.DeliveryError, "REPARSE_PATH_REJECTED"):
                delivery._no_reparse(alias / "new")

    def test_transport_uses_no_proxy_no_redirect_and_bounded_read(self) -> None:
        transport = delivery.TelegramTransport("synthetic")
        response = Mock(status=200)
        response.read.return_value = b'{"ok":true,"result":{"is_bot":true}}'
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        transport._opener = Mock()
        transport._opener.open.return_value = response
        self.assertTrue(transport.call("getMe", {})["is_bot"])
        response.read.assert_called_once_with(delivery.MAX_RESPONSE + 1)
        self.assertEqual(transport._opener.open.call_args.kwargs["timeout"], 15)
        with self.assertRaisesRegex(delivery.DeliveryError, "REDIRECT_REJECTED"):
            delivery.NoRedirect().redirect_request(None, None, 302, "private", {}, "https://wrong")

    def test_http_error_does_not_retain_token_url_or_body(self) -> None:
        transport = delivery.TelegramTransport("SYNTHETIC_SECRET")
        transport._opener = Mock()
        transport._opener.open.side_effect = delivery.urllib.error.URLError("https://api.telegram.org/botSYNTHETIC_SECRET/getMe")
        with self.assertRaises(delivery.DeliveryError) as error:
            transport.call("getMe", {})
        self.assertEqual(str(error.exception), "TRANSPORT_FAILED")
        self.assertIsNone(error.exception.__cause__)

    def test_unknown_cli_arguments_are_not_echoed(self) -> None:
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = delivery.main(["qualify", "--bot-token", "SYNTHETIC_SECRET"])
        self.assertEqual(code, 2)
        self.assertNotIn("SYNTHETIC_SECRET", stream.getvalue())


class TopologyTests(unittest.TestCase):
    def test_native_compose_json_is_valid_without_starting_services(self) -> None:
        if shutil.which("docker") is None:
            self.skipTest("Docker compose CLI unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            env = dict(os.environ)
            env["KAIROS_ALERT_CONFIG"] = str(root / "config/new/alertmanager.yml")
            env["KAIROS_ALERT_TOKEN_FILE"] = str(root / "secrets/telegram_bot_token")
            version = delivery.subprocess.run(["docker", "compose", "version", "--short"], stdin=delivery.subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=45)
            self.assertEqual(version.returncode, 0, "offline native compose version inspection failed")
            compose_version = version.stdout.strip()
            self.assertRegex(compose_version, r"\Av?[0-9]+\.[0-9]+\.[0-9]+\Z")
            for profile in ("base", "paper"):
                command = ["docker", "compose", "-f", str(delivery.ROOT / "docker-compose.alert-delivery.yml")]
                if profile == "paper":
                    command += ["-f", str(delivery.ROOT / "docker-compose.paper-alert-delivery.yml")]
                command += ["--profile", "alert-delivery", "config", "--format", "json"]
                result = delivery.subprocess.run(command, stdin=delivery.subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=45)
                self.assertEqual(result.returncode, 0, "offline native compose rendering failed")
                self.assertEqual(topology.validate(json.loads(result.stdout), profile=profile, ops_root=root, compose_version=compose_version), [])

    @staticmethod
    def config() -> dict:
        return {"name": "kairos-ops-alerts", "services": {"alertmanager": {"image": delivery.ALERTMANAGER_IMAGE, "platform": "linux/amd64", "profiles": ["alert-delivery"], "user": "65534:65534", "read_only": True, "init": True, "restart": "no", "mem_limit": 134217728, "cpus": 0.25, "pids_limit": 64, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "command": topology.COMMAND, "tmpfs": topology.TMPFS, "volumes": [{"type": "bind", "source": str(delivery.OPS_ROOT / "config/new/alertmanager.yml"), "target": "/etc/alertmanager/alertmanager.yml", "read_only": True, "bind": {"create_host_path": False}}, {"type": "bind", "source": str(delivery.OPS_ROOT / "secrets/telegram_bot_token"), "target": "/run/secrets/telegram_bot_token", "read_only": True, "bind": {"create_host_path": False}}], "networks": {"alert-input": {"aliases": ["kairos-ops-alertmanager"]}, "alert-egress": {}}}}, "networks": {"alert-input": {"name": "kairos_observability", "external": True}, "alert-egress": {"driver": "bridge"}}}

    def test_exact_standalone_topology_only(self) -> None:
        self.assertEqual(topology.validate(self.config(), profile="base"), [])
        paper = self.config()
        paper["networks"]["alert-input"]["name"] = "kairos-paper_paper-observability"
        self.assertEqual(topology.validate(paper, profile="paper"), [])

    def test_only_reviewed_legacy_renderers_can_omit_bind_false(self) -> None:
        for profile in ("base", "paper"):
            for version in ("2.38.2", "v2.38.2", "2.40.3", "v2.40.3"):
                with self.subTest(profile=profile, version=version):
                    config = self.config()
                    if profile == "paper":
                        config["networks"]["alert-input"]["name"] = "kairos-paper_paper-observability"
                    for mount in config["services"]["alertmanager"]["volumes"]:
                        mount["bind"] = {}
                    self.assertEqual(topology.validate(config, profile=profile, compose_version=version), [])
        config = self.config()
        for mount in config["services"]["alertmanager"]["volumes"]:
            mount["bind"] = {}
        for version in (None, "", "2.38.3", "5.0.0", "5.5.0", True, 2.38):
            with self.subTest(version=version):
                self.assertEqual(topology.validate(config, profile="base", compose_version=version), ["UNSAFE_MOUNT", "UNSAFE_MOUNT"])

    def test_explicit_false_does_not_require_legacy_version_metadata(self) -> None:
        for version in (None, "2.38.2", "2.40.3", "5.5.0", "unknown"):
            with self.subTest(version=version):
                self.assertEqual(topology.validate(self.config(), profile="base", compose_version=version), [])

    def test_legacy_version_cannot_authorize_unsafe_or_ambiguous_mounts(self) -> None:
        for version in ("2.38.2", "2.40.3"):
            for bind in (None, [], {"create_host_path": True}, {"create_host_path": 0}, {"create_host_path": "false"}, {"create_host_path": None}, {"create_host_path": False, "propagation": "rshared"}, {"propagation": "rprivate"}, {"recursive": "writable"}):
                with self.subTest(version=version, bind=bind):
                    config = self.config()
                    config["services"]["alertmanager"]["volumes"][0]["bind"] = bind
                    self.assertIn("UNSAFE_MOUNT", topology.validate(config, profile="base", compose_version=version))
            for change in ("missing-bind", "read-write", "volume-type", "extra-mount-field", "other-token-path"):
                with self.subTest(version=version, change=change):
                    config = self.config()
                    mount = config["services"]["alertmanager"]["volumes"][1]
                    mount["bind"] = {}
                    if change == "missing-bind":
                        del mount["bind"]
                    elif change == "read-write":
                        mount["read_only"] = False
                    elif change == "volume-type":
                        mount["type"] = "volume"
                    elif change == "extra-mount-field":
                        mount["consistency"] = "cached"
                    else:
                        mount["source"] = str(delivery.OPS_ROOT / "secrets/other_token")
                    self.assertTrue(topology.validate(config, profile="base", compose_version=version))

    def test_no_apps_database_mounts_ports_or_resource_expansion(self) -> None:
        mutations = [("ports", ["9093:9093"]), ("privileged", True), ("mem_limit", 268435456), ("environment", {"TOKEN": "synthetic"}), ("networks", {"paper-management": {}}), ("volumes", [{"type": "bind", "source": "/db", "target": "/data", "read_only": False}])]
        for key, value in mutations:
            with self.subTest(key=key):
                config = copy.deepcopy(self.config())
                config["services"]["alertmanager"][key] = value
                self.assertTrue(topology.validate(config, profile="base"))
        config = self.config()
        config["services"]["execution-engine"] = {}
        self.assertIn("ONLY_NATIVE_ALERTMANAGER_PERMITTED", topology.validate(config, profile="base"))

    def test_boolean_numeric_type_confusion_is_rejected(self) -> None:
        for key, value in (("read_only", 1), ("init", 1), ("pids_limit", 64.0), ("cpus", float("nan")), ("mem_limit", 134217728.0)):
            config = self.config()
            config["services"]["alertmanager"][key] = value
            self.assertTrue(topology.validate(config, profile="base"))
        config = self.config()
        config["networks"]["alert-input"]["external"] = 1
        self.assertIn("INPUT_NETWORK_IDENTITY_CHANGED", topology.validate(config, profile="base"))
        config = self.config()
        config["services"]["alertmanager"]["volumes"][0]["bind"]["create_host_path"] = 0
        self.assertIn("UNSAFE_MOUNT", topology.validate(config, profile="base"))

    def test_compose_defaults_cannot_hide_custom_entrypoint_or_ipam(self) -> None:
        config = self.config()
        service = config["services"]["alertmanager"]
        service["entrypoint"] = None
        service["mem_limit"] = "134217728"
        config["networks"]["alert-input"]["ipam"] = {}
        config["networks"]["alert-egress"].update({"name": "kairos-ops-alerts_alert-egress", "ipam": {}})
        self.assertEqual(topology.validate(config, profile="base"), [])
        service["entrypoint"] = ["/bin/sh"]
        self.assertIn("UNAPPROVED_SERVICE_CAPABILITY", topology.validate(config, profile="base"))
        service["entrypoint"] = None
        config["networks"]["alert-input"]["ipam"] = {"config": [{"subnet": "10.0.0.0/8"}]}
        self.assertIn("INPUT_NETWORK_IDENTITY_CHANGED", topology.validate(config, profile="base"))


class NativeComposeInspectionContractTests(unittest.TestCase):
    """Exercise the real inspection test with subprocesses fully mocked."""

    @staticmethod
    def response(command: list[str], *, version: str = "2.40.3", **kwargs):
        if command == ["docker", "compose", "version", "--short"]:
            output = version + "\n"
        else:
            config = TopologyTests.config()
            if str(delivery.ROOT / "docker-compose.paper-alert-delivery.yml") in command:
                config["networks"]["alert-input"]["name"] = "kairos-paper_paper-observability"
            mounts = config["services"]["alertmanager"]["volumes"]
            mounts[0]["source"] = kwargs["env"]["KAIROS_ALERT_CONFIG"]
            mounts[1]["source"] = kwargs["env"]["KAIROS_ALERT_TOKEN_FILE"]
            if version == "2.40.3":
                for mount in mounts:
                    mount["bind"] = {}
            output = json.dumps(config)
        return delivery.subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    @staticmethod
    def inspect() -> None:
        TopologyTests("test_native_compose_json_is_valid_without_starting_services").test_native_compose_json_is_valid_without_starting_services()

    def test_complete_native_json_uses_only_readonly_commands_closed_stdin_and_bounds(self) -> None:
        for version in ("2.40.3", "5.5.0"):
            with self.subTest(version=version), patch.object(shutil, "which", return_value="synthetic-docker-cli"), patch.object(delivery.subprocess, "run", side_effect=lambda command, **kwargs: self.response(command, version=version, **kwargs)) as run:
                self.inspect()
            standalone = ["docker", "compose", "-f", str(delivery.ROOT / "docker-compose.alert-delivery.yml")]
            paper = standalone + ["-f", str(delivery.ROOT / "docker-compose.paper-alert-delivery.yml")]
            suffix = ["--profile", "alert-delivery", "config", "--format", "json"]
            self.assertEqual([call.args[0] for call in run.call_args_list], [["docker", "compose", "version", "--short"], standalone + suffix, paper + suffix])
            for call in run.call_args_list:
                self.assertEqual(call.kwargs["stdin"], delivery.subprocess.DEVNULL)
                self.assertEqual(call.kwargs["timeout"], 45)
                self.assertTrue(call.kwargs["capture_output"])
                self.assertTrue(call.kwargs["text"])
                self.assertFalse(call.kwargs.get("shell", False))

    def test_timeout_or_nonzero_exit_fails_without_retry_or_skip(self) -> None:
        for stage in ("version", "config"):
            for category in ("timeout", "nonzero"):
                def failure(command, **kwargs):
                    is_version = command == ["docker", "compose", "version", "--short"]
                    if is_version == (stage == "version"):
                        if category == "timeout":
                            raise delivery.subprocess.TimeoutExpired(command, 45)
                        return delivery.subprocess.CompletedProcess(command, 1, stdout="", stderr="synthetic failure")
                    return self.response(command, **kwargs)

                error = delivery.subprocess.TimeoutExpired if category == "timeout" else AssertionError
                with self.subTest(stage=stage, category=category), patch.object(shutil, "which", return_value="synthetic-docker-cli"), patch.object(delivery.subprocess, "run", side_effect=failure) as run, self.assertRaises(error):
                    self.inspect()
                self.assertEqual(run.call_count, 1 if stage == "version" else 2)

    def test_invalid_version_json_or_topology_fails_instead_of_skip(self) -> None:
        for category in ("version", "json", "topology"):
            def failure(command, **kwargs):
                result = self.response(command, **kwargs)
                if command == ["docker", "compose", "version", "--short"]:
                    if category == "version":
                        result.stdout = "unsupported version output"
                elif category == "json":
                    result.stdout = "incomplete-json"
                elif category == "topology":
                    config = json.loads(result.stdout)
                    config["services"]["alertmanager"]["volumes"][0]["read_only"] = False
                    result.stdout = json.dumps(config)
                return result

            error = json.JSONDecodeError if category == "json" else AssertionError
            with self.subTest(category=category), patch.object(shutil, "which", return_value="synthetic-docker-cli"), patch.object(delivery.subprocess, "run", side_effect=failure) as run, self.assertRaises(error):
                self.inspect()
            self.assertEqual(run.call_count, 1 if category == "version" else 2)


if __name__ == "__main__":
    unittest.main()
