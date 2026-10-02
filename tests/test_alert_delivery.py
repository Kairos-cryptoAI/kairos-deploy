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
            for profile in ("base", "paper"):
                command = ["docker", "compose", "-f", str(delivery.ROOT / "docker-compose.alert-delivery.yml")]
                if profile == "paper":
                    command += ["-f", str(delivery.ROOT / "docker-compose.paper-alert-delivery.yml")]
                command += ["--profile", "alert-delivery", "config", "--format", "json"]
                result = delivery.subprocess.run(command, capture_output=True, text=True, env=env, timeout=15)
                self.assertEqual(result.returncode, 0, "offline native compose rendering failed")
                self.assertEqual(topology.validate(json.loads(result.stdout), profile=profile, ops_root=root), [])

    @staticmethod
    def config() -> dict:
        return {"name": "kairos-ops-alerts", "services": {"alertmanager": {"image": delivery.ALERTMANAGER_IMAGE, "platform": "linux/amd64", "profiles": ["alert-delivery"], "user": "65534:65534", "read_only": True, "init": True, "restart": "no", "mem_limit": 134217728, "cpus": 0.25, "pids_limit": 64, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "command": topology.COMMAND, "tmpfs": topology.TMPFS, "volumes": [{"type": "bind", "source": str(delivery.OPS_ROOT / "config/new/alertmanager.yml"), "target": "/etc/alertmanager/alertmanager.yml", "read_only": True, "bind": {"create_host_path": False}}, {"type": "bind", "source": str(delivery.OPS_ROOT / "secrets/telegram_bot_token"), "target": "/run/secrets/telegram_bot_token", "read_only": True, "bind": {"create_host_path": False}}], "networks": {"alert-input": {"aliases": ["kairos-ops-alertmanager"]}, "alert-egress": {}}}}, "networks": {"alert-input": {"name": "kairos_observability", "external": True}, "alert-egress": {"driver": "bridge"}}}

    def test_exact_standalone_topology_only(self) -> None:
        self.assertEqual(topology.validate(self.config(), profile="base"), [])
        paper = self.config()
        paper["networks"]["alert-input"]["name"] = "kairos-paper_paper-observability"
        self.assertEqual(topology.validate(paper, profile="paper"), [])

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


if __name__ == "__main__":
    unittest.main()
