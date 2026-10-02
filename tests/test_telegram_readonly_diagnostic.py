from __future__ import annotations

import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import telegram_readonly_diagnostic as diagnostic


class ReadOnlyDiagnosticTests(unittest.TestCase):
    def test_only_fixed_error_categories_and_numeric_codes_leave_classifier(self):
        for status, description, category in ((400, "Bad Request: chat not found PRIVATE_TITLE", "CHAT_NOT_FOUND"), (403, "bot is not a member PRIVATE", "BOT_NOT_MEMBER"), (403, "Forbidden PRIVATE", "PERMISSION_DENIED"), (429, "too many requests PRIVATE", "RATE_LIMIT"), (401, "Unauthorized PRIVATE", "AUTHENTICATION_REJECTED"), (500, "PRIVATE_DETAIL", "API_REJECTED")):
            result = diagnostic.classify(status, json.dumps({"error_code": status, "description": description}).encode())
            self.assertEqual(result["error_category"], category)
            self.assertEqual(result["api_error_code"], status)
            self.assertNotIn("PRIVATE", json.dumps(result))

    def test_http_error_is_read_bounded_then_description_discarded(self):
        transport = diagnostic.ReadOnlyTransport("SYNTHETIC_SECRET")
        transport._opener = Mock()
        error = urllib.error.HTTPError("https://private/SYNTHETIC_SECRET", 400, "PRIVATE_DESCRIPTION", {}, io.BytesIO(b'{"ok":false,"error_code":400,"description":"Bad Request: chat not found PRIVATE"}'))
        transport._opener.open.side_effect = error
        result = transport.call("getChat", {"chat_id": diagnostic.delivery.EXPECTED_TEST_CHAT})
        self.assertEqual(result["error_category"], "CHAT_NOT_FOUND")
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("SYNTHETIC_SECRET", json.dumps(result))

    def test_send_or_other_chat_is_rejected_before_any_request(self):
        transport = diagnostic.ReadOnlyTransport("synthetic")
        transport._opener = Mock()
        for method, params in (("sendMessage", {}), ("getChat", {"chat_id": diagnostic.delivery.EXPECTED_CHAT}), ("getMe", {"extra": 1})):
            self.assertEqual(transport.call(method, params)["error_category"], "READ_ONLY_METHOD_REJECTED")
        transport._opener.open.assert_not_called()

    def test_one_readonly_diagnostic_retains_guard_and_never_serializes_chat(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(diagnostic.delivery, "_private_acl"), patch.object(diagnostic, "ReadOnlyTransport") as factory:
            root = Path(temporary)
            (root / "secrets").mkdir()
            (root / "receipts").mkdir()
            token = root / "secrets/telegram_bot_token"
            token.write_text("123456:" + "A" * 35)
            factory.return_value.call.side_effect = [{"ok": True, "result": {"is_bot": True, "username": diagnostic.delivery.EXPECTED_BOT}}, {"ok": True, "result": {"id": diagnostic.delivery.EXPECTED_TEST_CHAT, "type": "supergroup", "title": "PRIVATE_TITLE"}}]
            with self.assertRaises(diagnostic.delivery.DeliveryError):
                diagnostic.diagnose(token, authorize_readonly=False, ops_root=root)
            factory.assert_not_called()
            result = diagnostic.diagnose(token, authorize_readonly=True, ops_root=root)
            self.assertEqual(result["http_method_counts"], {"getMe": 1, "getChat": 1})
            self.assertEqual(result["send_attempts"], 0)
            self.assertFalse(result["delivery_qualified"])
            self.assertNotIn("PRIVATE_TITLE", "".join(p.read_text() for p in (root / "receipts").iterdir()))
            with self.assertRaises(FileExistsError):
                diagnostic.diagnose(token, authorize_readonly=True, ops_root=root)
            self.assertEqual(factory.return_value.call.call_count, 2)


if __name__ == "__main__":
    unittest.main()
