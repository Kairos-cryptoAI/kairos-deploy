"""Synthetic host-report gate tests; no task, process, or runtime operation."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import runtime_epoch_current_boot as boot


class HostAcceptanceLatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "acceptance.report.json"
        self.value = {
            "schema": "kairos.current-runtime-host-acceptance.v1",
            "state": "PASS_CURRENT_NONTRADING_HOST_ACCEPTANCE",
            "owner": "a" * 32,
            "receipt_sha256": "b" * 64,
            "deploy_revision": "c" * 40,
            "old_resources_preserved": True,
            "production_trading_qualified": False,
            "trading_started": False,
            "orders_submitted": 0,
            "paid_calls": 0,
        }

    def check(self, *, bad_signature=False):
        with (
            patch.object(boot, "HOST_ACCEPTANCE_REPORT", self.path),
            patch.object(boot, "read_bounded_json", return_value=self.value),
            patch.object(boot, "verify_receipt_signature") as signature,
        ):
            if bad_signature:
                signature.side_effect = boot.CurrentBootRejected("untrusted synthetic signature")
            boot.require_host_acceptance(self.path, "a" * 32, "b" * 64, "c" * 40)
            signature.assert_called_once_with(
                self.path, self.path.with_name(self.path.name + ".asc"), boot.epoch._sha(self.path)
            )

    def write(self):
        self.path.write_text(json.dumps(self.value), encoding="utf-8")

    def test_absent_final_host_report_cannot_enable_scheduled_boot(self):
        with self.assertRaises(boot.CurrentBootRejected):
            self.check()

    def test_signed_matching_nontrading_pass_is_required(self):
        self.write()
        self.check()

    def test_failure_latch_blocks_even_otherwise_accepted_report(self):
        self.write()
        (self.path.parent / "acceptance.failure.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(boot.CurrentBootRejected):
            self.check()

    def test_signature_or_owner_scope_substitution_cannot_enable_boot(self):
        self.write()
        with self.assertRaises(boot.CurrentBootRejected):
            self.check(bad_signature=True)
        self.value["owner"] = "d" * 32
        with self.assertRaises(boot.CurrentBootRejected):
            self.check()

    def test_trading_or_failed_report_is_not_host_acceptance(self):
        for field, value in (("trading_started", True), ("state", "FAILED_CLOSED")):
            original = self.value[field]
            self.value[field] = value
            self.write()
            with self.subTest(field=field), self.assertRaises(boot.CurrentBootRejected):
                self.check()
            self.value[field] = original


if __name__ == "__main__":
    unittest.main()
