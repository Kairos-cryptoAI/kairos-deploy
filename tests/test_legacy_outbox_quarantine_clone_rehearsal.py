from __future__ import annotations

import importlib.util
import unittest
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


validator = _validator_module()


class LegacyOutboxQuarantineCloneRehearsalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = CONTROLLER.read_text(encoding="utf-8")
        self.runner = RUNNER.read_text(encoding="utf-8")

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
        self.assertIn("FailingNoNetworkPublisher", self.runner)
        self.assertIn("publisher.calls != 0", self.runner)
        self.assertNotIn("claim_expired_outbox_exact", self.runner)
        self.assertNotIn("OfflineOutboxReconciler", self.runner)

    def test_tampering_is_rejected(self) -> None:
        changed = self.controller.replace("018_offline_outbox_reconciliation.sql", "018_changed.sql", 1)
        self.assertIn("legacy clone rehearsal runtime migration suffix changed", validator.validate(changed, self.runner))
        self.assertTrue(any("runtime/provider route" in error for error in validator.validate(self.controller + "\ndocker compose up\n", self.runner)))
        unpinned = self.controller.replace("EXPECTED_RUNNER_SHA256", "OTHER_RUNNER_SHA256", 1)
        self.assertIn("clone controller must pin the exact reviewed worker bytes", validator.validate(unpinned, self.runner))


if __name__ == "__main__":
    unittest.main()
