from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "Invoke-RuntimeSchemaProfilePreflight.ps1"
VALIDATOR_PATH = ROOT / "scripts" / "validate_runtime_schema_profile_preflight.py"
HARNESS_PATH = ROOT / "scripts" / "Test-RuntimeSchemaProfilePreflight.ps1"


def _validator_module():
    specification = importlib.util.spec_from_file_location(
        "kairos_runtime_schema_profile_preflight_validator", VALIDATOR_PATH
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


validator = _validator_module()


class RuntimeSchemaProfilePreflightStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = SCRIPT_PATH.read_text(encoding="utf-8")

    def test_static_contract_is_valid(self) -> None:
        self.assertEqual(validator.validate_script(self.text), [])

    def test_runtime_profile_excludes_simulator_migration(self) -> None:
        self.assertIn(
            "$TargetMigrations = @($LegacyMigrations + $RuntimeMigrationSuffix)", self.text
        )
        self.assertIn('"017_simulator_journal.sql"', self.text)
        target_region = self.text.split("$TargetMigrations", 1)[1].split("$MigrationSha256", 1)[0]
        self.assertNotIn("017_simulator_journal.sql", target_region)
        self.assertIn("foreach ($migration in $RuntimeMigrationSuffix)", self.text)
        self.assertIn("simulator_journal_on_runtime_clone = \"ABSENT_AND_FORBIDDEN\"", self.text)
        self.assertIn("sim\\_%", self.text)
        self.assertIn("ESCAPE '\\'", self.text)

    def test_no_runtime_or_secret_route_exists(self) -> None:
        self.assertNotIn("docker compose", self.text)
        self.assertNotIn("--env-file", self.text)
        self.assertNotIn("KAIROS_SECRETS", self.text)
        self.assertNotIn("Database.migrate(", self.text)
        self.assertNotIn("--dbname=$manifest.database", self.text)
        self.assertIn("original_runtime_contacted = $false", self.text)
        self.assertIn("redis_contacted = $false", self.text)
        self.assertIn("publisher_contacted = $false", self.text)
        self.assertIn("--network", self.text)
        self.assertIn('"none"', self.text)

    def test_tampering_is_rejected(self) -> None:
        missing = self.text.replace('"018_offline_outbox_reconciliation.sql"', '"018_changed.sql"', 1)
        self.assertIn(
            "runtime schema preflight target migration profile changed",
            validator.validate_script(missing),
        )
        self.assertTrue(
            any(
                "runtime Compose project or secrets" in error
                for error in validator.validate_script(self.text + "\ndocker compose up\n")
            )
        )
        bad_authorization = self.text.replace("authorized = $false", "authorized = $true", 1)
        self.assertTrue(
            any("authorized = $false" in error for error in validator.validate_script(bad_authorization))
        )
        no_empty_owner_support = self.text.replace(
            "[AllowEmptyCollection()][string[]]$Owners", "[string[]]$Owners", 1
        )
        self.assertTrue(
            any(
                "[AllowEmptyCollection()][string[]]$Owners" in error
                for error in validator.validate_script(no_empty_owner_support)
            )
        )
        no_exact_digest_check = self.text.replace(
            "Migration runner image lacks a resolved immutable repository digest",
            "digest check removed",
            1,
        )
        self.assertTrue(
            any(
                "resolved immutable repository digest" in error
                for error in validator.validate_script(no_exact_digest_check)
            )
        )

    def test_clone_evidence_cannot_authorize_source_apply(self) -> None:
        self.assertIn("Recovery receipt migration profile", self.text)
        self.assertIn("Recovery receipt is not a fresh two-hour runtime verification", self.text)
        self.assertIn("Recovery receipt predates the verified backup manifest", self.text)
        self.assertIn("Assert-VettedLegacySchemaShape", self.text)
        self.assertIn("Assert-VettedRuntimeSchemaShape", self.text)
        self.assertIn("First pinned runtime clone migration pass", self.text)
        self.assertIn("Second pinned runtime clone migration pass", self.text)
        self.assertIn("Restored upgraded runtime clone drill", self.text)
        self.assertIn("SEPARATE_LEGACY_OUTBOX_QUARANTINE_CLONE_REHEARSAL", self.text)
        self.assertIn("target_ddl_permissions_verified = $false", self.text)
        self.assertIn("Clone container must have no network", self.text)
        self.assertIn("timescaledb_bgw_owners", self.text)
        self.assertIn("Ensure-TimescaleJobOwners", self.text)
        self.assertIn("NOLOGIN NOSUPERUSER", self.text)

    def test_synthetic_harness_is_isolated_from_runtime_inputs(self) -> None:
        harness = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn("synthetic-runtime-schema-profile-harness", harness)
        self.assertIn("Invoke-RuntimeSchemaProfilePreflight.ps1", harness)
        self.assertIn("CLONE_ONLY_RUNTIME_SCHEMA_PROFILE_PREFLIGHT", harness)
        self.assertIn("--network none", harness)
        self.assertIn('"127.0.0.1:${registryPort}:5000"', harness)
        self.assertIn("outbox_expired_leases -ne 1", harness)
        self.assertIn("017_simulator_journal.sql", harness)
        self.assertNotIn("docker compose", harness)
        self.assertNotIn("KAIROS_SECRETS", harness)


if __name__ == "__main__":
    unittest.main()
