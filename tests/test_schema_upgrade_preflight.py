from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate_schema_upgrade_preflight.py"
SCRIPT_PATH = ROOT / "scripts" / "Invoke-SchemaUpgradePreflight.ps1"


def _validator_module():
    specification = importlib.util.spec_from_file_location(
        "kairos_schema_upgrade_preflight_validator", VALIDATOR_PATH
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


validator = _validator_module()


class SchemaUpgradePreflightStaticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = SCRIPT_PATH.read_text(encoding="utf-8")

    def test_static_preflight_contract_is_valid(self) -> None:
        self.assertEqual(validator.validate_script(self.text), [])

    def test_no_original_database_or_runtime_compose_route_exists(self) -> None:
        self.assertNotIn("docker compose", self.text)
        self.assertNotIn("--env-file", self.text)
        self.assertNotIn("KAIROS_SECRETS", self.text)
        self.assertNotIn("Database.migrate(", self.text)
        self.assertNotIn("--dbname=$manifest.database", self.text)
        self.assertIn("original_runtime_contacted = $false", self.text)
        self.assertIn("--network none", self.text)
        self.assertIn("$CloneScope = \"clone-only-schema-upgrade-preflight\"", self.text)

    def test_exact_profiles_and_no_future_migration_are_pinned(self) -> None:
        for migration in validator.LEGACY + validator.TARGET_SUFFIX:
            with self.subTest(migration=migration):
                self.assertIn(f'"{migration}"', self.text)
        self.assertNotIn("019_", self.text)
        self.assertIn("Assert-ExactStringArray -Expected $LegacyMigrations", self.text)
        self.assertIn("Assert-ExactStringArray -Expected $TargetMigrations", self.text)
        self.assertIn("Pinned migration-runner migration inventory", self.text)
        self.assertIn("Pinned migration-runner byte hash differs", self.text)
        self.assertIn("$Expected[$index] -cne $actualArray[$index]", self.text)
        self.assertIn("ConvertTo-Base64PythonCommand", self.text)
        self.assertIn("b64decode", self.text)

    def test_validator_rejects_profile_tampering_and_runtime_route(self) -> None:
        missing = self.text.replace('"018_offline_outbox_reconciliation.sql"', '"018_changed.sql"', 1)
        self.assertIn("schema-upgrade preflight target migration profile changed", validator.validate_script(missing))
        self.assertTrue(
            any(
                "runtime Compose project or secrets" in error
                for error in validator.validate_script(self.text + "\ndocker compose up\n")
            )
        )

    def test_only_generated_drill_databases_can_be_created_or_dropped(self) -> None:
        self.assertIn("Assert-CloneDatabaseName -DatabaseName $upgradeDrillDatabase", self.text)
        self.assertIn("Assert-CloneDatabaseName -DatabaseName $restoreDrillDatabase", self.text)
        self.assertIn("Refusing a database name outside the generated clone-only drill namespace", self.text)
        self.assertIn('("exec", $CloneContainer, "dropdb", "--if-exists", "--force"', self.text)
        self.assertNotIn("dropdb --if-exists --force --username=$CloneDatabaseUser $Database", self.text)
        self.assertNotIn("[string]$Database", self.text.split("param(", 1)[1].split(")", 1)[0])

    def test_legacy_backup_and_post_baseline_residue_must_be_proven(self) -> None:
        self.assertIn("Baseline receipt migration profile", self.text)
        self.assertIn("$baselineReceipt.backup_sha256 -ne $manifest.sha256", self.text)
        self.assertIn("$baselineReceipt.backup_manifest_sha256 -ne $manifestHash", self.text)
        self.assertIn("Baseline receipt does not bind the exact backup manifest bytes", self.text)
        self.assertIn("Baseline receipt predates the verified backup manifest", self.text)
        self.assertIn("expected $($MigrationSha256[$name]); observed", self.text)
        self.assertIn("Raw Git-blob bytes", self.text)
        self.assertIn("^/kairos-stage/[A-Za-z0-9_.-]+\\.dump$", self.text)
        self.assertIn("^/kairos-stage/migrations$", self.text)
        self.assertIn("WITH relation_check AS", self.text)
        self.assertIn("FROM relation_check CROSS JOIN column_check", self.text)
        self.assertIn("Assert-PostBaselineObjects -Container $cloneContainer", self.text)
        self.assertIn("-Present $false", self.text)
        self.assertIn("-Present $true", self.text)
        self.assertIn("first_pass_schema_fingerprint_sha256", self.text)
        self.assertIn("second_pass_schema_fingerprint_sha256", self.text)
        self.assertIn("legacy_schema_fingerprint_sha256", self.text)
        self.assertIn("Assert-VettedLegacySchemaShape", self.text)
        self.assertIn("Get-LegacySchemaFingerprint", self.text)
        self.assertIn("$ExpectedLegacySchemaFingerprint", self.text)
        self.assertIn(validator.LEGACY_SCHEMA_FINGERPRINT, self.text)
        self.assertIn("Restored upgraded clone drill", self.text)
        self.assertIn("ConvertFrom-Json materializes an ISO-8601 Z value as DateTime", self.text)
        self.assertIn("must be an explicit UTC timestamp", self.text)
        self.assertIn("Baseline receipt is not a fresh two-hour runtime verification", self.text)

    def test_clone_pass_is_not_an_original_runtime_authorization(self) -> None:
        self.assertIn('$ExpectedSourceComposeProject = "kairos-paper-gate"', self.text)
        self.assertIn('$ExpectedSourceDatabase = "kairos"', self.text)
        self.assertIn("$MaximumBackupAge = [TimeSpan]::FromHours(2)", self.text)
        self.assertIn('$ExpectedMigrationRunnerUser = "10001:10001"', self.text)
        self.assertIn("--user $ExpectedMigrationRunnerUser", self.text)
        self.assertIn("Assert-CleanBaselineReceipt -Receipt $Receipt", self.text)
        self.assertIn("Baseline outbox does not permit a read-only consumer restart", self.text)
        self.assertIn('$cloneStageVolume = "kairos-schema-upgrade-preflight-stage-$suffix"', self.text)
        self.assertIn("Verified source backup is missing from the clone staging volume", self.text)
        self.assertIn("Assert-CloneVolumeIdentity -Volume $volume -Suffix $Suffix", self.text)
        self.assertIn("Docker Desktop does not support container-to-container docker cp", self.text)
        self.assertIn("Exported pinned migration byte hash differs", self.text)
        self.assertIn("Write-Utf8NoBom", self.text)
        self.assertIn("[System.IO.File]::WriteAllText", self.text)
        self.assertNotIn("Set-Content -LiteralPath $localRunnerFile -Encoding utf8NoBOM", self.text)
        self.assertIn('"${CloneContainer}:$TargetDirectory/$migration"', self.text)
        self.assertIn('result = "PASS_CLONE_ONLY"', self.text)
        self.assertIn("target_ddl_permissions_verified = $false", self.text)
        self.assertIn("SEPARATE_READ_ONLY_TARGET_ROLE_PREFLIGHT", self.text)
        self.assertIn("TESTED_ONLY_ARCHITECTURE_DECISION_UNRESOLVED", self.text)

    def test_vetted_shape_and_clone_ddl_preconditions_are_required(self) -> None:
        self.assertIn("Assert-CloneDdlPreconditions", self.text)
        self.assertIn("SELECT gen_random_uuid();", self.text)
        self.assertIn("CREATE TABLE public.$probeTable", self.text)
        self.assertIn("ROLLBACK;", self.text)
        self.assertIn("Assert-VettedPostBaselineSchemaShape", self.text)
        self.assertIn("conrelid='public.message_outbox'::regclass", self.text)
        self.assertIn("Clone post-baseline schema differs from the vetted 013--018 structure", self.text)

    def test_validator_rejects_clone_as_runtime_authorization(self) -> None:
        tampered = self.text.replace(
            "target_ddl_permissions_verified = $false",
            "target_ddl_permissions_verified = $true",
            1,
        )
        self.assertIn(
            "schema-upgrade preflight missing required invariant: target_ddl_permissions_verified = $false",
            validator.validate_script(tampered),
        )


if __name__ == "__main__":
    unittest.main()
