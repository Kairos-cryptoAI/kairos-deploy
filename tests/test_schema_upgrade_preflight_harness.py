from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "Test-SchemaUpgradePreflight.ps1"


class SchemaUpgradePreflightHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = HARNESS.read_text(encoding="utf-8")

    def test_harness_is_synthetic_and_never_uses_runtime_or_compose(self) -> None:
        for forbidden in (
            "docker compose",
            "--env-file",
            "KAIROS_SECRETS",
            "D:\\Kairos\\runtime",
            "kairos-paper-gate/.env",
            "docker system prune",
            "docker volume prune",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.text)
        self.assertIn("Synthetic clone-only schema-upgrade preflight integration", self.text)
        self.assertIn("Invoke-DockerQuiet", self.text)
        self.assertIn("NativeCommandError", self.text)
        self.assertIn("cannot resolve its script directory", self.text)
        self.assertIn("Join-Path $PSScriptRoot \"Invoke-SchemaUpgradePreflight.ps1\"", self.text)
        self.assertIn('result -cne "PASS_CLONE_ONLY"', self.text)
        self.assertIn("$receipt.original_migration.authorized -ne $false", self.text)
        self.assertIn("Synthetic clone-only receipt does not prove idempotency and restore coverage", self.text)
        self.assertIn("$receipt.restore_drill.passed -ne $true", self.text)
        self.assertIn("backup_manifest_sha256 = $manifestSha256", self.text)

    def test_runner_and_inputs_are_exact_and_pinned(self) -> None:
        self.assertIn("9219e5ef46c748703d949b324d84f6814ba0f196", self.text)
        self.assertIn(
            "python:3.11.15-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3",
            self.text,
        )
        self.assertIn("git -C $persistencePath -c core.autocrlf=false -c core.eol=lf archive", self.text)
        self.assertIn("migration hashes are", self.text)
        self.assertIn("--pull=false --network=none", self.text)
        self.assertIn("USER 10001:10001", self.text)
        self.assertIn("RepoDigest", self.text)
        self.assertIn('"kairos-schema-upgrade-runner-${suffix}:local"', self.text)
        self.assertIn('"${registryRepository}:immutable"', self.text)
        self.assertIn('"127.0.0.1:${registryPort}:5000"', self.text)
        self.assertIn('$bootstrapImportDirectory = Join-Path $tempRootFull "bootstrap-import"', self.text)
        self.assertIn("Could not export immutable legacy migration", self.text)
        self.assertIn("Docker Desktop does not reliably copy files into a tmpfs", self.text)
        self.assertIn("dst=/kairos-import,readonly", self.text)
        self.assertIn('$bootstrapExportDirectory = Join-Path $tempRootFull "bootstrap-export"', self.text)
        self.assertIn("dst=/kairos-export", self.text)
        self.assertIn("Synthetic host import is missing immutable legacy migration", self.text)
        self.assertIn("Synthetic host import is missing the generated legacy migration runner", self.text)
        self.assertIn("Synthetic host export is missing the generated legacy custom dump", self.text)
        self.assertIn("resolves the immutable dump relative to its", self.text)
        self.assertIn('$cloneReceiptPath = Join-Path $bootstrapExportDirectory', self.text)
        self.assertIn('Add("\\i $bootstrapMigrationDirectory/$migration")', self.text)
        self.assertIn("three successful", self.text)
        self.assertIn("observe it across the handoff", self.text)
        self.assertIn("PostgreSQL init process complete; ready for start up.", self.text)
        self.assertIn("harmless init warnings", self.text)
        self.assertIn("--command=SELECT 1;", self.text)
        self.assertIn("[System.Net.HttpWebRequest]::Create", self.text)
        self.assertIn("$request.Proxy = $null", self.text)
        self.assertIn("$response.Close()", self.text)

    def test_resources_are_scoped_and_cleanup_does_not_guess_preflight_suffix(self) -> None:
        self.assertIn('$HarnessScope = "synthetic-schema-upgrade-preflight-harness"', self.text)
        self.assertIn("--network none", self.text)
        self.assertIn("Docker Desktop does not publish", self.text)
        self.assertIn("--network bridge --read-only", self.text)
        self.assertIn('--publish "127.0.0.1:${registryPort}:5000"', self.text)
        self.assertIn("Assert-Labels", self.text)
        self.assertIn("Refusing to remove", self.text)
        cleanup = self.text.split("finally {", 1)[1]
        self.assertNotIn("kairos-schema-upgrade-preflight-$suffix", cleanup)
        self.assertNotIn("kairos-schema-upgrade-preflight-data-$suffix", cleanup)
        self.assertIn("must audit those separately labelled resources", cleanup)
        self.assertIn("Resolve the exact", self.text)
        self.assertIn("docker image rm -f $imageId", self.text)


if __name__ == "__main__":
    unittest.main()
