from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.create_current_runner_receipt import build_receipt, write_outputs


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "publish-current-runtime-runner.yml"


class ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / "image.docker.tar"
        self.archive.write_bytes(b"archive bytes")
        self.migrations = self.root / "migrations"
        self.migrations.mkdir()
        (self.migrations / "028_news_processing.sql").write_text("migration", encoding="utf-8")
        self.runtime = self.root / "runtime.json"
        migration_map = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.migrations.glob("*.sql")}
        self.runtime.write_text(json.dumps({"migrations": migration_map, "python": "3.11.15", "aiohttp": "3.14.5", "multidict": "6.9.1"}), encoding="utf-8")
        self.args = argparse.Namespace(
            archive=self.archive, output_directory=self.root / "out",
            registry_reference="ghcr.io/kairos-cryptoai/kairos-runtime-current-schema-runner@sha256:" + "a" * 64,
            local_image_id="sha256:" + "b" * 64,
            source_repository="https://github.com/Kairos-cryptoAI/kairos-persistence",
            source_revision="c" * 40, recipe_revision="d" * 40,
            workflow_repository="Kairos-cryptoAI/kairos-deploy", workflow_run_id="12345",
            workflow_commit="e" * 40, runtime_json=self.runtime, migration_source=self.migrations,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_receipt_binds_archive_source_runtime_and_migrations(self) -> None:
        receipt = build_receipt(self.args)
        self.assertEqual(receipt["archive"]["sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(receipt["source"]["revision"], "c" * 40)
        self.assertEqual(receipt["migrations"]["028_news_processing.sql"], hashlib.sha256(b"migration").hexdigest())
        self.assertEqual(receipt["transport_kind"], "docker-save-archive")

    def test_rejects_non_digest_registry_reference(self) -> None:
        self.args.registry_reference = "ghcr.io/kairos-cryptoai/kairos-runtime-current-schema-runner:latest"
        with self.assertRaises(ValueError):
            build_receipt(self.args)

    def test_rejects_source_migration_mismatch(self) -> None:
        self.runtime.write_text(json.dumps({"migrations": {}, "python": "3.11.15", "aiohttp": "3.14.5", "multidict": "6.9.1"}), encoding="utf-8")
        with self.assertRaises(ValueError):
            build_receipt(self.args)

    def test_rejects_wrong_dependency_profile(self) -> None:
        self.runtime.write_text(json.dumps({"migrations": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.migrations.glob("*.sql")}, "python": "3.11.15", "aiohttp": "3.14.3", "multidict": "6.7.1"}), encoding="utf-8")
        with self.assertRaises(ValueError):
            build_receipt(self.args)

    def test_workflow_pins_exact_reviewed_repositories_and_revisions(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("if: github.repository == 'Kairos-cryptoAI/kairos-deploy' && github.ref == 'refs/heads/main'", text)
        self.assertIn("repository: Kairos-cryptoAI/kairos-persistence", text)
        self.assertIn("PERSISTENCE_REVISION: 752c984ca276ccbb7fcbd1b60a6c75d95fe6f108", text)
        self.assertIn("DEPLOY_REVISION: 418b0979bd53fcfaa1816392efebcff59162f601", text)
        self.assertIn("SOURCE_REPOSITORY: https://github.com/Kairos-cryptoAI/kairos-persistence", text)
        self.assertRegex("752c984ca276ccbb7fcbd1b60a6c75d95fe6f108", r"^[0-9a-f]{40}$")
        self.assertRegex("418b0979bd53fcfaa1816392efebcff59162f601", r"^[0-9a-f]{40}$")
        self.assertIn("reviewed-persistence/kairos_persistence/migrations/028_news_processing.sql", text)

    def test_rejects_wrong_source_or_workflow_repository(self) -> None:
        self.args.source_repository = "https://github.com/example/other"
        with self.assertRaises(ValueError):
            build_receipt(self.args)
        self.args.source_repository = "https://github.com/Kairos-cryptoAI/kairos-persistence"
        self.args.workflow_repository = "Kairos-cryptoAI/other"
        with self.assertRaises(ValueError):
            build_receipt(self.args)

    def test_output_creation_writes_receipt_and_refuses_overwrite(self) -> None:
        write_outputs(self.args)
        receipt = self.args.output_directory / "receipt.json"
        sums = self.args.output_directory / "SHA256SUMS"
        self.assertEqual(json.loads(receipt.read_text(encoding="utf-8"))["archive"]["sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertIn("  receipt.json\n", sums.read_text(encoding="ascii"))
        receipt_before, sums_before = receipt.read_bytes(), sums.read_bytes()
        with self.assertRaises(FileExistsError):
            write_outputs(self.args)
        self.assertEqual(receipt.read_bytes(), receipt_before)
        self.assertEqual(sums.read_bytes(), sums_before)


if __name__ == "__main__":
    unittest.main()
