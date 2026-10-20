from __future__ import annotations

import argparse
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.create_current_runner_receipt import (
    OCI_CONFIG_TYPE,
    OCI_MANIFEST_TYPE,
    _archive_identity,
    build_receipt,
    write_outputs,
)

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "publish-current-runtime-runner.yml"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _tar(path: Path, entries: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:") as stream:
        for name, raw in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            stream.addfile(info, io.BytesIO(raw))


class ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / "image.docker.tar"
        self.migrations = self.root / "migrations"
        self.migrations.mkdir()
        (self.migrations / "028_news_processing.sql").write_text("migration", encoding="utf-8")
        migration_map = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.migrations.glob("*.sql")}
        self.runtime = self.root / "runtime.json"
        self.runtime.write_text(json.dumps({
            "migrations": migration_map, "python": "3.11.15", "aiohttp": "3.14.5", "multidict": "6.9.1"
        }), encoding="utf-8")
        self.args = argparse.Namespace(
            archive=self.archive, output_directory=self.root / "out",
            registry_reference="ghcr.io/kairos-cryptoai/kairos-runtime-current-schema-runner@sha256:" + "a" * 64,
            local_image_id="sha256:" + "b" * 64,
            source_repository="https://github.com/Kairos-cryptoAI/kairos-persistence",
            source_revision="c" * 40, recipe_revision="d" * 40,
            workflow_repository="Kairos-cryptoAI/kairos-deploy", workflow_run_id="12345",
            workflow_commit="e" * 40, runtime_json=self.runtime, migration_source=self.migrations,
        )
        self._write_legacy_docker_save()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_legacy_docker_save(self) -> tuple[str, bytes]:
        config = json.dumps({"architecture": "amd64", "os": "linux"}, sort_keys=True).encode()
        config_digest = _digest(config)
        config_name = config_digest[7:] + ".json"
        manifest = json.dumps([{"Config": config_name, "RepoTags": ["example/image:test"], "Layers": []}]).encode()
        _tar(self.archive, {"manifest.json": manifest, config_name: config})
        self.args.local_image_id = config_digest
        return config_digest, config

    def _write_oci(self, *, mutate_manifest_size: bool = False,
                   mutate_config_digest: bool = False, omit_config_blob: bool = False) -> tuple[str, str]:
        config = json.dumps({"architecture": "amd64", "os": "linux"}, sort_keys=True).encode()
        config_digest = _digest(config)
        manifest_config_digest = "sha256:" + "0" * 64 if mutate_config_digest else config_digest
        manifest = {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_TYPE,
            "config": {"mediaType": OCI_CONFIG_TYPE, "digest": manifest_config_digest, "size": len(config)},
            "layers": [],
        }
        manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        manifest_digest = _digest(manifest_raw)
        descriptor = {"mediaType": OCI_MANIFEST_TYPE, "digest": manifest_digest,
                      "size": len(manifest_raw) + int(mutate_manifest_size)}
        index_raw = json.dumps({"schemaVersion": 2, "manifests": [descriptor]},
                               sort_keys=True, separators=(",", ":")).encode()
        entries = {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": index_raw,
            "blobs/sha256/" + manifest_digest[7:]: manifest_raw,
        }
        if not omit_config_blob:
            entries["blobs/sha256/" + config_digest[7:]] = config
        self.args.local_image_id = config_digest
        _tar(self.archive, entries)
        return config_digest, manifest_digest

    def test_receipt_binds_legacy_docker_save_without_changing_schema_or_id(self) -> None:
        config_digest, _ = self._write_legacy_docker_save()
        receipt = build_receipt(self.args)
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(receipt["local_image_id"], config_digest)
        self.assertNotIn("archive_identity", receipt)
        self.assertEqual(receipt["transport_kind"], "docker-save-archive")
        self.assertEqual(receipt["archive"]["sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())

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
        self.runtime.write_text(json.dumps({
            "migrations": {}, "python": "3.11.15", "aiohttp": "3.14.5", "multidict": "6.9.1"
        }), encoding="utf-8")
        with self.assertRaises(ValueError):
            build_receipt(self.args)

    def test_rejects_wrong_dependency_profile(self) -> None:
        migration_map = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.migrations.glob("*.sql")}
        self.runtime.write_text(json.dumps({
            "migrations": migration_map, "python": "3.11.15", "aiohttp": "3.14.3", "multidict": "6.7.1"
        }), encoding="utf-8")
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
        self.assertIn("local_image_id is the config digest", text)
        self.assertNotIn("import preserves the image ID", text)

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

    def test_oci_receipt_separates_manifest_from_historical_config_id(self) -> None:
        config_digest, manifest_digest = self._write_oci()
        receipt = build_receipt(self.args)
        self.assertNotEqual(manifest_digest, config_digest)
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(receipt["local_image_id"], config_digest)
        self.assertEqual(receipt["archive_identity"], {
            "format": "oci-layout", "manifest_digest": manifest_digest, "config_digest": config_digest,
        })

    def test_rejects_corrupt_oci_manifest_size(self) -> None:
        config_digest, _ = self._write_oci(mutate_manifest_size=True)
        with self.assertRaisesRegex(ValueError, "manifest descriptor"):
            _archive_identity(self.archive, config_digest)

    def test_rejects_config_descriptor_with_missing_blob(self) -> None:
        config_digest, _ = self._write_oci(mutate_config_digest=True)
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            _archive_identity(self.archive, config_digest)

    def test_rejects_oci_config_hash_mismatch(self) -> None:
        config_digest, _ = self._write_oci()
        # Rebuild tar preserving layout but corrupt bytes under the claimed digest path.
        with tarfile.open(self.archive, "r:") as stream:
            entries = {m.name: stream.extractfile(m).read() for m in stream.getmembers() if m.isfile()}
        config_path = "blobs/sha256/" + config_digest[7:]
        entries[config_path] = b'{"changed":true}'
        _tar(self.archive, entries)
        with self.assertRaisesRegex(ValueError, "config descriptor does not match"):
            _archive_identity(self.archive, config_digest)

    def test_rejects_partial_oci_claim_instead_of_downgrading(self) -> None:
        _tar(self.archive, {"index.json": b"not json", "manifest.json": b"[]"})
        with self.assertRaisesRegex(ValueError, "claims OCI layout"):
            _archive_identity(self.archive, self.args.local_image_id)

    def test_rejects_non_archive_garbage(self) -> None:
        self.archive.write_bytes(b"archive bytes")
        with self.assertRaisesRegex(ValueError, "not a readable"):
            _archive_identity(self.archive, self.args.local_image_id)

    def test_rejects_local_config_id_mismatch(self) -> None:
        config_digest, _ = self._write_oci()
        with self.assertRaisesRegex(ValueError, "differs from local image ID"):
            _archive_identity(self.archive, "sha256:" + "f" * 64)
        self.assertNotEqual(config_digest, "sha256:" + "f" * 64)

    def test_output_is_create_only(self) -> None:
        write_outputs(self.args)
        receipt_path = self.args.output_directory / "receipt.json"
        sums_path = self.args.output_directory / "SHA256SUMS"
        before = (receipt_path.read_bytes(), sums_path.read_bytes())
        with self.assertRaises(FileExistsError):
            write_outputs(self.args)
        self.assertEqual((receipt_path.read_bytes(), sums_path.read_bytes()), before)


if __name__ == "__main__":
    unittest.main()
