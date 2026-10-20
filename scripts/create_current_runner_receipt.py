"""Create a non-secret receipt for a verified current-runner Docker archive.

This module performs no Docker, registry, or host operations. `local_image_id`
retains its established meaning: the SHA-256 of
the image config bytes (Docker image/config ID), not a registry manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path
from typing import Any


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
OCI_MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_TYPE = "application/vnd.oci.image.config.v1+json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_bytes(raw: bytes, description: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{description} is invalid JSON") from exc


def _descriptor_digest(descriptor: Any, *, media_type: str, description: str) -> tuple[str, int]:
    if not isinstance(descriptor, dict):
        raise ValueError(f"{description} descriptor must be an object")
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if (not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or descriptor.get("mediaType") != media_type
            or not isinstance(size, int) or isinstance(size, bool) or size < 0):
        raise ValueError(f"{description} descriptor identity is invalid")
    return digest, size


def _archive_identity(archive: Path, expected_local_image_id: str) -> dict[str, str] | None:
    """Validate an OCI archive or a single-image Docker-save archive.

    Presence of either OCI marker claims OCI layout. Such archives fail closed
    if incomplete or corrupt. Archives without either marker must have the
    standard `manifest.json` + content-addressed config shape of Docker save.
    A `None` result means valid legacy Docker save, not an unchecked file.
    """
    try:
        tf = tarfile.open(archive, mode="r:*")
    except tarfile.TarError as exc:
        raise ValueError("archive is not a readable Docker/OCI tar archive") from exc

    with tf:
        members = tf.getmembers()
        by_name: dict[str, list[tarfile.TarInfo]] = {}
        for member in members:
            by_name.setdefault(member.name, []).append(member)
        has_index = "index.json" in by_name
        has_layout = "oci-layout" in by_name

        def read_member(name: str, max_size: int) -> bytes:
            found = by_name.get(name, [])
            if len(found) != 1:
                raise ValueError(f"archive member missing or duplicated: {name}")
            member = found[0]
            if not member.isfile() or member.size < 0 or member.size > max_size:
                raise ValueError(f"archive member type/size is invalid: {name}")
            body = tf.extractfile(member)
            if body is None:
                raise ValueError(f"archive member unreadable: {name}")
            raw = body.read(max_size + 1)
            if len(raw) != member.size:
                raise ValueError(f"archive member byte count mismatch: {name}")
            return raw

        if has_index or has_layout:
            if not (has_index and has_layout):
                raise ValueError("archive claims OCI layout but is missing index/layout metadata")
            layout = _json_bytes(read_member("oci-layout", 4096), "OCI layout")
            if not isinstance(layout, dict) or layout.get("imageLayoutVersion") != "1.0.0":
                raise ValueError("OCI layout version is unsupported")

            index = _json_bytes(read_member("index.json", 1024 * 1024), "OCI index")
            descriptors = index.get("manifests") if isinstance(index, dict) else None
            if (not isinstance(index, dict) or index.get("schemaVersion") != 2
                    or not isinstance(descriptors, list) or len(descriptors) != 1):
                raise ValueError("OCI index must contain exactly one manifest descriptor")
            manifest_digest, manifest_size = _descriptor_digest(
                descriptors[0], media_type=OCI_MANIFEST_TYPE, description="OCI manifest"
            )
            manifest_path = "blobs/sha256/" + manifest_digest.removeprefix("sha256:")
            manifest_raw = read_member(manifest_path, 4 * 1024 * 1024)
            if len(manifest_raw) != manifest_size or hashlib.sha256(manifest_raw).hexdigest() != manifest_digest[7:]:
                raise ValueError("OCI manifest descriptor does not match raw bytes/size")

            manifest = _json_bytes(manifest_raw, "OCI manifest")
            if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
                raise ValueError("OCI manifest schema is invalid")
            config_digest, config_size = _descriptor_digest(
                manifest.get("config"), media_type=OCI_CONFIG_TYPE, description="OCI config"
            )
            config_path = "blobs/sha256/" + config_digest.removeprefix("sha256:")
            config_raw = read_member(config_path, 16 * 1024 * 1024)
            if len(config_raw) != config_size or hashlib.sha256(config_raw).hexdigest() != config_digest[7:]:
                raise ValueError("OCI config descriptor does not match raw bytes/size")
            image_config = _json_bytes(config_raw, "OCI image config")
            if not isinstance(image_config, dict):
                raise ValueError("OCI image config must be an object")
            if config_digest != expected_local_image_id:
                raise ValueError("OCI config digest differs from local image ID")
            return {
                "format": "oci-layout",
                "manifest_digest": manifest_digest,
                "config_digest": config_digest,
            }

        # Explicit legacy Docker-save path: manifest.json is the marker, and
        # its config filename/content must identify the supplied local image ID.
        docker_manifest = _json_bytes(read_member("manifest.json", 1024 * 1024), "Docker save manifest")
        if not isinstance(docker_manifest, list) or len(docker_manifest) != 1:
            raise ValueError("legacy Docker-save archive must contain exactly one image")
        image = docker_manifest[0]
        if not isinstance(image, dict):
            raise ValueError("Docker save image entry is invalid")
        config_name = image.get("Config")
        expected_name = expected_local_image_id.removeprefix("sha256:") + ".json"
        if config_name != expected_name:
            raise ValueError("Docker save config filename differs from local image ID")
        config_raw = read_member(config_name, 16 * 1024 * 1024)
        if hashlib.sha256(config_raw).hexdigest() != expected_local_image_id.removeprefix("sha256:"):
            raise ValueError("Docker save config bytes differ from local image ID")
        config = _json_bytes(config_raw, "Docker save image config")
        if not isinstance(config, dict):
            raise ValueError("Docker save image config must be an object")
        return None


def build_receipt(args: argparse.Namespace) -> dict[str, object]:
    if args.source_repository != "https://github.com/Kairos-cryptoAI/kairos-persistence":
        raise ValueError("source repository does not match reviewed persistence project")
    if args.workflow_repository != "Kairos-cryptoAI/kairos-deploy":
        raise ValueError("workflow repository does not match reviewed deploy project")
    if not re.fullmatch(r"ghcr\.io/kairos-cryptoai/kairos-runtime-current-schema-runner@sha256:[0-9a-f]{64}", args.registry_reference):
        raise ValueError("registry reference must be the current runner's immutable GHCR digest")
    if not HEX40.fullmatch(args.source_revision) or not HEX40.fullmatch(args.recipe_revision):
        raise ValueError("source and recipe revisions must be full lowercase Git SHAs")
    if not args.local_image_id.startswith("sha256:") or not HEX64.fullmatch(args.local_image_id[7:]):
        raise ValueError("local image ID must be sha256 plus 64 lowercase hex characters")
    if not args.workflow_repository or not args.workflow_run_id or not HEX40.fullmatch(args.workflow_commit):
        raise ValueError("workflow repository, run ID, and full commit are required")

    runtime = json.loads(args.runtime_json.read_text(encoding="utf-8"))
    migration_source = args.migration_source
    expected = {
        item.name: sha256(item)
        for item in migration_source.iterdir()
        if item.is_file() and item.name.endswith(".sql")
    }
    if runtime.get("migrations") != expected or "028_news_processing.sql" not in expected:
        raise ValueError("installed migration map does not equal source map")
    if (runtime.get("python"), runtime.get("aiohttp"), runtime.get("multidict")) != ("3.11.15", "3.14.5", "6.9.1"):
        raise ValueError("installed dependency/runtime versions do not match reviewed profile")
    size = args.archive.stat().st_size
    if size <= 0:
        raise ValueError("archive is empty")
    archive_identity = _archive_identity(args.archive, args.local_image_id)

    receipt: dict[str, object] = {
        "schema_version": 1,
        "transport_kind": "docker-save-archive",
        "registry_reference": args.registry_reference,
        # Historical schema semantics retained: this is the local image config digest.
        "local_image_id": args.local_image_id,
        "archive": {"filename": args.archive.name, "sha256": sha256(args.archive), "size_bytes": size},
        "source": {"repository": args.source_repository, "revision": args.source_revision},
        "recipe": {"repository": "https://github.com/Kairos-cryptoAI/kairos-deploy", "revision": args.recipe_revision},
        "workflow": {"repository": args.workflow_repository, "run_id": args.workflow_run_id, "commit": args.workflow_commit},
        "runtime": {"python": runtime["python"], "aiohttp": runtime["aiohttp"], "multidict": runtime["multidict"]},
        "migrations": dict(sorted(expected.items())),
        "limitations": [
            "local_image_id identifies the image config digest; it is not a registry manifest digest.",
            "Registry manifest bytes are not asserted to be preserved by Docker archive transport.",
            "Candidate artifact is not production qualification and is not wired to controllers.",
        ],
    }
    if archive_identity is not None:
        # Additive only. Historical schema_version and local_image_id meanings do not change.
        receipt["archive_identity"] = archive_identity
    return receipt


def write_outputs(args: argparse.Namespace) -> None:
    args.output_directory.mkdir(parents=True, exist_ok=True)
    receipt_path = args.output_directory / "receipt.json"
    sums_path = args.output_directory / "SHA256SUMS"
    if receipt_path.exists() or sums_path.exists():
        raise FileExistsError("receipt output already exists; refusing to overwrite")
    receipt = json.dumps(build_receipt(args), indent=2, sort_keys=True) + "\n"
    with receipt_path.open("x", encoding="utf-8") as stream:
        stream.write(receipt)
    lines = [f"{sha256(args.archive)}  {args.archive.name}", f"{sha256(receipt_path)}  {receipt_path.name}"]
    with sums_path.open("x", encoding="ascii") as stream:
        stream.write("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--registry-reference", required=True)
    parser.add_argument("--local-image-id", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--recipe-revision", required=True)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-commit", required=True)
    parser.add_argument("--runtime-json", type=Path, required=True)
    parser.add_argument("--migration-source", type=Path, required=True)
    args = parser.parse_args()
    write_outputs(args)


if __name__ == "__main__":
    main()
