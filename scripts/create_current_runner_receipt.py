"""Create a non-secret receipt for a verified current-runner Docker archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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

    return {
        "schema_version": 1,
        "transport_kind": "docker-save-archive",
        "registry_reference": args.registry_reference,
        "local_image_id": args.local_image_id,
        "archive": {"filename": args.archive.name, "sha256": sha256(args.archive), "size_bytes": size},
        "source": {"repository": args.source_repository, "revision": args.source_revision},
        "recipe": {"repository": "https://github.com/Kairos-cryptoAI/kairos-deploy", "revision": args.recipe_revision},
        "workflow": {"repository": args.workflow_repository, "run_id": args.workflow_run_id, "commit": args.workflow_commit},
        "runtime": {"python": runtime["python"], "aiohttp": runtime["aiohttp"], "multidict": runtime["multidict"]},
        "migrations": dict(sorted(expected.items())),
        "limitations": ["Docker archive transport retains the local image ID, not the registry manifest bytes.", "Candidate artifact is not production qualification and is not wired to controllers."],
    }


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
