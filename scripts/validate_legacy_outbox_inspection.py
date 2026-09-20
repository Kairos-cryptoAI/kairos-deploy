"""Validate the standalone read-only legacy 001--012 outbox inspection profile."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "tests" / "legacy_outbox_inspection" / "policy.py"


def _load_policy() -> ModuleType:
    specification = importlib.util.spec_from_file_location("kairos_legacy_outbox_policy", POLICY_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"could not load legacy outbox policy from {POLICY_PATH}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


policy = _load_policy()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return value


def _github_json(url: str, *, token: str | None) -> object:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "kairos-legacy-outbox-validator/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310 -- fixed GitHub API route
        return json.loads(response.read())


def _verify_remote_commit(
    *,
    repository: str,
    revision: str,
    label: str,
    token: str | None,
) -> list[str]:
    slug = repository.removeprefix("https://github.com/")
    try:
        resolved = _github_json(f"https://api.github.com/repos/{slug}/commits/{revision}", token=token)
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.HTTPError) as exc:
        return [f"legacy outbox {label} revision verification failed ({type(exc).__name__})"]
    if not isinstance(resolved, dict) or resolved.get("sha") != revision:
        return [f"legacy outbox GitHub resolved an unexpected {label} revision"]
    return []


def _verify_remote_bootstrap(lock: dict[str, Any], *, token: str | None) -> list[str]:
    profile = lock.get("profile") or {}
    bootstrap = profile.get("bootstrap") if isinstance(profile, dict) else None
    if not isinstance(bootstrap, dict):
        return ["legacy outbox bootstrap provenance is unavailable"]
    repository = str(bootstrap.get("repository", ""))
    revision = str(bootstrap.get("revision", ""))
    path = str(bootstrap.get("path", ""))
    expected_blob = str(bootstrap.get("git_blob_sha1", ""))
    expected_sha256 = str(bootstrap.get("sha256", ""))
    errors = _verify_remote_commit(
        repository=repository,
        revision=revision,
        label="bootstrap",
        token=token,
    )
    if errors:
        return errors
    slug = repository.removeprefix("https://github.com/")
    encoded_path = urllib.parse.quote(path, safe="/")
    try:
        content = _github_json(
            f"https://api.github.com/repos/{slug}/contents/{encoded_path}?ref={revision}",
            token=token,
        )
        if not isinstance(content, dict) or content.get("encoding") != "base64":
            return ["legacy outbox bootstrap content response is invalid"]
        encoded = content.get("content")
        if not isinstance(encoded, str):
            return ["legacy outbox bootstrap content is unavailable"]
        raw = base64.b64decode(b"".join(encoded.encode("ascii").split()), validate=True)
    except (OSError, UnicodeEncodeError, ValueError, json.JSONDecodeError, urllib.error.HTTPError) as exc:
        return [f"legacy outbox bootstrap content verification failed ({type(exc).__name__})"]
    if content.get("sha") != expected_blob:
        return ["legacy outbox bootstrap Git blob identity differs"]
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        return ["legacy outbox bootstrap content SHA-256 differs"]
    return []


def verify_remote_sources(lock: dict[str, Any], *, token: str | None = None) -> list[str]:
    """Verify immutable Git dependencies and the exact historical bootstrap."""

    source = (lock.get("dependencies") or {}).get("kairos-persistence") or {}
    errors = _verify_remote_commit(
        repository=str(source.get("repository", "")),
        revision=str(source.get("revision", "")),
        label="persistence",
        token=token,
    )
    return errors + _verify_remote_bootstrap(lock, token=token)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, default=Path("legacy-outbox-inspection.sources.lock.json"))
    parser.add_argument(
        "--packaged-lock",
        type=Path,
        default=Path("tests/legacy_outbox_inspection/source-lock.json"),
    )
    parser.add_argument("--compose-json", type=Path)
    parser.add_argument("--normal-up-compose-json", type=Path)
    parser.add_argument("--dockerfile", type=Path, default=Path("tests/legacy_outbox_inspection/Dockerfile"))
    parser.add_argument(
        "--dockerignore", type=Path, default=Path("tests/legacy_outbox_inspection/.dockerignore")
    )
    parser.add_argument("--verify-remote", action="store_true")
    args = parser.parse_args(argv)
    try:
        lock = load_json(args.source_lock)
        packaged_lock = load_json(args.packaged_lock)
        errors = policy.validate_source_lock(lock)
        if packaged_lock != lock:
            errors.append("packaged legacy outbox source lock differs from canonical lock")
        errors.extend(policy.validate_dockerfile(args.dockerfile.read_text(encoding="utf-8")))
        errors.extend(policy.validate_dockerignore(args.dockerignore.read_text(encoding="utf-8")))
        if args.compose_json:
            errors.extend(policy.validate_compose(load_json(args.compose_json)))
        if args.normal_up_compose_json:
            errors.extend(policy.validate_normal_up_compose(load_json(args.normal_up_compose_json)))
        if args.verify_remote:
            errors.extend(verify_remote_sources(lock, token=os.getenv("GITHUB_TOKEN")))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"legacy outbox validation could not start: {type(exc).__name__}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Kairos legacy 001--012 outbox inspection validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
