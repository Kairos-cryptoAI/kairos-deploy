"""Validate the sealed current-source REJECT_ALL integration gate."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "tests" / "current_release_gate" / "policy.py"


def _load_policy() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "kairos_current_release_gate_policy", POLICY_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"could not load current-release policy from {POLICY_PATH}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


policy = _load_policy()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return value


def _github_request(url: str, *, token: str | None) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "kairos-current-release-gate-validator/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310 -- fixed GitHub URLs
        return response.read()


def verify_remote_sources(
    lock: dict[str, Any], *, token: str | None = None
) -> list[str]:
    """Confirm each immutable Git revision exists without inferring runtime readiness."""

    errors: list[str] = []
    for name, source in sorted((lock.get("dependencies") or {}).items()):
        repository = str((source or {}).get("repository", ""))
        revision = str((source or {}).get("revision", ""))
        slug = repository.removeprefix("https://github.com/")
        try:
            metadata = json.loads(
                _github_request(
                    f"https://api.github.com/repos/{slug}/commits/{revision}",
                    token=token,
                )
            )
            if metadata.get("sha") != revision:
                errors.append(f"{name}: GitHub resolved an unexpected revision")
        except (
            OSError,
            ValueError,
            json.JSONDecodeError,
            urllib.error.HTTPError,
        ) as exc:
            errors.append(
                f"{name}: remote revision verification failed ({type(exc).__name__})"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-lock",
        type=Path,
        default=Path("current-release-gate.sources.lock.json"),
    )
    parser.add_argument(
        "--packaged-lock",
        type=Path,
        default=Path("tests/current_release_gate/source-lock.json"),
    )
    parser.add_argument("--compose-json", type=Path)
    parser.add_argument(
        "--dockerfile",
        type=Path,
        default=Path("tests/current_release_gate/Dockerfile"),
    )
    parser.add_argument(
        "--dockerignore",
        type=Path,
        default=Path("tests/current_release_gate/.dockerignore"),
    )
    parser.add_argument("--verify-remote", action="store_true")
    args = parser.parse_args(argv)
    try:
        lock = load_json(args.source_lock)
        packaged_lock = load_json(args.packaged_lock)
        errors = policy.validate_source_lock(lock)
        if packaged_lock != lock:
            errors.append(
                "packaged current-release source lock differs from canonical lock"
            )
        errors.extend(
            policy.validate_dockerfile(args.dockerfile.read_text(encoding="utf-8"))
        )
        errors.extend(
            policy.validate_dockerignore(args.dockerignore.read_text(encoding="utf-8"))
        )
        if args.compose_json:
            errors.extend(policy.validate_compose(load_json(args.compose_json)))
        if args.verify_remote:
            errors.extend(verify_remote_sources(lock, token=os.getenv("GITHUB_TOKEN")))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(
            f"current-release gate validation could not start: {exc}", file=sys.stderr
        )
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Kairos current-source REJECT_ALL gate validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
