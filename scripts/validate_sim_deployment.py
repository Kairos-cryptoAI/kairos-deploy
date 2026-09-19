"""Validate the sealed, offline ``kairos-sim`` deployment model.

The simulator is a development-only replay facility.  Its manifest and
rendered Compose document are checked separately from the production and
PAPER topologies so no value from either contour can be inherited by mistake.
"""

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

import tomllib

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "tests" / "sim_gate" / "policy.py"


def _load_policy() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "kairos_sim_gate_policy", POLICY_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"could not load simulator policy from {POLICY_PATH}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


policy = _load_policy()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return value


def _github_request(url: str, *, token: str | None, accept: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "User-Agent": "kairos-simulator-deployment-validator/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310 -- fixed GitHub URLs
        return response.read()


def verify_remote_sources(
    lock: dict[str, Any], *, token: str | None = None
) -> list[str]:
    """Verify source existence and the execution lock's two immutable parents."""

    errors: list[str] = []
    dependencies = lock.get("dependencies") or {}
    for name, source in sorted(dependencies.items()):
        repository = str((source or {}).get("repository", ""))
        revision = str((source or {}).get("revision", ""))
        slug = repository.removeprefix("https://github.com/")
        try:
            metadata = json.loads(
                _github_request(
                    f"https://api.github.com/repos/{slug}/commits/{revision}",
                    token=token,
                    accept="application/vnd.github+json",
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
    execution = dependencies.get("kairos-execution-engine") or {}
    try:
        repository = str(execution["repository"]).removeprefix("https://github.com/")
        revision = str(execution["revision"])
        raw_base = f"https://raw.githubusercontent.com/{repository}/{revision}"
        pyproject = tomllib.loads(
            _github_request(
                f"{raw_base}/pyproject.toml", token=token, accept="text/plain"
            ).decode()
        )
        sources = pyproject.get("tool", {}).get("uv", {}).get("sources", {})
        for dependency_name in ("kairos-core", "kairos-persistence"):
            expected = str((dependencies[dependency_name] or {})["revision"])
            if (sources.get(dependency_name) or {}).get("rev") != expected:
                errors.append(
                    f"execution engine: {dependency_name} source pin differs from simulator manifest"
                )
        lock_text = _github_request(
            f"{raw_base}/uv.lock", token=token, accept="text/plain"
        ).decode()
        for dependency_name in ("kairos-core", "kairos-persistence"):
            expected = str((dependencies[dependency_name] or {})["revision"])
            if expected not in lock_text:
                errors.append(
                    f"execution engine: uv.lock lacks {dependency_name} revision"
                )
    except (
        OSError,
        KeyError,
        ValueError,
        tomllib.TOMLDecodeError,
        urllib.error.HTTPError,
    ) as exc:
        errors.append(
            f"execution engine: remote dependency verification failed ({type(exc).__name__})"
        )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-lock", type=Path, default=Path("sim.sources.lock.json")
    )
    parser.add_argument("--compose-json", type=Path)
    parser.add_argument(
        "--dockerfile", type=Path, default=Path("tests/sim_gate/Dockerfile")
    )
    parser.add_argument("--verify-remote", action="store_true")
    args = parser.parse_args(argv)
    try:
        lock = load_json(args.source_lock)
        errors = policy.validate_source_lock(lock)
        errors.extend(
            policy.validate_dockerfile(
                args.dockerfile.read_text(encoding="utf-8"), lock
            )
        )
        if args.compose_json:
            errors.extend(policy.validate_compose(load_json(args.compose_json), lock))
        if args.verify_remote:
            errors.extend(verify_remote_sources(lock, token=os.getenv("GITHUB_TOKEN")))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(
            f"simulator deployment validation could not start: {exc}", file=sys.stderr
        )
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Kairos isolated simulator deployment validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
