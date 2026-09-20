"""Verify a redacted legacy 001--012 inspection receipt on the host.

This helper has no database, Docker, Redis, or provider route.  The operator
wrapper uses it before it persists or signs a container-produced receipt.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "tests" / "legacy_outbox_inspection" / "runner.py"


def _load_runner() -> ModuleType:
    specification = importlib.util.spec_from_file_location("kairos_legacy_outbox_runner", RUNNER_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("legacy inspection verifier cannot load its sealed runner")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--expectation", required=True, type=Path)
    parser.add_argument("--backup-manifest-sha256", required=True)
    parser.add_argument("--backup-sha256", required=True)
    parser.add_argument("--backup-created-at-utc", required=True)
    parser.add_argument("--require-eligible", action="store_true")
    args = parser.parse_args(argv)
    try:
        runner = _load_runner()
        expectation = runner.LegacyExpectation.from_json(_read_json(args.expectation))
        backup = runner.SourceBackup.from_values(
            manifest_sha256=args.backup_manifest_sha256,
            backup_sha256=args.backup_sha256,
            created_at_utc=args.backup_created_at_utc,
        )
        receipt = runner.verify_inspection_receipt(
            _read_json(args.receipt),
            expectation=expectation,
            source_backup=backup,
            require_eligible=args.require_eligible,
        )
        result = receipt["inspection"]["result"]
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"legacy outbox receipt verification failed: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "kairos.legacy-outbox-inspection-verification.v1",
                "state": "VERIFIED",
                "result": result,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
