"""Static fail-closed checks for the legacy clone-only quarantine rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path


EXPECTED_REVISION = "1ca8bf38d265ece7a95f749a268075549f80c043"
EXPECTED_FINGERPRINT = "a2fec9fe81d6af73a1e44038a0e71c21d9aaf2e3933ea8c76793d9e6f25b9adf"
RUNTIME_SUFFIX = (
    "013_campaign_source_budgets.sql",
    "014_bounded_canary_sessions.sql",
    "015_canary_dispatch_claims.sql",
    "016_global_canary_session_guard.sql",
    "018_offline_outbox_reconciliation.sql",
)


def _tuple_block(text: str, name: str) -> tuple[str, ...] | None:
    match = re.search(rf"^{name}\s*=\s*\((?P<body>.*?)^\)", text, re.MULTILINE | re.DOTALL)
    if match is None:
        return None
    return tuple(re.findall(r'"([0-9]{3}_[^"]+\.sql)"', match.group("body")))


def validate(controller: str, runner: str) -> list[str]:
    errors: list[str] = []
    required = (
        "CLONE_ONLY_LEGACY_OUTBOX_QUARANTINE_REHEARSAL",
        "LEGACY_BOOTSTRAPPED_RUNTIME_001_012",
        EXPECTED_FINGERPRINT,
        EXPECTED_REVISION,
        "--network", '"none"', 'f"container:{clone}"',
        "quarantine_expired_outbox_exact",
        "PUBLISH_OUTCOME_UNKNOWN",
        "ALREADY_QUARANTINED",
        "original_runtime_contacted\": False",
        "redis_contacted\": False",
        "publisher_contacted\": False",
        "original_quarantine_authorized\": False",
        "SEPARATE_TARGET_ROLE_AND_PRIMARY_MIGRATION_REVIEW",
        "receipt signature verification",
        "fresh two-hour runtime snapshot",
        "legacy inspection receipt is not eligible",
        "simulator_relations_present\": False",
        "timescaledb_pre_restore()",
        "timescaledb_post_restore()",
        "pg_restore",
        "--single-transaction",
    )
    for item in required:
        if item not in controller and item not in runner:
            errors.append(f"legacy clone rehearsal missing required invariant: {item}")
    actual_suffix = _tuple_block(controller, "RUNTIME_SUFFIX")
    if actual_suffix != RUNTIME_SUFFIX:
        errors.append("legacy clone rehearsal runtime migration suffix changed")
    if "017_simulator_journal.sql" in (actual_suffix or ()) or "019_simulator_book_frame_v2.sql" in (actual_suffix or ()):
        errors.append("legacy clone rehearsal must not apply simulator migrations")
    if "ALL_PACKAGE_MIGRATIONS" not in controller or "017_simulator_journal.sql" not in controller:
        errors.append("legacy clone rehearsal must inspect package inventory before excluding 017")
    for forbidden in (
        "docker compose",
        "--env-file",
        "KAIROS_SECRETS",
        "Database.migrate(",
        "Invoke-OfflineOutbox",
        "evedex",
        "openai",
        "deepseek",
        "requests.",
        "httpx",
        "redis",
    ):
        if forbidden.casefold() in controller.casefold() and forbidden not in {"redis"}:
            errors.append(f"legacy clone rehearsal must not contain runtime/provider route: {forbidden}")
    # Redis is permitted only as an explicit false observation in a receipt;
    # it must never be imported or instantiated by the clone worker.
    if "import redis" in runner or "Redis(" in runner or "redis." in runner:
        errors.append("clone worker must not include a Redis client route")
    if "import requests" in runner or "httpx" in runner or "websocket" in runner:
        errors.append("clone worker must not include an external transport route")
    if "FailingNoNetworkPublisher" not in runner or "publisher.calls != 0" not in runner:
        errors.append("clone worker must prove zero publisher calls")
    if "lease_owner_sha256" not in runner or "lease_owner\"" not in runner:
        errors.append("clone worker must bind and redact the raw legacy lease owner")
    if "print(json.dumps(result" not in runner or "except (CloneRunnerInputError" not in runner:
        errors.append("clone worker must return a redacted result on both paths")
    if '"payload":' in runner.split("def _redacted_row", 1)[1].split("async def _run", 1)[0]:
        errors.append("clone worker redacted row must not include raw payload")
    expected_runner_sha = hashlib.sha256(runner.encode("utf-8")).hexdigest()
    hash_match = re.search(r'EXPECTED_RUNNER_SHA256\s*=\s*"([0-9a-f]{64})"', controller)
    if hash_match is None or hash_match.group(1) != expected_runner_sha:
        errors.append("clone controller must pin the exact reviewed worker bytes")
    if '"--network", "none"' not in controller or '"--network", f"container:{clone}"' not in controller:
        errors.append("clone database and worker namespace isolation is not explicit")
    if "_verify_signature" not in controller or "--status-fd" not in controller or "VALIDSIG" not in controller:
        errors.append("clone controller must verify the detached legacy receipt signature")
    if "_assert_checkpoints" not in controller or "source dump changed during the clone-only rehearsal" not in controller:
        errors.append("clone controller must validate source checkpoints and immutable dump bytes")
    if "_cleanup(clone, data_volume, stage_volume, suffix)" not in controller or "_assert_labels" not in controller:
        errors.append("clone controller must remove only exact labelled generated resources")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", type=Path, default=Path("scripts/legacy_outbox_quarantine_clone_rehearsal.py"))
    parser.add_argument("--runner", type=Path, default=Path("scripts/legacy_outbox_clone_runner.py"))
    args = parser.parse_args(argv)
    try:
        errors = validate(args.controller.read_text(encoding="utf-8"), args.runner.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"legacy clone rehearsal validation could not start: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Kairos legacy clone-only quarantine rehearsal validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
