"""Static fail-closed validation for the clone-only schema-upgrade preflight."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


LEGACY = (
    "001_audit_and_idempotency.sql",
    "002_durable_runtime.sql",
    "003_execution_effect_journal.sql",
    "004_execution_recovery_delay.sql",
    "005_source_state_and_usage.sql",
    "006_paper_trade_lifecycle.sql",
    "007_execution_runtime_health.sql",
    "008_public_execution_events.sql",
    "009_paper_canary_arms.sql",
    "010_runtime_compensation_reserve.sql",
    "011_execution_mutation_budget.sql",
    "012_outbox_producer_order.sql",
)
TARGET_SUFFIX = (
    "013_campaign_source_budgets.sql",
    "014_bounded_canary_sessions.sql",
    "015_canary_dispatch_claims.sql",
    "016_global_canary_session_guard.sql",
    "017_simulator_journal.sql",
    "018_offline_outbox_reconciliation.sql",
)
PERSISTENCE_REVISION = "9219e5ef46c748703d949b324d84f6814ba0f196"
TIMESCALE_IMAGE = (
    "timescale/timescaledb:2.29.1-pg16@sha256:"
    "252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
)
LEGACY_SCHEMA_FINGERPRINT = "7c4c103c09badbe1a60a4fcc8d11e2119a3ece0c52e1145d69a0fc2a11be59de"


def validate_script(text: str) -> list[str]:
    """Return static violations without running Docker, PowerShell, or a database."""

    errors: list[str] = []
    required = (
        "CLONE_ONLY_SCHEMA_UPGRADE_PREFLIGHT",
        PERSISTENCE_REVISION,
        TIMESCALE_IMAGE,
        '$ExpectedSourceComposeProject = "kairos-paper-gate"',
        '$ExpectedSourceDatabase = "kairos"',
        "$MaximumBackupAge = [TimeSpan]::FromHours(2)",
        '$ExpectedMigrationRunnerUser = "10001:10001"',
        "$ExpectedLegacySchemaFingerprint =",
        f'$ExpectedLegacySchemaFingerprint = "{LEGACY_SCHEMA_FINGERPRINT}"',
        "--network none",
        "timescaledb_pre_restore()",
        "timescaledb_post_restore()",
        "pg_restore --exit-on-error --no-owner --no-privileges",
        "--single-transaction",
        "$SchemaAdvisoryLock = \"4907627681104115019\"",
        "SELECT pg_advisory_xact_lock($SchemaAdvisoryLock);",
        "kairos_schema_upgrade_drill_",
        "kairos_schema_upgrade_restore_drill_",
        "Assert-PostBaselineObjects",
        "Assert-VettedPostBaselineSchemaShape",
        "Assert-VettedLegacySchemaShape",
        "Get-LegacySchemaFingerprint",
        "Assert-CloneDdlPreconditions",
        "Assert-CleanBaselineReceipt",
        "Get-FreshVerifiedBaseline",
        "Assert-ManifestCheckpoints",
        "Get-PostBaselineSchemaFingerprint",
        "Get-PinnedMigrationSource",
        "ConvertTo-Base64PythonCommand",
        "b64decode",
        "RepoDigests",
        "--user $ExpectedMigrationRunnerUser",
        "org.opencontainers.image.revision",
        "original_runtime_contacted = $false",
        "result = \"PASS_CLONE_ONLY\"",
        "target_ddl_permissions_verified = $false",
        "simulator_journal_on_runtime_clone = \"TESTED_ONLY_ARCHITECTURE_DECISION_UNRESOLVED\"",
        "dropdb",
        'Invoke-DockerProbe -Arguments @("volume", "rm", $volume)',
    )
    for value in required:
        if value not in text:
            errors.append(f"schema-upgrade preflight missing required invariant: {value}")
    legacy_block = re.search(r"\$LegacyMigrations\s*=\s*@\((?P<body>.*?)\n\)", text, re.DOTALL)
    if legacy_block is None:
        errors.append("schema-upgrade preflight legacy migration block is missing")
    else:
        actual_legacy = tuple(re.findall(r'"([0-9]{3}_[^"]+\.sql)"', legacy_block.group("body")))
        if actual_legacy != LEGACY:
            errors.append("schema-upgrade preflight legacy migration profile changed")
    target_block = re.search(
        r"\$TargetMigrations\s*=\s*@\(\s*\$LegacyMigrations\s*\+\s*@\((?P<body>.*?)\n\s*\)\s*\n\)",
        text,
        re.DOTALL,
    )
    if target_block is None:
        errors.append("schema-upgrade preflight target migration block is missing")
    else:
        actual_suffix = tuple(re.findall(r'"([0-9]{3}_[^"]+\.sql)"', target_block.group("body")))
        if actual_suffix != TARGET_SUFFIX:
            errors.append("schema-upgrade preflight target migration profile changed")
    ordered_migrations = LEGACY + TARGET_SUFFIX
    positions: list[int] = []
    for migration in ordered_migrations:
        if migration not in text:
            errors.append(f"schema-upgrade preflight missing pinned migration: {migration}")
            continue
        positions.append(text.index(f'"{migration}"'))
    if len(positions) == len(ordered_migrations) and positions != sorted(positions):
        errors.append("schema-upgrade preflight migration profile order changed")
    if "Database.migrate(" in text or "kairos_persistence.Database" in text:
        errors.append("schema-upgrade preflight must not call the generic migration runner")
    if "docker compose" in text or "--env-file" in text or "KAIROS_SECRETS" in text:
        errors.append("schema-upgrade preflight must not attach to a runtime Compose project or secrets")
    if re.search(r"--dbname=\$manifest\.database", text):
        errors.append("schema-upgrade preflight must never target the manifest source database")
    if "dropdb --if-exists --force --username=$CloneDatabaseUser $Database" in text:
        errors.append("schema-upgrade preflight must not drop a caller-selected database")
    if "-Database" in text.split("param(", 1)[1].split(")", 1)[0]:
        errors.append("schema-upgrade preflight must not accept an operator-selected database")
    if text.count("Assert-CloneDatabaseName -DatabaseName") < 6:
        errors.append("schema-upgrade preflight must repeatedly validate generated clone database names")
    if "$Expected[$index] -cne $actualArray[$index]" not in text:
        errors.append("schema-upgrade preflight must compare migration profiles in order")
    if "Assert-PostBaselineObjects -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Present $false" not in text:
        errors.append("schema-upgrade preflight must reject post-baseline residue before DDL")
    if "conrelid='public.message_outbox'::regclass" not in text:
        errors.append("schema-upgrade preflight must scope reconciliation constraints to message_outbox")
    if "Baseline outbox does not permit a read-only consumer restart" not in text:
        errors.append("schema-upgrade preflight must require a clean recovered outbox receipt")
    if "Backup manifest is not a fresh two-hour runtime snapshot" not in text:
        errors.append("schema-upgrade preflight must reject stale runtime backups")
    if "Baseline receipt is not a fresh two-hour runtime verification" not in text:
        errors.append("schema-upgrade preflight must reject stale baseline receipts")
    if "backup_manifest_sha256" not in text or "does not bind the exact backup manifest bytes" not in text:
        errors.append("schema-upgrade preflight must bind recovery proof to exact manifest bytes")
    if "Baseline receipt predates the verified backup manifest" not in text:
        errors.append("schema-upgrade preflight must reject a recovery proof older than its backup")
    if "ConvertFrom-Json materializes an ISO-8601 Z value as DateTime" not in text:
        errors.append("schema-upgrade preflight must preserve UTC JSON timestamp provenance")
    if "must be an explicit UTC timestamp" not in text:
        errors.append("schema-upgrade preflight must require explicit UTC timestamp provenance")
    if "Raw Git-blob bytes" not in text:
        errors.append("schema-upgrade preflight must pin migration hashes to Git blobs, not Windows working-tree bytes")
    if "Clone legacy 001--012 schema fingerprint differs from the pinned profile" not in text:
        errors.append("schema-upgrade preflight must verify the canonical legacy schema before migration")
    if "[System.IO.File]::WriteAllText" not in text or "Set-Content -LiteralPath $localRunnerFile -Encoding utf8NoBOM" in text:
        errors.append("schema-upgrade preflight must write UTF-8 runner/receipts on both Windows PowerShell and pwsh")
    if "clone DDL capability does not prove original target-role permission" not in text:
        errors.append("schema-upgrade preflight must not authorize original migration from clone DDL")
    if "Assert-CloneVolumeIdentity -Volume $volume -Suffix $Suffix" not in text:
        errors.append("schema-upgrade preflight must verify every disposable clone volume before deletion")
    if '$cloneStageVolume = "kairos-schema-upgrade-preflight-stage-$suffix"' not in text:
        errors.append("schema-upgrade preflight must use a generated staging volume rather than tmpfs Docker copies")
    if "Verified source backup is missing from the clone staging volume" not in text:
        errors.append("schema-upgrade preflight must verify the staged source backup before restore")
    if "Docker Desktop does not support container-to-container docker cp" not in text:
        errors.append("schema-upgrade preflight must export runner migrations through a verified host transfer")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--script",
        type=Path,
        default=Path("scripts/Invoke-SchemaUpgradePreflight.ps1"),
    )
    args = parser.parse_args(argv)
    try:
        errors = validate_script(args.script.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        print(f"schema-upgrade preflight validation could not start: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Kairos clone-only schema-upgrade preflight validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
