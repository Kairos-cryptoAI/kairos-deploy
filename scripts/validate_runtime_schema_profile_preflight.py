"""Static fail-closed checks for the runtime-only clone schema preflight."""

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
RUNTIME_SUFFIX = (
    "013_campaign_source_budgets.sql",
    "014_bounded_canary_sessions.sql",
    "015_canary_dispatch_claims.sql",
    "016_global_canary_session_guard.sql",
    "018_offline_outbox_reconciliation.sql",
)
PERSISTENCE_REVISION = "1ca8bf38d265ece7a95f749a268075549f80c043"
TIMESCALE_IMAGE = (
    "timescale/timescaledb:2.29.1-pg16@sha256:"
    "252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
)
LEGACY_SCHEMA_FINGERPRINT = "7c4c103c09badbe1a60a4fcc8d11e2119a3ece0c52e1145d69a0fc2a11be59de"


def _array_values(text: str, name: str) -> tuple[str, ...] | None:
    match = re.search(rf"\${name}\s*=\s*@\((?P<body>.*?)\n\)", text, re.DOTALL)
    if match is None:
        return None
    return tuple(re.findall(r'"([0-9]{3}_[^"]+\.sql)"', match.group("body")))


def validate_script(text: str) -> list[str]:
    """Return violations without contacting Docker, a database, or a secret."""

    errors: list[str] = []
    required = (
        "CLONE_ONLY_RUNTIME_SCHEMA_PROFILE_PREFLIGHT",
        PERSISTENCE_REVISION,
        TIMESCALE_IMAGE,
        '$ExpectedSourceComposeProject = "kairos-paper-gate"',
        '$ExpectedSourceDatabase = "kairos"',
        "$MaximumBackupAge = [TimeSpan]::FromHours(2)",
        '$ExpectedMigrationRunnerUser = "10001:10001"',
        f'$ExpectedLegacySchemaFingerprint = "{LEGACY_SCHEMA_FINGERPRINT}"',
        "--network", "none",
        "timescaledb_pre_restore()",
        "timescaledb_post_restore()",
        "pg_restore", "--exit-on-error", "--single-transaction",
        '$SchemaAdvisoryLock = "4907627681104115019"',
        "Assert-VettedLegacySchemaShape",
        "Assert-RuntimeObjects",
        "Assert-VettedRuntimeSchemaShape",
        "Get-RuntimeSchemaFingerprint",
        "Assert-CloneDdlPreconditions",
        "Assert-ManifestCheckpoints",
        "Get-PinnedMigrationSource",
        "Copy-PinnedRuntimeMigrations",
        "Invoke-PinnedRuntimeMigrationRunner",
        "original_runtime_contacted = $false",
        "redis_contacted = $false",
        "publisher_contacted = $false",
        "authorized = $false",
        "target_ddl_permissions_verified = $false",
        'required_next_gate = "SEPARATE_LEGACY_OUTBOX_QUARANTINE_CLONE_REHEARSAL"',
        'simulator_journal_on_runtime_clone = "ABSENT_AND_FORBIDDEN"',
        "excluded_simulator_migration = \"017_simulator_journal.sql\"",
        "simulator_relations_present = $false",
        "result = \"PASS_CLONE_ONLY\"",
        "--read-only", "no-new-privileges:true",
        "org.opencontainers.image.revision",
        "Migration runner image lacks a resolved immutable repository digest",
        "Raw Git-blob bytes",
        "Recovery receipt is not a fresh two-hour runtime verification",
        "Recovery receipt predates the verified backup manifest",
        "Recovery receipt migration profile",
        "timescaledb_bgw_owners",
        "Ensure-TimescaleJobOwners",
        "[AllowEmptyCollection()][string[]]$Owners",
        "[AllowEmptyCollection()][string[]]$Values",
        "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
        "Verified source backup is missing from the clone staging volume",
        "Docker",
        "Assert-CloneVolumeIdentity -Volume $volume -Suffix $Suffix",
    )
    for value in required:
        if value not in text:
            errors.append(f"runtime schema preflight missing required invariant: {value}")

    legacy = _array_values(text, "LegacyMigrations")
    if legacy != LEGACY:
        errors.append("runtime schema preflight legacy migration profile changed")
    suffix = _array_values(text, "RuntimeMigrationSuffix")
    if suffix != RUNTIME_SUFFIX:
        errors.append("runtime schema preflight target migration profile changed")
    if "$TargetMigrations = @($LegacyMigrations + $RuntimeMigrationSuffix)" not in text:
        errors.append("runtime schema preflight must compose only the runtime target profile")
    target_slice = text.split("$TargetMigrations", 1)[1].split("$MigrationSha256", 1)[0]
    if "017_simulator_journal.sql" in target_slice:
        errors.append("runtime schema preflight target profile must exclude simulator migration 017")
    if "017_simulator_journal.sql" not in text:
        errors.append("runtime schema preflight must pin the complete package inventory including 017")
    if "foreach ($migration in $RuntimeMigrationSuffix)" not in text:
        errors.append("runtime schema preflight must copy only runtime suffix migrations")
    if "Pinned migration-runner package inventory" not in text:
        errors.append("runtime schema preflight must verify the full package inventory")
    if "Pinned migration-runner byte hash differs" not in text:
        errors.append("runtime schema preflight must verify raw migration bytes")
    if "Docker may unpack a platform-specific manifest" not in text:
        errors.append("runtime schema preflight must account for immutable multi-platform image resolution")
    if "LIKE 'sim\\_%' ESCAPE '\\'" not in text:
        errors.append("runtime schema preflight must query for simulator-table residue")
    if "Database.migrate(" in text or "kairos_persistence.Database" in text:
        errors.append("runtime schema preflight must not call a generic persistence migration route")
    if "docker compose" in text or "--env-file" in text or "KAIROS_SECRETS" in text:
        errors.append("runtime schema preflight must not attach to a runtime Compose project or secrets")
    if re.search(r"--dbname=\$manifest\.database", text):
        errors.append("runtime schema preflight must never target the manifest source database")
    parameter_block = text.split("param(", 1)[1].split(")", 1)[0]
    if "-Database" in parameter_block or "[string]$Database" in parameter_block:
        errors.append("runtime schema preflight must not accept an operator-selected database")
    if text.count("Assert-CloneDatabaseName -DatabaseName") < 6:
        errors.append("runtime schema preflight must repeatedly validate generated clone names")
    if "Assert-RuntimeObjects -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Present $false" not in text:
        errors.append("runtime schema preflight must reject pre-existing runtime or simulator residue")
    if "Assert-RuntimeObjects -Container $cloneContainer -DatabaseName $upgradeDrillDatabase -Present $true" not in text:
        errors.append("runtime schema preflight must prove runtime objects after migration")
    if "First pinned runtime clone migration pass" not in text or "Second pinned runtime clone migration pass" not in text:
        errors.append("runtime schema preflight must prove idempotency")
    if "Restored upgraded runtime clone drill" not in text:
        errors.append("runtime schema preflight must run an upgraded restore drill")
    if "clone DDL capability does not prove original target-role permission" not in text:
        errors.append("runtime schema preflight must not authorize source-side DDL")
    if "Backup manifest lacks TimescaleDB background-job owner provenance" not in text:
        errors.append("runtime schema preflight must require TimescaleDB owner provenance")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--script",
        type=Path,
        default=Path("scripts/Invoke-RuntimeSchemaProfilePreflight.ps1"),
    )
    args = parser.parse_args(argv)
    try:
        errors = validate_script(args.script.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        print(f"runtime schema preflight validation could not start: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Kairos runtime-only clone schema-profile preflight validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
