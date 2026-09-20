"""Run one no-network quarantine rehearsal against a disposable legacy clone.

This operator command is intentionally narrower than the generic runtime
schema preflight.  The historical PAPER database is a verified
``LEGACY_BOOTSTRAPPED_RUNTIME_001_012`` topology rather than the clean
migration-only topology used by the generic tool.  It therefore has its own
identity gates and never treats clone success as source mutation authority.

The command reads a source *backup file* and signed, redacted evidence only.
It does not open the original database, attach to a Compose network, load a
secret, contact Redis, call a publisher, or start an application service.
Every Docker object is newly generated, labelled, checked before deletion,
and created with a network-none database namespace.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
BACKUP_ROOT = ROOT / "backups"
LEGACY_RECEIPT_VERIFIER = ROOT / "scripts" / "verify_legacy_outbox_receipt.py"
RUNNER_PATH = ROOT / "scripts" / "legacy_outbox_clone_runner.py"
SOURCE_LOCK = ROOT / "legacy-outbox-inspection.sources.lock.json"

EXPECTED_PROJECT = "kairos-paper-gate"
EXPECTED_DATABASE = "kairos"
EXPECTED_PERSISTENCE_REPOSITORY = "https://github.com/Kairos-cryptoAI/kairos-persistence"
EXPECTED_PERSISTENCE_REVISION = "1ca8bf38d265ece7a95f749a268075549f80c043"
EXPECTED_TIMESCALE_IMAGE = (
    "timescale/timescaledb:2.29.1-pg16@sha256:"
    "252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
)
EXPECTED_SIGNER = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
EXPECTED_LEGACY_FINGERPRINT = "a2fec9fe81d6af73a1e44038a0e71c21d9aaf2e3933ea8c76793d9e6f25b9adf"
EXPECTED_RUNNER_USER = "10001:10001"
EXPECTED_RUNNER_SHA256 = "1412b5952690925c17cac12036f8c863fa5e5d1acb952d30ad9aca77bc3803ba"
MAXIMUM_EVIDENCE_AGE = timedelta(hours=2)
CLONE_SCOPE = "legacy-outbox-quarantine-clone-rehearsal"
SCHEMA_ADVISORY_LOCK = "4907627681104115019"

LEGACY_MIGRATIONS = (
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
ALL_PACKAGE_MIGRATIONS = LEGACY_MIGRATIONS + (
    "013_campaign_source_budgets.sql",
    "014_bounded_canary_sessions.sql",
    "015_canary_dispatch_claims.sql",
    "016_global_canary_session_guard.sql",
    "017_simulator_journal.sql",
    "018_offline_outbox_reconciliation.sql",
)
TARGET_MIGRATIONS = LEGACY_MIGRATIONS + RUNTIME_SUFFIX
MIGRATION_SHA256 = {
    "001_audit_and_idempotency.sql": "e1bd549846225dbbf627b5204edb8298d39f10c856aa22ba570ee1b14d68bccb",
    "002_durable_runtime.sql": "19f65eb325579fb0b5820c1ac3e4869e776af7b63248681b9803ca6d5a9d9739",
    "003_execution_effect_journal.sql": "dd1fb9ef84375890d675bfdda3bf87ff0715e4c7f08bb0ac89e9967668d249df",
    "004_execution_recovery_delay.sql": "5a68a639316d3fdd530e86e6c1747e1924d618d427097bc2d481760a811744fa",
    "005_source_state_and_usage.sql": "f9d2cdb7bde828591c796158791eb8670e3b868aa40fc618cbbc06fa98b3e83c",
    "006_paper_trade_lifecycle.sql": "57d32944c98d84d9870dc7cd11630e542ae7038f45721f515d98f31291309393",
    "007_execution_runtime_health.sql": "24bf34bc82fe6e9f7a7217795600ac414df24f6b7c6da756243a697bf9defc57",
    "008_public_execution_events.sql": "0adc1093b350ccb55049c5f8065e8a315cff1bac36f309e09984122608b3ea40",
    "009_paper_canary_arms.sql": "c457ba2e1aacfec2b7810abd0cfbe4ef82cb5b132513ac3a9b6f759df7a2969a",
    "010_runtime_compensation_reserve.sql": "8f960c0a34cc855549b45c89d81c8e46760de90e3acfeb3216fc5444aaef4190",
    "011_execution_mutation_budget.sql": "b407a8089132b4f12cf692d5c04b0bcda0cc3022d0e1afb36dc7da27260a312f",
    "012_outbox_producer_order.sql": "53abce1864959c0dade0afea57daf2486a58c0d94ceebf6c0fee0797019328e8",
    "013_campaign_source_budgets.sql": "9fbf3aa02ebdc77174061b9f7969e1d2a0114bdf3881b0e6fc646b38857f4c77",
    "014_bounded_canary_sessions.sql": "0809635fe32c1ee9b7dbe977e8b52b0291e34fe8a9b5faa32c866c021f000af4",
    "015_canary_dispatch_claims.sql": "e78204aa7164194d68052a93e83d608dcac3da8b18fdd3a8b00288b58d78ac4c",
    "016_global_canary_session_guard.sql": "c3a36bf1ecda579a4281e7c09b5cfcb809874ed30691a079c40737a86711cc73",
    "017_simulator_journal.sql": "d7d1fe54e6993cd24d79626d3a15546c55f3909a8cba43b1891392a27f6d027e",
    "018_offline_outbox_reconciliation.sql": "f2d5db9e6810c2715acb8c804b97f4c4779d44ef2ff7851956c5bb482a8f9347",
}
CHECKPOINT_TABLES = {
    "event_audit",
    "message_inbox",
    "message_outbox",
    "execution_orders",
    "account_snapshots",
    "position_snapshots",
    "source_cursors",
    "source_usage_reservations",
    "execution_effects",
    "execution_effect_events",
    "execution_trades",
    "execution_trade_events",
    "execution_recovery_state",
    "public_execution_events",
    "account_equity_state",
    "paper_canary_arms",
    "execution_runtime_health",
    "execution_mutation_budget_scopes",
    "execution_mutation_reservations",
}

LEGACY_INVENTORY_QUERY = r"""
WITH inventory AS (
    SELECT 'extension|' || e.extname || '|' || e.extversion AS item FROM pg_extension e WHERE e.extname='timescaledb'
    UNION ALL
    SELECT 'relation|' || c.relkind::text || '|' || c.relname || '|' || CASE WHEN c.relkind IN ('v','m') THEN md5(pg_get_viewdef(c.oid, true)) ELSE '' END
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
    UNION ALL
    SELECT 'column|' || c.relname || '|' || a.attnum::text || '|' || a.attname || '|' || format_type(a.atttypid, a.atttypmod) || '|' || a.attnotnull::text || '|' || a.attidentity::text || '|' || a.attgenerated::text || '|' || COALESCE(md5(pg_get_expr(ad.adbin, ad.adrelid, true)), '') || '|' || COALESCE(coll.collname, '')
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum LEFT JOIN pg_collation coll ON coll.oid=a.attcollation
    WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f') AND a.attnum > 0 AND NOT a.attisdropped
    UNION ALL
    SELECT 'constraint|' || c.relname || '|' || con.conname || '|' || con.contype::text || '|' || md5(pg_get_constraintdef(con.oid, true))
    FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
    UNION ALL
    SELECT 'index|' || t.relname || '|' || i.relname || '|' || x.indisunique::text || '|' || x.indisprimary::text || '|' || x.indisvalid::text || '|' || md5(pg_get_indexdef(i.oid))
    FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='public'
    UNION ALL
    SELECT 'trigger|' || c.relname || '|' || tg.tgname || '|' || md5(pg_get_triggerdef(tg.oid, true))
    FROM pg_trigger tg JOIN pg_class c ON c.oid=tg.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT tg.tgisinternal
    UNION ALL
    SELECT 'sequence|' || c.relname || '|' || s.seqstart::text || '|' || s.seqincrement::text || '|' || s.seqmin::text || '|' || s.seqmax::text || '|' || s.seqcache::text || '|' || s.seqcycle::text
    FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
    UNION ALL
    SELECT 'type|' || t.typtype::text || '|' || t.typname || '|' || COALESCE(format_type(t.typbasetype, t.typtypmod), '')
    FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype IN ('b','c','d','e','r')
)
SELECT COALESCE(string_agg(item, E'\\n' ORDER BY item), '') FROM inventory;
"""


class RehearsalError(RuntimeError):
    """Fail closed without reflecting sensitive process output."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for part in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RehearsalError(f"{label} is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise RehearsalError(f"{label} must be a JSON object")
    return value


def _utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RehearsalError(f"{label} must be an explicit UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RehearsalError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RehearsalError(f"{label} is not timezone-aware")
    return parsed.astimezone(UTC)


def _ensure_below(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise RehearsalError(f"{label} must remain below the approved backup root") from exc
    return resolved


def _safe_name(value: str, label: str) -> str:
    if not re.fullmatch(r"[a-z0-9_]+", value):
        raise RehearsalError(f"{label} is outside the generated clone namespace")
    return value


def _docker(arguments: Iterable[str], label: str, *, allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode and not allow_failure:
        raise RehearsalError(f"{label} failed")
    return result


def _docker_text(arguments: Iterable[str], label: str) -> str:
    return _docker(arguments, label).stdout.strip()


def _docker_json(arguments: Iterable[str], label: str) -> Mapping[str, Any]:
    raw = _docker_text(arguments, label)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RehearsalError(f"{label} returned malformed JSON") from exc
    if not isinstance(value, Mapping):
        raise RehearsalError(f"{label} returned an unexpected JSON value")
    return value


def _container_labels(name: str) -> Mapping[str, Any]:
    return _docker_json(["inspect", "--format", "{{json .Config.Labels}}", name], "clone object label inspection")


def _volume_labels(name: str) -> Mapping[str, Any]:
    return _docker_json(["volume", "inspect", "--format", "{{json .Labels}}", name], "clone volume label inspection")


def _assert_labels(labels: Mapping[str, Any], suffix: str) -> None:
    if labels.get("com.kairos.scope") != CLONE_SCOPE or labels.get("com.kairos.drill") != suffix:
        raise RehearsalError("refusing an object with mismatched clone rehearsal labels")


def _gpg_command() -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "config", "--get", "gpg.program"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    command = result.stdout.strip() if result.returncode == 0 else ""
    if not command:
        raise RehearsalError("configured GPG program is unavailable")
    return command


def _gpg(arguments: list[str], label: str) -> subprocess.CompletedProcess[str]:
    program = _gpg_command()
    # The configured loopback wrapper accepts the standard GnuPG argument
    # contract.  Paths below are resolved local files and never include shell
    # metacharacters supplied by an untrusted source.
    command = subprocess.list2cmdline([program, *arguments])
    result = subprocess.run(
        command,
        shell=True,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode:
        raise RehearsalError(f"{label} failed")
    return result


def _verify_signature(receipt: Path, signature: Path) -> None:
    status = _gpg(["--batch", "--status-fd", "1", "--verify", str(signature), str(receipt)], "receipt signature verification").stdout
    valid = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if len(valid) != 1 or len(valid[0]) < 12 or valid[0][11] != EXPECTED_SIGNER:
        raise RehearsalError("receipt signature does not bind the reviewed signer")


@dataclass(frozen=True)
class Inputs:
    manifest_path: Path
    dump_path: Path
    manifest: Mapping[str, Any]
    manifest_sha256: str
    recovery_path: Path
    recovery_sha256: str
    inspection_path: Path
    inspection_sha256: str
    inspection_signature_path: Path
    expectation_path: Path
    expectation_sha256: str
    inspection: Mapping[str, Any]
    lease_owner_sha256: str
    lease_until_utc: str


def _verify_manifest(manifest_path: Path) -> tuple[Mapping[str, Any], Path, str]:
    manifest_path = _ensure_below(manifest_path, BACKUP_ROOT, "backup manifest")
    manifest = _read_json(manifest_path, "backup manifest")
    required = {
        "schema_version",
        "compose_project",
        "database",
        "created_at_utc",
        "file",
        "bytes",
        "sha256",
        "checkpoints",
    }
    if set(manifest) != required or manifest.get("schema_version") != 1:
        raise RehearsalError("backup manifest has an unexpected schema")
    if manifest.get("compose_project") != EXPECTED_PROJECT or manifest.get("database") != EXPECTED_DATABASE:
        raise RehearsalError("backup manifest does not identify the isolated PAPER runtime")
    created = _utc(manifest.get("created_at_utc"), "backup manifest timestamp")
    if datetime.now(UTC) - created > MAXIMUM_EVIDENCE_AGE or created > datetime.now(UTC):
        raise RehearsalError("backup manifest is not a fresh two-hour runtime snapshot")
    filename = manifest.get("file")
    if not isinstance(filename, str) or not re.fullmatch(r"kairos-paper-gate-[0-9]{8}T[0-9]{6}Z\.dump", filename):
        raise RehearsalError("backup manifest dump name is invalid")
    if not isinstance(manifest.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"]):
        raise RehearsalError("backup manifest SHA-256 is invalid")
    if not isinstance(manifest.get("bytes"), int) or isinstance(manifest["bytes"], bool) or manifest["bytes"] <= 0:
        raise RehearsalError("backup manifest byte count is invalid")
    if not isinstance(manifest.get("checkpoints"), Mapping) or set(manifest["checkpoints"]) != CHECKPOINT_TABLES | {"public_execution_events_max_sequence"}:
        raise RehearsalError("backup manifest checkpoint profile is not exact")
    if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in manifest["checkpoints"].values()):
        raise RehearsalError("backup manifest checkpoint values are invalid")
    dump_path = (manifest_path.parent / filename).resolve(strict=True)
    if dump_path.parent != manifest_path.parent or _file_sha256(dump_path) != manifest["sha256"] or dump_path.stat().st_size != manifest["bytes"]:
        raise RehearsalError("backup dump does not match its manifest")
    return manifest, dump_path, _file_sha256(manifest_path)


def _verify_recovery(receipt_path: Path, manifest: Mapping[str, Any], manifest_sha256: str) -> str:
    receipt_path = _ensure_below(receipt_path, BACKUP_ROOT, "recovery receipt")
    receipt = _read_json(receipt_path, "recovery receipt")
    required = {
        "schema_version", "result", "created_at_utc", "compose_project", "database", "backup_sha256",
        "backup_manifest_sha256", "migrations", "outbox", "inbox", "bars", "execution_journal",
        "running_services", "offline_bar_recovery_permitted", "recovery_profile",
    }
    if set(receipt) != required or receipt.get("schema_version") != 1 or receipt.get("result") != "PASS":
        raise RehearsalError("recovery receipt is not a passing exact profile")
    if receipt.get("compose_project") != EXPECTED_PROJECT or receipt.get("database") != EXPECTED_DATABASE:
        raise RehearsalError("recovery receipt identifies the wrong runtime")
    if receipt.get("backup_sha256") != manifest["sha256"] or receipt.get("backup_manifest_sha256") != manifest_sha256:
        raise RehearsalError("recovery receipt does not bind the exact source backup")
    created = _utc(receipt.get("created_at_utc"), "recovery receipt timestamp")
    backup_created = _utc(manifest.get("created_at_utc"), "backup manifest timestamp")
    if created < backup_created - timedelta(minutes=5) or datetime.now(UTC) - created > MAXIMUM_EVIDENCE_AGE:
        raise RehearsalError("recovery receipt is not a fresh matching runtime verification")
    if tuple(receipt.get("migrations", ())) != LEGACY_MIGRATIONS:
        raise RehearsalError("recovery receipt migration profile is not legacy 001--012")
    outbox = receipt.get("outbox")
    inbox = receipt.get("inbox")
    if not isinstance(outbox, Mapping) or not isinstance(inbox, Mapping):
        raise RehearsalError("recovery receipt outbox/inbox facts are invalid")
    expected_outbox = {
        "pending", "expired_leases", "active_leases", "dead_lettered", "duplicate_audit_ids",
        "duplicate_outbox_ids", "outbox_without_audit", "read_only_consumer_restart_permitted",
    }
    if set(outbox) != expected_outbox or set(inbox) != {"processing", "failed", "expired_processing"}:
        raise RehearsalError("recovery receipt outbox/inbox profile is invalid")
    if (
        outbox.get("expired_leases") != 1
        or outbox.get("active_leases") != 0
        or outbox.get("dead_lettered") != 0
        or outbox.get("duplicate_audit_ids") != 0
        or outbox.get("duplicate_outbox_ids") != 0
        or outbox.get("outbox_without_audit") != 0
        or outbox.get("read_only_consumer_restart_permitted") is not False
        or any(inbox.get(name) != 0 for name in inbox)
    ):
        raise RehearsalError("recovery receipt does not prove one bounded expired-lease case")
    return _file_sha256(receipt_path)


def _verify_inspection(
    receipt_path: Path,
    signature_path: Path,
    expectation_path: Path,
    manifest: Mapping[str, Any],
    manifest_sha256: str,
) -> tuple[Mapping[str, Any], str, str, str, str]:
    for path, label in ((receipt_path, "legacy inspection receipt"), (signature_path, "legacy inspection signature"), (expectation_path, "legacy expectation")):
        if not path.resolve(strict=True).is_file():
            raise RehearsalError(f"{label} is unavailable")
    _verify_signature(receipt_path, signature_path)
    verifier = subprocess.run(
        [
            sys.executable,
            str(LEGACY_RECEIPT_VERIFIER),
            "--receipt", str(receipt_path),
            "--expectation", str(expectation_path),
            "--backup-manifest-sha256", manifest_sha256,
            "--backup-sha256", str(manifest["sha256"]),
            "--backup-created-at-utc", str(manifest["created_at_utc"]),
            "--require-eligible",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if verifier.returncode:
        raise RehearsalError("signed legacy inspection receipt is not eligible for this exact backup")
    inspection = _read_json(receipt_path, "legacy inspection receipt")
    inspected = _utc(inspection.get("inspected_at_utc"), "legacy inspection timestamp")
    if datetime.now(UTC) - inspected > MAXIMUM_EVIDENCE_AGE:
        raise RehearsalError("legacy inspection receipt is not a fresh two-hour verification")
    if inspection.get("classification") != "LEGACY_BOOTSTRAPPED_RUNTIME_001_012_READ_ONLY":
        raise RehearsalError("legacy inspection receipt has the wrong classification")
    result = inspection.get("inspection")
    if not isinstance(result, Mapping) or result.get("result") != "ELIGIBLE_FOR_CLONE_REHEARSAL":
        raise RehearsalError("legacy inspection receipt is not eligible for clone rehearsal")
    observations = result.get("observations")
    if not isinstance(observations, Mapping) or not isinstance(observations.get("lease"), Mapping):
        raise RehearsalError("legacy inspection receipt lacks redacted lease evidence")
    lease = observations["lease"]
    owner_sha = lease.get("lease_owner_sha256")
    until = lease.get("lease_until_utc")
    if not isinstance(owner_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", owner_sha):
        raise RehearsalError("legacy inspection lease hash is invalid")
    _utc(until, "legacy inspection lease timestamp")
    return inspection, _file_sha256(receipt_path), _file_sha256(expectation_path), owner_sha, str(until)


def _verify_inputs(args: argparse.Namespace) -> Inputs:
    if args.confirmation != "CLONE_ONLY_LEGACY_OUTBOX_QUARANTINE_REHEARSAL":
        raise RehearsalError("literal clone-only confirmation is required")
    if _file_sha256(RUNNER_PATH) != EXPECTED_RUNNER_SHA256:
        raise RehearsalError("clone quarantine runner bytes differ from the reviewed artifact")
    lock = _read_json(SOURCE_LOCK, "legacy source lock")
    profile = lock.get("profile")
    if not isinstance(profile, Mapping) or profile.get("schema_profile") != "LEGACY_BOOTSTRAPPED_RUNTIME_001_012" or profile.get("expected_schema_fingerprint_sha256") != EXPECTED_LEGACY_FINGERPRINT:
        raise RehearsalError("legacy source lock topology is not the reviewed bootstrap profile")
    manifest, dump, manifest_hash = _verify_manifest(Path(args.manifest_path))
    recovery_hash = _verify_recovery(Path(args.recovery_receipt_path), manifest, manifest_hash)
    inspection, inspection_hash, expectation_hash, owner_sha, until = _verify_inspection(
        Path(args.legacy_inspection_receipt_path),
        Path(args.legacy_inspection_signature_path),
        Path(args.expectation_path),
        manifest,
        manifest_hash,
    )
    return Inputs(
        manifest_path=Path(args.manifest_path).resolve(strict=True),
        dump_path=dump,
        manifest=manifest,
        manifest_sha256=manifest_hash,
        recovery_path=Path(args.recovery_receipt_path).resolve(strict=True),
        recovery_sha256=recovery_hash,
        inspection_path=Path(args.legacy_inspection_receipt_path).resolve(strict=True),
        inspection_sha256=inspection_hash,
        inspection_signature_path=Path(args.legacy_inspection_signature_path).resolve(strict=True),
        expectation_path=Path(args.expectation_path).resolve(strict=True),
        expectation_sha256=expectation_hash,
        inspection=inspection,
        lease_owner_sha256=owner_sha,
        lease_until_utc=until,
    )


def _wait_postgres(container: str, user: str) -> None:
    for _ in range(60):
        probe = _docker(["exec", container, "psql", f"--username={user}", "--dbname=postgres", "--tuples-only", "--no-align", "--command=SELECT 1;"], "clone database readiness", allow_failure=True)
        if probe.returncode == 0 and probe.stdout.strip() == "1":
            return
        time.sleep(2)
    raise RehearsalError("isolated clone database did not become ready")


def _psql(container: str, user: str, database: str, query: str, label: str) -> list[str]:
    _safe_name(database, "clone database name")
    result = _docker(
        ["exec", container, "psql", f"--username={user}", f"--dbname={database}", "--tuples-only", "--no-align", "--quiet", "--set=ON_ERROR_STOP=1", "--command", query],
        label,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _migrations(container: str, user: str, database: str) -> tuple[str, ...]:
    return tuple(_psql(container, user, database, "SELECT version FROM schema_migrations ORDER BY version;", "clone migration profile"))


def _fingerprint(container: str, user: str, database: str) -> str:
    lines = _psql(container, user, database, LEGACY_INVENTORY_QUERY, "clone schema fingerprint")
    if len(lines) != 1:
        raise RehearsalError("clone schema fingerprint inventory is malformed")
    return hashlib.sha256(lines[0].encode("utf-8")).hexdigest()


def _assert_checkpoints(container: str, user: str, database: str, checkpoints: Mapping[str, Any]) -> None:
    for table in sorted(CHECKPOINT_TABLES):
        value = _psql(container, user, database, f"SELECT COUNT(*) FROM public.{table};", "clone checkpoint validation")
        if len(value) != 1 or int(value[0]) != checkpoints[table]:
            raise RehearsalError("clone table checkpoint differs from the verified backup")
    maximum = _psql(container, user, database, "SELECT COALESCE(MAX(sequence), 0) FROM public.public_execution_events;", "clone sequence checkpoint validation")
    if len(maximum) != 1 or int(maximum[0]) != checkpoints["public_execution_events_max_sequence"]:
        raise RehearsalError("clone execution-event sequence differs from the verified backup")


def _assert_runtime_shape(container: str, user: str, database: str) -> None:
    if _migrations(container, user, database) != TARGET_MIGRATIONS:
        raise RehearsalError("clone migration profile is not exact 001--016,018")
    facts = _psql(
        container,
        user,
        database,
        """SELECT
              (SELECT COUNT(*) FROM schema_migrations WHERE version='017_simulator_journal.sql'),
              (SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname LIKE 'sim\\_%' ESCAPE '\\'),
              (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='message_outbox' AND column_name IN ('reconciliation_state','reconciliation_id','reconciliation_started_at','reconciliation_outcome_at')),
              (SELECT COUNT(*) FROM pg_constraint WHERE conrelid='public.message_outbox'::regclass AND conname IN ('message_outbox_reconciliation_state','message_outbox_reconciliation_identity'));""",
        "clone runtime schema shape validation",
    )
    if facts != ["0|0|4|2"]:
        raise RehearsalError("clone runtime schema has simulator residue or lacks reconciliation constraints")


def _restore_dump(container: str, user: str, database: str, dump_path: str, label: str) -> None:
    _safe_name(database, "clone database name")
    if not re.fullmatch(r"/kairos-stage/[A-Za-z0-9_.-]+\.dump", dump_path):
        raise RehearsalError("clone dump path is outside the generated staging volume")
    for arguments, step in (
        (["exec", container, "createdb", f"--username={user}", database], "create generated clone database"),
        (["exec", container, "psql", f"--username={user}", f"--dbname={database}", "--set=ON_ERROR_STOP=1", "--command=CREATE EXTENSION IF NOT EXISTS timescaledb;"], "initialize TimescaleDB in clone"),
        (["exec", container, "psql", f"--username={user}", f"--dbname={database}", "--set=ON_ERROR_STOP=1", "--command=SELECT timescaledb_pre_restore();"], "enter TimescaleDB restore mode"),
        (["exec", container, "pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", f"--username={user}", f"--dbname={database}", dump_path], label),
        (["exec", container, "psql", f"--username={user}", f"--dbname={database}", "--set=ON_ERROR_STOP=1", "--command=SELECT timescaledb_post_restore();"], "leave TimescaleDB restore mode"),
    ):
        _docker(arguments, step)


def _inspect_migration_runner(image: str, probe_name: str, suffix: str) -> str:
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image):
        raise RehearsalError("migration runner must use an immutable repository@sha256 digest")
    digests = _docker_text(["image", "inspect", "--format", "{{json .RepoDigests}}", image], "migration runner digest inspection")
    try:
        digest_values = json.loads(digests)
    except json.JSONDecodeError as exc:
        raise RehearsalError("migration runner digest inventory is malformed") from exc
    if not isinstance(digest_values, list) or not any(isinstance(item, str) and re.fullmatch(r".+@sha256:[0-9a-f]{64}", item) for item in digest_values):
        raise RehearsalError("migration runner has no resolved repository digest")
    labels = _docker_json(["image", "inspect", "--format", "{{json .Config.Labels}}", image], "migration runner label inspection")
    if labels.get("org.opencontainers.image.source") != EXPECTED_PERSISTENCE_REPOSITORY or labels.get("org.opencontainers.image.revision") != EXPECTED_PERSISTENCE_REVISION:
        raise RehearsalError("migration runner does not identify the reviewed persistence source")
    user = _docker_text(["image", "inspect", "--format", "{{.Config.User}}", image], "migration runner user inspection")
    if user != EXPECTED_RUNNER_USER:
        raise RehearsalError("migration runner must execute as the reviewed unprivileged user")
    probe = """
import hashlib,json
from importlib.resources import files
root=files('kairos_persistence').joinpath('migrations')
items=[{'name':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(root.iterdir(),key=lambda p:p.name) if p.name.endswith('.sql')]
print(json.dumps({'directory':str(root),'migrations':items},sort_keys=True,separators=(',',':')))
"""
    _docker([
        "create", "--name", probe_name, "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "32", "--memory", "128m", "--cpus", "0.25",
        "--user", EXPECTED_RUNNER_USER, "--label", f"com.kairos.scope={CLONE_SCOPE}", "--label", f"com.kairos.drill={suffix}",
        "--entrypoint", "python", image, "-c", probe,
    ], "create immutable migration runner probe")
    output = _docker_text(["start", "-a", probe_name], "run immutable migration runner probe")
    try:
        observation = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RehearsalError("migration runner probe returned malformed JSON") from exc
    if not isinstance(observation, Mapping) or not isinstance(observation.get("directory"), str) or not isinstance(observation.get("migrations"), list):
        raise RehearsalError("migration runner probe returned an invalid migration inventory")
    entries = observation["migrations"]
    names = tuple(item.get("name") for item in entries if isinstance(item, Mapping))
    if names != ALL_PACKAGE_MIGRATIONS:
        raise RehearsalError("migration runner package inventory is not the exact reviewed set")
    for item in entries:
        if not isinstance(item, Mapping) or item.get("sha256") != MIGRATION_SHA256[item["name"]]:
            raise RehearsalError("migration runner byte hash differs from the reviewed source")
    directory = observation["directory"]
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", directory) or ".." in directory:
        raise RehearsalError("migration runner reported an unsafe resource directory")
    return directory


def _copy_runtime_migrations(probe: str, source_directory: str, clone: str, stage_directory: str, temporary: Path) -> None:
    _docker(["exec", "--user=root", clone, "mkdir", "-p", f"{stage_directory}/runtime-migrations"], "create clone migration staging directory")
    for name in RUNTIME_SUFFIX:
        local = temporary / name
        _docker(["cp", f"{probe}:{source_directory}/{name}", str(local)], "export pinned runtime migration")
        if _file_sha256(local) != MIGRATION_SHA256[name]:
            raise RehearsalError("exported migration bytes differ from the reviewed source")
        target = f"{stage_directory}/runtime-migrations/{name}"
        _docker(["cp", str(local), f"{clone}:{target}"], "copy pinned runtime migration into clone")
        copied = _docker_text(["exec", "--user=root", clone, "sha256sum", "--", target], "verify copied runtime migration")
        if not copied.startswith(MIGRATION_SHA256[name] + " "):
            raise RehearsalError("copied migration bytes differ from the reviewed source")


def _apply_runtime_migrations(container: str, user: str, database: str, stage_directory: str, expected_before: tuple[str, ...], temporary: Path) -> None:
    before = ",".join("'" + item + "'" for item in expected_before)
    after = ",".join("'" + item + "'" for item in TARGET_MIGRATIONS)
    lines = [
        "SET LOCAL lock_timeout = '5s';",
        "SET LOCAL statement_timeout = '120s';",
        f"SELECT pg_advisory_xact_lock({SCHEMA_ADVISORY_LOCK});",
        "DO $guard$ DECLARE actual text[]; BEGIN SELECT COALESCE(array_agg(version ORDER BY version), ARRAY[]::text[]) INTO actual FROM schema_migrations; IF actual IS DISTINCT FROM ARRAY[" + before + "]::text[] THEN RAISE EXCEPTION 'clone baseline migration profile differs'; END IF; END $guard$;",
    ]
    for name in RUNTIME_SUFFIX:
        marker = name[:3]
        lines.extend((
            f"SELECT CASE WHEN EXISTS (SELECT 1 FROM schema_migrations WHERE version='{name}') THEN 'false' ELSE 'true' END AS apply_{marker} \\gset",
            f"\\if :apply_{marker}",
            f"\\i {stage_directory}/runtime-migrations/{name}",
            f"INSERT INTO schema_migrations(version) VALUES ('{name}');",
            "\\endif",
        ))
    lines.append("DO $guard$ DECLARE actual text[]; BEGIN SELECT COALESCE(array_agg(version ORDER BY version), ARRAY[]::text[]) INTO actual FROM schema_migrations; IF actual IS DISTINCT FROM ARRAY[" + after + "]::text[] THEN RAISE EXCEPTION 'clone target migration profile differs'; END IF; END $guard$;")
    local = temporary / "apply-runtime-profile.sql"
    local.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    target = f"{stage_directory}/apply-runtime-profile.sql"
    _docker(["cp", str(local), f"{container}:{target}"], "copy clone migration transaction")
    _docker(["exec", container, "psql", f"--username={user}", f"--dbname={database}", "--set=ON_ERROR_STOP=1", "--single-transaction", f"--file={target}"], "apply pinned runtime profile on clone")


def _run_quarantine_worker(
    image: str,
    clone: str,
    stage_volume: str,
    stage_directory: str,
    user: str,
    password: str,
    database: str,
    inputs: Inputs,
) -> Mapping[str, Any]:
    runner_target = f"{stage_directory}/legacy_outbox_clone_runner.py"
    expectation_target = f"{stage_directory}/expectation.json"
    _docker(["cp", str(RUNNER_PATH), f"{clone}:{runner_target}"], "stage clone quarantine worker")
    _docker(["cp", str(inputs.expectation_path), f"{clone}:{expectation_target}"], "stage clone exact expectation")
    worker_hash = _docker_text(["exec", "--user=root", clone, "sha256sum", "--", runner_target], "verify staged clone worker")
    if not worker_hash.startswith(EXPECTED_RUNNER_SHA256 + " "):
        raise RehearsalError("staged clone quarantine worker differs from the reviewed artifact")
    quoted_user = urllib.parse.quote(user, safe="")
    quoted_password = urllib.parse.quote(password, safe="")
    dsn = f"postgresql://{quoted_user}:{quoted_password}@127.0.0.1:5432/{database}"
    result = _docker(
        [
            "run", "--rm", "--network", f"container:{clone}", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--pids-limit", "64", "--memory", "256m", "--cpus", "0.5",
            "--user", EXPECTED_RUNNER_USER, "--mount", f"type=volume,src={stage_volume},dst={stage_directory},readonly",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=32m",
            "--env", f"KAIROS_CLONE_EXPECTATION_PATH={expectation_target}",
            "--env", f"KAIROS_CLONE_LEASE_OWNER_SHA256={inputs.lease_owner_sha256}",
            "--env", f"KAIROS_CLONE_LEASE_UNTIL_UTC={inputs.lease_until_utc}",
            "--env", f"KAIROS_CLONE_DATABASE_URL={dsn}",
            "--entrypoint", "python", image, runner_target,
        ],
        "run DB-only clone quarantine worker",
        allow_failure=True,
    )
    json_lines = [line for line in result.stdout.splitlines() if line.startswith("{") and line.endswith("}")]
    if len(json_lines) != 1:
        raise RehearsalError("clone quarantine worker did not return one redacted result")
    try:
        payload = json.loads(json_lines[0])
    except json.JSONDecodeError as exc:
        raise RehearsalError("clone quarantine worker result is malformed") from exc
    if result.returncode != 0:
        raise RehearsalError("clone quarantine worker rejected the exact lease")
    if not isinstance(payload, Mapping):
        raise RehearsalError("clone quarantine worker result is not an object")
    required = {"schema_version", "kind", "first_state", "repeat_state", "before_sha256", "after_sha256", "after", "runtime_profile", "simulator_relations", "publisher_calls"}
    if set(payload) != required or payload.get("schema_version") != 1 or payload.get("kind") != "kairos.legacy-outbox-clone-quarantine-result.v1":
        raise RehearsalError("clone quarantine worker result has an unexpected schema")
    after = payload.get("after")
    if (
        payload.get("first_state") != "QUARANTINED"
        or payload.get("repeat_state") != "ALREADY_QUARANTINED"
        or payload.get("runtime_profile") != list(TARGET_MIGRATIONS)
        or payload.get("simulator_relations") != 0
        or payload.get("publisher_calls") != 0
        or not isinstance(after, Mapping)
        or after.get("published") is not False
        or after.get("dead_lettered") is not False
        or after.get("lease_owner_sha256") is not None
        or after.get("lease_until_utc") is not None
        or after.get("reconciliation_state") != "PUBLISH_OUTCOME_UNKNOWN"
        or after.get("reconciliation_id") != inputs.inspection.get("reconciliation_id")
    ):
        raise RehearsalError("clone quarantine worker postconditions are not exact")
    return payload


def _verify_restore_state(container: str, user: str, database: str, inputs: Inputs) -> str:
    _assert_runtime_shape(container, user, database)
    # The exact identity stays in the expectation file; use a second bounded
    # query with only the known public ID substituted after strict JSON parsing.
    expectation = _read_json(inputs.expectation_path, "clone expectation")
    identity = expectation.get("identity")
    if not isinstance(identity, Mapping) or not isinstance(identity.get("id"), int) or identity["id"] <= 0:
        raise RehearsalError("clone expectation identity is invalid")
    values = _psql(
        container,
        user,
        database,
        "SELECT publish_attempts::text || '|' || (published_at IS NULL)::text || '|' || (dead_lettered_at IS NULL)::text || '|' || (lease_owner IS NULL)::text || '|' || (lease_until IS NULL)::text || '|' || reconciliation_state || '|' || reconciliation_id FROM message_outbox WHERE id=" + str(identity["id"]) + ";",
        "verify restored quarantine state",
    )
    expected = f"{identity['publish_attempts']}|t|t|t|t|PUBLISH_OUTCOME_UNKNOWN|{expectation['reconciliation_id']}"
    if values != [expected]:
        raise RehearsalError("restored clone does not preserve the exact quarantine state")
    return _fingerprint(container, user, database)


def _cleanup(container: str | None, data_volume: str | None, stage_volume: str | None, suffix: str) -> None:
    errors: list[str] = []
    if container:
        probe = _docker(["inspect", "--format", "{{.Id}}", container], "clone container existence", allow_failure=True)
        if probe.returncode == 0:
            try:
                _assert_labels(_container_labels(container), suffix)
                _docker(["rm", "-f", container], "remove generated clone container")
            except RehearsalError as exc:
                errors.append(str(exc))
    for volume in (stage_volume, data_volume):
        if not volume:
            continue
        probe = _docker(["volume", "inspect", "--format", "{{.Name}}", volume], "clone volume existence", allow_failure=True)
        if probe.returncode == 0:
            try:
                _assert_labels(_volume_labels(volume), suffix)
                _docker(["volume", "rm", volume], "remove generated clone volume")
            except RehearsalError as exc:
                errors.append(str(exc))
    if errors:
        raise RehearsalError("clone-only resource cleanup failed")


def _sign_receipt(path: Path, signature: Path) -> None:
    _gpg(["--batch", "--armor", "--local-user", EXPECTED_SIGNER, "--detach-sign", "--output", str(signature), str(path)], "clone rehearsal receipt signing")
    _verify_signature(path, signature)


def _run(inputs: Inputs, migration_runner_image: str) -> Mapping[str, Any]:
    suffix = secrets.token_hex(6)
    clone = f"kairos-legacy-outbox-clone-{suffix}"
    data_volume = f"kairos-legacy-outbox-clone-data-{suffix}"
    stage_volume = f"kairos-legacy-outbox-clone-stage-{suffix}"
    upgrade_database = _safe_name(f"kairos_legacy_outbox_clone_{suffix}", "upgrade clone database")
    restore_database = _safe_name(f"kairos_legacy_outbox_restore_{suffix}", "restore clone database")
    clone_user = "kairos_legacy_clone"
    clone_password = secrets.token_urlsafe(32)
    stage_directory = "/kairos-stage"
    source_dump = f"{stage_directory}/source.dump"
    upgraded_dump = f"{stage_directory}/upgraded.dump"
    runner_probe: str | None = f"kairos-legacy-outbox-runner-{suffix}"
    temporary = Path(tempfile.mkdtemp(prefix=f"kairos-legacy-outbox-clone-{suffix}-"))
    operation_error: BaseException | None = None
    receipt: Mapping[str, Any] | None = None
    try:
        for volume in (data_volume, stage_volume):
            _docker(["volume", "create", "--label", f"com.kairos.scope={CLONE_SCOPE}", "--label", f"com.kairos.drill={suffix}", volume], "create generated clone volume")
            _assert_labels(_volume_labels(volume), suffix)
        _docker(
            [
                "create", "--name", clone, "--network", "none", "--memory", "2g", "--cpus", "2", "--pids-limit", "256",
                "--label", f"com.kairos.scope={CLONE_SCOPE}", "--label", f"com.kairos.drill={suffix}",
                "--mount", f"type=volume,src={data_volume},dst=/var/lib/postgresql/data",
                "--mount", f"type=volume,src={stage_volume},dst={stage_directory}",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m",
                "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,noexec,mode=1777,size=16m",
                "--env", f"POSTGRES_USER={clone_user}", "--env", "POSTGRES_DB=postgres", "--env", f"POSTGRES_PASSWORD={clone_password}",
                EXPECTED_TIMESCALE_IMAGE,
            ],
            "create no-network legacy clone",
        )
        _assert_labels(_container_labels(clone), suffix)
        network = _docker_text(["inspect", "--format", "{{.HostConfig.NetworkMode}}", clone], "clone network verification")
        if network != "none":
            raise RehearsalError("clone container must have no network")
        _docker(["start", clone], "start no-network legacy clone")
        _wait_postgres(clone, clone_user)
        migration_directory = _inspect_migration_runner(migration_runner_image, runner_probe, suffix)
        _docker(["cp", str(inputs.dump_path), f"{clone}:{source_dump}"], "stage verified source dump into clone")
        staged_hash = _docker_text(["exec", "--user=root", clone, "sha256sum", "--", source_dump], "verify staged source dump")
        if not staged_hash.startswith(str(inputs.manifest["sha256"]) + " "):
            raise RehearsalError("staged source dump differs from its verified manifest")
        _restore_dump(clone, clone_user, upgrade_database, source_dump, "restore verified legacy source backup")
        if _migrations(clone, clone_user, upgrade_database) != LEGACY_MIGRATIONS:
            raise RehearsalError("restored clone migration profile is not exact legacy 001--012")
        legacy_fingerprint = _fingerprint(clone, clone_user, upgrade_database)
        if legacy_fingerprint != EXPECTED_LEGACY_FINGERPRINT:
            raise RehearsalError("restored clone legacy schema fingerprint differs from the reviewed bootstrap profile")
        _assert_checkpoints(clone, clone_user, upgrade_database, inputs.manifest["checkpoints"])
        _copy_runtime_migrations(runner_probe, migration_directory, clone, stage_directory, temporary)
        _apply_runtime_migrations(clone, clone_user, upgrade_database, stage_directory, LEGACY_MIGRATIONS, temporary)
        _assert_runtime_shape(clone, clone_user, upgrade_database)
        first_fingerprint = _fingerprint(clone, clone_user, upgrade_database)
        _apply_runtime_migrations(clone, clone_user, upgrade_database, stage_directory, TARGET_MIGRATIONS, temporary)
        second_fingerprint = _fingerprint(clone, clone_user, upgrade_database)
        if first_fingerprint != second_fingerprint:
            raise RehearsalError("repeat clone migration pass changed the schema fingerprint")
        result = _run_quarantine_worker(migration_runner_image, clone, stage_volume, stage_directory, clone_user, clone_password, upgrade_database, inputs)
        _assert_checkpoints(clone, clone_user, upgrade_database, inputs.manifest["checkpoints"])
        _docker(["exec", clone, "pg_dump", "--format=custom", "--no-owner", "--no-privileges", f"--username={clone_user}", f"--dbname={upgrade_database}", f"--file={upgraded_dump}"], "create post-quarantine clone restore dump")
        _restore_dump(clone, clone_user, restore_database, upgraded_dump, "restore post-quarantine clone dump")
        restore_fingerprint = _verify_restore_state(clone, clone_user, restore_database, inputs)
        _assert_checkpoints(clone, clone_user, restore_database, inputs.manifest["checkpoints"])
        if restore_fingerprint != second_fingerprint:
            raise RehearsalError("restored clone schema fingerprint differs from quarantined clone")
        if _file_sha256(inputs.dump_path) != inputs.manifest["sha256"] or inputs.dump_path.stat().st_size != inputs.manifest["bytes"]:
            raise RehearsalError("verified source dump changed during the clone-only rehearsal")
        receipt = {
            "schema_version": 1,
            "classification": "CLONE_ONLY_LEGACY_OUTBOX_QUARANTINE_REHEARSAL",
            "result": "PASS_CLONE_ONLY",
            "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "readiness": {"paper_qualified": False, "alpha_ready": False, "live_ready": False, "strategy_policy": "REJECT_ALL"},
            "source_backup": {
                "sha256": inputs.manifest["sha256"], "bytes": inputs.manifest["bytes"], "manifest_sha256": inputs.manifest_sha256,
                "recovery_receipt_sha256": inputs.recovery_sha256, "legacy_inspection_receipt_sha256": inputs.inspection_sha256,
                "legacy_inspection_signature_sha256": _file_sha256(inputs.inspection_signature_path), "expectation_sha256": inputs.expectation_sha256,
                "legacy_schema_fingerprint_sha256": legacy_fingerprint,
            },
            "migration_runner": {"persistence_repository": EXPECTED_PERSISTENCE_REPOSITORY, "persistence_revision": EXPECTED_PERSISTENCE_REVISION, "image_digest": migration_runner_image, "exact_runtime_profile": list(TARGET_MIGRATIONS), "excluded_simulator_migration": "017_simulator_journal.sql"},
            "clone": {"isolated": True, "original_runtime_contacted": False, "redis_contacted": False, "publisher_contacted": False, "network_mode": "none", "legacy_schema_fingerprint_sha256": legacy_fingerprint, "first_runtime_schema_fingerprint_sha256": first_fingerprint, "second_runtime_schema_fingerprint_sha256": second_fingerprint, "simulator_relations_present": False},
            "quarantine": result,
            "restore_drill": {"passed": True, "schema_fingerprint_sha256": restore_fingerprint},
            "original_migration": {"authorized": False, "original_quarantine_authorized": False, "required_next_gate": "SEPARATE_TARGET_ROLE_AND_PRIMARY_MIGRATION_REVIEW"},
            "assertions": ["clone-only no-network rehearsal", "no source database or runtime volume was contacted", "DB-only primitive made zero publisher calls", "success does not authorize PAPER, alpha, or LIVE"],
        }
    except BaseException as exc:  # ensure exact generated cleanup before surface failure
        operation_error = exc
    finally:
        try:
            if runner_probe:
                probe = _docker(["inspect", "--format", "{{.Id}}", runner_probe], "runner probe existence", allow_failure=True)
                if probe.returncode == 0:
                    _assert_labels(_container_labels(runner_probe), suffix)
                    _docker(["rm", "-f", runner_probe], "remove generated migration runner probe")
            _cleanup(clone, data_volume, stage_volume, suffix)
        except BaseException as cleanup_error:
            if operation_error is None:
                operation_error = cleanup_error
        shutil.rmtree(temporary, ignore_errors=True)
    if operation_error is not None:
        if isinstance(operation_error, RehearsalError):
            raise operation_error
        raise RehearsalError("clone-only rehearsal failed") from operation_error
    if receipt is None:
        raise RehearsalError("clone-only rehearsal did not produce a receipt")
    return receipt


def _write_signed_receipt(receipt: Mapping[str, Any], manifest_path: Path, requested: str | None) -> Path:
    directory = manifest_path.parent.resolve()
    if requested:
        output = Path(requested).resolve()
    else:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        output = directory / f"legacy-outbox-quarantine-clone-rehearsal-{stamp}.json"
    if output.parent != directory or output.exists() or output.with_suffix(output.suffix + ".asc").exists():
        raise RehearsalError("clone rehearsal receipt must be a new file beside the verified backup manifest")
    unsigned = dict(receipt)
    unsigned["receipt_sha256"] = _sha256_json(unsigned)
    staged = output.with_name("." + output.name + ".staged")
    signature = output.with_suffix(output.suffix + ".asc")
    staged_signature = staged.with_suffix(staged.suffix + ".asc")
    try:
        staged.write_text(_canonical_json(unsigned) + "\n", encoding="utf-8", newline="\n")
        _sign_receipt(staged, staged_signature)
        staged_signature.replace(signature)
        staged.replace(output)
    finally:
        staged.unlink(missing_ok=True)
        staged_signature.unlink(missing_ok=True)
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--recovery-receipt-path", required=True)
    parser.add_argument("--legacy-inspection-receipt-path", required=True)
    parser.add_argument("--legacy-inspection-signature-path", required=True)
    parser.add_argument("--expectation-path", required=True)
    parser.add_argument("--migration-runner-image", required=True)
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--receipt-path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        inputs = _verify_inputs(args)
        receipt = _run(inputs, args.migration_runner_image)
        output = _write_signed_receipt(receipt, inputs.manifest_path, args.receipt_path)
    except RehearsalError as exc:
        print(f"legacy clone quarantine rehearsal rejected: {exc}", file=sys.stderr)
        return 2
    print(f"Legacy clone-only quarantine rehearsal passed: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
