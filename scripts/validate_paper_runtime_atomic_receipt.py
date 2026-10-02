"""Offline verifier: model success is NOT an accepted physical clone/apply proof."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import paper_runtime_atomic_contract as contract
from paper_runtime_atomic_clone_rehearsal import FAULTS


def verify_receipt(receipt: dict[str, Any], plan: contract.AtomicPlan, *, now: datetime) -> dict[str, Any]:
    required = {"schema_version", "kind", "result", "created_at_utc", "evidence_mode", "plan_sha256", "runner", "profile", "source_before_sha256", "source_after_sha256", "rollback_snapshots", "worker", "backup_after_sha256", "restored_history_sha256", "unknown_outcomes", "actual_postgres_rollback_proven", "primary_apply_implemented", "primary_quarantine_authorized", "primary_mutations", "consumer_restart_permitted", "forbidden_network_calls", "publisher_calls", "redis_contacted", "consumers_started", "readiness", "required_next_gate", "receipt_sha256"}
    native = isinstance(receipt, dict) and receipt.get("evidence_mode") == "native-postgresql-clone"
    if native:
        required |= {"primary_history_observed_during_rehearsal", "stopped_primary_before", "stopped_primary_after", "code_sha256", "resource_bounds", "preflight_sha256", "unknown_outcome_proof", "retained_attempt_directory"}
    contract.AtomicPlan.from_document(plan.document, now=now)
    if not isinstance(receipt, dict) or set(receipt) != required or type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1 or receipt["kind"] != contract.RECEIPT_KIND or receipt["result"] != ("PASS_NATIVE_ATOMIC_CLONE_ONLY" if native else "PASS_OFFLINE_MODEL_ONLY") or receipt["evidence_mode"] != ("native-postgresql-clone" if native else "offline-model"):
        raise contract.AtomicError("atomic evidence mode/receipt shape differs")
    if receipt["receipt_sha256"] != contract.digest({name: value for name, value in receipt.items() if name != "receipt_sha256"}):
        raise contract.AtomicError("atomic receipt content hash differs")
    contract.fresh(receipt["created_at_utc"], now)
    if contract.utc(receipt["created_at_utc"]) < contract.utc(plan.document["created_at_utc"]):
        raise contract.AtomicError("atomic receipt predates plan")
    if receipt["plan_sha256"] != plan.sha256 or receipt["runner"] != contract.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE or tuple(receipt["profile"]) != contract.RUNTIME_PROFILE or receipt["required_next_gate"] != contract.NEXT_GATE or receipt["readiness"] != contract.READINESS:
        raise contract.AtomicError("atomic receipt scope/frozen source differs")
    baseline = contract.digest(plan.document["legacy_history"])
    if receipt["source_before_sha256"] != baseline or receipt["source_after_sha256"] != baseline or not isinstance(receipt["rollback_snapshots"], dict) or set(receipt["rollback_snapshots"]) != set(FAULTS) or any(value != baseline for value in receipt["rollback_snapshots"].values()):
        raise contract.AtomicError("all-history rollback/source proof differs")
    if receipt["actual_postgres_rollback_proven"] is not native:
        raise contract.AtomicError("native/model rollback proof distinction differs")
    for name in ("primary_apply_implemented", "primary_quarantine_authorized", "consumer_restart_permitted", "redis_contacted"):
        if receipt[name] is not False:
            raise contract.AtomicError("offline receipt broadens protected authority")
    for name in ("primary_mutations", "forbidden_network_calls", "publisher_calls", "consumers_started"):
        if type(receipt[name]) is not int or receipt[name] != 0:
            raise contract.AtomicError("forbidden operation count differs")
    worker = receipt["worker"]
    required_worker = {"state", "intent", "history", "quarantine_calls", "bound_acquisitions", "primary_mutations", "consumer_restart_permitted"}
    if not isinstance(worker, dict) or set(worker) != required_worker or worker["state"] != ("COMMITTED_EXACT_READONLY" if native else "COMMITTED_ACKNOWLEDGED") or type(worker["quarantine_calls"]) is not int or worker["quarantine_calls"] != 1 or type(worker["bound_acquisitions"]) is not int or worker["bound_acquisitions"] != 2 or type(worker["primary_mutations"]) is not int or worker["primary_mutations"] != 0 or worker["consumer_restart_permitted"] is not False:
        raise contract.AtomicError("worker atomic assertion differs")
    history = contract.validate_history(worker["history"], runtime=True)
    if history["schema_fingerprint_sha256"] != plan.document["runtime_schema_fingerprint_sha256"] or receipt["restored_history_sha256"] != contract.digest(history) or contract.classify_readonly_outcome(plan, worker["intent"], history) != "COMMITTED_EXACT":
        raise contract.AtomicError("committed/runtime restore binding differs")
    if receipt["unknown_outcomes"] != {"commit": "COMMITTED_EXACT", "rollback": "ROLLED_BACK", "mixed": "INDETERMINATE"}:
        raise contract.AtomicError("unknown response handling differs")
    contract.require_hash(receipt["backup_after_sha256"])
    if native:
        from paper_runtime_atomic_clone_rehearsal import CODE_FILES, SCRIPTS, MAX_SECONDS
        if receipt["primary_history_observed_during_rehearsal"] is not False or receipt["preflight_sha256"] != plan.document["preflight_sha256"] or receipt["stopped_primary_before"] != receipt["stopped_primary_after"]:
            raise contract.AtomicError("native stopped-source scope differs")
        stopped = receipt["stopped_primary_before"]
        if not isinstance(stopped, dict) or set(stopped) != {"identity", "state", "volume"} or stopped["identity"] != plan.document["source_identity"] or not isinstance(stopped["state"], dict) or set(stopped["state"]) != {"Status", "Running", "Paused", "Restarting", "Dead", "StartedAt", "FinishedAt", "ExitCode"} or any(stopped["state"][name] is not False for name in ("Running", "Paused", "Restarting", "Dead")) or stopped["state"]["Status"] != "exited" or type(stopped["state"]["ExitCode"]) is not int or not isinstance(stopped["volume"], dict) or set(stopped["volume"]) != {"Name", "Driver", "CreatedAt", "Labels", "Scope"} or stopped["volume"].get("Name") != contract.readonly.SOURCE_VOLUME:
            raise contract.AtomicError("native source was not exact stopped primary")
        if receipt["code_sha256"] != {name: contract.readonly._sha(SCRIPTS / name) for name in CODE_FILES} or not isinstance(receipt["resource_bounds"], dict) or any(type(value) is not int for value in receipt["resource_bounds"].values()) or receipt["resource_bounds"] != {"database_memory_bytes": 3 * 1024**3, "database_tmpfs_bytes": 2 * 1024**3, "database_cpus": 1, "worker_memory_bytes": 512 * 1024**2, "maximum_seconds": MAX_SECONDS, "maximum_parallel_databases": 1}:
            raise contract.AtomicError("native code/resource identity differs")
        if receipt["unknown_outcome_proof"] != {"commit": "native injected lost response after COMMIT; fresh read-only connection", "rollback": "native fault rollback full baseline; read-only classifier", "mixed": "offline metadata-only negative classifier; no mixed DB mutation"}:
            raise contract.AtomicError("native unknown-response proof scope differs")
        attempt = Path(receipt["retained_attempt_directory"])
        if attempt.parent.resolve(strict=True) != contract.CATALOG.BACKUP_ROOT.resolve(strict=True) or not re.fullmatch(r"paper-runtime-atomic-attempt-[0-9a-f]{12}", attempt.name) or attempt.is_symlink() or not attempt.is_dir():
            raise contract.AtomicError("native retained artifact directory differs")
        retained_plan = contract.AtomicPlan.from_document(contract.read_json(attempt / "atomic-plan.json"), now=now)
        if retained_plan != plan or contract.readonly._sha(attempt / "atomic-after.dump") != receipt["backup_after_sha256"]:
            raise contract.AtomicError("native retained plan/backup-after differs")
        matching_intent = attempt / "atomic-intents" / ("atomic-precommit-" + contract.digest(worker["intent"]) + ".json")
        if contract.read_json(matching_intent) != worker["intent"]:
            raise contract.AtomicError("native retained durable precommit intent differs")
    return {"result": "VERIFIED_UNSIGNED_NATIVE_CLONE_ONLY" if native else "VERIFIED_OFFLINE_MODEL_ONLY", "primary_quarantine_authorized": False, "actual_postgres_rollback_proven": native}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--signature", type=Path)
    args = parser.parse_args(argv)
    try:
        now = datetime.now(UTC)
        plan = contract.AtomicPlan.from_document(contract.read_json(args.plan), now=now)
        result = verify_receipt(contract.read_json(args.receipt), plan, now=now)
        if args.signature:
            contract.CATALOG._verify_signature(args.receipt, args.signature)
            if result["actual_postgres_rollback_proven"]:
                result["result"] = "VERIFIED_SIGNED_NATIVE_CLONE_ONLY"
    except Exception as error:
        print(json.dumps({"result": "REJECTED", "error_type": type(error).__name__}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
