"""One create-only R2-to-R3 recovery after exact clean-queue admission.

This path never drains, republishes, acknowledges, or restarts the failed R2
serve. It proves the existing completed queue and Redis stream, makes two
independent disposable restore proofs, catches up audit history only, then
starts one new non-trading serve generation.
"""

from __future__ import annotations

import argparse
import json
import secrets
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_boot as boot
    from scripts import runtime_epoch_incident_recovery as incident
else:
    import runtime_epoch_boot as boot
    import runtime_epoch_incident_recovery as incident

epoch = boot.epoch
fresh = epoch.fresh
INCIDENT_ROOT = Path("D:/Kairos/runtime/runtime-incident-20261012")
ROOT = INCIDENT_ROOT
LEASE_DIR = ROOT / "clean-queue-r3-latch"
LEASE = LEASE_DIR / "latch.json"
FAILED_STATUS_SHA256 = (
    "2a09a36905b46e5e01052e17f2bca1a48187e637081c489a1fdbf76814f92a83"
)
ACCEPTED_RECEIPT_SHA256 = (
    "095d8965d561851c57aff4e412ee4082422c6026f2f612841c703e4689efc855"
)
R3_NAME = "kairos-epoch-69893dc7b7c6-serve-r3"
R1_NAME = "kairos-epoch-69893dc7b7c6-serve"
R1_ID = "f171285853b1ddae798dd11767c2292a133b874ab2928cce8bb8434fe5798981"
R3_RESTORE_SUFFIX = "-transport03"
BASE_AUDIT_ROWS = 335_379
BASE_QUEUE_ROWS = 4_626
MAX_SECONDS = 1800


def validate_clean_baseline(value: dict) -> None:
    """Pin the observed clean baseline and enforce the worker's full proof shape."""
    queue = value.get("queue", {})
    if (
        value.get("state") != "PASS_BOOT_STATE"
        or value.get("trading_started") is not False
        or value.get("tables", {}).get("event_audit", {}).get("count")
        != BASE_AUDIT_ROWS
        or value.get("tables", {}).get("message_outbox", {}).get("count")
        != BASE_QUEUE_ROWS
        or value.get("tables", {}).get("message_inbox", {}).get("count")
        != BASE_QUEUE_ROWS
        or queue.get("outbox_rows") != BASE_QUEUE_ROWS
        or queue.get("inbox_rows") != BASE_QUEUE_ROWS
        or queue.get("completed_inbox") != BASE_QUEUE_ROWS
        or queue.get("pending_outbox") != 0
        or queue.get("unresolved_inbox") != 0
        or queue.get("trading_rows") != 0
    ):
        raise epoch.Rejected("EXACT_CLEAN_QUEUE_BOOT_STATE_REQUIRED")


def admitted_failure() -> dict:
    """Admit only the exact failed R2 status and accepted receipt; do not infer cause."""
    failed_status = boot.SERVE_WORK / "output-serve/status.json"
    if (
        fresh.sha(failed_status) != FAILED_STATUS_SHA256
        or fresh.sha(boot.SERVE_WORK / boot.RECEIPT_NAME) != ACCEPTED_RECEIPT_SHA256
        or epoch.ACTIVE_LEASE.read_text(encoding="ascii") != boot.OWNER + "\n"
    ):
        raise epoch.Rejected("EXACT_FAILED_R2_STATUS_AND_RECEIPT_REQUIRED")
    # Hash admission is deliberate: the recorded TimeoutError remains generic,
    # and this controller does not claim the underlying cause was established.
    return {
        "failed_status_sha256": FAILED_STATUS_SHA256,
        "accepted_r2_receipt_sha256": ACCEPTED_RECEIPT_SHA256,
        "failure_cause": "UNCONFIRMED_GENERIC_TIMEOUT",
    }


def preserved_native_evidence() -> dict:
    """Hash R2 worker outputs and its stale boot latch without parsing either."""
    output = boot.SERVE_WORK / "output-serve"
    if not output.is_dir() or output.is_symlink():
        raise epoch.Rejected("R2_OUTPUT_EVIDENCE_DIRECTORY_REQUIRED")
    files = {}
    total = 0
    for path in sorted(output.rglob("*")):
        safe = fresh.safe(path)
        if path.is_symlink():
            raise epoch.Rejected("R2_OUTPUT_EVIDENCE_LINK_REJECTED")
        if path.is_dir():
            continue
        if not path.is_file():
            raise epoch.Rejected("R2_OUTPUT_EVIDENCE_SPECIAL_FILE_REJECTED")
        total += path.stat().st_size
        if len(files) >= 512 or total > 64 * 1024 * 1024:
            raise epoch.Rejected("R2_OUTPUT_EVIDENCE_BOUNDS_EXCEEDED")
        files[path.relative_to(output).as_posix()] = fresh.sha(safe)
    latch = boot.LEASE
    if latch.is_symlink() or (latch.exists() and not latch.is_file()):
        raise epoch.Rejected("R2_BOOT_LATCH_LINK_REJECTED")
    latch_sha = fresh.sha(latch) if latch.is_file() else None
    return {"output_sha256": files, "boot_latch_sha256": latch_sha}


class CleanQueueController(incident.IncidentController):
    """R3-specific controller; old global generation names remain untouched."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        names = epoch.resource_names(boot.OWNER)
        self.names["restore_pg"] = names["restore_pg"] + R3_RESTORE_SUFFIX
        self.names["restore_volume"] = names["restore_volume"] + R3_RESTORE_SUFFIX

    def start_new_generation(self, serving: dict) -> dict:
        existing = self.docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=^/" + R3_NAME + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        if existing.strip():
            raise epoch.Rejected("R3_GENERATION_MUST_BE_ABSENT")
        self.names["serve"] = R3_NAME
        self.proofs["serve_start_intent"] = True
        self.phase("serve", serving)
        output = self.work / "output-serve/status.json"
        deadline = min(self.deadline, time.monotonic() + 180)
        initial = None
        while time.monotonic() < deadline:
            view = self.inspect_container(R3_NAME)
            if view.get("state", {}).get("Status") != "running":
                raise epoch.Rejected("R3_GENERATION_FAILED_CLOSED")
            if output.is_file():
                status = boot.read_json(output)
                epoch.validate_running_status(status, boot.OWNER)
                if initial is None:
                    initial = status
                elif status["completed_inbox"] > initial["completed_inbox"] and all(
                    status["watermarks_ms"][symbol] > initial["watermarks_ms"][symbol]
                    for symbol in epoch.SYMBOLS
                ):
                    return {
                        "name": R3_NAME,
                        "container_id": view["id"],
                        "status": status,
                        "original_failed_serve_retained": True,
                    }
            time.sleep(2)
        raise epoch.Rejected("R3_FRESH_FIVE_SYMBOL_ADVANCE_REQUIRED")

    def run_clean_recovery(self) -> dict:
        admitted = admitted_failure()
        resources_before = self.validate_resources(allow_running=True)
        if resources_before["views"]["serve"]["state"]["Status"] != "exited" or any(
            resources_before["views"][key]["state"]["Status"] != "running"
            for key in ("pg", "redis")
        ):
            raise epoch.Rejected("R2_FAILED_SERVE_MUST_REMAIN_STOPPED")
        r1_before = self.inspect_container(R1_NAME)
        standby_before = self.inspect_container(boot.STANDBY_NAME)
        if (
            r1_before.get("id") != R1_ID
            or r1_before.get("state", {}).get("Status") != "exited"
            or standby_before.get("id") != boot.STANDBY_ID
        ):
            raise epoch.Rejected("ORIGINAL_R1_AND_STANDBY_METADATA_REQUIRED")
        inputs_before = incident.preserved_inputs()
        native_evidence_before = preserved_native_evidence()
        failed_status = boot.SERVE_WORK / "output-serve/status.json"
        failure_sha_before = fresh.sha(failed_status)
        receipt_sha_before = fresh.sha(boot.SERVE_WORK / boot.RECEIPT_NAME)
        serving = self.load_private_inputs()
        self.prepare_reviewed_snapshots()

        before = self.boot_state("clean-r3-before")
        validate_clean_baseline(before)
        redis_before = self.phase("boot-redis-state", serving, suffix="clean-r3-before")
        self.prepare_boot_restore_volume("bootbefore")
        backup_before = self.backup_and_verify(
            seed=before,
            restore_password=secrets.token_hex(32),
            tag="bootbefore",
            verification_mode="boot-verify-restore",
        )
        rechecked = self.boot_state("clean-r3-pre-catchup")
        if rechecked != before:
            raise epoch.Rejected("CLEAN_R2_STATE_CHANGED_DURING_BACKUP")

        after, catchup = self.audit_only_tail(before, "clean-r3-initial")
        boot.validate_preserved_state(before, after)
        if (
            after["queue"] != before["queue"]
            or after["tables"]["message_outbox"] != before["tables"]["message_outbox"]
            or after["tables"]["message_inbox"] != before["tables"]["message_inbox"]
        ):
            raise epoch.Rejected("AUDIT_CATCHUP_CHANGED_CLEAN_QUEUE")
        self.prepare_boot_restore_volume("bootafter")
        backup_after = self.backup_and_verify(
            seed=after,
            restore_password=secrets.token_hex(32),
            tag="bootafter",
            verification_mode="boot-verify-restore",
        )
        final_state, final_catchup = self.audit_only_tail(after, "clean-r3-postrestore")
        boot.validate_preserved_state(after, final_state)
        if (
            final_state["queue"] != before["queue"]
            or final_state["tables"]["message_outbox"]
            != before["tables"]["message_outbox"]
            or final_state["tables"]["message_inbox"]
            != before["tables"]["message_inbox"]
        ):
            raise epoch.Rejected("FINAL_AUDIT_TAIL_CHANGED_CLEAN_QUEUE")
        redis_after = self.phase(
            "boot-redis-state", serving, suffix="clean-r3-before-start"
        )
        if redis_after != redis_before:
            raise epoch.Rejected("CLEAN_REDIS_STREAM_OR_RECEIPT_STATE_CHANGED")

        generation = self.start_new_generation(serving)
        old_views_after = {
            key: self.inspect_container(identifier)
            for key, identifier in boot.CONTAINERS.items()
        }
        if any(
            old_views_after[key] != resources_before["views"][key]
            for key in boot.CONTAINERS
        ):
            raise epoch.Rejected("R2_RESOURCE_METADATA_OR_FAILURE_STATE_CHANGED")
        if (
            self.inspect_container(R1_NAME) != r1_before
            or self.inspect_container(boot.STANDBY_NAME) != standby_before
        ):
            raise epoch.Rejected("ORIGINAL_R1_OR_STANDBY_METADATA_CHANGED")
        if (
            fresh.sha(failed_status) != failure_sha_before
            or failure_sha_before != admitted["failed_status_sha256"]
            or fresh.sha(boot.SERVE_WORK / boot.RECEIPT_NAME) != receipt_sha_before
            or receipt_sha_before != admitted["accepted_r2_receipt_sha256"]
            or inputs_before != incident.preserved_inputs()
            or native_evidence_before != preserved_native_evidence()
        ):
            raise epoch.Rejected("R2_FAILURE_OR_ACCEPTED_INPUTS_CHANGED")
        legacy_after = self.assert_legacy_sources_stopped(
            legacy_redis_id=epoch.LEGACY_REDIS_ID
        )
        if legacy_after != resources_before["legacy"]:
            raise epoch.Rejected("LEGACY_METADATA_CHANGED_DURING_R3_RECOVERY")
        return {
            "result": "PASS_NEW_NONTRADING_GENERATION",
            "owner": boot.OWNER,
            "source_revision": self.expected_revision,
            "generation": generation,
            "backup_before_sha256": backup_before,
            "backup_after_sha256": backup_after,
            "redis_before": redis_before,
            "redis_after": redis_after,
            "audit_only_catchup": catchup,
            "postrestore_audit_only_catchup": final_catchup,
            "final_state_sha256": fresh.digest(final_state),
            "original_failure_sha256": failure_sha_before,
            "original_receipt_sha256": receipt_sha_before,
            "original_r1_id": R1_ID,
            "original_r1_metadata_sha256": fresh.digest(r1_before),
            "standby_metadata_sha256": fresh.digest(standby_before),
            "r2_native_evidence_sha256": fresh.digest(native_evidence_before),
            "failure_cause": admitted["failure_cause"],
            "legacy_preservation": legacy_after,
            "trading_started": False,
            "PAPER_QUALIFIED": False,
            "ALPHA_READY": False,
            "LIVE_READY": False,
            "STRATEGY_POLICY": "REJECT_ALL",
            "completed_at_utc": datetime.now(UTC).isoformat(),
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--expected-revision")
    parser.add_argument("--failed-status-sha256")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"result": "PLAN_ONLY", "trading_started": False}))
        return 0
    controller = None
    work = None
    try:
        boot.verify_source(args.expected_revision or "")
        if args.failed_status_sha256 != FAILED_STATUS_SHA256:
            raise epoch.Rejected("EXACT_FAILED_R2_STATUS_CLAIM_REQUIRED")
        boot.configure_generation_r2()
        admitted_failure()
        if LEASE_DIR.exists() or LEASE_DIR.is_symlink():
            raise epoch.Rejected("CLEAN_R3_LATCH_EXISTS_NO_AUTOMATIC_RETRY")
        run = uuid.uuid4().hex
        work = ROOT / ("clean-recovery-" + run)
        epoch._private_directory(work)
        epoch._private_directory(LEASE_DIR)
        fresh.save(
            LEASE,
            {
                "state": "IN_PROGRESS",
                "run": run,
                "owner": boot.OWNER,
                "source_revision": args.expected_revision,
                "failed_status_sha256": FAILED_STATUS_SHA256,
                "accepted_r2_receipt_sha256": ACCEPTED_RECEIPT_SHA256,
                "automatic_retry": False,
            },
        )
        controller = CleanQueueController(
            boot.OWNER,
            expected_revision=args.expected_revision,
            workdir=work,
            continuation_attempt="clean-r3-" + run[:8],
            deadline=time.monotonic() + MAX_SECONDS,
        )
        result = controller.run_clean_recovery()
        receipt = work / "receipt.json"
        fresh.save(receipt, result)
        fresh.save(
            work / "accepted.json",
            {
                "state": "ACCEPTED",
                "run": run,
                "receipt_sha256": fresh.sha(receipt),
                "trading_started": False,
                "automatic_retry": False,
            },
        )
        print(
            json.dumps(
                {
                    "result": result["result"],
                    "receipt": str(receipt),
                    "sha256": fresh.sha(receipt),
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - preserve a private, sanitized fail-closed receipt.
        reason = str(exc) if isinstance(exc, epoch.Rejected) else type(exc).__name__
        if controller is not None:
            controller.fail_closed_cleanup()
        if work is not None:
            fresh.save(
                work / "failure.json",
                {
                    "result": "FAILED_CLOSED",
                    "reason": reason,
                    "phase": controller.current_phase if controller else "ADMISSION",
                    "automatic_retry": False,
                    "trading_started": False,
                },
            )
        print(
            json.dumps(
                {
                    "result": "FAILED_CLOSED",
                    "reason": reason,
                    "automatic_retry": False,
                    "trading_started": False,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
