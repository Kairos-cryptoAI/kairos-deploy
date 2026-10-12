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
R3_FAILED_WORK = ROOT / "clean-recovery-33250d8141f040a8a2688c5e7276da53"
R3_FAILED_RUN = "33250d8141f040a8a2688c5e7276da53"
R3_FAILED_STATUS_SHA256 = (
    "8438413112814f7916db8c6c4c2645c9d4b70adef686aff4791ef0edde70f4ca"
)
R3_FAILURE_SHA256 = "4ec59a4d3d57ab35a8c0a6dfe46ad9319c3d8e3de4d784dfece68bf39853f5f1"
R3_OPERATOR_ZIP_SHA256 = (
    "739bb37adb7bdbce8ae5d8335bce06faec4bec2abf5109f7025bc799cd1f9ea8"
)
R3_SOURCE_REVISION = "2069e9b2e999840a16297d3e94214a8fe210fc43"
R3_CONTAINER_ID = "f2a84266958b1b6faf502d1d6f055287f0900712bef63d8d8fb9ceea9612b849"
R4_NAME = "kairos-epoch-69893dc7b7c6-serve-r4"
R3_RESTORE_SUFFIX = "-transport03"
R4_RESTORE_SUFFIX = "-transport04"
BASE_AUDIT_ROWS = 335_379
BASE_QUEUE_ROWS = 4_626
R4_BASE_AUDIT_ROWS = 335_559
R4_BASE_QUEUE_ROWS = 4_651
R4_LEASE_DIR = ROOT / "clean-queue-r4-reviewed-latch"
R4_LEASE = R4_LEASE_DIR / "latch.json"
MAX_SECONDS = 1800


def validate_clean_baseline(
    value: dict, *, audit_rows: int = BASE_AUDIT_ROWS, queue_rows: int = BASE_QUEUE_ROWS
) -> None:
    """Pin the observed clean baseline and enforce the worker's full proof shape."""
    queue = value.get("queue", {})
    if (
        value.get("state") != "PASS_BOOT_STATE"
        or value.get("trading_started") is not False
        or value.get("tables", {}).get("event_audit", {}).get("count") != audit_rows
        or value.get("tables", {}).get("message_outbox", {}).get("count") != queue_rows
        or value.get("tables", {}).get("message_inbox", {}).get("count") != queue_rows
        or queue.get("outbox_rows") != queue_rows
        or queue.get("inbox_rows") != queue_rows
        or queue.get("completed_inbox") != queue_rows
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


def inventory_files(directory: Path) -> dict:
    """Bounded hash-only inventory for immutable prior attempt evidence."""
    if not directory.is_dir() or directory.is_symlink():
        raise epoch.Rejected("PRIOR_RECOVERY_WORK_DIRECTORY_REQUIRED")
    files = {}
    total = 0
    for path in sorted(directory.rglob("*")):
        safe = fresh.safe(path)
        if path.is_symlink():
            raise epoch.Rejected("PRIOR_RECOVERY_EVIDENCE_LINK_REJECTED")
        if path.is_dir():
            continue
        if not path.is_file():
            raise epoch.Rejected("PRIOR_RECOVERY_EVIDENCE_SPECIAL_FILE_REJECTED")
        total += path.stat().st_size
        if len(files) >= 2048 or total > 256 * 1024 * 1024:
            raise epoch.Rejected("PRIOR_RECOVERY_EVIDENCE_BOUNDS_EXCEEDED")
        files[path.relative_to(directory).as_posix()] = fresh.sha(safe)
    return files


class CleanQueueController(incident.IncidentController):
    """R3-specific controller; old global generation names remain untouched."""

    generation_name = R3_NAME
    generation_label = "r3"
    restore_suffix = R3_RESTORE_SUFFIX
    audit_rows = BASE_AUDIT_ROWS
    queue_rows = BASE_QUEUE_ROWS
    failed_status_sha256 = FAILED_STATUS_SHA256
    accepted_receipt_sha256 = ACCEPTED_RECEIPT_SHA256
    failure_cause = "UNCONFIRMED_GENERIC_TIMEOUT"

    def failed_status_path(self) -> Path:
        return boot.SERVE_WORK / "output-serve/status.json"

    def additional_preserved_resources(self) -> dict:
        return {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        names = epoch.resource_names(boot.OWNER)
        self.names["restore_pg"] = names["restore_pg"] + self.restore_suffix
        self.names["restore_volume"] = names["restore_volume"] + self.restore_suffix

    def admission_evidence(self) -> dict:
        return admitted_failure()

    def preserved_recovery_evidence(self) -> dict:
        return preserved_native_evidence()

    def preservation_inputs(self) -> dict:
        return incident.preserved_inputs()

    def start_new_generation(self, serving: dict) -> dict:
        existing = self.docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=^/" + self.generation_name + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        if existing.strip():
            raise epoch.Rejected("NEW_GENERATION_MUST_BE_ABSENT")
        self.names["serve"] = self.generation_name
        self.proofs["serve_start_intent"] = True
        self.phase("serve", serving)
        output = self.work / "output-serve/status.json"
        deadline = min(self.deadline, time.monotonic() + 180)
        initial = None
        while time.monotonic() < deadline:
            view = self.inspect_container(self.generation_name)
            if view.get("state", {}).get("Status") != "running":
                raise epoch.Rejected("NEW_GENERATION_FAILED_CLOSED")
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
                        "name": self.generation_name,
                        "container_id": view["id"],
                        "status": status,
                        "original_failed_serve_retained": True,
                    }
            time.sleep(2)
        raise epoch.Rejected("NEW_GENERATION_FRESH_FIVE_SYMBOL_ADVANCE_REQUIRED")

    def run_clean_recovery(self) -> dict:
        admitted = self.admission_evidence()
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
        standby_projection_before = boot.stable_standby_metadata(standby_before)
        inputs_before = self.preservation_inputs()
        native_evidence_before = self.preserved_recovery_evidence()
        failed_status = self.failed_status_path()
        failure_sha_before = fresh.sha(failed_status)
        receipt_sha_before = fresh.sha(boot.SERVE_WORK / boot.RECEIPT_NAME)
        additional_resources_before = self.additional_preserved_resources()
        serving = self.load_private_inputs()
        self.prepare_reviewed_snapshots()

        before = self.boot_state("clean-r3-before")
        validate_clean_baseline(
            before, audit_rows=self.audit_rows, queue_rows=self.queue_rows
        )
        redis_before = self.phase(
            "boot-redis-state",
            serving,
            suffix="clean-" + self.generation_label + "-before",
        )
        self.prepare_boot_restore_volume("bootbefore")
        backup_before = self.backup_and_verify(
            seed=before,
            restore_password=secrets.token_hex(32),
            tag="bootbefore",
            verification_mode="boot-verify-restore",
        )
        rechecked = self.boot_state("clean-" + self.generation_label + "-pre-catchup")
        if rechecked != before:
            raise epoch.Rejected("CLEAN_R2_STATE_CHANGED_DURING_BACKUP")

        after, catchup = self.audit_only_tail(
            before, "clean-" + self.generation_label + "-initial"
        )
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
        final_state, final_catchup = self.audit_only_tail(
            after, "clean-" + self.generation_label + "-postrestore"
        )
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
            "boot-redis-state",
            serving,
            suffix="clean-" + self.generation_label + "-before-start",
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
            or boot.stable_standby_metadata(self.inspect_container(boot.STANDBY_NAME))
            != standby_projection_before
        ):
            raise epoch.Rejected("ORIGINAL_R1_OR_STANDBY_METADATA_CHANGED")
        if self.additional_preserved_resources() != additional_resources_before:
            raise epoch.Rejected("PRIOR_FAILED_GENERATION_METADATA_CHANGED")
        if (
            fresh.sha(failed_status) != failure_sha_before
            or failure_sha_before != admitted["failed_status_sha256"]
            or fresh.sha(boot.SERVE_WORK / boot.RECEIPT_NAME) != receipt_sha_before
            or receipt_sha_before != admitted["accepted_r2_receipt_sha256"]
            or inputs_before != self.preservation_inputs()
            or native_evidence_before != self.preserved_recovery_evidence()
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
            "standby_metadata_sha256": fresh.digest(standby_projection_before),
            "r2_native_evidence_sha256": fresh.digest(native_evidence_before),
            "failure_cause": self.failure_cause,
            "legacy_preservation": legacy_after,
            "trading_started": False,
            "PAPER_QUALIFIED": False,
            "ALPHA_READY": False,
            "LIVE_READY": False,
            "STRATEGY_POLICY": "REJECT_ALL",
            "completed_at_utc": datetime.now(UTC).isoformat(),
        }


class ReviewedR3SupplementController(CleanQueueController):
    """One independently latched R4 attempt after exact stopped-R3 evidence."""

    generation_name = R4_NAME
    generation_label = "r4"
    restore_suffix = R4_RESTORE_SUFFIX
    audit_rows = R4_BASE_AUDIT_ROWS
    queue_rows = R4_BASE_QUEUE_ROWS
    failed_status_sha256 = R3_FAILED_STATUS_SHA256
    accepted_receipt_sha256 = ACCEPTED_RECEIPT_SHA256
    failure_cause = "VERIFIED_PASSIVE_HEALTH_TIMESTAMP_GUARD_REFUSAL"

    def failed_status_path(self) -> Path:
        return R3_FAILED_WORK / "output-serve/status.json"

    def admission_evidence(self, claim: str | None = None) -> dict:
        claim = claim or getattr(self, "reviewed_failure_claim", None)
        failure = R3_FAILED_WORK / "failure.json"
        status = self.failed_status_path()
        operator = R3_FAILED_WORK / "operator.zip"
        r3_latch_path = LEASE_DIR / "latch.json"
        if r3_latch_path.is_symlink() or not r3_latch_path.is_file():
            raise epoch.Rejected("ORIGINAL_R3_CREATE_ONLY_LATCH_REQUIRED")
        r3_latch = boot.read_json(r3_latch_path)
        r3_views = self.reviewed_r3_standby_views()
        if (
            claim != R3_FAILURE_SHA256
            or set(r3_latch)
            != {
                "state",
                "run",
                "owner",
                "source_revision",
                "failed_status_sha256",
                "accepted_r2_receipt_sha256",
                "automatic_retry",
            }
            or r3_latch.get("state") != "IN_PROGRESS"
            or r3_latch.get("run") != R3_FAILED_RUN
            or r3_latch.get("owner") != boot.OWNER
            or r3_latch.get("source_revision") != R3_SOURCE_REVISION
            or r3_latch.get("failed_status_sha256") != FAILED_STATUS_SHA256
            or r3_latch.get("accepted_r2_receipt_sha256") != ACCEPTED_RECEIPT_SHA256
            or r3_latch.get("automatic_retry") is not False
            or fresh.sha(failure) != R3_FAILURE_SHA256
            or fresh.sha(status) != R3_FAILED_STATUS_SHA256
            or fresh.sha(operator) != R3_OPERATOR_ZIP_SHA256
            or fresh.sha(boot.SERVE_WORK / "output-serve/status.json")
            != FAILED_STATUS_SHA256
            or fresh.sha(boot.SERVE_WORK / boot.RECEIPT_NAME) != ACCEPTED_RECEIPT_SHA256
            or epoch.ACTIVE_LEASE.read_text(encoding="ascii") != boot.OWNER + "\n"
        ):
            raise epoch.Rejected("EXACT_REVIEWED_R3_FAILURE_EVIDENCE_REQUIRED")
        return {
            "failed_status_sha256": R3_FAILED_STATUS_SHA256,
            "failure_json_sha256": R3_FAILURE_SHA256,
            "operator_zip_sha256": R3_OPERATOR_ZIP_SHA256,
            "accepted_r2_receipt_sha256": ACCEPTED_RECEIPT_SHA256,
            "r3_source_revision": R3_SOURCE_REVISION,
            "r3_standby_refusal_sha256": fresh.digest(r3_views),
            "failure_cause": self.failure_cause,
        }

    @staticmethod
    def reviewed_r3_standby_views() -> dict:
        """Recheck only the two reviewed sanitized Docker VIEW captures."""
        view_fields = {
            "id",
            "name",
            "image",
            "state",
            "labels",
            "mounts",
            "network",
            "networks",
            "privileged",
            "ports",
            "memory",
            "swap",
            "cpus",
            "readonly",
            "caps",
        }
        work = R3_FAILED_WORK
        first = boot.read_json(work / "cli-010.stdout", limit=16_384)
        second = boot.read_json(work / "cli-190.stdout", limit=16_384)
        if any(
            set(view) != view_fields or view.get("name") != "/" + boot.STANDBY_NAME
            for view in (first, second)
        ):
            raise epoch.Rejected("R3_STANDBY_REFUSAL_VIEW_SCHEMA_CONFLICT")
        try:
            first_stable = boot.stable_standby_metadata(first)
            second_stable = boot.stable_standby_metadata(second)
        except epoch.Rejected as exc:
            raise epoch.Rejected("R3_STANDBY_REFUSAL_VIEW_INVALID") from exc
        if first_stable != second_stable:
            raise epoch.Rejected("R3_STANDBY_REFUSAL_NOT_TIMESTAMP_ONLY")
        first_log = first["state"]["Health"]["Log"]
        second_log = second["state"]["Health"]["Log"]
        if [(row["Start"], row["End"]) for row in first_log] == [
            (row["Start"], row["End"]) for row in second_log
        ]:
            raise epoch.Rejected("R3_STANDBY_REFUSAL_CLOCK_CHANGE_NOT_OBSERVED")
        return {"cli010": first_stable, "cli190": second_stable}

    def preserved_recovery_evidence(self) -> dict:
        r3_latch = LEASE_DIR / "latch.json"
        if r3_latch.is_symlink() or not r3_latch.is_file():
            raise epoch.Rejected("ORIGINAL_R3_CREATE_ONLY_LATCH_REQUIRED")
        return {
            "r2": preserved_native_evidence(),
            "r3_work": inventory_files(R3_FAILED_WORK),
            "r1_work": inventory_files(boot.PARENT / "continuation-05"),
            "r3_latch_sha256": fresh.sha(r3_latch),
        }

    def additional_preserved_resources(self) -> dict:
        failed_r3 = self.inspect_container(R3_NAME)
        if (
            failed_r3.get("id") != R3_CONTAINER_ID
            or failed_r3.get("state", {}).get("Status") != "exited"
            or failed_r3.get("state", {}).get("ExitCode") != 137
        ):
            raise epoch.Rejected("EXACT_STOPPED_FAILED_R3_CONTAINER_REQUIRED")
        return {"r3": failed_r3}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--expected-revision")
    parser.add_argument("--failed-status-sha256")
    parser.add_argument("--reviewed-r3-failure-sha256")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"result": "PLAN_ONLY", "trading_started": False}))
        return 0
    controller = None
    work = None
    latch_dir = LEASE_DIR
    attempt_class = CleanQueueController
    attempt_label = "r3"
    try:
        boot.verify_source(args.expected_revision or "")
        if args.reviewed_r3_failure_sha256:
            if (
                args.reviewed_r3_failure_sha256 != R3_FAILURE_SHA256
                or args.failed_status_sha256 is not None
            ):
                raise epoch.Rejected("EXACT_REVIEWED_R3_FAILURE_CLAIM_REQUIRED")
            attempt_class = ReviewedR3SupplementController
            attempt_label = "r4"
            latch_dir = R4_LEASE_DIR
        elif args.failed_status_sha256 != FAILED_STATUS_SHA256:
            raise epoch.Rejected("EXACT_FAILED_R2_STATUS_CLAIM_REQUIRED")
        boot.configure_generation_r2()
        if attempt_class is CleanQueueController:
            admitted_failure()
        else:
            probe = attempt_class.__new__(attempt_class)
            probe.admission_evidence(args.reviewed_r3_failure_sha256)
        if latch_dir.exists() or latch_dir.is_symlink():
            raise epoch.Rejected("CLEAN_GENERATION_LATCH_EXISTS_NO_AUTOMATIC_RETRY")
        run = uuid.uuid4().hex
        work = ROOT / ("clean-recovery-" + attempt_label + "-" + run)
        epoch._private_directory(work)
        epoch._private_directory(latch_dir)
        lease_path = latch_dir / "latch.json"
        fresh.save(
            lease_path,
            {
                "state": "IN_PROGRESS",
                "run": run,
                "owner": boot.OWNER,
                "source_revision": args.expected_revision,
                "failed_status_sha256": (
                    R3_FAILED_STATUS_SHA256
                    if attempt_label == "r4"
                    else FAILED_STATUS_SHA256
                ),
                "accepted_r2_receipt_sha256": ACCEPTED_RECEIPT_SHA256,
                "reviewed_failure_sha256": (
                    R3_FAILURE_SHA256 if attempt_label == "r4" else None
                ),
                "automatic_retry": False,
            },
        )
        controller = attempt_class(
            boot.OWNER,
            expected_revision=args.expected_revision,
            workdir=work,
            continuation_attempt="clean-" + attempt_label + "-" + run[:8],
            deadline=time.monotonic() + MAX_SECONDS,
        )
        if attempt_class is ReviewedR3SupplementController:
            controller.reviewed_failure_claim = args.reviewed_r3_failure_sha256
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
