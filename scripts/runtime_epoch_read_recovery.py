"""One create-only R5 read-recovery after the exact stopped R4 failure.

This path preserves every prior generation and receipt. It snapshots the full
R5 queue before draining only the five already-published/unprocessed records,
then proves the resulting state before creating one non-trading R5 serve.
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
    from scripts import runtime_epoch_clean_queue_recovery as clean
    from scripts import runtime_epoch_incident_recovery as incident
    from scripts import runtime_epoch_read_recovery_worker as read_worker
else:
    import runtime_epoch_boot as boot
    import runtime_epoch_clean_queue_recovery as clean
    import runtime_epoch_incident_recovery as incident
    import runtime_epoch_read_recovery_worker as read_worker

epoch = boot.epoch
fresh = epoch.fresh
ROOT = Path("D:/Kairos/runtime/runtime-incident-20261012")
R4_WORK = ROOT / "clean-recovery-r4-97469e3b772b4d00b0b531282ba01b55"
R4_STATUS_SHA256 = "ebb10dfa1050aea1fd95b473e0834a520959fcbeba8461a2183f90fce96a0593"
R4_RECEIPT_SHA256 = "0a7a621991a328d9fedb8c203cc0da53a835e0a3c02f6549bacf4ef650dba03f"
R4_OPERATOR_SHA256 = "c5177adbffc374b380a170d58475b70efc08563049a92d61d3eef961935d3a96"
R4_ACCEPTED_SHA256 = "d6c005c113766897fee5ef64115439ebab20fc883f88ecdbec0d4253019a8334"
R4_LATCH_SHA256 = "b35f0fe85664bb96cc37c75fbb62a49ec4a84d95f3beace73d42fa9ee0e96747"
R4_CONTAINER_ID = "1f9da09121bd509c5aa1d1a698c98334bc1e5378ee4978b65d98885cff19e199"
R4_NAME = "kairos-epoch-69893dc7b7c6-serve-r4"
R5_NAME = "kairos-epoch-69893dc7b7c6-serve-r5"
R5_RESTORE_SUFFIX = "-transport05"
R5_LATCH_DIR = ROOT / "read-recovery-r5-latch"
R5_LATCH = R5_LATCH_DIR / "latch.json"
R5_WORK_PREFIX = "read-recovery-r5-"
BASE_AUDIT_ROWS = 336_429
BASE_OUTBOX_ROWS = 5_336
BASE_INBOX_ROWS = 5_331
REQUIRED_DRAIN_COUNT = 5
MAX_SECONDS = 3600


def validate_r4_evidence() -> dict:
    """Admit only the reviewed immutable R4 failure, receipt, and latch."""
    status = R4_WORK / "output-serve/status.json"
    receipt = R4_WORK / "receipt.json"
    operator = R4_WORK / "operator.zip"
    accepted = R4_WORK / "accepted.json"
    latch = clean.R4_LEASE
    for path in (status, receipt, operator, accepted, latch):
        if path.is_symlink() or not path.is_file():
            raise epoch.Rejected("EXACT_R4_FAILED_EVIDENCE_REQUIRED")
    actual = {
        "failed_status_sha256": fresh.sha(status),
        "accepted_receipt_sha256": fresh.sha(receipt),
        "operator_snapshot_sha256": fresh.sha(operator),
        "accepted_record_sha256": fresh.sha(accepted),
        "r4_latch_sha256": fresh.sha(latch),
    }
    if actual != {
        "failed_status_sha256": R4_STATUS_SHA256,
        "accepted_receipt_sha256": R4_RECEIPT_SHA256,
        "operator_snapshot_sha256": R4_OPERATOR_SHA256,
        "accepted_record_sha256": R4_ACCEPTED_SHA256,
        "r4_latch_sha256": R4_LATCH_SHA256,
    }:
        raise epoch.Rejected("EXACT_R4_FAILED_EVIDENCE_REQUIRED")
    status_value = boot.read_json(status)
    if (
        status_value.get("state") != "FAILED_CLOSED"
        or status_value.get("owner") not in {None, boot.OWNER}
        or status_value.get("error_type") != "TimeoutError"
        or status_value.get("mode") != "serve"
        or status_value.get("trading_started") is not False
    ):
        raise epoch.Rejected("EXACT_STOPPED_R4_FAILURE_REQUIRED")
    return actual


def validate_r5_state(value: dict, *, stage: str) -> None:
    """Check controller-facing summary; worker owns exact SQL/Redis comparison."""
    if not isinstance(value, dict) or value.get("state") != "PASS_R5_STATE":
        raise epoch.Rejected("R5_FULL_STATE_PROOF_REQUIRED_" + stage.upper())
    if value.get("trading_started") is not False:
        raise epoch.Rejected("R5_TRADING_ROWS_MUST_REMAIN_ZERO")
    tables = value.get("tables")
    queue = value.get("queue")
    if not isinstance(queue, dict) or queue.get("trading_rows") != 0:
        raise epoch.Rejected("R5_TRADING_ROWS_MUST_REMAIN_ZERO")
    if (
        not isinstance(tables, dict)
        or tables.get("event_audit", {}).get("count") != BASE_AUDIT_ROWS
        or value.get("matched_public_tables")
        != len(read_worker.epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES)
    ):
        raise epoch.Rejected("R5_FIXED_BASELINE_REQUIRED")
    for key in (
        "tables",
        "sequences",
        "anchors",
        "original_prefix",
        "queue",
        "preserved_queue_prefixes",
        "redis",
    ):
        if key not in value:
            raise epoch.Rejected("R5_FULL_STATE_PROOF_REQUIRED_" + stage.upper())
    if stage == "before" and (
        tables.get("message_outbox", {}).get("count") != BASE_OUTBOX_ROWS
        or tables.get("message_inbox", {}).get("count") != BASE_INBOX_ROWS
        or queue.get("outbox_rows") != BASE_OUTBOX_ROWS
        or queue.get("inbox_rows") != BASE_INBOX_ROWS
        or queue.get("completed_inbox") != BASE_INBOX_ROWS
        or queue.get("pending_outbox") != 0
        or queue.get("unresolved_inbox") != 0
        or queue.get("missing_inbox_message_ids") != sorted(read_worker.TARGET_IDS)
    ):
        raise epoch.Rejected("R5_EXACT_FIVE_PUBLISHED_PENDING_REQUIRED")
    if stage == "after-drain" and (
        tables.get("message_outbox", {}).get("count") != BASE_OUTBOX_ROWS
        or tables.get("message_inbox", {}).get("count")
        != BASE_INBOX_ROWS + REQUIRED_DRAIN_COUNT
        or queue.get("completed_inbox") != BASE_INBOX_ROWS + REQUIRED_DRAIN_COUNT
        or queue.get("missing_inbox_message_ids") != []
    ):
        raise epoch.Rejected("R5_DRAIN_NOT_COMPLETE")
    redis = value.get("redis", {})
    if (
        not isinstance(redis, dict)
        or redis.get("stream_entries") != BASE_OUTBOX_ROWS + 1
        or redis.get("publication_receipts") != BASE_OUTBOX_ROWS
        or type(redis.get("pending_deliveries")) is not int
        or redis.get("pending_deliveries") > REQUIRED_DRAIN_COUNT
        or not isinstance(redis.get("pending_target_message_ids"), list)
        or len(redis.get("pending_target_message_ids", []))
        != redis.get("pending_deliveries")
        or (
            stage == "after-drain"
            and (
                redis.get("pending_deliveries") != 0
                or redis.get("pending_target_message_ids") != []
            )
        )
    ):
        raise epoch.Rejected("R5_REDIS_STATE_PROOF_REQUIRED")


def validate_graceful_stop_receipt(receipt: dict, status: dict) -> None:
    """Require the worker's immutable clean-stop report to match its last status."""
    fields = (
        "owner",
        "cycles",
        "watermarks_ms",
        "pending_outbox",
        "unresolved_inbox",
        "completed_inbox",
        "uncompleted_publications",
        "new_publications",
        "observed_at_utc",
        "PAPER_QUALIFIED",
        "ALPHA_READY",
        "LIVE_READY",
        "STRATEGY_POLICY",
    )
    if (
        receipt.get("state") != "STOPPED_NONTRADING"
        or receipt.get("mode") != "serve"
        or receipt.get("new_epoch_database") != "kairos_epoch_" + boot.OWNER[:12]
        or receipt.get("graceful_shutdown") is not True
        or status.get("state") != "RUNNING_NONTRADING"
        or any(receipt.get(key) != status.get(key) for key in fields)
    ):
        raise epoch.Rejected("R5_GRACEFUL_STOP_RECEIPT_REQUIRED")
    epoch.validate_running_status(status, boot.OWNER)


class R5ReadRecoveryController(clean.ReviewedR3SupplementController):
    """Exact R4->R5 path; never reuses or mutates an earlier generation."""

    generation_name = R5_NAME
    generation_label = "r5"
    restore_suffix = R5_RESTORE_SUFFIX

    def admission_evidence(self, claim: str | None = None) -> dict:
        prior = super().admission_evidence(clean.R3_FAILURE_SHA256)
        return {"r3": prior, "r4": validate_r4_evidence()}

    def preserved_recovery_evidence(self) -> dict:
        prior = super().preserved_recovery_evidence()
        return {
            **prior,
            "r4_work": clean.inventory_files(R4_WORK),
            "r4_evidence": validate_r4_evidence(),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        names = epoch.resource_names(boot.OWNER)
        self.names["restore_pg"] = names["restore_pg"] + self.restore_suffix
        self.names["restore_volume"] = names["restore_volume"] + self.restore_suffix

    def additional_preserved_resources(self) -> dict:
        prior = super().additional_preserved_resources()
        r4 = self.inspect_container(R4_NAME)
        restart_count = self.docker(
            ["inspect", "--format", "{{json .RestartCount}}", R4_CONTAINER_ID]
        ).strip()
        if (
            r4.get("id") != R4_CONTAINER_ID
            or r4.get("state", {}).get("Status") != "exited"
            or r4.get("state", {}).get("ExitCode") != 1
            or r4.get("state", {}).get("OOMKilled") is not False
            or restart_count != "0"
        ):
            raise epoch.Rejected("EXACT_FAILED_R4_METADATA_REQUIRED")
        return {**prior, "r4": r4, "r4_restart_count": 0}

    def _state_config(self, serving: dict) -> dict:
        return {
            **serving,
            "owner": boot.OWNER,
            "database": "kairos_epoch_" + boot.OWNER[:12],
            "pg_host": self.names["target_pg"],
            "redis_host": self.names["redis"],
            "admin_password": self._admin_password,
        }

    def _r5_state(self, suffix: str, config: dict) -> dict:
        value = self.phase("r5-state", config, suffix=suffix)
        validate_r5_state(value, stage=suffix)
        return value

    def _start_r5_and_check_progress(self, serving: dict, baseline: dict) -> dict:
        existing = self.docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=^/" + R5_NAME + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        if existing.strip():
            raise epoch.Rejected("R5_GENERATION_MUST_BE_ABSENT")
        self.names["serve"] = R5_NAME
        self.proofs["serve_start_intent"] = True
        self.phase("serve", serving)
        status_path = self.work / "output-serve/status.json"
        deadline = min(self.deadline, time.monotonic() + 240)
        first = None
        while time.monotonic() < deadline:
            view = self.inspect_container(R5_NAME)
            if view.get("state", {}).get("Status") != "running":
                raise epoch.Rejected("R5_NEW_SERVE_FAILED_CLOSED")
            if status_path.is_file():
                status = boot.read_json(status_path)
                epoch.validate_running_status(status, boot.OWNER)
                if first is None:
                    first = status
                elif status["completed_inbox"] > first["completed_inbox"] and all(
                    status["watermarks_ms"][symbol]
                    > baseline["anchors"][symbol]["last_close_time_ms"]
                    for symbol in epoch.SYMBOLS
                ):
                    epoch.validate_running_status(status, boot.OWNER, previous=first)
                    container_id = view.get("id")
                    self.docker(["stop", "--time=120", R5_NAME], seconds=130)
                    stopped = self.inspect_container(R5_NAME)
                    if (
                        stopped.get("id") != container_id
                        or stopped.get("state", {}).get("Status") != "exited"
                        or stopped.get("state", {}).get("ExitCode") != 0
                        or stopped.get("state", {}).get("OOMKilled") is not False
                    ):
                        raise epoch.Rejected(
                            "R5_CONTROLLED_RESTART_STOP_PROOF_REQUIRED"
                        )
                    stop_receipts = list(status_path.parent.glob("serve-stop-*.json"))
                    if len(stop_receipts) != 1 or stop_receipts[0].is_symlink():
                        raise epoch.Rejected("R5_GRACEFUL_STOP_RECEIPT_REQUIRED")
                    stop_receipt = boot.read_json(stop_receipts[0], limit=16_384)
                    stopped_status = boot.read_json(status_path)
                    validate_graceful_stop_receipt(stop_receipt, stopped_status)
                    if stopped_status["completed_inbox"] < status[
                        "completed_inbox"
                    ] or any(
                        stopped_status["watermarks_ms"][symbol]
                        < status["watermarks_ms"][symbol]
                        for symbol in epoch.SYMBOLS
                    ):
                        raise epoch.Rejected("R5_GRACEFUL_STOP_PROGRESS_ROLLBACK")
                    self.docker(["start", R5_NAME], seconds=25)
                    restart_deadline = min(self.deadline, time.monotonic() + 240)
                    prior = stopped_status
                    while time.monotonic() < restart_deadline:
                        current = boot.read_json(status_path)
                        current_view = self.inspect_container(R5_NAME)
                        if (
                            current_view.get("id") != container_id
                            or current_view.get("state", {}).get("Status") != "running"
                        ):
                            raise epoch.Rejected(
                                "R5_CONTROLLED_RESTART_IDENTITY_REQUIRED"
                            )
                        if current.get("state") == "FAILED_CLOSED":
                            raise epoch.Rejected(
                                "R5_FAILED_CLOSED_AFTER_CONTROLLED_RESTART"
                            )
                        epoch.validate_running_status(current, boot.OWNER)
                        if current.get("completed_inbox", -1) > prior.get(
                            "completed_inbox", -1
                        ) and all(
                            current.get("watermarks_ms", {}).get(symbol, -1)
                            > prior.get("watermarks_ms", {}).get(symbol, -1)
                            for symbol in epoch.SYMBOLS
                        ):
                            epoch.validate_running_status(
                                current, boot.OWNER, previous=prior
                            )
                            return {
                                "name": R5_NAME,
                                "container_id": container_id,
                                "status": current,
                                "controlled_restart": True,
                            }
                        time.sleep(2)
                    raise epoch.Rejected("R5_POST_RESTART_STABILITY_REQUIRED")
            time.sleep(2)
        raise epoch.Rejected("R5_FRESH_FIVE_SYMBOL_PROGRESS_REQUIRED")

    def run_recovery(self) -> dict:
        admitted = self.admission_evidence(clean.R3_FAILURE_SHA256)
        evidence_before = self.preserved_recovery_evidence()
        resources_before = self.validate_resources(allow_running=True)
        if resources_before["views"]["serve"]["state"]["Status"] != "exited" or any(
            resources_before["views"][key]["state"]["Status"] != "running"
            for key in ("pg", "redis")
        ):
            raise epoch.Rejected("R5_FIXED_POSTGRES_REDIS_MUST_BE_RUNNING")
        r4_before = self.additional_preserved_resources()
        r1_before = self.inspect_container(clean.R1_NAME)
        if (
            r1_before.get("id") != clean.R1_ID
            or r1_before.get("state", {}).get("Status") != "exited"
        ):
            raise epoch.Rejected("EXACT_STOPPED_R1_METADATA_REQUIRED")
        standby_before = self.inspect_container(boot.STANDBY_NAME)
        standby_projection = boot.stable_standby_metadata(standby_before)
        prior_inputs = incident.preserved_inputs()
        serving = self.load_private_inputs()
        self.prepare_reviewed_snapshots()
        state_config = self._state_config(serving)
        before = self._r5_state("before", state_config)
        self.prepare_boot_restore_volume("bootbefore")
        backup_before = self.backup_and_verify(
            seed=before,
            restore_password=secrets.token_hex(32),
            tag="bootbefore",
            verification_mode="r5-verify-restore",
        )
        rechecked = self._r5_state("pre-drain", state_config)
        if before != rechecked:
            raise epoch.Rejected("R5_PRESTATE_CHANGED_DURING_BACKUP")
        drain = self.phase("r5-drain", {**state_config, "expected_state": before})
        if (
            drain.get("state") != "PASS_EXACT_R5_INBOX_RECOVERY"
            or drain.get("completed_message_ids") != sorted(read_worker.TARGET_IDS)
            or drain.get("completed_inbox_increment") != REQUIRED_DRAIN_COUNT
            or drain.get("published_messages") != 0
            or drain.get("stream_entries_added") != 0
            or drain.get("publication_receipts_added") != 0
            or drain.get("pending_deliveries") != 0
            or drain.get("audit_history_preserved") is not True
            or drain.get("outbox_and_sequences_preserved") is not True
        ):
            raise epoch.Rejected("R5_EXACT_EXISTING_FIVE_DRAIN_REQUIRED")
        self._r5_state("after-drain", state_config)
        boot_state = self.boot_state("r5-after-drain")
        after, catchup = self.audit_only_tail(boot_state, "r5-initial")
        self.prepare_boot_restore_volume("bootafter")
        backup_after = self.backup_and_verify(
            seed=after,
            restore_password=secrets.token_hex(32),
            tag="bootafter",
            verification_mode="boot-verify-restore",
        )
        final_state, final_catchup = self.audit_only_tail(boot_state, "r5-postrestore")
        boot.validate_preserved_state(after, final_state)
        if (
            final_state["original_prefix"] != after["original_prefix"]
            or final_state["queue"] != after["queue"]
            or final_state["sequences"] != after["sequences"]
        ):
            raise epoch.Rejected("R5_FINAL_AUDIT_STATE_CHANGED")
        redis_proof = self.phase("boot-redis-state", serving, suffix="r5-before-start")
        generation = self._start_r5_and_check_progress(serving, boot_state)
        r4_after = self.additional_preserved_resources()
        old_views_after = {
            key: self.inspect_container(identifier)
            for key, identifier in boot.CONTAINERS.items()
        }
        if (
            r4_after != r4_before
            or self.preserved_recovery_evidence() != evidence_before
            or incident.preserved_inputs() != prior_inputs
            or any(
                old_views_after[key] != resources_before["views"][key]
                for key in boot.CONTAINERS
            )
            or self.inspect_container(clean.R1_NAME) != r1_before
            or boot.stable_standby_metadata(self.inspect_container(boot.STANDBY_NAME))
            != standby_projection
            or self.assert_legacy_sources_stopped(legacy_redis_id=epoch.LEGACY_REDIS_ID)
            != resources_before["legacy"]
        ):
            raise epoch.Rejected("R5_PRIOR_GENERATION_OR_EVIDENCE_CHANGED")
        return {
            "result": "PASS_NEW_NONTRADING_GENERATION",
            "recovery_kind": "R5_EXACT_READ_RECOVERY",
            "owner": boot.OWNER,
            "source_revision": self.expected_revision,
            "r4_failure_cause": "EXPLICIT_REDIS_READ_TIMEOUT_NOT_INFRA_CAUSE_CONFIRMED",
            "r4_evidence": evidence_before,
            "prior_generation_admission": admitted,
            "r5_prebackup_sha256": backup_before,
            "r5_postdrain_backup_sha256": backup_after,
            "r5_drain": drain,
            "audit_only_catchup": catchup,
            "postrestore_audit_only_catchup": final_catchup,
            "redis_proof": redis_proof,
            "generation": generation,
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
    parser.add_argument("--failed-r4-status-sha256")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"result": "PLAN_ONLY", "trading_started": False}))
        return 0
    controller = None
    work = None
    try:
        boot.verify_source(args.expected_revision or "")
        if args.failed_r4_status_sha256 != R4_STATUS_SHA256:
            raise epoch.Rejected("EXACT_FAILED_R4_STATUS_CLAIM_REQUIRED")
        # Validate against the already-running, reviewed R2 resource names.
        # R5 does not exist until this controller creates its new serve.
        boot.configure_generation_r2()
        if R5_LATCH_DIR.exists() or R5_LATCH_DIR.is_symlink():
            raise epoch.Rejected("R5_CREATE_ONLY_LATCH_EXISTS_NO_AUTOMATIC_RETRY")
        run_id = uuid.uuid4().hex
        work = ROOT / (R5_WORK_PREFIX + run_id)
        epoch._private_directory(work)
        controller = R5ReadRecoveryController(
            boot.OWNER,
            expected_revision=args.expected_revision,
            workdir=work,
            continuation_attempt="read-r5-" + run_id[:8],
            deadline=time.monotonic() + MAX_SECONDS,
        )
        controller.reviewed_failure_claim = clean.R3_FAILURE_SHA256
        validate_r4_evidence()
        controller.admission_evidence(clean.R3_FAILURE_SHA256)
        controller.preserved_recovery_evidence()
        resources = controller.validate_resources(allow_running=True)
        if resources["views"]["serve"]["state"]["Status"] != "exited" or any(
            resources["views"][key]["state"]["Status"] != "running"
            for key in ("pg", "redis")
        ):
            raise epoch.Rejected("R5_FIXED_POSTGRES_REDIS_MUST_BE_RUNNING")
        controller.additional_preserved_resources()
        r1 = controller.inspect_container(clean.R1_NAME)
        if r1.get("id") != clean.R1_ID or r1.get("state", {}).get("Status") != "exited":
            raise epoch.Rejected("EXACT_STOPPED_R1_METADATA_REQUIRED")
        boot.stable_standby_metadata(controller.inspect_container(boot.STANDBY_NAME))
        if (
            controller.assert_legacy_sources_stopped(
                legacy_redis_id=epoch.LEGACY_REDIS_ID
            )
            != resources["legacy"]
        ):
            raise epoch.Rejected("LEGACY_SOURCE_PRESERVATION_REQUIRED")
        incident.preserved_inputs()
        existing = controller.docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=^/" + R5_NAME + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        if existing.strip():
            raise epoch.Rejected("R5_GENERATION_MUST_BE_ABSENT")
        epoch._private_directory(R5_LATCH_DIR)
        fresh.save(
            R5_LATCH,
            {
                "state": "IN_PROGRESS",
                "run": run_id,
                "owner": boot.OWNER,
                "source_revision": args.expected_revision,
                "failed_r4_status_sha256": R4_STATUS_SHA256,
                "automatic_retry": False,
            },
        )
        receipt = controller.run_recovery()
        receipt_path = work / "receipt.json"
        fresh.save(receipt_path, receipt)
        receipt_sha256 = fresh.sha(receipt_path)
        fresh.save(
            work / "accepted.json",
            {
                "state": "ACCEPTED",
                "run": run_id,
                "receipt_sha256": receipt_sha256,
                "source_revision": args.expected_revision,
                "automatic_retry": False,
                "trading_started": False,
            },
        )
        print(
            json.dumps(
                {
                    "result": receipt["result"],
                    "receipt": str(receipt_path),
                    "sha256": receipt_sha256,
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - only sanitized categories leave this boundary.
        if controller is not None:
            controller.fail_closed_cleanup()
        if work is not None and not (work / "failure.json").exists():
            fresh.save(
                work / "failure.json",
                {
                    "result": "FAILED_CLOSED",
                    "reason": (
                        str(exc)
                        if isinstance(exc, epoch.Rejected)
                        else type(exc).__name__
                    ),
                    "automatic_retry": False,
                    "trading_started": False,
                },
            )
        print(
            json.dumps(
                {
                    "result": "FAILED_CLOSED",
                    "automatic_retry": False,
                    "trading_started": False,
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
