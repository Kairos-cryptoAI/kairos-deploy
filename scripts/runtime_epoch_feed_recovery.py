"""Create one guarded R6 generation after the exact R5 feed timeout.

The failed R5 generation is retained. R6 is admitted only after exact current
state capture, isolated backup/restore, four-row publication/drain, audit-only
catch-up, a second verified backup, and a controlled graceful restart.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_boot as boot
    from scripts import runtime_epoch_clean_queue_recovery as clean
    from scripts import runtime_epoch_feed_recovery_worker as feed_worker
    from scripts import runtime_epoch_incident_recovery as incident
else:
    import runtime_epoch_boot as boot
    import runtime_epoch_clean_queue_recovery as clean
    import runtime_epoch_feed_recovery_worker as feed_worker
    import runtime_epoch_incident_recovery as incident

epoch = boot.epoch
fresh = epoch.fresh
ROOT = Path("D:/Kairos/runtime/runtime-incident-20261012")
R5_STATUS_SHA256 = "31d0ec7cfbb61ed871e20536567cd6bbe91e172ed9341d405304269eea5d69a5"
R5_RECEIPT_SHA256 = "a0b16bfc3953b39f63767df228fcae43a0afdc1a70a5ba45973ab4dc4a1c06fd"
R6_NAME = "kairos-epoch-" + boot.OWNER[:12] + "-serve-r6"
R6_RESTORE_SUFFIX = "-transport06"
R6_LATCH_DIR = ROOT / "read-recovery-r6-feed-latch"
R6_LATCH = R6_LATCH_DIR / "latch.json"
R6_CONTINUATION_LATCH_DIR = ROOT / "read-recovery-r6-feed-continuation-latch"
R6_CONTINUATION_LATCH = R6_CONTINUATION_LATCH_DIR / "latch.json"
R6_WORK_PREFIX = "read-recovery-r6-feed-"
R6_RETAINED_WORK = ROOT / "read-recovery-r6-feed-f4072c03a9c4430c9cb1a92ebe2e78a0"
R6_RETAINED_RUN = "f4072c03a9c4430c9cb1a92ebe2e78a0"
R6_RETAINED_FAILURE_SHA256 = (
    "e7129b439b4b2bc3603002a7042e83831b38d9e4fb277db8ce091c8982c0f2a4"
)
R6_ORIGINAL_LATCH_SHA256 = (
    "c9d06bdc6b1a94a9974767b3fbe296c94611fed8e073e2803d1e2fe0b21fb901"
)
R6_RETAINED_INVENTORY_SHA256 = (
    "4117ec4b518d2102b62f9008ac18397adebf893e5c8b908b44ee97bf88f552d1"
)
R6_ORIGINAL_SOURCE_REVISION = "b627152cdef1e913517aeafd9bce3ff4a6a790e7"
R6_RETAINED_FAILURE = {
    "result": "FAILED_CLOSED",
    "reason": "EXACT_INCIDENT_FAILURE_INVENTORY_REQUIRED",
    "phase": "ADMISSION",
    "automatic_retry": False,
    "trading_started": False,
}
R6_RETAINED_LATCH = {
    "state": "IN_PROGRESS",
    "run": R6_RETAINED_RUN,
    "owner": boot.OWNER,
    "source_revision": R6_ORIGINAL_SOURCE_REVISION,
    "failed_r5_status_sha256": R5_STATUS_SHA256,
    "automatic_retry": False,
}
R6_RETAINED_INVENTORY_PATHS = frozenset(
    {
        *(
            f"cli-{index:03d}.{stream}"
            for index in range(1, 16)
            for stream in ("stdout", "stderr")
        ),
        "docker-config/config.json",
        "failure.json",
    }
)
MAX_SECONDS = 7200
MAX_CATCHUP_BATCHES = 1000


def validate_reviewed_continuation(
    *,
    explicit_flag: bool,
    failure: dict | None,
    failure_sha256: str | None,
    original_latch: dict | None,
    original_latch_sha256: str | None,
    inventory: dict | None,
) -> dict:
    """Bind one explicit continuation to the exact retained admission refusal."""
    if not explicit_flag:
        raise epoch.Rejected("EXPLICIT_REVIEWED_R6_CONTINUATION_REQUIRED")
    if (
        failure != R6_RETAINED_FAILURE
        or failure_sha256 != R6_RETAINED_FAILURE_SHA256
        or original_latch != R6_RETAINED_LATCH
        or original_latch_sha256 != R6_ORIGINAL_LATCH_SHA256
        or not isinstance(inventory, dict)
        or set(inventory) != R6_RETAINED_INVENTORY_PATHS
        or inventory.get("failure.json") != R6_RETAINED_FAILURE_SHA256
        or any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in inventory.values()
        )
        or fresh.digest(inventory) != R6_RETAINED_INVENTORY_SHA256
    ):
        raise epoch.Rejected("EXACT_RETAINED_R6_ADMISSION_EVIDENCE_REQUIRED")
    return {
        "retained_work": R6_RETAINED_WORK.name,
        "retained_failure_sha256": failure_sha256,
        "original_latch_sha256": original_latch_sha256,
        "original_inventory": dict(inventory),
        "original_inventory_sha256": fresh.digest(inventory),
        "reviewed_continuation": True,
        "automatic_retry": False,
        "trading_started": False,
    }


def require_continuation_latch_absent(path: Path = R6_CONTINUATION_LATCH) -> None:
    directory = path.parent
    if path.is_symlink() or directory.is_symlink():
        raise epoch.Rejected("R6_CONTINUATION_LATCH_LINK_REJECTED")
    if path.exists() or directory.exists():
        raise epoch.Rejected("R6_CONTINUATION_LATCH_EXISTS_NO_AUTOMATIC_RETRY")


def read_reviewed_continuation(explicit_flag: bool) -> dict:
    """Read and hash-only inventory the single admissible failed R6 attempt."""
    if not explicit_flag:
        raise epoch.Rejected("EXPLICIT_REVIEWED_R6_CONTINUATION_REQUIRED")
    failure_path = R6_RETAINED_WORK / "failure.json"
    for path in (failure_path, R6_LATCH):
        if path.is_symlink() or not path.is_file():
            raise epoch.Rejected("EXACT_RETAINED_R6_ADMISSION_EVIDENCE_REQUIRED")
    inventory = clean.inventory_files(R6_RETAINED_WORK)
    failure_sha = fresh.sha(failure_path)
    latch_sha = fresh.sha(R6_LATCH)
    return validate_reviewed_continuation(
        explicit_flag=explicit_flag,
        failure=boot.read_json(failure_path),
        failure_sha256=failure_sha,
        original_latch=boot.read_json(R6_LATCH),
        original_latch_sha256=latch_sha,
        inventory=inventory,
    )


def validate_r5_failure() -> dict:
    """Admit only the current pinned R5 timeout; never infer from a title."""
    status = boot.SERVE_WORK / "output-serve/status.json"
    receipt = boot.SERVE_WORK / boot.RECEIPT_NAME
    for path in (status, receipt):
        if path.is_symlink() or not path.is_file():
            raise epoch.Rejected("EXACT_R5_FAILURE_EVIDENCE_REQUIRED")
    status_sha = fresh.sha(status)
    receipt_sha = fresh.sha(receipt)
    value = boot.read_json(status)
    if (
        status_sha != R5_STATUS_SHA256
        or receipt_sha != R5_RECEIPT_SHA256
        or value.get("state") != "FAILED_CLOSED"
        or value.get("mode") != "serve"
        or value.get("error_type") != "EpochError"
        or value.get("reason") != "OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT"
        or value.get("trading_started") is not False
    ):
        raise epoch.Rejected("EXACT_R5_FEED_TIMEOUT_REQUIRED")
    return {
        "failed_status_sha256": status_sha,
        "accepted_r5_receipt_sha256": receipt_sha,
    }


def validate_prestate(value: dict) -> None:
    state = feed_worker.validate_expected_state(value, include_redis=True)
    queue = state["queue"]
    if (
        state["tables"]["event_audit"]["count"] != feed_worker.BASE_AUDIT_ROWS
        or state["tables"]["message_outbox"]["count"] != feed_worker.BASE_OUTBOX_ROWS
        or state["tables"]["message_inbox"]["count"] != feed_worker.BASE_INBOX_ROWS
        or queue["pending_outbox"] != len(feed_worker.TARGETS)
        or queue["missing_inbox_message_ids"] != sorted(feed_worker.TARGET_IDS)
        or queue["completed_inbox"] != feed_worker.BASE_INBOX_ROWS
    ):
        raise epoch.Rejected("R6_EXACT_FOUR_UNPUBLISHED_PRESTATE_REQUIRED")


def validate_drained(value: dict) -> None:
    state = feed_worker.validate_expected_state(value, include_redis=True)
    queue = state["queue"]
    if (
        queue["pending_outbox"] != 0
        or queue["missing_inbox_message_ids"] != []
        or queue["completed_inbox"] != feed_worker.BASE_OUTBOX_ROWS
        or state["tables"]["message_outbox"]["count"] != feed_worker.BASE_OUTBOX_ROWS
        or state["tables"]["message_inbox"]["count"] != feed_worker.BASE_OUTBOX_ROWS
        or state["tables"]["event_audit"]["count"] != feed_worker.BASE_AUDIT_ROWS
    ):
        raise epoch.Rejected("R6_EXACT_FOUR_DRAIN_REQUIRED")


def validate_boot_bridge(r6_state: dict, boot_state: dict) -> dict:
    """Bridge the R6 Redis proof to generic boot-state's strict SQL projection."""
    state = feed_worker.validate_expected_state(r6_state, include_redis=True)
    if (
        boot_state.get("state") != "PASS_BOOT_STATE"
        or boot_state.get("tables") != state["tables"]
        or boot_state.get("sequences") != state["sequences"]
        or boot_state.get("anchors") != state["anchors"]
        or boot_state.get("original_prefix") != state["original_prefix"]
    ):
        raise epoch.Rejected("R6_POSTDRAIN_BOOT_STATE_BRIDGE_REQUIRED")
    expected_queue = {
        "outbox_rows": state["queue"]["outbox_rows"],
        "inbox_rows": state["queue"]["inbox_rows"],
        "completed_inbox": state["queue"]["completed_inbox"],
        "pending_outbox": state["queue"]["pending_outbox"],
        "unresolved_inbox": state["queue"]["unresolved_inbox"],
        "trading_rows": state["queue"]["trading_rows"],
    }
    if boot_state.get("queue") != expected_queue:
        raise epoch.Rejected("R6_POSTDRAIN_BOOT_QUEUE_BRIDGE_REQUIRED")
    if (
        state["queue"]["pending_outbox"] != 0
        or state["queue"]["missing_inbox_message_ids"]
        or state["redis"]["pending_deliveries"] != 0
        or state["redis"]["pending_target_message_ids"]
    ):
        raise epoch.Rejected("R6_POSTDRAIN_BOOT_QUEUE_NOT_CLEAN")
    return boot_state


def validate_graceful_stop_receipt(receipt: dict, status: dict) -> None:
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
        raise epoch.Rejected("R6_GRACEFUL_STOP_RECEIPT_REQUIRED")
    epoch.validate_running_status(status, boot.OWNER)


class R6FeedRecoveryController(incident.IncidentController):
    """Fresh R6 generation with exact failure admission and no automatic retry."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        names = epoch.resource_names(boot.OWNER)
        self.names["restore_pg"] = names["restore_pg"] + R6_RESTORE_SUFFIX
        self.names["restore_volume"] = names["restore_volume"] + R6_RESTORE_SUFFIX

    def r6_state(self, serving: dict, suffix: str) -> dict:
        value = self.phase(
            "r6-state",
            {**serving, "admin_password": self._admin_password},
            suffix=suffix,
        )
        feed_worker.validate_expected_state(value, include_redis=True)
        return value

    def audit_only_tail(self, baseline: dict, serving: dict, suffix: str):
        """Catch up audit history in bounded existing-cap chunks only."""
        current = self.boot_state("r6-before-tail-" + suffix)
        boot.validate_preserved_state(baseline, current)
        target_end = (
            (int(time.time() * 1000) - 65_000) // epoch.MINUTE_MS
        ) * epoch.MINUTE_MS
        receipts = []
        for index in range(MAX_CATCHUP_BATCHES):
            anchors = current["anchors"]
            required = sum(
                max(
                    0, (target_end - (row["last_close_time_ms"] + 1)) // epoch.MINUTE_MS
                )
                for row in anchors.values()
            )
            if required == 0:
                break
            batch_end = epoch.catchup_end_exclusive_ms(
                current, target_end, append_limit=epoch.MAX_CATCHUP_BARS
            )
            receipt = self.phase(
                "boot-catchup",
                {
                    "owner": boot.OWNER,
                    "database": "kairos_epoch_" + boot.OWNER[:12],
                    "pg_host": self.names["target_pg"],
                    "redis_host": self.names["redis"],
                    "history_password": self._history_password,
                    "end_exclusive_ms": batch_end,
                    "maximum_bars": epoch.MAX_CATCHUP_BARS,
                    "expected_seed": current,
                },
                suffix=suffix + "-" + str(index),
            )
            if receipt.get("state") != "AUDIT_ONLY_CATCHUP_COMPLETE":
                raise epoch.Rejected("R6_AUDIT_ONLY_BATCH_REQUIRED")
            receipts.append(receipt)
            current = self.boot_state("r6-after-tail-" + suffix + "-" + str(index))
            boot.validate_preserved_state(baseline, current)
        else:
            raise epoch.Rejected("R6_AUDIT_CATCHUP_BATCH_LIMIT")
        if sum(
            max(0, (target_end - (row["last_close_time_ms"] + 1)) // epoch.MINUTE_MS)
            for row in current["anchors"].values()
        ):
            raise epoch.Rejected("R6_AUDIT_CATCHUP_INCOMPLETE")
        return current, receipts

    def _start_r6_and_restart(self, serving: dict, baseline: dict) -> dict:
        existing = self.docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=^/" + R6_NAME + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        if existing.strip():
            raise epoch.Rejected("R6_GENERATION_MUST_BE_ABSENT")
        self.names["serve"] = R6_NAME
        self.proofs["serve_start_intent"] = True
        self.phase("serve", serving)
        status_path = self.work / "output-serve/status.json"
        deadline = min(self.deadline, time.monotonic() + 300)
        first = None
        while time.monotonic() < deadline:
            view = self.inspect_container(R6_NAME)
            if view.get("state", {}).get("Status") != "running":
                raise epoch.Rejected("R6_NEW_SERVE_FAILED_CLOSED")
            if status_path.is_file():
                status = boot.read_json(status_path)
                if status.get("state") == "FAILED_CLOSED":
                    raise epoch.Rejected("R6_NEW_SERVE_FAILED_CLOSED")
                if status.get("state") != "RUNNING_NONTRADING":
                    # SourceCircuit may report a bounded outage or catch-up state.
                    # Keep waiting until the fixed progress deadline instead of
                    # misclassifying a recoverable source pause as a bad serve.
                    time.sleep(2)
                    continue
                epoch.validate_running_status(status, boot.OWNER)
                if first is None:
                    first = status
                elif status["completed_inbox"] > first["completed_inbox"] and all(
                    status["watermarks_ms"][s] > first["watermarks_ms"][s]
                    for s in epoch.SYMBOLS
                ):
                    epoch.validate_running_status(status, boot.OWNER, previous=first)
                    container_id = view["id"]
                    self.docker(["stop", "--time=120", R6_NAME], seconds=130)
                    stopped = self.inspect_container(R6_NAME)
                    if (
                        stopped.get("id") != container_id
                        or stopped.get("state", {}).get("Status") != "exited"
                        or stopped.get("state", {}).get("ExitCode") != 0
                        or stopped.get("state", {}).get("OOMKilled") is not False
                    ):
                        raise epoch.Rejected("R6_GRACEFUL_STOP_IDENTITY_REQUIRED")
                    receipts = list(status_path.parent.glob("serve-stop-*.json"))
                    if len(receipts) != 1 or receipts[0].is_symlink():
                        raise epoch.Rejected("R6_GRACEFUL_STOP_RECEIPT_REQUIRED")
                    stop_receipt = boot.read_json(receipts[0], limit=16_384)
                    stopped_status = boot.read_json(status_path)
                    validate_graceful_stop_receipt(stop_receipt, stopped_status)
                    if stopped_status["completed_inbox"] < status[
                        "completed_inbox"
                    ] or any(
                        stopped_status["watermarks_ms"][s] < status["watermarks_ms"][s]
                        for s in epoch.SYMBOLS
                    ):
                        raise epoch.Rejected("R6_GRACEFUL_STOP_PROGRESS_ROLLBACK")
                    self.docker(["start", R6_NAME], seconds=25)
                    restart_deadline = min(self.deadline, time.monotonic() + 300)
                    previous = stopped_status
                    while time.monotonic() < restart_deadline:
                        current = boot.read_json(status_path)
                        current_view = self.inspect_container(R6_NAME)
                        if (
                            current_view.get("id") != container_id
                            or current_view.get("state", {}).get("Status") != "running"
                        ):
                            raise epoch.Rejected("R6_RESTART_IDENTITY_REQUIRED")
                        if current.get("state") == "FAILED_CLOSED":
                            raise epoch.Rejected("R6_FAILED_CLOSED_AFTER_RESTART")
                        if current.get("state") != "RUNNING_NONTRADING":
                            time.sleep(2)
                            continue
                        epoch.validate_running_status(current, boot.OWNER)
                        if all(
                            current["watermarks_ms"][s] > previous["watermarks_ms"][s]
                            for s in epoch.SYMBOLS
                        ):
                            epoch.validate_running_status(
                                current, boot.OWNER, previous=previous
                            )
                            return {
                                "name": R6_NAME,
                                "container_id": container_id,
                                "status": current,
                                "graceful_stop_receipt_sha256": fresh.sha(receipts[0]),
                                "controlled_restart": True,
                            }
                        previous = current
                        time.sleep(2)
                    raise epoch.Rejected("R6_POST_RESTART_STABILITY_REQUIRED")
            time.sleep(2)
        raise epoch.Rejected("R6_FRESH_FIVE_SYMBOL_PROGRESS_REQUIRED")

    def run_recovery(self, *, reviewed_continuation: dict | None = None) -> dict:
        failure = validate_r5_failure()
        preserved_inputs = incident.preserved_inputs()
        preserved_r5_inventory = clean.inventory_files(boot.SERVE_WORK / "output-serve")
        if (
            reviewed_continuation is not None
            and read_reviewed_continuation(True) != reviewed_continuation
        ):
            raise epoch.Rejected("R6_RETAINED_ADMISSION_EVIDENCE_CHANGED")
        resources_before = self.validate_resources(allow_running=True)
        if (
            resources_before["views"]["serve"]["state"]["Status"] != "exited"
            or resources_before["views"]["pg"]["state"]["Status"] != "running"
            or resources_before["views"]["redis"]["state"]["Status"] != "running"
        ):
            raise epoch.Rejected("R6_FAILED_R5_AND_FIXED_DATA_SERVICES_REQUIRED")
        serving = self.load_private_inputs()
        self.prepare_reviewed_snapshots()
        before = self.r6_state(serving, "before")
        validate_prestate(before)
        self.prepare_boot_restore_volume("bootbefore")
        backup_before = self.backup_and_verify(
            seed=before,
            restore_password=secrets.token_hex(32),
            tag="bootbefore",
            verification_mode="r6-verify-restore",
        )
        rechecked = self.r6_state(serving, "pre-drain")
        if before != rechecked:
            raise epoch.Rejected("R6_PRESTATE_CHANGED_DURING_BACKUP")
        drain = self.phase(
            "r6-drain",
            {
                **serving,
                "admin_password": self._admin_password,
                "expected_state": before,
            },
        )
        if (
            drain.get("state") != "PASS_EXACT_R6_PUBLICATION_AND_DRAIN"
            or drain.get("published_message_ids") != sorted(feed_worker.TARGET_IDS)
            or drain.get("completed_message_ids") != sorted(feed_worker.TARGET_IDS)
            or drain.get("published_messages") != len(feed_worker.TARGETS)
            or drain.get("completed_inbox_increment") != len(feed_worker.TARGETS)
            or drain.get("pending_deliveries") != 0
            or drain.get("trading_started") is not False
        ):
            raise epoch.Rejected("R6_EXACT_FOUR_PUBLICATION_AND_DRAIN_REQUIRED")
        clean_state = self.r6_state(serving, "after-drain")
        validate_drained(clean_state)
        clean_boot = self.boot_state("r6-after-drain-boot")
        validate_boot_bridge(clean_state, clean_boot)
        after_tail, catchup = self.audit_only_tail(clean_boot, serving, "initial")
        self.prepare_boot_restore_volume("bootafter")
        backup_after = self.backup_and_verify(
            seed=after_tail,
            restore_password=secrets.token_hex(32),
            tag="bootafter",
            verification_mode="boot-verify-restore",
        )
        final_tail, final_catchup = self.audit_only_tail(
            clean_boot, serving, "postrestore"
        )
        redis_proof = self.phase("boot-redis-state", serving, suffix="r6-before-start")
        generation = self._start_r6_and_restart(serving, after_tail)
        old_after = {
            key: self.inspect_container(identifier)
            for key, identifier in boot.CONTAINERS.items()
        }
        if (
            any(
                old_after[key] != resources_before["views"][key]
                for key in boot.CONTAINERS
            )
            or incident.preserved_inputs() != preserved_inputs
            or clean.inventory_files(boot.SERVE_WORK / "output-serve")
            != preserved_r5_inventory
            or (
                reviewed_continuation is not None
                and read_reviewed_continuation(True) != reviewed_continuation
            )
            or validate_r5_failure() != failure
            or self.assert_legacy_sources_stopped(legacy_redis_id=epoch.LEGACY_REDIS_ID)
            != resources_before["legacy"]
        ):
            raise epoch.Rejected("R6_PRIOR_R5_OR_INPUT_EVIDENCE_CHANGED")
        return {
            "result": "PASS_NEW_NONTRADING_GENERATION",
            "recovery_kind": "R6_EXACT_FEED_TIMEOUT_RECOVERY",
            "owner": boot.OWNER,
            "source_revision": self.expected_revision,
            "r5_failure": failure,
            "retained_r6_admission_continuation": reviewed_continuation,
            "prebackup_sha256": backup_before,
            "postcatchup_backup_sha256": backup_after,
            "exact_drain": drain,
            "audit_only_catchup": catchup,
            "postrestore_audit_only_catchup": final_catchup,
            "final_state_sha256": fresh.digest(final_tail),
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
    parser.add_argument("--failed-r5-status-sha256")
    parser.add_argument("--reviewed-admission-continuation", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({"result": "PLAN_ONLY", "trading_started": False}))
        return 0
    controller = None
    work = None
    try:
        boot.configure_generation_r5()
        boot.verify_source(args.expected_revision or "")
        if args.failed_r5_status_sha256 != R5_STATUS_SHA256:
            raise epoch.Rejected("EXACT_FAILED_R5_STATUS_CLAIM_REQUIRED")
        validate_r5_failure()
        require_continuation_latch_absent()
        reviewed_continuation = None
        if args.reviewed_admission_continuation:
            reviewed_continuation = read_reviewed_continuation(True)
            active_latch_dir = R6_CONTINUATION_LATCH_DIR
            active_latch = R6_CONTINUATION_LATCH
        else:
            if R6_LATCH_DIR.exists() or R6_LATCH_DIR.is_symlink():
                raise epoch.Rejected("R6_CREATE_ONLY_LATCH_EXISTS_NO_AUTOMATIC_RETRY")
            active_latch_dir = R6_LATCH_DIR
            active_latch = R6_LATCH
        run_id = uuid.uuid4().hex
        work_path = ROOT / (R6_WORK_PREFIX + run_id)
        # Acquire the separate create-only claim before any new attempt writes.
        # The original claim and failed work remain byte-for-byte unchanged.
        epoch._private_directory(active_latch_dir)
        fresh.save(
            active_latch,
            {
                "state": (
                    "REVIEWED_CONTINUATION_IN_PROGRESS"
                    if reviewed_continuation is not None
                    else "IN_PROGRESS"
                ),
                "run": run_id,
                "owner": boot.OWNER,
                "source_revision": args.expected_revision,
                "failed_r5_status_sha256": R5_STATUS_SHA256,
                "reviewed_admission_continuation": reviewed_continuation,
                "automatic_retry": False,
                "trading_started": False,
            },
        )
        epoch._private_directory(work_path)
        work = work_path
        controller = R6FeedRecoveryController(
            boot.OWNER,
            expected_revision=args.expected_revision,
            workdir=work_path,
            continuation_attempt="feed-r6-" + run_id[:8],
            deadline=time.monotonic() + MAX_SECONDS,
        )
        resources = controller.validate_resources(allow_running=True)
        if resources["views"]["serve"].get("state", {}).get(
            "Status"
        ) != "exited" or any(
            resources["views"][key].get("state", {}).get("Status") != "running"
            for key in ("pg", "redis")
        ):
            raise epoch.Rejected("R6_FAILED_R5_AND_FIXED_DATA_SERVICES_REQUIRED")
        existing = controller.docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=^/" + R6_NAME + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        if existing.strip():
            raise epoch.Rejected("R6_GENERATION_MUST_BE_ABSENT")
        if (
            reviewed_continuation is not None
            and read_reviewed_continuation(True) != reviewed_continuation
        ):
            raise epoch.Rejected("R6_RETAINED_ADMISSION_EVIDENCE_CHANGED")
        receipt = controller.run_recovery(reviewed_continuation=reviewed_continuation)
        receipt_path = work / "receipt.json"
        fresh.save(receipt_path, receipt)
        fresh.save(
            work / "accepted.json",
            {
                "state": "ACCEPTED",
                "run": run_id,
                "owner": boot.OWNER,
                "source_revision": args.expected_revision,
                "failed_r5_status_sha256": R5_STATUS_SHA256,
                "receipt_sha256": fresh.sha(receipt_path),
                "trading_started": False,
            },
        )
        print(
            json.dumps(
                {
                    "result": "ACCEPTED",
                    "receipt": str(receipt_path),
                    "trading_started": False,
                }
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - sanitized failure, immutable evidence.
        if controller is not None:
            controller.fail_closed_cleanup()
        if work is not None:
            fresh.save(
                work / "failure.json",
                {
                    "result": "FAILED_CLOSED",
                    "reason": str(exc)
                    if isinstance(exc, epoch.Rejected)
                    else "operation failed; private diagnostic withheld",
                    "phase": getattr(controller, "current_phase", "ADMISSION"),
                    "automatic_retry": False,
                    "trading_started": False,
                },
            )
        print(json.dumps({"result": "FAILED_CLOSED", "trading_started": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
