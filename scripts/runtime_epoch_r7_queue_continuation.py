"""One explicit reviewed continuation after R7's exact clean-queue refusal.

Only the ten fixed already-published CLOSED_BAR deliveries may be completed.
Full before-state dump and isolated SQL restore precede consumer-only drain.
Nothing publishes in that drain. R6, the failed R7 attempt, cold backups and
legacy databases/queues are retained; any conflict fails closed, never retries.
"""

from __future__ import annotations

import argparse
import json
import secrets
import time
import uuid
from datetime import UTC, datetime

if __package__:
    from scripts import runtime_epoch_r7_read_profile as profile
    from scripts import runtime_epoch_r7_recovery as recovery
else:
    import runtime_epoch_r7_read_profile as profile
    import runtime_epoch_r7_recovery as recovery

boot, epoch, fresh = recovery.boot, recovery.epoch, recovery.fresh
RETAINED = recovery.ROOT / "read-recovery-r7-671d54912d014d21ba6058ba34cab238"
FAILURE_SHA256 = "1d9d6143335b56c75321b25c404fec9776c344b5c6740ff0f3de5b8640779cfc"
CLAIM = recovery.ROOT / "read-recovery-r7-reviewed-ten-claim"
FAILURE = {
    "automatic_retry": False,
    "phase": "boot-state-r7-before",
    "reason": "WORKER_MODE_FAILED_BOOT-STATE",
    "result": "FAILED_CLOSED",
    "trading_started": False,
}


def retained_evidence() -> dict:
    failure = RETAINED / "failure.json"
    status = RETAINED / "output-boot-state-r7-before/status.json"
    if fresh.sha(failure) != FAILURE_SHA256 or boot.read_json(failure) != FAILURE:
        raise epoch.Rejected("EXACT_R7_RETAINED_REFUSAL_REQUIRED")
    observed = boot.read_json(status)
    if (
        observed.get("state") != "FAILED_CLOSED"
        or observed.get("mode") != "boot-state"
        or observed.get("reason") != "BOOT_QUEUE_ORPHAN_OR_UNRESOLVED_ROW"
        or observed.get("trading_started") is not False
    ):
        raise epoch.Rejected("EXACT_R7_CLEAN_QUEUE_REFUSAL_REQUIRED")
    cold = {
        key: boot.read_json(RETAINED / ("cold-" + key + ".json"))
        for key in ("pg", "redis")
    }
    for key, proof in cold.items():
        if (
            proof.get("state") != "PASS_COLD_BYTE_COPY"
            or proof.get("source_unchanged") is not True
            or proof.get("retained_volume")
            != "kairos-epoch-" + boot.OWNER[:12] + "-r7-cold-" + key + "-671d5491"
        ):
            raise epoch.Rejected("EXACT_RETAINED_COLD_BACKUPS_REQUIRED")
    return {
        "failure_sha256": FAILURE_SHA256,
        "failed_work_inventory": recovery.clean.inventory_files(RETAINED),
        "cold_backups": cold,
        "automatic_retry": False,
    }


class ReviewedQueueController(recovery.R7RecoveryController):
    def prepare_reviewed_snapshots(self) -> None:
        super().prepare_reviewed_snapshots()
        copied = self.work / "r7-profile-input"
        manifest = epoch.extract_git_snapshot(
            epoch.REPO,
            self.expected_revision,
            ("scripts/runtime_epoch_r7_read_profile.py",),
            copied,
            strip_prefix="scripts",
        )
        fresh.write(
            self.operator_snapshot / "runtime_epoch_r7_read_profile.py",
            (copied / "runtime_epoch_r7_read_profile.py").read_bytes(),
        )
        self.proofs["r7_profile_snapshot_sha256"] = fresh.digest(manifest)

    def r7_state(self, serving: dict, tag: str) -> dict:
        return self.phase(
            "r7-state", {**serving, "admin_password": self._admin_password}, suffix=tag
        )

    def run_continuation(self) -> dict:
        admitted = retained_evidence()
        failure = recovery.admitted_failure()
        preserved_r6 = recovery.clean.inventory_files(boot.SERVE_WORK / "output-serve")
        original_inputs = recovery.feed.incident.preserved_inputs()
        resources = self.validate_resources(allow_running=True)
        if resources["views"]["serve"]["state"]["Status"] != "exited" or any(
            resources["views"][k]["state"]["Status"] != "running"
            for k in ("pg", "redis")
        ):
            raise epoch.Rejected("REVIEWED_R7_REQUIRES_FIXED_DATA_SERVICES_ONLY")
        self.assert_new_generation_absent()
        for proof in admitted["cold_backups"].values():
            view = json.loads(
                self.docker(
                    [
                        "volume",
                        "inspect",
                        "--format",
                        "{{json .}}",
                        proof["retained_volume"],
                    ]
                )
            )
            if (
                view.get("Labels", {}).get(epoch.EPOCH_LABEL) != boot.OWNER
                or view.get("Labels", {}).get("com.kairos.runtime-epoch.scope")
                != epoch.EPOCH_SCOPE
            ):
                raise epoch.Rejected("RETAINED_COLD_BACKUP_OWNERSHIP_REQUIRED")
        serving = self.load_private_inputs()
        self.prepare_reviewed_snapshots()
        before = self.r7_state(serving, "before")
        profile.validate_expected_state(before)
        self.prepare_boot_restore_volume("bootbefore")
        before_hash = self.backup_and_verify(
            seed=before,
            restore_password=secrets.token_hex(32),
            tag="bootbefore",
            verification_mode="r7-verify-restore",
        )
        if self.r7_state(serving, "pre-drain") != before:
            raise epoch.Rejected("EXACT_TEN_PRESTATE_CHANGED_DURING_RESTORE")
        drain = self.phase(
            "r7-drain",
            {
                **serving,
                "admin_password": self._admin_password,
                "expected_state": before,
            },
        )
        if (
            drain.get("state") != "PASS_EXACT_R7_INBOX_RECOVERY"
            or drain.get("completed_message_ids") != sorted(profile.R7_TARGET_IDS)
            or drain.get("completed_inbox_increment") != 10
            or any(
                drain.get(k) != 0
                for k in (
                    "published_messages",
                    "stream_entries_added",
                    "publication_receipts_added",
                    "pending_deliveries",
                )
            )
            or drain.get("audit_history_preserved") is not True
            or drain.get("outbox_and_sequences_preserved") is not True
            or drain.get("trading_started") is not False
        ):
            raise epoch.Rejected("EXACT_TEN_NONPUBLISHING_DRAIN_REQUIRED")
        clean = self.boot_state("r7-clean-after-ten")
        recovery.validate_clean_before_start(clean)
        if clean["queue"]["completed_inbox"] != 8045:
            raise epoch.Rejected("EXACT_REVIEWED_R7_COMPLETION_COUNT_REQUIRED")
        after, catchup = self.audit_only_tail(clean, serving, "r7-reviewed-initial")
        self.prepare_boot_restore_volume("bootafter")
        after_hash = self.backup_and_verify(
            seed=after,
            restore_password=secrets.token_hex(32),
            tag="bootafter",
            verification_mode="boot-verify-restore",
        )
        final, final_tail = self.audit_only_tail(clean, serving, "r7-reviewed-final")
        redis_proof = self.phase(
            "boot-redis-state", serving, suffix="r7-reviewed-before-start"
        )
        generation = self.start_and_restart(serving)
        if (
            retained_evidence() != admitted
            or recovery.admitted_failure() != failure
            or recovery.clean.inventory_files(boot.SERVE_WORK / "output-serve")
            != preserved_r6
            or recovery.feed.incident.preserved_inputs() != original_inputs
            or self.inspect_container(boot.CONTAINERS["serve"])
            != resources["views"]["serve"]
            or self.assert_legacy_sources_stopped(legacy_redis_id=epoch.LEGACY_REDIS_ID)
            != resources["legacy"]
        ):
            raise epoch.Rejected("RETAINED_R7_OR_R6_OR_LEGACY_EVIDENCE_CHANGED")
        return {
            "result": "PASS_NEW_NONTRADING_GENERATION",
            "recovery_kind": "R7_REDIS_TRANSPORT_RECOVERY",
            "owner": boot.OWNER,
            "source_revision": self.expected_revision,
            "r6_failure": failure,
            "reviewed_queue_continuation": admitted,
            "exact_nonpublishing_drain": drain,
            "cold_backups": admitted["cold_backups"],
            "prebackup_sha256": before_hash,
            "postcatchup_backup_sha256": after_hash,
            "audit_only_catchup": catchup,
            "postrestore_audit_only_catchup": final_tail,
            "final_state_sha256": fresh.digest(final),
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
    parser.add_argument("--execute-reviewed-ten", action="store_true")
    parser.add_argument("--expected-revision")
    parser.add_argument("--retained-failure-sha256")
    args = parser.parse_args(argv)
    if not args.execute_reviewed_ten:
        print(
            json.dumps(
                {"result": "PLAN_ONLY", "publisher_calls": 0, "trading_started": False}
            )
        )
        return 0
    controller, work = None, None
    try:
        boot.configure_generation_r6()
        boot.verify_source(args.expected_revision or "")
        if args.retained_failure_sha256 != FAILURE_SHA256:
            raise epoch.Rejected("EXPLICIT_REVIEWED_R7_FAILURE_BINDING_REQUIRED")
        retained_evidence()
        if CLAIM.exists() or CLAIM.is_symlink():
            raise epoch.Rejected("REVIEWED_R7_CLAIM_EXISTS_NO_AUTOMATIC_RETRY")
        run_id = uuid.uuid4().hex
        epoch._private_directory(CLAIM)
        fresh.save(
            CLAIM / "claim.json",
            {
                "run": run_id,
                "source_revision": args.expected_revision,
                "retained_failure_sha256": FAILURE_SHA256,
                "automatic_retry": False,
                "publisher_calls": 0,
                "trading_started": False,
            },
        )
        work = recovery.ROOT / ("read-recovery-r7-" + run_id)
        epoch._private_directory(work)
        controller = ReviewedQueueController(
            boot.OWNER,
            run_id=run_id,
            expected_revision=args.expected_revision,
            workdir=work,
            continuation_attempt="r7-reviewed-" + run_id[:8],
            deadline=time.monotonic() + recovery.MAX_SECONDS,
        )
        receipt = controller.run_continuation()
        fresh.save(work / "receipt.json", receipt)
        fresh.save(
            work / "accepted.json",
            {
                "state": "ACCEPTED",
                "run": run_id,
                "owner": boot.OWNER,
                "source_revision": args.expected_revision,
                "receipt_sha256": fresh.sha(work / "receipt.json"),
                "trading_started": False,
            },
        )
        print(
            json.dumps(
                {
                    "result": "ACCEPTED",
                    "receipt": str(work / "receipt.json"),
                    "trading_started": False,
                }
            )
        )
        return 0
    except (Exception, KeyboardInterrupt, SystemExit) as exc:  # noqa: BLE001 - fixed diagnostics only, immutable failures.
        if controller is not None:
            controller.deadline = time.monotonic() + 60
            controller.fail_closed_cleanup()
        if work is not None:
            fresh.save(
                work / "failure.json",
                {
                    "result": "FAILED_CLOSED",
                    "reason": str(exc)
                    if isinstance(exc, epoch.Rejected)
                    else "PRIVATE_DIAGNOSTIC_WITHHELD",
                    "phase": getattr(controller, "current_phase", "ADMISSION"),
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
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
