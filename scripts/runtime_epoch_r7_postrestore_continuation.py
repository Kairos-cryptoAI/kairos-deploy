"""One reviewed R7 post-drain continuation; never reprocess the exact ten.

The refused attempt's dumps, exact inbox completion and full post-catchup state
are immutable inputs. Fresh full backups/restores use a new transport08 clone.
The old created read-only helper is never started. No old queue is addressed.
"""

from __future__ import annotations

import argparse
import json
import secrets
import time
import uuid
from datetime import UTC, datetime

if __package__:
    from scripts import runtime_epoch_r7_queue_continuation as reviewed
else:
    import runtime_epoch_r7_queue_continuation as reviewed

recovery, boot, epoch, fresh = (
    reviewed.recovery,
    reviewed.boot,
    reviewed.epoch,
    reviewed.fresh,
)
RETAINED = recovery.ROOT / "read-recovery-r7-8f27f0f753ef4016877eeecce9969aad"
FAILURE_SHA256 = "35bc44a146cb183ccf4105307b21a35dced800916157cf5087cf822e828eb355"
DRAIN_SHA256 = "38ebda67898452c32ea48d22e8327bdec9ed0feea867ab7a9e1d76b35e2c2609"
STATE_SHA256 = "962a3407b589cb891f53dbeceb38e8e651c0bf8f03dd4b8273e716dc91d0c01a"
DUMP_SHA256 = "1d5b5db0a009a9a3db4b4316926deb8f315e3c0838a7f7c050e83a3b993fccc1"
CLONE_ID = "dd5abb38197187e523d8b12e9b4b91e5346f8a66ed63d60cbfe79be5c5a41fc9"
UNSTARTED_ID = "efc506dd6e7ed0e9edb0f24cb67b2e30290908adc17ae24e77a23066d81a49fe"
UNSTARTED_NAME = "kairos-epoch-69893dc7b7c6-continue-r7-reviewed-8f27f0f7-boot-verify-restore-bootafter"
CLAIM = recovery.ROOT / "read-recovery-r7-reviewed-postrestore-claim"


def retained_evidence() -> dict:
    files = {
        "failure.json": FAILURE_SHA256,
        "output-r7-drain/r7-drain.json": DRAIN_SHA256,
        "output-boot-state-r6-after-tail-r7-reviewed-initial-0/boot-state.json": STATE_SHA256,
        "epoch-history-bootafter.dump": DUMP_SHA256,
    }
    if any(
        fresh.sha(fresh.safe(RETAINED / path)) != digest
        for path, digest in files.items()
    ):
        raise epoch.Rejected("EXACT_RETAINED_R7_POSTRESTORE_EVIDENCE_REQUIRED")
    failure = boot.read_json(RETAINED / "failure.json")
    if failure != {
        "automatic_retry": False,
        "phase": "boot-verify-restore-bootafter",
        "reason": "BOUNDED_DOCKER_OPERATION_FAILED_GATEERROR",
        "result": "FAILED_CLOSED",
        "trading_started": False,
    }:
        raise epoch.Rejected("EXACT_POSTRESTORE_CLI_REFUSAL_REQUIRED")
    drain = boot.read_json(RETAINED / "output-r7-drain/r7-drain.json")
    if (
        drain.get("state") != "PASS_EXACT_R7_INBOX_RECOVERY"
        or drain.get("completed_message_ids") != sorted(reviewed.profile.R7_TARGET_IDS)
        or drain.get("completed_inbox_increment") != 10
        or any(
            drain.get(key) != 0
            for key in (
                "published_messages",
                "stream_entries_added",
                "publication_receipts_added",
                "pending_deliveries",
            )
        )
        or drain.get("trading_started") is not False
    ):
        raise epoch.Rejected("EXACT_COMPLETED_TEN_NO_REPLAY_REQUIRED")
    state = boot.core_snapshot(
        boot.read_json(
            RETAINED / next(path for path in files if path.endswith("boot-state.json"))
        )
    )
    recovery.validate_clean_before_start(state)
    if state["queue"]["completed_inbox"] != 8045:
        raise epoch.Rejected("EXACT_POSTDRAIN_8045_REQUIRED")
    return {
        "bound_files": files,
        "inventory": recovery.clean.inventory_files(RETAINED),
        "state": state,
        "completed_ten_receipt": drain,
        "first_r7_admission": reviewed.retained_evidence(),
        "automatic_retry": False,
        "repeated_drain": False,
    }


class PostRestoreController(recovery.R7RecoveryController):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        names = epoch.resource_names(boot.OWNER)
        self.names["restore_pg"] = names["restore_pg"] + "-transport08"
        self.names["restore_volume"] = names["restore_volume"] + "-transport08"

    def retain_failed_clone_and_helper(self) -> dict:
        clone = self.inspect_container(CLONE_ID)
        helper = self.inspect_container(UNSTARTED_ID)
        for view, name, identifier, image in (
            (
                clone,
                "kairos-epoch-69893dc7b7c6-restore-transport07",
                CLONE_ID,
                epoch.PG_IMAGE,
            ),
            (helper, UNSTARTED_NAME, UNSTARTED_ID, epoch.WORKER_IMAGE),
        ):
            if (
                view.get("id") != identifier
                or view.get("name") != "/" + name
                or view.get("image") != image.split("@", 1)[-1]
                or view.get("labels", {}).get(epoch.EPOCH_LABEL) != boot.OWNER
                or view.get("labels", {}).get("com.kairos.runtime-epoch.scope")
                != epoch.EPOCH_SCOPE
                or view.get("ports")
                or view.get("privileged")
                or view.get("readonly") is not True
                or view.get("caps") != ["ALL"]
            ):
                raise epoch.Rejected(
                    "EXACT_RETAINED_READONLY_ATTEMPT_RESOURCES_REQUIRED"
                )
        if (
            helper.get("state", {}).get("Status") != "created"
            or helper["state"].get("StartedAt") != "0001-01-01T00:00:00Z"
        ):
            raise epoch.Rejected("OLD_READONLY_HELPER_MUST_NEVER_HAVE_STARTED")
        if clone.get("state", {}).get("Status") == "running":
            self.docker(["stop", "--time=30", CLONE_ID], seconds=45)
        stopped = self.inspect_container(CLONE_ID)
        if (
            stopped.get("id") != CLONE_ID
            or stopped.get("state", {}).get("Status") != "exited"
        ):
            raise epoch.Rejected("RETAINED_CLONE_STOP_REQUIRED_NO_REMOVAL")
        return {"clone": stopped, "unstarted_helper": helper, "removed": False}

    def run_postrestore(self) -> dict:
        admitted = retained_evidence()
        failure = recovery.admitted_failure()
        preserved_r6 = recovery.clean.inventory_files(boot.SERVE_WORK / "output-serve")
        original_inputs = recovery.feed.incident.preserved_inputs()
        self.assert_legacy_sources_stopped(legacy_redis_id=epoch.LEGACY_REDIS_ID)
        self.assert_new_generation_absent()
        allowed = {
            "kairos-epoch-69893dc7b7c6-pg",
            "kairos-epoch-69893dc7b7c6-redis",
            "kairos-epoch-69893dc7b7c6-restore-transport07",
            boot.STANDBY_NAME,
        }
        if any(
            name.startswith("kairos-") and name not in allowed
            for name in self.docker(["ps", "--format", "{{.Names}}"]).splitlines()
        ):
            raise epoch.Rejected("POSTRESTORE_OTHER_KAIROS_PROCESS_RUNNING")
        retained_resources = self.retain_failed_clone_and_helper()
        resources = self.validate_resources(allow_running=True)
        if resources["views"]["serve"]["state"]["Status"] != "exited" or any(
            resources["views"][key]["state"]["Status"] != "running"
            for key in ("pg", "redis")
        ):
            raise epoch.Rejected("FIXED_NONTRADING_DATA_SERVICES_ONLY_REQUIRED")
        serving = self.load_private_inputs()
        self.prepare_reviewed_snapshots()
        before = self.boot_state("r7-postrestore-before")
        if before != admitted["state"]:
            raise epoch.Rejected("POSTDRAIN_STATE_CHANGED_NO_REPLAY")
        self.prepare_boot_restore_volume("bootbefore")
        before_hash = self.backup_and_verify(
            seed=before,
            restore_password=secrets.token_hex(32),
            tag="bootbefore",
            verification_mode="boot-verify-restore",
        )
        if self.boot_state("r7-postrestore-after-first-restore") != before:
            raise epoch.Rejected("POSTDRAIN_STATE_CHANGED_DURING_RESTORE")
        after, catchup = self.audit_only_tail(before, serving, "r7-postrestore-initial")
        self.prepare_boot_restore_volume("bootafter")
        after_hash = self.backup_and_verify(
            seed=after,
            restore_password=secrets.token_hex(32),
            tag="bootafter",
            verification_mode="boot-verify-restore",
        )
        final, final_tail = self.audit_only_tail(
            before, serving, "r7-postrestore-final"
        )
        redis = self.phase(
            "boot-redis-state", serving, suffix="r7-postrestore-before-start"
        )
        generation = self.start_and_restart(serving)
        if (
            retained_evidence() != admitted
            or recovery.admitted_failure() != failure
            or recovery.clean.inventory_files(boot.SERVE_WORK / "output-serve")
            != preserved_r6
            or recovery.feed.incident.preserved_inputs() != original_inputs
            or self.inspect_container(CLONE_ID) != retained_resources["clone"]
            or self.inspect_container(UNSTARTED_ID)
            != retained_resources["unstarted_helper"]
            or self.inspect_container(boot.CONTAINERS["serve"])
            != resources["views"]["serve"]
            or self.assert_legacy_sources_stopped(legacy_redis_id=epoch.LEGACY_REDIS_ID)
            != resources["legacy"]
        ):
            raise epoch.Rejected("RETAINED_POSTRESTORE_OR_LEGACY_EVIDENCE_CHANGED")
        return {
            "result": "PASS_NEW_NONTRADING_GENERATION",
            "recovery_kind": "R7_REDIS_TRANSPORT_RECOVERY",
            "owner": boot.OWNER,
            "source_revision": self.expected_revision,
            "r6_failure": failure,
            "postrestore_reviewed_continuation": admitted,
            "retained_resources": retained_resources,
            "exact_nonpublishing_drain": admitted["completed_ten_receipt"],
            "cold_backups": admitted["first_r7_admission"]["cold_backups"],
            "prebackup_sha256": before_hash,
            "postcatchup_backup_sha256": after_hash,
            "audit_only_catchup": catchup,
            "postrestore_audit_only_catchup": final_tail,
            "final_state_sha256": fresh.digest(final),
            "redis_proof": redis,
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
    parser.add_argument("--execute-reviewed-postrestore", action="store_true")
    parser.add_argument("--expected-revision")
    parser.add_argument("--retained-failure-sha256")
    args = parser.parse_args(argv)
    if not args.execute_reviewed_postrestore:
        print(
            json.dumps(
                {
                    "result": "PLAN_ONLY",
                    "repeated_drain": False,
                    "trading_started": False,
                }
            )
        )
        return 0
    controller, work = None, None
    try:
        boot.configure_generation_r6()
        boot.verify_source(args.expected_revision or "")
        if args.retained_failure_sha256 != FAILURE_SHA256:
            raise epoch.Rejected("EXPLICIT_POSTRESTORE_REFUSAL_BINDING_REQUIRED")
        retained_evidence()
        if CLAIM.exists() or CLAIM.is_symlink():
            raise epoch.Rejected("POSTRESTORE_CLAIM_EXISTS_NO_AUTOMATIC_RETRY")
        run_id = uuid.uuid4().hex
        epoch._private_directory(CLAIM)
        fresh.save(
            CLAIM / "claim.json",
            {
                "run": run_id,
                "source_revision": args.expected_revision,
                "retained_failure_sha256": FAILURE_SHA256,
                "automatic_retry": False,
                "repeated_drain": False,
                "trading_started": False,
            },
        )
        work = recovery.ROOT / ("read-recovery-r7-" + run_id)
        epoch._private_directory(work)
        controller = PostRestoreController(
            boot.OWNER,
            run_id=run_id,
            expected_revision=args.expected_revision,
            workdir=work,
            continuation_attempt="r7-postrestore-" + run_id[:8],
            deadline=time.monotonic() + recovery.MAX_SECONDS,
        )
        receipt = controller.run_postrestore()
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
    except (Exception, KeyboardInterrupt, SystemExit) as exc:  # noqa: BLE001 - preserve every interrupted contour.
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
