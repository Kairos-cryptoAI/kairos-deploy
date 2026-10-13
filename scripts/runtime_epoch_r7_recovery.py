"""Reviewed R7 non-trading recovery; never restart failed R6 or legacy queues.

Default is PLAN_ONLY. One create-only claim binds this operation to the exact
failed R6 receipt. Cold byte copies precede starting the two epoch data services;
full SQL state and isolated restore precede any new consumer/producer. Unknown
or dirty queues are refused, not reset or guessed. All failed work is retained.
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
    from scripts import runtime_epoch_feed_recovery as feed
else:
    import runtime_epoch_boot as boot
    import runtime_epoch_clean_queue_recovery as clean
    import runtime_epoch_feed_recovery as feed

epoch, fresh = boot.epoch, boot.epoch.fresh
ROOT = Path("D:/Kairos/runtime/runtime-incident-20261013")
CLAIM = ROOT / "read-recovery-r7-claim"
FAILED_STATUS_SHA256 = (
    "ff04fb579a9fb0313eac34707da620b2c3ca429fbdf0fb77e2edf43736ddf082"
)
NAME = "kairos-epoch-" + boot.OWNER[:12] + "-serve-r7"
MAX_SECONDS = 7200


def admitted_failure() -> dict:
    status = boot.SERVE_WORK / "output-serve/status.json"
    receipt = boot.SERVE_WORK / boot.RECEIPT_NAME
    if (
        status.is_symlink()
        or receipt.is_symlink()
        or fresh.sha(status) != FAILED_STATUS_SHA256
        or fresh.sha(receipt) != boot.PARENT_RECEIPT_SHA256
    ):
        raise epoch.Rejected("R7_EXACT_RETAINED_R6_EVIDENCE_REQUIRED")
    value = boot.read_json(status)
    if (
        value.get("state") != "FAILED_CLOSED"
        or value.get("mode") != "serve"
        or value.get("error_type") != "EpochError"
        or value.get("reason") != "REDIS_RECOVERY_DEADLINE_EXCEEDED"
        or value.get("trading_started") is not False
    ):
        raise epoch.Rejected("R7_EXACT_REVIEWED_REDIS_FAILURE_REQUIRED")
    accepted = boot.read_json(receipt)
    progress = accepted.get("generation", {}).get("status")
    if not isinstance(progress, dict):
        raise epoch.Rejected("R7_ACCEPTED_R6_PROGRESS_REQUIRED")
    observed = datetime.fromisoformat(
        progress["observed_at_utc"].replace("Z", "+00:00")
    )
    epoch.validate_running_status(
        progress, boot.OWNER, now_ms=int(observed.timestamp() * 1000)
    )
    return {
        "failed_status_sha256": FAILED_STATUS_SHA256,
        "accepted_r6_receipt_sha256": boot.PARENT_RECEIPT_SHA256,
        "historical_root_cause_proven": False,
        "automatic_retry": False,
        "accepted_minimum_completed_inbox": progress["completed_inbox"],
        "accepted_minimum_watermarks_ms": progress["watermarks_ms"],
    }


def validate_clean_before_start(state: dict) -> None:
    queue = state.get("queue", {})
    if (
        state.get("state") != "PASS_BOOT_STATE"
        or state.get("trading_started") is not False
        or queue.get("pending_outbox") != 0
        or queue.get("unresolved_inbox") != 0
        or queue.get("trading_rows") != 0
        or queue.get("outbox_rows") != queue.get("inbox_rows")
        or queue.get("completed_inbox") != queue.get("inbox_rows")
        or state.get("matched_public_tables") != 32
        or any(
            type(queue.get(k)) is not int or queue[k] < 0
            for k in ("outbox_rows", "inbox_rows", "completed_inbox")
        )
    ):
        raise epoch.Rejected("R7_REQUIRES_EXACT_CLEAN_NONTRADING_STATE")


class R7RecoveryController(feed.R6FeedRecoveryController):
    def __init__(self, *args, run_id: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.run_id = run_id
        names = epoch.resource_names(boot.OWNER)
        self.names["restore_pg"] = names["restore_pg"] + "-transport07"
        self.names["restore_volume"] = names["restore_volume"] + "-transport07"

    def assert_new_generation_absent(self) -> None:
        if self.docker(
            ["ps", "-a", "--filter", "name=^/" + NAME + "$", "--format", "{{.Names}}"]
        ).strip():
            raise epoch.Rejected("R7_MUST_BE_ABSENT_NO_AUTOMATIC_RETRY")

    def cold_backup(self, key: str, *, uid: int) -> dict:
        """Retain an independent owner-labelled cold volume, without network."""
        self.current_phase = "COLD_BACKUP_" + key.upper()
        source = self.names["target_volume" if key == "pg" else "redis_volume"]
        target = (
            "kairos-epoch-"
            + boot.OWNER[:12]
            + "-r7-cold-"
            + key
            + "-"
            + self.run_id[:8]
        )
        if self.docker(
            [
                "volume",
                "ls",
                "--filter",
                "name=^" + target + "$",
                "--format",
                "{{.Name}}",
            ]
        ).strip():
            raise epoch.Rejected("R7_COLD_VOLUME_MUST_BE_ABSENT")
        original_source = self.names["source_volume"]
        self.names["source_volume"] = target
        try:
            self.create_volume(target)
            # distinct initializer identity; the fixed owned source is never initialized.
            self.initialize_volume(target, uid=uid)
        finally:
            self.names["source_volume"] = original_source
        snapshot = self.work / "cold-operator"
        if not snapshot.exists():
            epoch.extract_git_snapshot(
                epoch.REPO,
                self.expected_revision,
                ("scripts/runtime_epoch_cold_snapshot.py",),
                snapshot,
                strip_prefix="scripts",
            )
        name = (
            "kairos-epoch-"
            + boot.OWNER[:12]
            + "-r7-cold-copy-"
            + key
            + "-"
            + self.run_id[:8]
        )
        self.docker(
            [
                "create",
                "--pull=never",
                "--name",
                name,
                "--network=none",
                "--user=" + str(uid) + ":" + str(uid),
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--memory=512m",
                "--memory-swap=512m",
                "--cpus=1",
                "--pids-limit=32",
                "--label",
                epoch.EPOCH_LABEL + "=" + boot.OWNER,
                "--label",
                "com.kairos.runtime-epoch.scope=" + epoch.EPOCH_SCOPE,
                "--mount",
                "type=volume,src=" + source + ",dst=/source,readonly",
                "--mount",
                "type=volume,src=" + target + ",dst=/target",
                "--mount",
                "type=bind,src=" + str(snapshot) + ",dst=/operator,readonly",
                "--entrypoint",
                "/usr/bin/timeout",
                epoch.WORKER_IMAGE,
                "-s",
                "KILL",
                "930",
                "python",
                "-B",
                "/operator/runtime_epoch_cold_snapshot.py",
                "--copy-owned-cold-volume",
            ]
        )
        self.created.append(name)
        view = self.inspect_container(name)
        if (
            view.get("network") != "none"
            or view.get("ports")
            or view.get("readonly") is not True
            or view.get("caps") != ["ALL"]
            or view.get("privileged")
            or view.get("memory") != 512 * 1024**2
            or view.get("swap") != 512 * 1024**2
            or view.get("cpus") != 1_000_000_000
            or view.get("image") != epoch.WORKER_IMAGE.split("@", 1)[-1]
        ):
            raise epoch.Rejected("R7_COLD_COPY_SANDBOX_REQUIRED")
        self.require_mount_set(
            name,
            {
                source: ("/source", False),
                target: ("/target", True),
                str(snapshot): ("/operator", False),
            },
        )
        output = self.docker(["start", "--attach", name], seconds=940)
        finished = self.inspect_container(name)
        if (
            finished.get("id") != view.get("id")
            or finished.get("state", {}).get("ExitCode") != 0
            or len(output) > 16_384
        ):
            raise epoch.Rejected("R7_COLD_COPY_SUCCESS_REQUIRED")
        proof = json.loads(output)
        if (
            proof.get("state") != "PASS_COLD_BYTE_COPY"
            or proof.get("source_unchanged") is not True
            or proof.get("restore_proven") is not False
        ):
            raise epoch.Rejected("R7_COLD_BYTE_PROOF_REQUIRED")
        self.docker(["rm", name])
        self.created.remove(name)
        proof = {**proof, "source_volume": source, "retained_volume": target}
        fresh.save(self.work / ("cold-" + key + ".json"), proof)
        return proof

    def await_progress(self, previous: dict | None = None) -> dict:
        until = min(self.deadline - 30, time.monotonic() + 300)
        first = previous
        while time.monotonic() < until:
            view = self.inspect_container(NAME)
            if view.get("state", {}).get("Status") != "running":
                raise epoch.Rejected("R7_SERVE_EXITED_FAIL_CLOSED")
            path = self.work / "output-serve/status.json"
            if path.is_file():
                status = boot.read_json(path)
                if status.get("state") == "FAILED_CLOSED":
                    raise epoch.Rejected("R7_SERVE_FAILED_CLOSED")
                if status.get("state") == "RUNNING_NONTRADING":
                    epoch.validate_running_status(status, boot.OWNER)
                    if first is None:
                        first = status
                    elif status["completed_inbox"] > first["completed_inbox"] and all(
                        status["watermarks_ms"][s] > first["watermarks_ms"][s]
                        for s in epoch.SYMBOLS
                    ):
                        epoch.validate_running_status(
                            status, boot.OWNER, previous=first
                        )
                        return {"container_id": view["id"], "status": status}
            time.sleep(2)
        raise epoch.Rejected("R7_FRESH_FIVE_SYMBOL_PROGRESS_TIMEOUT")

    def start_and_restart(self, serving: dict) -> dict:
        self.assert_new_generation_absent()
        self.names["serve"] = NAME
        self.proofs["serve_start_intent"] = True
        self.phase("serve", serving)
        initial = self.await_progress()
        self.docker(["stop", "--time=120", NAME], seconds=130)
        stopped = self.inspect_container(NAME)
        if (
            stopped.get("id") != initial["container_id"]
            or stopped.get("state", {}).get("Status") != "exited"
            or stopped["state"].get("ExitCode") != 0
            or stopped["state"].get("OOMKilled") is not False
        ):
            raise epoch.Rejected("R7_GRACEFUL_STOP_REQUIRED")
        status_path = self.work / "output-serve/status.json"
        paths = list(status_path.parent.glob("serve-stop-*.json"))
        if len(paths) != 1 or paths[0].is_symlink():
            raise epoch.Rejected("R7_EXACT_STOP_RECEIPT_REQUIRED")
        stopped_status = boot.read_json(status_path)
        stop_receipt = boot.read_json(paths[0])
        feed.validate_graceful_stop_receipt(stop_receipt, stopped_status)
        self.docker(["start", NAME], seconds=25)
        restarted = self.await_progress(stopped_status)
        if restarted["container_id"] != initial["container_id"]:
            raise epoch.Rejected("R7_RESTART_IDENTITY_CONFLICT")
        return {
            "name": NAME,
            **restarted,
            "graceful_restart_proven": True,
            "stop_receipt_sha256": fresh.sha(paths[0]),
            "failed_r6_retained": True,
        }

    def run_recovery(self) -> dict:
        failure = admitted_failure()
        preserved = feed.incident.preserved_inputs()
        output_inventory = clean.inventory_files(boot.SERVE_WORK / "output-serve")
        resources = self.validate_resources(allow_running=True)
        if any(
            resources["views"][key]["state"]["Status"] != "exited"
            for key in ("pg", "redis", "serve")
        ):
            raise epoch.Rejected("R7_ALL_REVIEWED_RESOURCES_MUST_BE_STOPPED")
        self.assert_new_generation_absent()
        serving = self.load_private_inputs()
        self.prepare_reviewed_snapshots()
        cold = {
            "pg": self.cold_backup("pg", uid=70),
            "redis": self.cold_backup("redis", uid=999),
        }
        if self.validate_resources(allow_running=True) != resources:
            raise epoch.Rejected("R7_STOPPED_RESOURCES_CHANGED_DURING_COLD_BACKUP")
        for key in ("target_pg", "redis"):
            self.docker(["start", self.names[key]], seconds=30)
        self.wait_postgres(self.names["target_pg"])
        self.validate_resources()
        before = self.boot_state("r7-before")
        validate_clean_before_start(before)
        if before["queue"]["completed_inbox"] < failure[
            "accepted_minimum_completed_inbox"
        ] or any(
            before["anchors"][symbol]["last_close_time_ms"] + 1
            < failure["accepted_minimum_watermarks_ms"][symbol]
            for symbol in epoch.SYMBOLS
        ):
            raise epoch.Rejected("R7_ACCEPTED_R6_PROGRESS_ROLLBACK_REJECTED")
        self.prepare_boot_restore_volume("bootbefore")
        before_hash = self.backup_and_verify(
            seed=before,
            restore_password=secrets.token_hex(32),
            tag="bootbefore",
            verification_mode="boot-verify-restore",
        )
        if self.boot_state("r7-after-backup") != before:
            raise epoch.Rejected("R7_STATE_CHANGED_DURING_BACKUP")
        redis_proof = self.phase(
            "boot-redis-state", serving, suffix="r7-before-catchup"
        )
        after, catchup = self.audit_only_tail(before, serving, "r7-initial")
        self.prepare_boot_restore_volume("bootafter")
        after_hash = self.backup_and_verify(
            seed=after,
            restore_password=secrets.token_hex(32),
            tag="bootafter",
            verification_mode="boot-verify-restore",
        )
        final, final_tail = self.audit_only_tail(before, serving, "r7-final")
        self.phase("boot-redis-state", serving, suffix="r7-before-start")
        generation = self.start_and_restart(serving)
        if (
            admitted_failure() != failure
            or feed.incident.preserved_inputs() != preserved
            or clean.inventory_files(boot.SERVE_WORK / "output-serve")
            != output_inventory
            or self.inspect_container(boot.CONTAINERS["serve"])
            != resources["views"]["serve"]
            or self.assert_legacy_sources_stopped(legacy_redis_id=epoch.LEGACY_REDIS_ID)
            != resources["legacy"]
        ):
            raise epoch.Rejected("R7_RETAINED_OR_LEGACY_EVIDENCE_CHANGED")
        return {
            "result": "PASS_NEW_NONTRADING_GENERATION",
            "recovery_kind": "R7_REDIS_TRANSPORT_RECOVERY",
            "owner": boot.OWNER,
            "source_revision": self.expected_revision,
            "r6_failure": failure,
            "cold_backups": cold,
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
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--expected-revision")
    parser.add_argument("--failed-r6-status-sha256")
    args = parser.parse_args(argv)
    if not args.execute:
        print(
            json.dumps(
                {
                    "result": "PLAN_ONLY",
                    "old_serve_restart": False,
                    "trading_started": False,
                }
            )
        )
        return 0
    controller, work = None, None
    try:
        boot.configure_generation_r6()
        boot.verify_source(args.expected_revision or "")
        if args.failed_r6_status_sha256 != FAILED_STATUS_SHA256:
            raise epoch.Rejected("R7_EXPLICIT_FAILED_STATUS_BINDING_REQUIRED")
        admitted_failure()
        if CLAIM.exists() or CLAIM.is_symlink():
            raise epoch.Rejected("R7_CREATE_ONLY_CLAIM_EXISTS_NO_RETRY")
        if not ROOT.exists():
            epoch._private_directory(ROOT)
        run_id = uuid.uuid4().hex
        epoch._private_directory(CLAIM)
        fresh.save(
            CLAIM / "claim.json",
            {
                "run": run_id,
                "source_revision": args.expected_revision,
                "failed_r6_status_sha256": FAILED_STATUS_SHA256,
                "automatic_retry": False,
                "trading_started": False,
            },
        )
        work = ROOT / ("read-recovery-r7-" + run_id)
        epoch._private_directory(work)
        controller = R7RecoveryController(
            boot.OWNER,
            run_id=run_id,
            expected_revision=args.expected_revision,
            workdir=work,
            continuation_attempt="r7-" + run_id[:8],
            deadline=time.monotonic() + MAX_SECONDS,
        )
        receipt = controller.run_recovery()
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
    except (Exception, KeyboardInterrupt, SystemExit) as exc:  # noqa: BLE001 - preserve interrupted native evidence as well.
        if controller is not None:
            # A global operation deadline must not consume the cleanup reserve.
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
                    "trading_started": False,
                    "automatic_retry": False,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
