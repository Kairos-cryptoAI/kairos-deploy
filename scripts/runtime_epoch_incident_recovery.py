"""One reviewed continuation of the stopped non-trading epoch, not a retry loop.

The original failed serve and all its inputs/receipts are retained. Only a fresh
generation may start, after full read-only reconciliation, backup/clone proof,
exact one-message completion, audit-only catch-up and a second restore proof.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_boot as boot
    from scripts import runtime_epoch_incident_observation as observation
else:
    import runtime_epoch_boot as boot
    import runtime_epoch_incident_observation as observation

epoch = boot.epoch
fresh = epoch.fresh
ROOT = Path("D:/Kairos/runtime/runtime-incident-20261012")
LEASE = ROOT / "recovery.active"
PREBACKUP_WORK = ROOT / "recovery-d97a2bf75ace41ed8ba498de2b1919f8"
PREBACKUP_FAILURE_SHA256 = (
    "e01819d87959162e97dc34d4c29b491f42ae003fee64cd58ca466111709ac0c6"
)
PREBACKUP_STATE_SHA256 = (
    "1c9a1b1473f77cfa26c91127595cd753263d9203e69337669032dbc14fa41b9d"
)
REVIEWED_LEASE = ROOT / "reviewed-prebackup-02.active"
RESTORE_REFUSAL_WORK = ROOT / "recovery-1006ced2555a4e90a609b2f436146667"
RESTORE_REFUSAL_SHA256 = (
    "ce580c73e069fb7c88a3c3965ba4b4d7c976e8998c2fd8d2e58d9a5b8381b987"
)
RESTORE_REFUSAL_DUMP_SHA256 = (
    "38bb064ad6d6e53dc9e35381bf2e5c1323326cf40a8b00518027e79e767fad4f"
)
RESTORE_REFUSAL_CLONE_ID = (
    "04c62398273ac7bedcfa036e2d035ff0ac7406aeb6deb1b43a3aefb69ef75895"
)
REVIEWED_RESTORE_LEASE = ROOT / "reviewed-restore-03.active"
OBSERVATION = ROOT / "observation-eca4d844945b493daf669366945d266e/receipt.json"
OBSERVATION_SHA256 = "f47dff8bfc56cb5c387188cd5b7fb465809321c55c9d0580c3d172b97059b312"
GENERATION_NAME = "kairos-epoch-" + boot.OWNER[:12] + "-serve-r2"
MAX_SECONDS = 1800


def preserved_inputs() -> dict:
    return {str(path): fresh.sha(path) for path in boot.input_paths()}


def load_observation() -> dict:
    if fresh.sha(OBSERVATION) != OBSERVATION_SHA256:
        raise epoch.Rejected("EXACT_READONLY_INCIDENT_OBSERVATION_REQUIRED")
    value = boot.read_json(OBSERVATION)
    if (
        value.get("result") != "PASS_READONLY_INCIDENT_OBSERVATION"
        or value.get("owner") != boot.OWNER
        or value.get("trading_started") is not False
        or set(value.get("comparisons", {})) != set(observation.SYMBOLS)
        or any(
            row.get("pages_equal") is not True
            or row.get("persisted_anchor_matches") is not True
            for row in value["comparisons"].values()
        )
        or value.get("database_counts")
        != {
            "audit_rows": 334355,
            "outbox_rows": 4546,
            "pending_outbox": 1,
            "inbox_rows": 4545,
            "unresolved_inbox": 0,
            "trading_rows": 0,
        }
    ):
        raise epoch.Rejected("INCIDENT_RECONCILIATION_PRECONDITIONS_REQUIRED")
    return value


def validate_reviewed_prebackup_failure(
    claim: str,
    *,
    accepted_work: Path | None = None,
    active_lease: Path = REVIEWED_LEASE,
) -> dict:
    """One exact operator-reviewed refusal, before dump or publication, not an automatic retry."""
    failure_path = PREBACKUP_WORK / "failure.json"
    state_path = PREBACKUP_WORK / "output-incident-state-before/incident-state.json"
    if (
        claim != PREBACKUP_FAILURE_SHA256
        or fresh.sha(failure_path) != claim
        or fresh.sha(state_path) != PREBACKUP_STATE_SHA256
        or boot.read_json(failure_path)
        != {
            "automatic_retry": False,
            "phase": "incident-state-before",
            "reason": "PRIVATE_CREATE_ONLY_EPOCH_DUMP_REQUIRED",
            "result": "FAILED_CLOSED",
            "trading_started": False,
        }
        or boot.read_json(LEASE)
        != {
            "owner": boot.OWNER,
            "run": "d97a2bf75ace41ed8ba498de2b1919f8",
            "source_revision": "72c781c1aa15e97ac990bfede4c2ddf74ae85418",
        }
        or any(PREBACKUP_WORK.glob("epoch-history-*.dump"))
        or (PREBACKUP_WORK / "config-incident-drain.json").exists()
        or (PREBACKUP_WORK / "output-incident-drain").exists()
    ):
        raise epoch.Rejected("EXACT_REVIEWED_PREBACKUP_REFUSAL_REQUIRED")
    if accepted_work is not None:
        active = boot.read_json(active_lease)
        if (
            active.get("owner") != boot.OWNER
            or re.fullmatch(r"[0-9a-f]{32}", str(active.get("run"))) is None
            or fresh.safe(accepted_work) != ROOT / ("recovery-" + active["run"])
        ):
            raise epoch.Rejected("EXACT_CURRENT_ACCEPTED_RECOVERY_WORK_REQUIRED")
    for candidate in ROOT.glob("recovery-*"):
        if candidate == accepted_work or not candidate.is_dir():
            continue
        if (
            (candidate / "config-incident-drain.json").exists()
            or (candidate / "output-incident-drain").exists()
            or any(candidate.rglob("one-publication-intent.json"))
        ):
            raise epoch.Rejected("PRIOR_PUBLICATION_INTENT_REQUIRES_SEPARATE_REVIEW")
    inventory = {
        path.relative_to(PREBACKUP_WORK).as_posix(): fresh.sha(fresh.safe(path))
        for path in sorted(PREBACKUP_WORK.rglob("*"))
        if path.is_file()
    }
    return {
        "failure_sha256": claim,
        "state_sha256": PREBACKUP_STATE_SHA256,
        "inventory_sha256": fresh.digest(inventory),
        "lease_sha256": fresh.sha(LEASE),
        "state": boot.read_json(state_path),
        "old_attempt_retained": True,
    }


def validate_reviewed_restore_refusal(claim: str) -> dict:
    if (
        claim != RESTORE_REFUSAL_SHA256
        or fresh.sha(RESTORE_REFUSAL_WORK / "failure.json") != claim
        or fresh.sha(RESTORE_REFUSAL_WORK / "epoch-history-bootbefore.dump")
        != RESTORE_REFUSAL_DUMP_SHA256
        or boot.read_json(RESTORE_REFUSAL_WORK / "failure.json")
        != {
            "automatic_retry": False,
            "phase": "incident-verify-restore-bootbefore",
            "reason": "WORKER_MODE_REQUIRED",
            "result": "FAILED_CLOSED",
            "trading_started": False,
        }
        or boot.read_json(REVIEWED_LEASE)
        != {
            "owner": boot.OWNER,
            "run": "1006ced2555a4e90a609b2f436146667",
            "source_revision": "297c9e3edb876e6efaa03cc3bd85135de47f271f",
        }
        or (RESTORE_REFUSAL_WORK / "config-incident-drain.json").exists()
        or (RESTORE_REFUSAL_WORK / "output-incident-drain").exists()
    ):
        raise epoch.Rejected("EXACT_REVIEWED_RESTORE_REFUSAL_REQUIRED")
    inventory = {
        path.relative_to(RESTORE_REFUSAL_WORK).as_posix(): fresh.sha(fresh.safe(path))
        for path in sorted(RESTORE_REFUSAL_WORK.rglob("*"))
        if path.is_file()
    }
    return {
        "failure_sha256": claim,
        "backup_sha256": RESTORE_REFUSAL_DUMP_SHA256,
        "inventory_sha256": fresh.digest(inventory),
        "lease_sha256": fresh.sha(REVIEWED_LEASE),
        "retained_clone_id": RESTORE_REFUSAL_CLONE_ID,
        "old_attempt_retained": True,
    }


class IncidentController(boot.BootController):
    def load_private_inputs(self) -> dict:
        serving = boot.read_json(boot.SERVE_WORK / "config-serve.json")
        epoch.validate_worker_config(serving, mode="serve")
        self._admin_password = (
            (boot.PARENT / "target-admin-password").read_text().strip()
        )
        self._history_password = epoch.read_attempt_04_rotated_history_secret(
            boot.PARENT / "continuation-04/continuation-private.json", owner=boot.OWNER
        )
        if any(
            re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in (self._admin_password, self._history_password)
        ):
            raise epoch.Rejected("EXACT_GENERATED_EPOCH_CREDENTIALS_REQUIRED")
        return serving

    def prepare_reviewed_snapshots(self) -> None:
        quant_lock = subprocess.run(
            [
                str(epoch.GIT),
                "-C",
                str(epoch.QUANT_REPO),
                "show",
                epoch.QUANT_REVISION + ":uv.lock",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=True,
            shell=False,
        ).stdout
        epoch.validate_aux_wheelhouse(epoch.AUX_WHEELHOUSE, quant_lock)
        self.prepare_snapshots()

    def audit_only_tail(self, baseline: dict, suffix: str) -> tuple[dict, dict | None]:
        current = self.boot_state("before-tail-" + suffix)
        boot.validate_preserved_state(baseline, current)
        end = ((int(time.time() * 1000) - 65_000) // epoch.MINUTE_MS) * epoch.MINUTE_MS
        required = sum(
            (end - anchor["last_close_time_ms"] - 1) // epoch.MINUTE_MS
            for anchor in current["anchors"].values()
        )
        if not 0 <= required <= epoch.MAX_CATCHUP_BARS:
            raise epoch.Rejected("INCIDENT_FIXED_AUDIT_CATCHUP_CAP_EXCEEDED")
        receipt = None
        if required:
            receipt = self.phase(
                "boot-catchup",
                {
                    "owner": boot.OWNER,
                    "database": "kairos_epoch_" + boot.OWNER[:12],
                    "pg_host": self.names["target_pg"],
                    "redis_host": self.names["redis"],
                    "history_password": self._history_password,
                    "end_exclusive_ms": end,
                    "maximum_bars": epoch.MAX_CATCHUP_BARS,
                    "expected_seed": current,
                },
                suffix=suffix,
            )
        after = self.boot_state("after-tail-" + suffix)
        boot.validate_preserved_state(baseline, after)
        return after, receipt

    def start_new_generation(self, serving: dict) -> dict:
        existing = self.docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=^/" + GENERATION_NAME + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        if existing.strip():
            raise epoch.Rejected("NEW_SERVE_GENERATION_MUST_BE_ABSENT")
        self.names["serve"] = GENERATION_NAME
        self.phase("serve", serving)
        output = self.work / "output-serve/status.json"
        deadline = min(self.deadline, time.monotonic() + 180)
        initial = None
        while time.monotonic() < deadline:
            view = self.inspect_container(GENERATION_NAME)
            if view["state"]["Status"] != "running":
                raise epoch.Rejected("NEW_GENERATION_FAILED_CLOSED")
            if output.is_file():
                status = boot.read_json(output)
                epoch.validate_running_status(status, boot.OWNER)
                if initial is None:
                    initial = status
                elif status["completed_inbox"] > initial["completed_inbox"] and all(
                    status["watermarks_ms"][symbol] > initial["watermarks_ms"][symbol]
                    for symbol in observation.SYMBOLS
                ):
                    return {
                        "name": GENERATION_NAME,
                        "container_id": view["id"],
                        "status": status,
                        "original_failed_serve_retained": True,
                    }
            time.sleep(2)
        raise epoch.Rejected("NEW_GENERATION_FRESH_FIVE_SYMBOL_ADVANCE_REQUIRED")

    def run_incident_recovery(self) -> dict:
        admitted = load_observation()
        if (
            fresh.sha(boot.SERVE_WORK / "runtime-epoch-continuation-receipt.json")
            != boot.PARENT_RECEIPT_SHA256
            or epoch.ACTIVE_LEASE.read_text().strip() != boot.OWNER
        ):
            raise epoch.Rejected("ACCEPTED_ORIGINAL_EPOCH_AND_OWNER_REQUIRED")
        before_resources = self.validate_resources(allow_running=True)
        reviewed_restore = getattr(self, "reviewed_restore", None)
        retained_clone = None
        if reviewed_restore is not None:
            retained_clone = self.inspect_container(RESTORE_REFUSAL_CLONE_ID)
            if (
                retained_clone.get("state", {}).get("Status") != "exited"
                or retained_clone.get("id") != RESTORE_REFUSAL_CLONE_ID
                or retained_clone.get("image") != epoch.PG_IMAGE.split("@", 1)[-1]
                or retained_clone.get("labels", {}).get(epoch.EPOCH_LABEL) != boot.OWNER
                or retained_clone.get("ports")
            ):
                raise epoch.Rejected("EXACT_STOPPED_RESTORE_REFUSAL_CLONE_REQUIRED")
        if before_resources["views"]["serve"]["state"]["Status"] != "exited" or any(
            before_resources["views"][key]["state"]["Status"] != "running"
            for key in ("pg", "redis")
        ):
            raise epoch.Rejected("ORIGINAL_FAILED_SERVE_MUST_REMAIN_STOPPED")
        failure_before = observation.failure_snapshot(boot.SERVE_WORK / "output-serve")
        if failure_before != admitted["preserved_failures"]:
            raise epoch.Rejected("ORIGINAL_INCIDENT_FAILURE_CHANGED")
        input_before = preserved_inputs()
        serving = self.load_private_inputs()
        self.prepare_reviewed_snapshots()
        incident_config = {**serving, "admin_password": self._admin_password}
        before = self.phase("incident-state", incident_config, suffix="before")
        reviewed = getattr(self, "reviewed_prebackup", None)
        if reviewed is not None:
            if before != reviewed["state"]:
                raise epoch.Rejected("REVIEWED_PREBACKUP_NATIVE_STATE_CHANGED")
            # Preserve the original initialized-but-unused volume, too. A wholly
            # new disposable restore volume is used by the reviewed continuation.
            self.names["restore_volume"] += (
                "-incident03" if reviewed_restore is not None else "-incident02"
            )
            if reviewed_restore is not None:
                self.names["restore_pg"] += "-incident03"
        self.prepare_boot_restore_volume("bootbefore")
        backup_before = self.backup_and_verify(
            seed=before,
            restore_password=secrets.token_hex(32),
            tag="bootbefore",
            verification_mode="incident-verify-restore",
        )
        # Re-read the entire state after restore; a stale observation cannot authorize dispatch.
        rechecked = self.phase("incident-state", incident_config, suffix="pre-drain")
        if before != rechecked:
            raise epoch.Rejected("INCIDENT_PRESTATE_CHANGED_DURING_BACKUP")
        completed = self.phase(
            "incident-drain", {**incident_config, "expected_state": before}
        )
        clean = self.boot_state("after-exact-drain")
        after, catchup = self.audit_only_tail(clean, "incident-initial")
        self.prepare_boot_restore_volume("bootafter")
        backup_after = self.backup_and_verify(
            seed=after,
            restore_password=secrets.token_hex(32),
            tag="bootafter",
            verification_mode="boot-verify-restore",
        )
        final_state, final_catchup = self.audit_only_tail(clean, "incident-postrestore")
        redis_proof = self.phase(
            "boot-redis-state", serving, suffix="clean-generation-input"
        )
        generation = self.start_new_generation(serving)
        # Validate old resources by exact IDs after launching the new generation.
        old_views = {
            key: self.inspect_container(identifier)
            for key, identifier in boot.CONTAINERS.items()
        }
        if any(
            before_resources["views"][key] != old_views[key] for key in boot.CONTAINERS
        ):
            raise epoch.Rejected("ORIGINAL_EPOCH_RESOURCE_IDENTITY_CHANGED")
        legacy = self.assert_legacy_sources_stopped(
            legacy_redis_id=epoch.LEGACY_REDIS_ID
        )
        if (
            legacy != before_resources["legacy"]
            or input_before != preserved_inputs()
            or failure_before
            != observation.failure_snapshot(boot.SERVE_WORK / "output-serve")
        ):
            raise epoch.Rejected("INCIDENT_PRESERVED_EVIDENCE_OR_LEGACY_CHANGED")
        if reviewed is not None and reviewed != validate_reviewed_prebackup_failure(
            PREBACKUP_FAILURE_SHA256,
            accepted_work=self.work,
            active_lease=REVIEWED_RESTORE_LEASE
            if reviewed_restore is not None
            else REVIEWED_LEASE,
        ):
            raise epoch.Rejected("REVIEWED_PREBACKUP_EVIDENCE_CHANGED")
        if reviewed_restore is not None and (
            reviewed_restore
            != validate_reviewed_restore_refusal(RESTORE_REFUSAL_SHA256)
            or retained_clone != self.inspect_container(RESTORE_REFUSAL_CLONE_ID)
        ):
            raise epoch.Rejected("REVIEWED_RESTORE_REFUSAL_EVIDENCE_CHANGED")
        return {
            "result": "PASS_NEW_NONTRADING_GENERATION",
            "owner": boot.OWNER,
            "source_revision": self.expected_revision,
            "observation_sha256": OBSERVATION_SHA256,
            "backup_before_sha256": backup_before,
            "backup_after_sha256": backup_after,
            "exact_drain": completed,
            "audit_only_catchup": catchup,
            "postrestore_audit_only_catchup": final_catchup,
            "before_generation_state_sha256": fresh.digest(final_state),
            "redis_proof": redis_proof,
            "generation": generation,
            "original_inputs_sha256": fresh.digest(input_before),
            "original_failure_sha256": fresh.digest(failure_before),
            "reviewed_restore_refusal": reviewed_restore,
            "reviewed_prebackup_failure": (
                {k: v for k, v in reviewed.items() if k != "state"}
                if reviewed is not None
                else None
            ),
            "legacy_preservation": legacy,
            "worker_wheel_manifest_sha256": epoch.WHEEL_MANIFEST_SHA256,
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
    parser.add_argument("--reviewed-prebackup-failure-sha256")
    parser.add_argument("--reviewed-restore-refusal-sha256")
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
    controller = None
    work = None
    active_lease = LEASE
    try:
        boot.verify_source(args.expected_revision or "")
        load_observation()
        reviewed = None
        reviewed_restore = None
        if (
            args.reviewed_prebackup_failure_sha256
            and args.reviewed_restore_refusal_sha256
        ):
            raise epoch.Rejected("REVIEWED_CONTINUATION_CHOICES_ARE_EXCLUSIVE")
        if args.reviewed_restore_refusal_sha256:
            reviewed = validate_reviewed_prebackup_failure(PREBACKUP_FAILURE_SHA256)
            reviewed_restore = validate_reviewed_restore_refusal(
                args.reviewed_restore_refusal_sha256
            )
            active_lease = REVIEWED_RESTORE_LEASE
        elif args.reviewed_prebackup_failure_sha256:
            reviewed = validate_reviewed_prebackup_failure(
                args.reviewed_prebackup_failure_sha256
            )
            active_lease = REVIEWED_LEASE
        if active_lease.exists():
            raise epoch.Rejected("FAILED_OR_ACTIVE_INCIDENT_RECOVERY_REQUIRES_REVIEW")
        run = uuid.uuid4().hex
        work = ROOT / ("recovery-" + run)
        epoch._private_directory(work)
        fresh.save(
            active_lease,
            {
                "run": run,
                "owner": boot.OWNER,
                "source_revision": args.expected_revision,
            },
        )
        controller = IncidentController(
            boot.OWNER,
            expected_revision=args.expected_revision,
            workdir=work,
            continuation_attempt="r2-" + run[:8],
            deadline=time.monotonic() + MAX_SECONDS,
        )
        controller.reviewed_prebackup = reviewed
        controller.reviewed_restore = reviewed_restore
        result = controller.run_incident_recovery()
        path = work / "receipt.json"
        fresh.save(path, result)
        if boot.read_json(active_lease).get("run") != run:
            raise epoch.Rejected("INCIDENT_RECOVERY_LEASE_CHANGED")
        active_lease.unlink()
        print(
            json.dumps(
                {
                    "result": result["result"],
                    "receipt": str(path),
                    "sha256": fresh.sha(path),
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - no native/credential-bearing diagnostics.
        reason = str(exc) if isinstance(exc, epoch.Rejected) else type(exc).__name__
        if controller:
            controller.fail_closed_cleanup()
        if work:
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
