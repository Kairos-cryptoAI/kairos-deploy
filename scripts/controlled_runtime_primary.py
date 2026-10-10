"""Guarded primary schema/quarantine transition after signed clone acceptance.

The default command is a plan-only report. Execution is explicit and limited
to the original PostgreSQL container: no compose, Redis, consumers, publisher,
trading, strategy, orders, PAPER/LIVE, or paid APIs are started or contacted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import controlled_runtime_transition as current
    from scripts import fresh_runtime_recovery as fresh
else:
    import controlled_runtime_transition as current
    import fresh_runtime_recovery as fresh

KIND = "controlled-runtime-primary-v1"
CONFIRM_PRIMARY = "CONTROLLED_RUNTIME_PRIMARY_SCHEMA_QUARANTINE_ONLY_NO_CONSUMERS"
SIGNER = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
TRUSTED_KEY = fresh.REPO / "tests/offline_outbox_reconciliation/trusted-signer.asc"
TRUSTED_KEY_SHA256 = "3d130656e0fdff59c5efd44cb0779ea89af49b5684a3435863d24d403ccf9358"
GPG = (
    Path(r"C:\Program Files\Git\usr\bin\gpg.exe")
    if os.name == "nt"
    else Path("/usr/bin/gpg")
)
GPGV = (
    Path(r"C:\Program Files\Git\usr\bin\gpgv.exe")
    if os.name == "nt"
    else Path("/usr/bin/gpgv")
)
MAX_SECONDS = 1800
MAX_PRIVATE_SQL_BYTES = 64 * 1024
MAX_PRIMARY_TEMP_BYTES = 256 * 1024 * 1024


def remote_artifact_specs(owner: str) -> dict[str, tuple[str, str]]:
    if not re.fullmatch(r"[0-9a-f]{32}", owner):
        raise fresh.Rejected("PRIMARY_REMOTE_ARTIFACT_OWNER_INVALID")
    short = owner[:12]
    return {
        "provision-sql": ("/tmp/controlled-runtime-" + short + ".sql", "provision.sql"),
        "cleanup-sql": (
            "/tmp/controlled-runtime-cleanup-" + short + ".sql",
            "cleanup-role.sql",
        ),
        "backup-after": (
            "/tmp/controlled-primary-after-" + short + ".dump",
            "primary-after.dump",
        ),
    }


def remote_artifact_cleanup_evidence(run: Path, owner: str, revision: str) -> dict:
    """Bind immutable create/remove records without reading SQL or auth values."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise fresh.Rejected("PRIMARY_REMOTE_ARTIFACT_REVISION_INVALID")
    specs = remote_artifact_specs(owner)
    if run.is_symlink() or getattr(run.lstat(), "st_file_attributes", 0) & 0x400:
        raise fresh.Rejected("PRIMARY_REMOTE_ARTIFACT_DIRECTORY_INVALID")
    expected_names = {
        prefix + purpose + ".json"
        for purpose in specs
        for prefix in ("remote-create-", "remote-remove-")
    }
    observed_names = {
        path.name
        for prefix in ("remote-create-", "remote-remove-")
        for path in run.glob(prefix + "*.json")
    }
    if observed_names - expected_names:
        raise fresh.Rejected("PRIMARY_REMOTE_ARTIFACT_RECORD_SET_INVALID")
    bindings, pending = {}, []
    created = completed = 0
    for purpose, (remote_path, _local_name) in specs.items():
        intent_path = run / ("remote-create-" + purpose + ".json")
        remove_path = run / ("remote-remove-" + purpose + ".json")
        if not intent_path.exists():
            if remove_path.exists() or intent_path.is_symlink():
                raise fresh.Rejected("PRIMARY_REMOTE_ARTIFACT_ORPHAN_RECORD")
            continue
        intent = _json(intent_path)
        expected_size = intent.get("expected_bytes")
        expected_sha = intent.get("expected_sha256")
        maximum = intent.get("maximum_bytes")
        if (
            set(intent)
            != {
                "schema_version",
                "kind",
                "owner",
                "source_container_id",
                "purpose",
                "remote_path",
                "expected_revision",
                "expected_sha256",
                "expected_bytes",
                "maximum_bytes",
            }
            or intent.get("schema_version") != 1
            or intent.get("kind") != "controlled-primary-remote-create-v1"
            or intent.get("owner") != owner
            or intent.get("source_container_id") != fresh.SOURCE_ID
            or intent.get("purpose") != purpose
            or intent.get("remote_path") != remote_path
            or intent.get("expected_revision") != revision
            or type(maximum) is not int
            or (
                purpose == "backup-after"
                and (
                    expected_size is not None
                    or expected_sha is not None
                    or maximum != MAX_PRIMARY_TEMP_BYTES
                )
            )
            or (
                purpose != "backup-after"
                and (
                    type(expected_size) is not int
                    or not 0 < expected_size <= MAX_PRIVATE_SQL_BYTES
                    or maximum != expected_size
                    or not re.fullmatch(r"[0-9a-f]{64}", str(expected_sha))
                )
            )
        ):
            raise fresh.Rejected("PRIMARY_REMOTE_CREATE_INTENT_INVALID")
        created += 1
        intent_sha = fresh.sha(intent_path)
        bindings[intent_path.name] = intent_sha
        if not remove_path.exists():
            if remove_path.is_symlink():
                raise fresh.Rejected("PRIMARY_REMOTE_REMOVE_RECORD_INVALID")
            pending.append(purpose)
            continue
        removal = _json(remove_path)
        observed_size = removal.get("observed_bytes")
        observed_sha = removal.get("observed_sha256")
        outcome = removal.get("outcome")
        if (
            set(removal)
            != {
                "schema_version",
                "kind",
                "owner",
                "source_container_id",
                "purpose",
                "remote_path",
                "create_intent_sha256",
                "outcome",
                "observed_sha256",
                "observed_bytes",
            }
            or removal.get("schema_version") != 1
            or removal.get("kind") != "controlled-primary-remote-remove-v1"
            or removal.get("owner") != owner
            or removal.get("source_container_id") != fresh.SOURCE_ID
            or removal.get("purpose") != purpose
            or removal.get("remote_path") != remote_path
            or removal.get("create_intent_sha256") != intent_sha
            or outcome not in {"ABSENT", "OWNED_BYTES_REMOVED"}
            or (
                outcome == "ABSENT"
                and (observed_size is not None or observed_sha is not None)
            )
            or (
                outcome == "OWNED_BYTES_REMOVED"
                and (
                    type(observed_size) is not int
                    or not 0 <= observed_size <= maximum
                    or not re.fullmatch(r"[0-9a-f]{64}", str(observed_sha))
                    or (
                        purpose != "backup-after"
                        and observed_size == expected_size
                        and observed_sha != expected_sha
                    )
                )
            )
        ):
            raise fresh.Rejected("PRIMARY_REMOTE_REMOVE_RECORD_INVALID")
        completed += 1
        bindings[remove_path.name] = fresh.sha(remove_path)
    return {
        "verified": not pending,
        "created_count": created,
        "completed_count": completed,
        "pending_purposes": pending,
        "record_sha256": bindings,
    }


class SupervisorContext(current.Controller):
    """Minimal fresh bounded Docker/process owner for the outer watchdog."""

    def __init__(self, directory: Path):
        self.owner = uuid.uuid4().hex
        self.work = fresh.safe(directory)
        self.work.mkdir()
        (self.work / "docker-config").mkdir()
        fresh.save(
            self.work / "docker-config/config.json", fresh.auth_free_docker_config()
        )
        self.deadline = time.monotonic() + MAX_SECONDS + 180
        self.cleanup_deadline = None
        self.native = fresh.bounded.Native(self.work)
        self.proofs, self.scratch_directories, self.owned, self.workers = {}, [], {}, {}
        self.protect_backup_directory()


def _supervisor_stop_if_started(context: SupervisorContext, owner: str) -> bool:
    run = current.ROOT / ("primary-run-" + owner)
    marker_path = run / "started-primary.json"
    if not marker_path.exists():
        return True
    marker = _json(marker_path)
    if (
        marker.get("owner") != owner
        or marker.get("source_container_id") != fresh.SOURCE_ID
        or marker.get("start_intent_written_before_docker_start") is not True
    ):
        raise fresh.Rejected("PRIMARY_START_MARKER_IDENTITY_INVALID")
    view = context.inspect(fresh.SOURCE)
    if (
        view["id"] != fresh.SOURCE_ID
        or view["image"] != fresh.IMAGE_ID
        or (view["labels"] or {}).get("com.docker.compose.service") != "timescaledb"
    ):
        raise fresh.Rejected("SUPERVISOR_REFUSES_CHANGED_PRIMARY_CONTAINER")
    if view["state"].get("Status") == "running":
        mounts = [
            m
            for m in view["mounts"]
            if m.get("Destination") == "/var/lib/postgresql/data"
        ]
        if (
            len(mounts) != 1
            or mounts[0].get("Name") != fresh.VOLUME
            or mounts[0].get("Type") != "volume"
            or view["ports"]
            or view["privileged"]
        ):
            raise fresh.Rejected("SUPERVISOR_PRIMARY_VOLUME_BOUNDARY_CHANGED")
        context.docker(["stop", "--time=30", fresh.SOURCE], seconds=45)
    stopped = context.inspect(fresh.SOURCE)
    if (
        stopped["id"] != fresh.SOURCE_ID
        or stopped["state"].get("Status") != "exited"
        or stopped["state"].get("Running")
        or stopped["state"].get("Pid")
    ):
        raise fresh.Rejected("SUPERVISOR_COULD_NOT_STOP_ORIGINAL_PRIMARY")
    context.cleanup_deadline = time.monotonic() + 60
    for identifier in context.docker(
        ["ps", "-aq", "--filter", "label=" + fresh.OWNER_LABEL + "=" + owner]
    ).splitlines():
        item = context.inspect(identifier)
        labels = item["labels"] or {}
        name = item["name"].lstrip("/")
        allowed_prefixes = (
            "kairos-controlled-" + owner[:12] + "-",
            "kairos-recovery-" + owner[:12] + "-",
        )
        if (
            labels.get(fresh.OWNER_LABEL) != owner
            or labels.get("com.kairos.recovery.scope")
            not in {current.KIND, fresh.SCOPE}
            or not name.startswith(allowed_prefixes)
            or item["image"] not in {current.RUNNER, fresh.IMAGE_ID}
        ):
            raise fresh.Rejected("SUPERVISOR_OWNED_CONTAINER_IDENTITY_MISMATCH")
        context.docker(["rm", "-f", name], seconds=20)
    if context.docker(
        ["ps", "-aq", "--filter", "label=" + fresh.OWNER_LABEL + "=" + owner]
    ):
        raise fresh.Rejected("SUPERVISOR_OWNED_CONTAINER_CLEANUP_UNVERIFIED")
    return True


def supervise_primary(args) -> int:
    if args.supervisor_directory is not None:
        raise fresh.Rejected("PRIMARY_SUPERVISOR_DIRECTORY_IS_AUTOGENERATED")
    owner_match = re.fullmatch(
        r"run-([0-9a-f]{32})", fresh.safe(args.clone_directory).name
    )
    if owner_match is None:
        raise fresh.Rejected("SIGNED_CURRENT_CLONE_DIRECTORY_REQUIRED")
    owner = owner_match.group(1)
    directory = fresh.safe(current.ROOT / ("primary-supervisor-" + uuid.uuid4().hex))
    context = SupervisorContext(directory)
    stdout, stderr = directory / "child.stdout", directory / "child.stderr"
    admission = directory / "child-admission.json"
    token = secrets.token_urlsafe(32)
    fresh.save(
        admission,
        {
            "owner": owner,
            "nonce_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "confirmation": CONFIRM_PRIMARY,
        },
    )
    job = fresh.bounded._job_module().WindowsProcessJob()
    child = None
    error = None
    started = time.monotonic()
    tree = None
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(Path(__file__).absolute()),
                    "--execute-primary",
                    "--supervised-child",
                    "--supervisor-token",
                    token,
                    "--supervisor-directory",
                    str(directory),
                    "--confirmation",
                    CONFIRM_PRIMARY,
                    "--clone-directory",
                    str(args.clone_directory),
                    "--clone-supervisor-directory",
                    str(args.clone_supervisor_directory),
                    "--expected-revision",
                    args.expected_revision,
                    "--wheelhouse",
                    str(args.wheelhouse),
                ],
                cwd=fresh.REPO,
                env=fresh.supervisor_environment(),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                shell=False,
                creationflags=job.creation_flags,
            )
            job.attach_and_resume(child)
            fresh.save(
                directory / "started.json",
                {
                    "supervisor_pid": os.getpid(),
                    "child_pid": child.pid,
                    "owner": owner,
                    "maximum_seconds": MAX_SECONDS + 90,
                    "assigned_before_resume": True,
                },
            )
            while child.poll() is None:
                if (
                    time.monotonic() - started >= MAX_SECONDS + 90
                    or max(stdout.stat().st_size, stderr.stat().st_size) > 256 * 1024
                ):
                    raise fresh.Rejected("PRIMARY_SUPERVISOR_BOUND_EXCEEDED")
                time.sleep(0.1)
    except BaseException as caught:  # noqa: BLE001 -- capture interruption, stop source, and retain evidence.
        error = (
            str(caught) if isinstance(caught, fresh.Rejected) else type(caught).__name__
        )
    finally:
        try:
            tree = job.finish(child, cancel=child is None or child.poll() is None)
            fresh.require_tree_proof(tree)
        except BaseException as caught:  # noqa: BLE001 -- preserve watchdog cleanup proof on interruption.
            error = error or type(caught).__name__
        finally:
            job.close()
    stopped = False
    try:
        stopped = _supervisor_stop_if_started(context, owner)
    except BaseException as caught:  # noqa: BLE001 -- cleanup must run even when child supervision is interrupted.
        error = error or (
            str(caught) if isinstance(caught, fresh.Rejected) else type(caught).__name__
        )
    remote_cleanup = None
    run_directory = current.ROOT / ("primary-run-" + owner)
    try:
        if run_directory.exists():
            remote_cleanup = remote_artifact_cleanup_evidence(
                run_directory, owner, args.expected_revision
            )
            if not remote_cleanup["verified"]:
                raise fresh.Rejected("PRIMARY_REMOTE_ARTIFACT_CLEANUP_UNVERIFIED")
    except BaseException as caught:  # noqa: BLE001 -- preserve uncertainty; never restart the stopped primary for cleanup.
        error = error or (
            str(caught) if isinstance(caught, fresh.Rejected) else type(caught).__name__
        )
    child_output = None
    child_receipt_sha256 = None
    if not error and child is not None and child.returncode == 0:
        try:
            child_output = json.loads(stdout.read_text(encoding="utf-8").strip())
            receipt_path = fresh.safe(Path(child_output["receipt"]))
            expected_run = current.ROOT / ("primary-run-" + owner)
            if receipt_path != expected_run / "primary-receipt.json":
                raise fresh.Rejected("PRIMARY_CHILD_RECEIPT_PATH_MISMATCH")
            receipt = _json(receipt_path)
            mutations = receipt.get("primary_mutations")
            proofs = receipt.get("proofs")
            if (
                receipt.get("result") != "PASS_PRIMARY_SCHEMA_QUARANTINE_ONLY"
                or receipt.get("cleanup_verified") is not True
                or receipt.get("owner") != owner
                or not isinstance(mutations, dict)
                or mutations.get("temporary_role") != "CREATED_AND_DROPPED"
                or mutations.get("schema_quarantine") != "COMMITTED"
                or not isinstance(proofs, dict)
                or not proofs.get("native_apply_sha256")
                or not proofs.get("native_verify_sha256")
                or not proofs.get("restored_primary_verify_sha256")
                or proofs.get("restored_primary_pg_amcheck_exit_code") != 0
                or not proofs.get("operator_snapshot_sha256")
                or not proofs.get("primary_controller_sha256")
                or not isinstance(remote_cleanup, dict)
                or remote_cleanup.get("verified") is not True
                or remote_cleanup.get("created_count") != 3
                or remote_cleanup.get("completed_count") != 3
                or proofs.get("remote_artifact_cleanup") != remote_cleanup
            ):
                raise fresh.Rejected("PRIMARY_CHILD_RESULT_NOT_ACCEPTED")
            child_receipt_sha256 = fresh.sha(receipt_path)
        except BaseException as caught:  # noqa: BLE001 -- classify any child failure without leaking details.
            error = (
                str(caught)
                if isinstance(caught, fresh.Rejected)
                else type(caught).__name__
            )
    else:
        error = error or "PRIMARY_CHILD_FAILED_OR_INTERRUPTED"
    result = {
        "schema_version": 1,
        "kind": "controlled-runtime-primary-supervisor-v1",
        "owner": owner,
        "result": "PASS" if not error and stopped else "FAILED_CLOSED",
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "cli_tree": tree,
        "child_result": child_output,
        "child_receipt_sha256": child_receipt_sha256,
        "original_primary_stopped": stopped,
        "remote_artifact_cleanup": remote_cleanup,
        "error_category": error,
        "primary_consumers_started": 0,
        "publisher_calls": 0,
    }
    fresh.save(directory / "receipt.json", result)
    print(
        json.dumps(
            {
                "result": result["result"],
                "receipt": str(directory / "receipt.json"),
                "error_category": error,
            },
            sort_keys=True,
        )
    )
    return 0 if result["result"] == "PASS" else 1


def _json(path: Path) -> dict:
    try:
        if (
            path.is_symlink()
            or not path.is_file()
            or getattr(path.lstat(), "st_file_attributes", 0) & 0x400
        ):
            raise fresh.Rejected("PRIVATE_ACCEPTANCE_ARTIFACT_INVALID")
        value = json.loads(path.read_text(encoding="utf-8"))
    except fresh.Rejected:
        raise
    except (OSError, ValueError):
        raise fresh.Rejected("PRIVATE_ACCEPTANCE_ARTIFACT_INVALID") from None
    if not isinstance(value, dict):
        raise fresh.Rejected("PRIVATE_ACCEPTANCE_ARTIFACT_INVALID")
    return value


def verify_primary_script_snapshot(controller) -> str:
    """Independently bind this running entrypoint to the frozen operator tree."""
    snapshot = getattr(controller, "operator_snapshot", None)
    manifest = getattr(controller, "operator_manifest", None)
    if snapshot is None or not isinstance(manifest, dict):
        raise fresh.Rejected("SIGNED_PRIMARY_OPERATOR_SNAPSHOT_REQUIRED")
    running = Path(__file__).resolve(strict=True)
    try:
        relative = (
            running.relative_to(fresh.REPO.resolve())
            .as_posix()
            .removeprefix("scripts/")
        )
    except ValueError:
        raise fresh.Rejected("RUNNING_PRIMARY_SCRIPT_OUTSIDE_REPOSITORY") from None
    expected = manifest.get(relative)
    observed = fresh.sha(running)
    if not isinstance(expected, str) or observed != expected:
        raise fresh.Rejected("RUNNING_PRIMARY_SCRIPT_DIFFERS_FROM_SIGNED_SNAPSHOT")
    current.verify_operator_snapshot(snapshot, manifest)
    controller.proofs["primary_controller_sha256"] = observed
    return observed


def _rooted(path: Path, parent: Path) -> Path:
    resolved = fresh.safe(path)
    if resolved.parent != parent or resolved.is_symlink():
        raise fresh.Rejected("ACCEPTANCE_DIRECTORY_OUTSIDE_CONTROLLED_ROOT")
    return resolved


def _gpg_file_arg(path: Path) -> str:
    """Git's MSYS GPG expects /d/... instead of native Windows drive paths."""
    if not path.is_absolute():
        raise fresh.Rejected("ABSOLUTE_GPG_FILE_PATH_REQUIRED")
    value = path.as_posix()
    drive = re.fullmatch(r"([A-Za-z]):/(.+)", value)
    if drive:
        return "/" + drive[1].lower() + "/" + drive[2]
    if value.startswith("/") and not value.startswith("//"):
        return value
    raise fresh.Rejected("LOCAL_GPG_FILE_PATH_REQUIRED")


def _verify_signature(
    controller: fresh.Controller, receipt: Path, signature: Path, label: str
) -> None:
    if fresh.sha(TRUSTED_KEY) != TRUSTED_KEY_SHA256:
        raise fresh.Rejected("PINNED_TRUSTED_SIGNER_KEY_CHANGED")
    if any(not exe.is_absolute() or not exe.is_file() for exe in (GPG, GPGV)):
        raise fresh.Rejected("DIRECT_GPG_UNAVAILABLE")
    try:
        resolved_gpg = GPG.resolve(strict=True)
        resolved_gpgv = GPGV.resolve(strict=True)
    except OSError:
        raise fresh.Rejected("DIRECT_GPG_UNAVAILABLE") from None
    home = controller.work / ("gpg-home-" + label)
    home.mkdir(mode=0o700)
    # Public-key dearmoring and gpgv never need an agent or a trust database.
    # Importing with gpg still probes its agent socket even with no-autostart;
    # MSYS rejects that socket on the long, owner-bound acceptance paths.
    # gpgv uses only this hash-pinned keyring; exact primary signer checks below
    # remain mandatory. Never use the user's keyring or fetch additional keys.
    keyring = home / "trusted-signer.gpg"
    controller.process(
        resolved_gpg,
        [
            "--homedir",
            _gpg_file_arg(home),
            "--batch",
            "--no-options",
            "--no-autostart",
            "--dearmor",
            "--output",
            _gpg_file_arg(keyring),
            _gpg_file_arg(TRUSTED_KEY),
        ],
        15,
        label=label + "-gpg-dearmor",
    )
    controller.process(
        resolved_gpgv,
        [
            "--homedir",
            _gpg_file_arg(home),
            "--keyring",
            _gpg_file_arg(keyring),
            "--status-fd=1",
            _gpg_file_arg(signature),
            _gpg_file_arg(receipt),
        ],
        20,
        label=label + "-gpg-verify",
    )
    status = (controller.work / (label + "-gpg-verify.stdout")).read_text(
        encoding="utf-8", errors="replace"
    )
    valid = [
        line.split()
        for line in status.splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ")
    ]
    if len(valid) != 1 or len(valid[0]) < 12 or valid[0][11] != SIGNER:
        raise fresh.Rejected("ACCEPTANCE_SIGNATURE_SIGNER_MISMATCH")


def validate_acceptance(
    clone_directory: Path,
    supervisor_directory: Path,
    *,
    expected_revision: str,
    wheelhouse: Path,
    verifier: fresh.Controller,
) -> tuple[str, dict, dict, dict]:
    """Validate exact signed clone and supervisor evidence before any start."""
    root = current.ROOT
    clone_directory = fresh.safe(clone_directory)
    supervisor_directory = fresh.safe(supervisor_directory)
    clone_receipt_path = clone_directory / "receipt.json"
    supervisor_receipt_path = supervisor_directory / "receipt.json"
    if (
        clone_directory.parent != root
        or not re.fullmatch(r"run-[0-9a-f]{32}", clone_directory.name)
        or supervisor_directory.parent != root
        or not re.fullmatch(r"supervisor-[0-9a-f]{32}", supervisor_directory.name)
    ):
        raise fresh.Rejected("SIGNED_ACCEPTED_RUN_PATH_REQUIRED")
    owner = clone_directory.name.removeprefix("run-")
    if any(
        path.is_symlink()
        or not path.is_file()
        or getattr(path.lstat(), "st_file_attributes", 0) & 0x400
        for path in (
            clone_receipt_path,
            supervisor_receipt_path,
            clone_directory / "receipt.json.asc",
            supervisor_directory / "receipt.json.asc",
        )
    ):
        raise fresh.Rejected("SIGNED_ACCEPTANCE_RECEIPTS_REQUIRED")
    _verify_signature(
        verifier, clone_receipt_path, clone_directory / "receipt.json.asc", "clone"
    )
    _verify_signature(
        verifier,
        supervisor_receipt_path,
        supervisor_directory / "receipt.json.asc",
        "supervisor",
    )
    clone = _json(clone_receipt_path)
    supervisor = _json(supervisor_receipt_path)
    if (
        clone.get("kind") != current.KIND
        or clone.get("owner") != owner
        or clone.get("result") != "PASS_CURRENT_CONTROLLED_CLONE"
        or clone.get("cleanup_verified") is not True
        or clone.get("primary_mutations") != 0
        or clone.get("primary_consumers_started") != 0
    ):
        raise fresh.Rejected("SIGNED_CURRENT_CLONE_ACCEPTANCE_REQUIRED")
    if (
        supervisor.get("kind") != "controlled-runtime-hidden-supervisor-v1"
        or supervisor.get("result") != "PASS"
        or supervisor.get("child_receipt_sha256") != fresh.sha(clone_receipt_path)
        or not isinstance(supervisor.get("child_result"), dict)
        or fresh.safe(Path(supervisor["child_result"].get("receipt", "")))
        != clone_receipt_path
    ):
        raise fresh.Rejected("SIGNED_HIDDEN_SUPERVISOR_ACCEPTANCE_REQUIRED")
    fresh.require_tree_proof(supervisor.get("cli_tree"))
    expected_artifacts = {
        "source-before.json",
        "cold-fingerprint.json",
        "plan.json",
        "native-inspection.json",
        "native-rehearsal.json",
        "native-verify.json",
    }
    proofs = clone.get("proofs")
    artifacts = proofs.get("artifact_sha256") if isinstance(proofs, dict) else None
    if not isinstance(artifacts, dict) or set(artifacts) != expected_artifacts:
        raise fresh.Rejected("SIGNED_CLONE_ARTIFACT_BINDINGS_REQUIRED")
    for name, digest in artifacts.items():
        artifact_path = clone_directory / name
        if (
            artifact_path.is_symlink()
            or not artifact_path.is_file()
            or getattr(artifact_path.lstat(), "st_file_attributes", 0) & 0x400
            or not re.fullmatch(r"[0-9a-f]{64}", str(digest))
            or fresh.sha(artifact_path) != digest
        ):
            raise fresh.Rejected("SIGNED_CLONE_ARTIFACT_CHANGED")
    if (
        proofs.get("current_rehearsal_sha256") != artifacts["native-rehearsal.json"]
        or proofs.get("current_restore_verify_sha256")
        != artifacts["native-verify.json"]
        or proofs.get("reviewed_deploy_revision") != expected_revision
        or not re.fullmatch(r"[0-9a-f]{40}", expected_revision)
    ):
        raise fresh.Rejected("SIGNED_CLONE_REVISION_OR_NATIVE_PROOF_MISMATCH")
    wheelhouse = fresh.safe(wheelhouse)
    manifest_path = wheelhouse / "manifest.json"
    manifest = current.require_manifest(_json(manifest_path), wheelhouse)
    manifest_sha256 = fresh.sha(manifest_path)
    if proofs.get("wheel_manifest_sha256") != manifest_sha256:
        raise fresh.Rejected("ACCEPTED_CLONE_WHEEL_MANIFEST_MISMATCH")
    revisions = {item["name"]: item["revision"] for item in manifest["packages"]}
    if proofs.get("package_revisions") != revisions:
        raise fresh.Rejected("ACCEPTED_CLONE_PACKAGE_REVISIONS_MISMATCH")
    plan = _json(clone_directory / "plan.json")
    inspection = _json(clone_directory / "native-inspection.json")
    rehearsal = _json(clone_directory / "native-rehearsal.json")
    verification = _json(clone_directory / "native-verify.json")
    if (
        plan.get("owner") != owner
        or plan.get("primary_authorized") is not False
        or plan.get("package_revisions") != revisions
        or inspection.get("state") != "INSPECTED"
        or rehearsal.get("result") != "PASS"
        or verification.get("state") != "VERIFIED_HISTORY_ONLY"
        or any(
            item.get("plan_binding_sha256") != inspection.get("plan_binding_sha256")
            for item in (rehearsal, verification)
        )
    ):
        raise fresh.Rejected("ACCEPTED_NATIVE_CLONE_EVIDENCE_MISMATCH")
    return (
        owner,
        clone,
        plan,
        {
            "manifest": manifest,
            "manifest_sha256": manifest_sha256,
            "revisions": revisions,
            "inspection": inspection,
            "rehearsal": rehearsal,
            "verification": verification,
            "clone_receipt_sha256": fresh.sha(clone_receipt_path),
            "supervisor_receipt_sha256": fresh.sha(supervisor_receipt_path),
            "source_before_sha256": artifacts["source-before.json"],
            "cold_fingerprint_sha256": artifacts["cold-fingerprint.json"],
        },
    )


class PrimaryController(current.Controller):
    """Reuses bounded current-source primitives, with a distinct owner lease."""

    def __init__(
        self,
        owner: str,
        wheelhouse: Path,
        manifest: dict,
        manifest_sha256: str,
        revision: str,
    ):
        if not re.fullmatch(r"[0-9a-f]{32}", owner):
            raise fresh.Rejected("ACCEPTED_CLONE_OWNER_REQUIRED")
        self.owner = owner
        self.work = fresh.safe(current.ROOT / ("primary-run-" + owner))
        self.work.mkdir()
        self.lease = fresh.safe(
            current.ROOT / ("controlled-runtime-primary-" + owner + ".execution.lock")
        )
        fresh.write(self.lease, owner.encode("ascii"))
        self.deadline = time.monotonic() + MAX_SECONDS
        self.native = fresh.bounded.Native(self.work)
        (self.work / "docker-config").mkdir()
        fresh.save(
            self.work / "docker-config/config.json", fresh.auth_free_docker_config()
        )
        self.owned, self.scratch_directories, self.workers = {}, [], {}
        self.phase, self.proofs, self.cleanup_deadline = "ACCEPTANCE_RECHECK", {}, None
        self.wheelhouse = fresh.safe(wheelhouse)
        self.manifest = manifest
        self.revision = revision
        self.proofs["wheel_manifest_sha256"] = manifest_sha256
        self.proofs["clone_acceptance_verified"] = True
        self.started_source = False
        self.provision_attempted = False
        self.primary_apply_invoked = False
        self.worker_cleanup_verified = True
        self.remote_owned_files: dict[str, str] = {}
        self.remote_create_intents: dict[str, dict] = {}
        self.temp_role = "kairos_transition_" + owner[:12]
        self.temp_sql = "/tmp/controlled-runtime-" + owner[:12] + ".sql"
        self.temp_cleanup_sql = "/tmp/controlled-runtime-cleanup-" + owner[:12] + ".sql"
        self.protect_backup_directory()

    def assert_primary_target(self):
        view = self.inspect(fresh.SOURCE)
        mounts = view["mounts"]
        data = [
            mount
            for mount in mounts
            if mount.get("Destination") == "/var/lib/postgresql/data"
        ]
        state = view["state"]
        if (
            view["id"] != fresh.SOURCE_ID
            or view["image"] != fresh.IMAGE_ID
            or (view["labels"] or {}).get("com.docker.compose.project")
            != "kairos-paper-gate"
            or (view["labels"] or {}).get("com.docker.compose.service") != "timescaledb"
            or state.get("Status") != "running"
            or not state.get("Running")
            or state.get("Paused")
            or state.get("Restarting")
            or state.get("Dead")
            or view["privileged"]
            or view["ports"]
            or set(view["networks"]) != {fresh.NETWORK}
            or len(data) != 1
            or data[0].get("Name") != fresh.VOLUME
            or data[0].get("Type") != "volume"
        ):
            raise fresh.Rejected("EXACT_RUNNING_PRIMARY_TARGET_REQUIRED")
        allowed = {
            "/docker-entrypoint-initdb.d/001-kairos.sql",
            "/run/secrets/paper_postgres_password",
        }
        for mount in mounts:
            if mount not in data and (
                mount.get("Type") != "bind"
                or mount.get("RW") is not False
                or mount.get("Destination") not in allowed
            ):
                raise fresh.Rejected("PRIMARY_MOUNT_SET_CHANGED")
        for identifier in self.docker(["ps", "-q"]).splitlines():
            other = self.inspect(identifier)
            if other["id"] == view["id"]:
                continue
            if (other["labels"] or {}).get(
                "com.docker.compose.project"
            ) == "kairos-paper-gate" or fresh.NETWORK in other["networks"]:
                raise fresh.Rejected("PROTECTED_PRIMARY_SERVICE_RUNNING")
            if any(mount.get("Name") == fresh.VOLUME for mount in other["mounts"]):
                raise fresh.Rejected("PRIMARY_DATA_VOLUME_IN_USE")

    def _require_remote_absent(self, container_path: str):
        self.docker(
            ["exec", fresh.SOURCE, "test", "!", "-e", container_path], seconds=10
        )
        self.docker(
            ["exec", fresh.SOURCE, "test", "!", "-L", container_path], seconds=10
        )

    def _copy_sql(self, path: Path, container_path: str):
        if path.parent != self.work or not path.is_file() or path.is_symlink():
            raise fresh.Rejected("PRIVATE_SQL_FILE_REQUIRED")
        purposes = {
            remote_path: purpose
            for purpose, (remote_path, local_name) in remote_artifact_specs(
                self.owner
            ).items()
            if local_name == path.name and purpose != "backup-after"
        }
        purpose = purposes.get(container_path)
        if purpose is None:
            raise fresh.Rejected("PRIMARY_PRIVATE_SQL_TARGET_NOT_OWNED")
        self._reserve_remote_file(purpose, local_sql=path)
        self.docker(["cp", str(path), fresh.SOURCE + ":" + container_path], seconds=20)
        # Docker cp creates this exact owned file as UID 0. Keep that ownership:
        # the primary drops ALL capabilities, so even UID 0 cannot chown it.
        # Only the bounded UID-0 psql process below reads the mode-0600 file;
        # its database identity is still explicitly kairos, not an OS-derived role.
        self.docker(
            ["exec", "--user=0", fresh.SOURCE, "chmod", "0600", container_path],
            seconds=10,
        )
        digest = fresh.sha(path)
        observed = self.docker(
            ["exec", "--user=0", fresh.SOURCE, "sha256sum", "--", container_path],
            seconds=10,
        ).split()
        if len(observed) != 2 or observed[0] != digest or observed[1] != container_path:
            raise fresh.Rejected("COPIED_PRIVATE_SQL_HASH_MISMATCH")
        self.remote_owned_files[container_path] = digest

    def _reserve_remote_file(self, purpose: str, *, local_sql: Path | None = None):
        specs = remote_artifact_specs(self.owner)
        if purpose not in specs:
            raise fresh.Rejected("PRIMARY_REMOTE_CREATE_PURPOSE_INVALID")
        container_path, local_name = specs[purpose]
        if container_path in self.remote_create_intents:
            raise fresh.Rejected("PRIMARY_REMOTE_CREATE_ALREADY_RESERVED")
        expected_sha = expected_size = None
        maximum = MAX_PRIMARY_TEMP_BYTES
        if purpose != "backup-after":
            if (
                local_sql != self.work / local_name
                or local_sql.is_symlink()
                or not local_sql.is_file()
                or getattr(local_sql.lstat(), "st_file_attributes", 0) & 0x400
                or not 0 < local_sql.stat().st_size <= MAX_PRIVATE_SQL_BYTES
            ):
                raise fresh.Rejected("PRIMARY_PRIVATE_SQL_SOURCE_INVALID")
            payload = local_sql.read_bytes()
            expected_sha = hashlib.sha256(payload).hexdigest()
            expected_size = maximum = len(payload)
        elif local_sql is not None:
            raise fresh.Rejected("PRIMARY_BACKUP_CREATE_SOURCE_INVALID")
        self.assert_primary_target()
        self._require_remote_absent(container_path)
        record = {
            "schema_version": 1,
            "kind": "controlled-primary-remote-create-v1",
            "owner": self.owner,
            "source_container_id": fresh.SOURCE_ID,
            "purpose": purpose,
            "remote_path": container_path,
            "expected_revision": self.revision,
            "expected_sha256": expected_sha,
            "expected_bytes": expected_size,
            "maximum_bytes": maximum,
        }
        intent_path = self.work / ("remote-create-" + purpose + ".json")
        # Durable, create-only reservation BEFORE cp/pg_dump can create bytes.
        # A disconnected child therefore cannot silently forget a temp secret.
        fresh.save(intent_path, record)
        self.remote_create_intents[container_path] = {
            "record": record,
            "sha256": fresh.sha(intent_path),
        }

    def _remote_file_state(self, container_path: str) -> str:
        script = (
            'if [ -L "$1" ]; then exit 90; fi; '
            'if [ ! -e "$1" ]; then printf ABSENT; exit 0; fi; '
            '[ -f "$1" ] || exit 91; '
            'stat -c "%d:%i:%s:%u:%h:%f" -- "$1"'
        )
        return self.docker(
            [
                "exec",
                "--user=0",
                fresh.SOURCE,
                "/bin/sh",
                "-c",
                script,
                "controlled-owned-file-state",
                container_path,
            ],
            seconds=10,
        ).strip()

    def _remove_owned_container_file(self, container_path: str):
        intent = self.remote_create_intents.get(container_path)
        if not isinstance(intent, dict):
            raise fresh.Rejected("UNOWNED_CONTAINER_FILE_CLEANUP_REFUSED")
        record = intent["record"]
        purpose = record["purpose"]
        expected_path, local_name = remote_artifact_specs(self.owner)[purpose]
        intent_path = self.work / ("remote-create-" + purpose + ".json")
        if (
            container_path != expected_path
            or _json(intent_path) != record
            or fresh.sha(intent_path) != intent["sha256"]
        ):
            raise fresh.Rejected("PRIMARY_REMOTE_CREATE_INTENT_CHANGED")
        self.assert_primary_target()
        state = self._remote_file_state(container_path)
        observed_sha = observed_size = None
        outcome = "ABSENT"
        if state != "ABSENT":
            if not re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9a-f]+", state):
                raise fresh.Rejected("PRIMARY_REMOTE_FILE_METADATA_INVALID")
            _device, _inode, size, uid, links, mode = state.split(":")
            observed_size = int(size)
            postgres_uid = self.docker(
                ["exec", fresh.SOURCE, "id", "-u", "postgres"], seconds=10
            ).strip()
            if (
                not postgres_uid.isdecimal()
                or int(uid) not in {0, int(postgres_uid)}
                or int(links) != 1
                or int(mode, 16) & 0xF000 != 0x8000
                or not 0 <= observed_size <= record["maximum_bytes"]
            ):
                raise fresh.Rejected("PRIMARY_REMOTE_FILE_OWNERSHIP_UNVERIFIED")
            observed = self.docker(
                ["exec", "--user=0", fresh.SOURCE, "sha256sum", "--", container_path],
                seconds=15,
            ).split()
            if (
                len(observed) != 2
                or not re.fullmatch(r"[0-9a-f]{64}", observed[0])
                or observed[1] != container_path
            ):
                raise fresh.Rejected("PRIMARY_REMOTE_FILE_HASH_UNVERIFIED")
            observed_sha = observed[0]
            expected = self.remote_owned_files.get(container_path)
            if purpose != "backup-after":
                expected = record["expected_sha256"]
                if observed_size != record["expected_bytes"]:
                    source = self.work / local_name
                    if (
                        source.is_symlink()
                        or not source.is_file()
                        or getattr(source.lstat(), "st_file_attributes", 0) & 0x400
                        or source.stat().st_size != record["expected_bytes"]
                        or fresh.sha(source) != record["expected_sha256"]
                    ):
                        raise fresh.Rejected("PRIMARY_PARTIAL_SQL_SOURCE_UNVERIFIED")
                    # A failed copy may leave only a prefix. Verify its exact
                    # bytes against our protected generated SQL, never its text.
                    expected = hashlib.sha256(
                        source.read_bytes()[:observed_size]
                    ).hexdigest()
            elif expected is None:
                header = self.docker(
                    [
                        "exec",
                        "--user=0",
                        fresh.SOURCE,
                        "head",
                        "-c",
                        "5",
                        "--",
                        container_path,
                    ],
                    seconds=10,
                )
                if header != "PGDMP"[: min(5, observed_size)]:
                    raise fresh.Rejected("PRIMARY_PARTIAL_DUMP_HEADER_UNVERIFIED")
            if expected is not None and observed_sha != expected:
                raise fresh.Rejected("CONTAINER_TEMP_FILE_IDENTITY_CHANGED")
            if self._remote_file_state(container_path) != state:
                raise fresh.Rejected("PRIMARY_REMOTE_FILE_CHANGED_DURING_CLEANUP")
            self.docker(
                ["exec", "--user=0", fresh.SOURCE, "rm", "-f", "--", container_path],
                seconds=10,
            )
            outcome = "OWNED_BYTES_REMOVED"
        self._require_remote_absent(container_path)
        fresh.save(
            self.work / ("remote-remove-" + purpose + ".json"),
            {
                "schema_version": 1,
                "kind": "controlled-primary-remote-remove-v1",
                "owner": self.owner,
                "source_container_id": fresh.SOURCE_ID,
                "purpose": purpose,
                "remote_path": container_path,
                "create_intent_sha256": intent["sha256"],
                "outcome": outcome,
                "observed_sha256": observed_sha,
                "observed_bytes": observed_size,
            },
        )
        self.remote_owned_files.pop(container_path, None)
        self.remote_create_intents.pop(container_path)

    def _run_sql_file(self, path: Path, container_path: str, label: str):
        self._copy_sql(path, container_path)
        self.assert_primary_target()
        self.docker(
            [
                "exec",
                "--user=0",
                fresh.SOURCE,
                "psql",
                "--no-psqlrc",
                "--no-password",
                "--username=kairos",
                "--dbname=postgres",
                "--set=ON_ERROR_STOP=1",
                "--file=" + container_path,
            ],
            seconds=25,
        )
        self.proofs[label + "_acknowledged"] = True
        self._remove_owned_container_file(container_path)

    def run(
        self,
        clone_directory: Path,
        plan: dict,
        accepted: dict,
        source_baseline: dict,
        cold_baseline: dict,
    ):
        # A final independent stopped-source and cold-volume check precedes the
        # only start; compare the exact signed artifacts, not a sampled subset.
        if (
            self.source() != source_baseline
            or self.current_cold_verify() != cold_baseline
        ):
            raise fresh.Rejected("ORIGINAL_PRIMARY_COLD_IDENTITY_CHANGED")
        self.phase = "PRIMARY_AUTH_PROVISIONING"
        primary_plan = dict(plan)
        primary_plan["primary_authorized"] = True
        fresh.save(self.work / "plan.json", primary_plan)
        for filename in ("native-inspection.json", "native-rehearsal.json"):
            fresh.write(self.work / filename, (clone_directory / filename).read_bytes())
        runtime_password = secrets.token_urlsafe(48)
        temp_password = secrets.token_urlsafe(48)
        fresh.save(
            self.work / "runtime-auth.json",
            {"user": "kairos_runtime", "password": runtime_password},
        )
        fresh.save(
            self.work / "native-auth.json",
            {"user": self.temp_role, "password": temp_password, "role": "kairos"},
        )
        # Literals are confined to this private file; never put SQL or secrets
        # in process arguments, stdout, stderr, or public receipts.
        provision = self.work / "provision.sql"
        role_name_literal = "'" + self.temp_role + "'"
        marker = "controlled-runtime-transition-v1:" + self.owner
        marker_literal = "'" + marker + "'"
        provision_sql = (
            "BEGIN;\nDO $provision$ DECLARE role_name text := "
            + role_name_literal
            + "; "
            "role_password text := '"
            + temp_password
            + "'; marker text := "
            + marker_literal
            + "; BEGIN "
            "IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN RAISE EXCEPTION 'unique temporary role conflict'; END IF; "
            "EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION NOINHERIT PASSWORD %L', role_name, role_password); "
            "EXECUTE format('COMMENT ON ROLE %I IS %L', role_name, marker); "
            "EXECUTE format('GRANT kairos TO %I WITH INHERIT FALSE, SET TRUE, ADMIN FALSE', role_name); "
            "END $provision$;\nCOMMIT;\n"
        )
        fresh.write(provision, provision_sql.encode())
        cleanup = self.work / "cleanup-role.sql"
        cleanup_sql = (
            "BEGIN;\nDO $cleanup$ DECLARE target_oid oid; role_name text := "
            + role_name_literal
            + "; marker text := "
            + marker_literal
            + "; BEGIN "
            "SELECT oid INTO target_oid FROM pg_roles WHERE rolname=role_name; IF target_oid IS NULL THEN RETURN; END IF; "
            "IF shobj_description(target_oid, 'pg_authid') IS DISTINCT FROM marker THEN RAISE EXCEPTION 'temporary role identity mismatch'; END IF; "
            "EXECUTE format('REVOKE kairos FROM %I', role_name); EXECUTE format('DROP ROLE %I', role_name); "
            "END $cleanup$;\nCOMMIT;\n"
        )
        fresh.write(cleanup, cleanup_sql.encode())
        self.assert_primary_stopped()
        fresh.save(
            self.work / "started-primary.json",
            {
                "owner": self.owner,
                "source_container_id": fresh.SOURCE_ID,
                "accepted_clone_receipt_sha256": self.proofs[
                    "accepted_clone_receipt_sha256"
                ],
                "start_intent_written_before_docker_start": True,
            },
        )
        self.proofs["started_primary_marker_sha256"] = fresh.sha(
            self.work / "started-primary.json"
        )
        self.started_source = True
        self.docker(["start", fresh.SOURCE])
        self.assert_primary_target()
        self.provision_attempted = True
        self._wait_postgres_ready()
        self._run_sql_file(provision, self.temp_sql, "temporary_login_provision")
        provision.unlink()
        self.phase = "PRIMARY_ATOMIC_RUNTIME_TRANSITION"
        self.primary_apply_invoked = True
        self.worker(fresh.SOURCE, "kairos", "apply", primary=True)
        apply_receipt = _json(self.work / "native-apply.json")
        if apply_receipt.get(
            "kind"
        ) != "controlled-runtime-native-apply-v1" or apply_receipt.get("state") not in {
            "COMMITTED_ACKNOWLEDGED",
            "COMMITTED_EXACT_READONLY",
        }:
            raise fresh.Rejected("PRIMARY_APPLY_NOT_CLASSIFIED_EXACT")
        self.phase = "PRIMARY_AUTHENTICATED_VERIFY"
        self.worker(fresh.SOURCE, "kairos", "verify", primary=True)
        verify_receipt = _json(self.work / "native-verify.json")
        if (
            verify_receipt.get("state") != "VERIFIED"
            or verify_receipt.get("runtime_permissions") != "VERIFIED"
        ):
            raise fresh.Rejected("PRIMARY_RUNTIME_LOGIN_VERIFY_REQUIRED")
        cleanup_role_sql = self.work / "cleanup-role.sql"
        self._run_sql_file(
            cleanup_role_sql, self.temp_cleanup_sql, "temporary_login_drop"
        )
        cleanup_role_sql.unlink()
        auth_file = self.work / "native-auth.json"
        if auth_file.exists() and not auth_file.is_symlink():
            auth_file.unlink()
        self.phase = "BACKUP_AFTER_AND_RESTORED_HISTORY_ONLY"
        dump = self.work / "primary-after.dump"
        if dump.exists() or dump.is_symlink():
            raise fresh.Rejected("PRIMARY_BACKUP_ARTIFACT_ALREADY_EXISTS")
        self._reserve_remote_file("backup-after")
        self.docker(
            [
                "exec",
                "--user=0",
                fresh.SOURCE,
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-privileges",
                "--username=kairos",
                "--dbname=kairos",
                "--file=/tmp/controlled-primary-after-" + self.owner[:12] + ".dump",
            ],
            seconds=240,
        )
        self.docker(
            [
                "exec",
                fresh.SOURCE,
                "test",
                "-f",
                "/tmp/controlled-primary-after-" + self.owner[:12] + ".dump",
            ],
            seconds=10,
        )
        self.docker(
            [
                "exec",
                fresh.SOURCE,
                "test",
                "!",
                "-L",
                "/tmp/controlled-primary-after-" + self.owner[:12] + ".dump",
            ],
            seconds=10,
        )
        self.docker(
            [
                "cp",
                fresh.SOURCE
                + ":/tmp/controlled-primary-after-"
                + self.owner[:12]
                + ".dump",
                str(dump),
            ],
            seconds=40,
        )
        dump_path = "/tmp/controlled-primary-after-" + self.owner[:12] + ".dump"
        dump_sha = fresh.sha(dump)
        remote_dump_sha = self.docker(
            ["exec", "--user=0", fresh.SOURCE, "sha256sum", "--", dump_path], seconds=15
        ).split()
        if (
            len(remote_dump_sha) != 2
            or remote_dump_sha[0] != dump_sha
            or remote_dump_sha[1] != dump_path
        ):
            raise fresh.Rejected("PRIMARY_BACKUP_COPY_HASH_MISMATCH")
        self.remote_owned_files[dump_path] = dump_sha
        self.proofs["primary_backup_after_sha256"] = fresh.sha(dump)
        name, database = self.restore(dump, "current_second")
        # A restored pg_dump omits role globals; deliberately prove only data,
        # schema and exact history, not runtime-login privileges.
        plan_for_restore = dict(primary_plan)
        plan_for_restore["primary_authorized"] = False
        fresh.save(self.work / "plan.json", plan_for_restore)
        self.worker(name, database, "verify-restored-primary")
        restored = _json(self.work / "native-verify-restored-primary.json")
        if (
            restored.get("state") != "HISTORY_ONLY_RESTORED_PRIMARY"
            or restored.get("runtime_permissions") != "NOT_CHECKED_RESTORED_CLUSTER"
        ):
            raise fresh.Rejected("PRIMARY_RESTORE_HISTORY_VERIFY_REQUIRED")
        self.docker(
            [
                "exec",
                name,
                "pg_amcheck",
                "--database=" + database,
                "--username=kairos",
                "--install-missing",
                "--heapallindexed",
                "--parent-check",
                "--rootdescend",
            ],
            seconds=240,
        )
        self.proofs["restored_primary_pg_amcheck_exit_code"] = 0
        self.proofs["native_apply_sha256"] = fresh.sha(self.work / "native-apply.json")
        self.proofs["native_verify_sha256"] = fresh.sha(
            self.work / "native-verify.json"
        )
        self.proofs["restored_primary_verify_sha256"] = fresh.sha(
            self.work / "native-verify-restored-primary.json"
        )
        self.proofs["primary_apply_state"] = apply_receipt["state"]
        self.proofs["primary_verify_state"] = verify_receipt["state"]
        self.proofs["restored_primary_history_state"] = restored["state"]
        self.proofs["primary_consumers_started"] = 0
        self.proofs["publisher_calls"] = 0
        self.proofs["redis_contacted"] = False
        self.proofs["trading_strategy_orders_paper_live_paid_apis"] = "OFF"
        self.remove(name)

    def _wait_postgres_ready(self):
        end = min(self.deadline - 45, time.monotonic() + 90)
        consecutive = 0
        while consecutive < 3:
            if time.monotonic() >= end:
                raise fresh.Rejected("ORIGINAL_PRIMARY_READINESS_TIMEOUT")
            self.assert_primary_target()
            code, _ = self.native.call(
                [
                    "exec",
                    fresh.SOURCE,
                    "pg_isready",
                    "--host=127.0.0.1",
                    "--username=kairos",
                    "--dbname=postgres",
                ],
                self.deadline,
                seconds=8,
                allow_failure=True,
            )
            consecutive = consecutive + 1 if code == 0 else 0
            if consecutive < 3:
                time.sleep(1)

    def assert_primary_stopped(self):
        view = self.source()
        if (
            view["id"] != fresh.SOURCE_ID
            or view["image"] != fresh.IMAGE_ID
            or view["state"].get("Status") != "exited"
            or view["state"].get("Running")
            or view["state"].get("Pid")
        ):
            raise fresh.Rejected("ORIGINAL_PRIMARY_STOPPED_STATE_REQUIRED")

    def cleanup_primary(self):
        if self.started_source:
            # First drop only the run-unique temporary login. If the primary
            # state is uncertain, preserve evidence and never retry apply.
            failure = None
            try:
                observed = self.inspect(fresh.SOURCE)
                if (
                    observed["id"] != fresh.SOURCE_ID
                    or observed["image"] != fresh.IMAGE_ID
                ):
                    raise fresh.Rejected(
                        "PRIMARY_CONTAINER_IDENTITY_CHANGED_DURING_CLEANUP"
                    )
                if observed["state"].get("Status") == "exited":
                    self.started_source = False
                    raise fresh.Rejected(
                        "PRIMARY_STOPPED_UNEXPECTEDLY_DURING_TRANSITION"
                    )
            except BaseException:
                self.proofs["primary_cleanup_uncertain"] = True
                raise
            try:
                self.assert_primary_target()
                if (
                    self.provision_attempted
                    and self.worker_cleanup_verified
                    and not self.proofs.get("temporary_login_drop_acknowledged")
                ):
                    cleanup = self.work / "cleanup-role.sql"
                    if cleanup.exists():
                        self._run_sql_file(
                            cleanup, self.temp_cleanup_sql, "temporary_login_drop"
                        )
                        cleanup.unlink()
            except BaseException as caught:  # noqa: BLE001 -- continue fail-closed cleanup of other owned files.
                failure = caught
            for container_path in list(self.remote_create_intents):
                try:
                    self._remove_owned_container_file(container_path)
                except BaseException as caught:  # noqa: BLE001 -- still clean other exact owned paths and stop primary.
                    failure = failure or caught
            try:
                self.docker(["stop", "--time=30", fresh.SOURCE], seconds=45)
                self.started_source = False
                self.assert_primary_stopped()
                for name in ("provision.sql", "cleanup-role.sql", "native-auth.json"):
                    secret_file = self.work / name
                    if secret_file.exists() and not secret_file.is_symlink():
                        secret_file.unlink()
            except BaseException as caught:  # noqa: BLE001 -- record cleanup uncertainty and keep evidence.
                failure = failure or caught
            if failure:
                self.proofs["primary_cleanup_uncertain"] = True
                raise failure

    def finish(self, success: bool, error=None):
        self.cleanup_deadline = time.monotonic() + 120
        cleanup = True
        worker_cleanup_ok = True
        for name, expected in list(self.workers.items()):
            try:
                value = self.inspect(name)
                if (
                    value["image"] != expected["image"]
                    or (value["labels"] or {}).get(fresh.OWNER_LABEL) != self.owner
                ):
                    raise fresh.Rejected("PRIMARY_WORKER_CLEANUP_IDENTITY_CONFLICT")
                self.docker(["rm", "-f", name])
                self.workers.pop(name)
            except BaseException:  # noqa: BLE001 -- treat interrupted worker cleanup as unverified.
                cleanup = False
                worker_cleanup_ok = False
        self.worker_cleanup_verified = worker_cleanup_ok
        for name in list(self.owned):
            try:
                self.remove(name)
            except BaseException:  # noqa: BLE001 -- do not claim owned-container cleanup after any failure.
                cleanup = False
        try:
            self.cleanup_primary()
        except BaseException as caught:  # noqa: BLE001 -- failed cleanup must be recorded in final receipt.
            success, error = False, caught
        try:
            remote_cleanup = remote_artifact_cleanup_evidence(
                self.work, self.owner, self.revision
            )
            self.proofs["remote_artifact_cleanup"] = remote_cleanup
            if not remote_cleanup["verified"] or self.remote_create_intents:
                raise fresh.Rejected("PRIMARY_REMOTE_ARTIFACT_CLEANUP_UNVERIFIED")
        except BaseException as caught:  # noqa: BLE001 -- missing/malformed/unclosed intents forbid acceptance.
            self.proofs["primary_cleanup_uncertain"] = True
            success, error, cleanup = False, error or caught, False
        cleanup = (
            cleanup
            and not self.started_source
            and not self.proofs.get("primary_cleanup_uncertain")
        )
        try:
            remaining = self.docker(
                [
                    "ps",
                    "-aq",
                    "--filter",
                    "label=" + fresh.OWNER_LABEL + "=" + self.owner,
                ]
            )
            cleanup = cleanup and not remaining
        except BaseException:  # noqa: BLE001 -- inability to enumerate cleanup state means unverified.
            cleanup = False
        apply_state = None
        apply_path = self.work / "native-apply.json"
        if apply_path.is_file() and not apply_path.is_symlink():
            try:
                apply_state = _json(apply_path).get("state")
            except BaseException:  # noqa: BLE001 -- malformed state cannot prove whether commit occurred.
                apply_state = None
        if apply_state in {"COMMITTED_ACKNOWLEDGED", "COMMITTED_EXACT_READONLY"}:
            schema_state = "COMMITTED"
        elif self.primary_apply_invoked:
            schema_state = "UNKNOWN"
        else:
            schema_state = "NOT_ATTEMPTED"
        if self.proofs.get("temporary_login_drop_acknowledged"):
            role_state = "CREATED_AND_DROPPED"
        elif self.proofs.get("temporary_login_provision_acknowledged"):
            role_state = "CREATED"
        elif self.provision_attempted:
            role_state = "UNKNOWN"
        else:
            role_state = "NOT_ATTEMPTED"
        mutation_state = {
            "temporary_role": role_state,
            "schema_quarantine": schema_state,
        }
        receipt = {
            "schema_version": 1,
            "kind": KIND,
            "owner": self.owner,
            "result": "PASS_PRIMARY_SCHEMA_QUARANTINE_ONLY"
            if success and cleanup
            else "FAILED_CLOSED",
            "phase": self.phase,
            "error_category": str(error)
            if isinstance(error, fresh.Rejected)
            else type(error).__name__
            if error
            else None,
            "proofs": self.proofs,
            "cleanup_verified": cleanup,
            "primary_mutations": mutation_state,
            "primary_mutation_scope": "CONTROLLED_RUNTIME_SCHEMA_AND_EXACT_EXPIRED_OUTBOX_QUARANTINE_ONLY",
            "primary_consumers_started": 0,
            "publisher_calls": 0,
            "redis_contacted": False,
            "trading_strategy_orders_paper_live_paid_apis": "OFF",
            "native_operations": self.native.operations,
            "created_at_utc": datetime.now(UTC).isoformat(),
        }
        fresh.save(self.work / "primary-receipt.json", receipt)
        if success and cleanup and self.lease.read_bytes() == self.owner.encode():
            self.lease.unlink()
        print(
            json.dumps(
                {
                    "result": receipt["result"],
                    "receipt": str(self.work / "primary-receipt.json"),
                    "error_category": receipt["error_category"],
                },
                sort_keys=True,
            )
        )
        return 0 if success and cleanup else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-primary", action="store_true")
    parser.add_argument("--supervised-child", action="store_true")
    parser.add_argument("--supervisor-token")
    parser.add_argument("--confirmation")
    parser.add_argument("--clone-directory", type=Path)
    parser.add_argument("--clone-supervisor-directory", type=Path)
    parser.add_argument("--supervisor-directory", type=Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--wheelhouse", type=Path)
    args = parser.parse_args(argv)
    if not args.execute_primary:
        print(
            json.dumps(
                {
                    "kind": KIND,
                    "mode": "PLAN_ONLY",
                    "primary_mutations": 0,
                    "primary_consumers_started": 0,
                    "trading_authority": "NONE",
                },
                sort_keys=True,
            )
        )
        return 0
    if args.confirmation != CONFIRM_PRIMARY or not all(
        (
            args.clone_directory,
            args.clone_supervisor_directory,
            args.expected_revision,
            args.wheelhouse,
        )
    ):
        raise fresh.Rejected("EXPLICIT_SIGNED_PRIMARY_ADMISSION_REQUIRED")
    if not args.supervised_child:
        if args.supervisor_token is not None:
            raise fresh.Rejected("UNEXPECTED_PRIMARY_SUPERVISOR_TOKEN")
        return supervise_primary(args)
    if args.supervisor_directory is None or args.supervisor_token is None:
        raise fresh.Rejected("PRIVATE_PRIMARY_SUPERVISOR_ADMISSION_REQUIRED")
    supervisor_directory = fresh.safe(args.supervisor_directory)
    if supervisor_directory.parent != current.ROOT or not re.fullmatch(
        r"primary-supervisor-[0-9a-f]{32}", supervisor_directory.name
    ):
        raise fresh.Rejected("PRIMARY_SUPERVISOR_PATH_INVALID")
    admission_path = supervisor_directory / "child-admission.json"
    admission = _json(admission_path)
    owner_match = re.fullmatch(
        r"run-([0-9a-f]{32})", fresh.safe(args.clone_directory).name
    )
    if (
        owner_match is None
        or admission.get("owner") != owner_match.group(1)
        or admission.get("confirmation") != CONFIRM_PRIMARY
        or admission.get("nonce_sha256")
        != hashlib.sha256(args.supervisor_token.encode()).hexdigest()
    ):
        raise fresh.Rejected("PRIMARY_SUPERVISOR_ADMISSION_MISMATCH")
    # Do not catch or retry an unknown native COMMIT. The controller catches
    # only to emit a private failure receipt; each worker artifact is retained.
    prelim = object.__new__(PrimaryController)
    prelim.owner = "00000000000000000000000000000000"
    prelim.work = current.ROOT / ("signature-validation-" + uuid.uuid4().hex)
    prelim.work.mkdir()
    prelim.deadline = time.monotonic() + 180
    prelim.native = fresh.bounded.Native(prelim.work)
    prelim.proofs, prelim.scratch_directories, prelim.cleanup_deadline = {}, [], None
    prelim.owned = {}
    prelim.protect_backup_directory()
    owner, _clone, plan, accepted = validate_acceptance(
        args.clone_directory,
        args.clone_supervisor_directory,
        expected_revision=args.expected_revision,
        wheelhouse=args.wheelhouse,
        verifier=prelim,
    )
    accepted["signature_validation_directory"] = str(prelim.work)
    accepted["signature_validation_cli_trees"] = prelim.proofs
    controller = PrimaryController(
        owner,
        args.wheelhouse,
        accepted["manifest"],
        accepted["manifest_sha256"],
        args.expected_revision,
    )
    controller.proofs["accepted_clone_receipt_sha256"] = accepted[
        "clone_receipt_sha256"
    ]
    controller.proofs["accepted_supervisor_receipt_sha256"] = accepted[
        "supervisor_receipt_sha256"
    ]
    controller.proofs["accepted_clone_source_before_sha256"] = accepted[
        "source_before_sha256"
    ]
    controller.proofs["accepted_clone_cold_fingerprint_sha256"] = accepted[
        "cold_fingerprint_sha256"
    ]
    controller.proofs["accepted_package_revisions"] = accepted["revisions"]
    controller.proofs["signature_validation_directory"] = accepted[
        "signature_validation_directory"
    ]
    controller.proofs["signature_validation_cli_trees"] = accepted[
        "signature_validation_cli_trees"
    ]
    source_baseline = _json(fresh.safe(args.clone_directory) / "source-before.json")
    cold_baseline = _json(fresh.safe(args.clone_directory) / "cold-fingerprint.json")
    error = None
    try:
        controller.admit()
        verify_primary_script_snapshot(controller)
        if controller.proofs.get("reviewed_deploy_revision") != args.expected_revision:
            raise fresh.Rejected("CURRENT_SIGNED_REVISION_ADMISSION_MISMATCH")
        controller.run(
            fresh.safe(args.clone_directory),
            plan,
            accepted,
            source_baseline,
            cold_baseline,
        )
    except BaseException as caught:  # noqa: BLE001 -- emit sanitized receipt and never retry uncertain apply.
        error = caught
    return controller.finish(error is None, error)


if __name__ == "__main__":
    sys.exit(main())
