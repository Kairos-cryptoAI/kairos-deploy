"""Create a fresh, non-trading successor runtime from the accepted history baseline.

This wrapper is plan-only unless ``--execute`` is supplied.  It creates a
separate owner/work root and never resumes a prior epoch or edits its lease.
The baseline is deliberately the signed historical 18-migration source used by
the existing worker; current public bars are then natively caught up by the
unchanged runtime-epoch controller before serving.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import time
import uuid
from contextlib import AbstractContextManager
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_controller as epoch
else:
    import runtime_epoch_controller as epoch


SUCCESSOR_ROOT = Path("D:/Kairos/runtime/nontrading-successor-20261023")
MUTEX_NAME = r"Global\KairosNonTradingSuccessor20261023"
ACCEPTED_BASELINE_SHA256 = (
    "2408db1335dc856122750e4604f14a436184f54a7f4ffab22bc35eb69747a7bc"
)
ACCEPTED_SOURCE_PROFILE = "historical-18-migration-nontrading-baseline"
EXPECTED_HISTORY_ROWS = 173_164
EXPECTED_HISTORY_LAST_OPEN_MS = 1_789_832_580_000
EXPECTED_CATCHUP_CAP = 150_000
SOURCE_REPOSITORIES = (
    (Path("D:/Kairos/kairos-core"), epoch.CORE_REVISION),
    (Path("D:/Kairos/kairos-persistence"), epoch.PERSISTENCE_REVISION),
    (epoch.QUANT_REPO, epoch.QUANT_REVISION),
)
# Historical source commits are inputs to the accepted runtime baseline, not
# the current main heads of these repositories. Keep that distinction explicit.
PINNED_DEPLOY_SOURCES = (
    "scripts/runtime_epoch_successor.py",
    "scripts/runtime_epoch_controller.py",
    "scripts/fresh_runtime_recovery.py",
    "scripts/buildkit_resource_gate.py",
)
# Immutable allowlist for the stopped Oct21/current containers. Only safe
# identity/state/mount fields are queried; config, command, and environment are
# intentionally outside the inspection format.
PRESERVED_OLD_CONTAINERS = {
    "kairos-epoch-69893dc7b7c6-cutover-164d902c-serve": {
        "id": "a54242dd365bd55d77564bfc05bae8d9d25b280fd5543f0514b9b3413c293d1d",
        "image": "sha256:2e10e9e936eae3a4a411f65d8b0bd14670ba808368eeff94b4e24021aa291077",
        "status": "exited",
        "exit_code": 1,
        "mounts": (),
    },
    "kairos-epoch-69893dc7b7c6-cutover-164d902c-pg": {
        "id": "a7f09b41a31897efe2f22bdfc19110505ddd1188c0a718769cfadcb7e8748395",
        "image": "sha256:252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a",
        "status": "exited",
        "exit_code": 255,
        "mounts": (
            (
                "kairos-epoch-69893dc7b7c6-cutover-164d902c-pg-vol",
                "/var/lib/postgresql/data",
                True,
            ),
        ),
    },
    "kairos-epoch-69893dc7b7c6-cutover-164d902c-redis": {
        "id": "62be243575454cf93f71fbebb10c11290dab2efdaceaf8dbd29ff07935a1c1e8",
        "image": "sha256:a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103",
        "status": "exited",
        "exit_code": 255,
        "mounts": (
            ("kairos-epoch-69893dc7b7c6-cutover-164d902c-redis-vol", "/data", True),
        ),
    },
    "kairos-epoch-69893dc7b7c6-pg": {
        "id": "9dbce00f1d682871a177fba9fc4a63caa8ed28b355044598b1bc3718f7058e7e",
        "image": "sha256:252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a",
        "status": "exited",
        "exit_code": 255,
        "mounts": (
            ("kairos-epoch-69893dc7b7c6-pg-data", "/var/lib/postgresql/data", True),
        ),
    },
    "kairos-epoch-69893dc7b7c6-redis": {
        "id": "c8d57b7e6c22817eac5fb176aca8b645d0a577039b01719c338dd397a8029b8f",
        "image": "sha256:a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103",
        "status": "exited",
        "exit_code": 255,
        "mounts": (("kairos-epoch-69893dc7b7c6-redis-data", "/data", True),),
    },
}


class SuccessorRejected(RuntimeError):
    """Stable, non-sensitive refusal category."""


class WindowsMutex(AbstractContextManager["WindowsMutex"]):
    """A process-lifetime OS mutex independent of the historical epoch lease."""

    def __init__(self, name: str = MUTEX_NAME) -> None:
        self.name = name
        self.handle = None

    def __enter__(self) -> WindowsMutex:
        if os.name != "nt":
            raise SuccessorRejected("WINDOWS_RUNTIME_REQUIRED")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = (
            ctypes.c_void_p,
            ctypes.c_bool,
            ctypes.c_wchar_p,
        )
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.ReleaseMutex.argtypes = (ctypes.c_void_p,)
        kernel32.ReleaseMutex.restype = ctypes.c_bool
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = ctypes.c_bool
        handle = kernel32.CreateMutexW(None, True, self.name)
        if not handle:
            raise SuccessorRejected("SUCCESSOR_MUTEX_CREATE_FAILED")
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            raise SuccessorRejected("SUCCESSOR_ALREADY_RUNNING")
        self.handle = (kernel32, ctypes.c_void_p(handle))
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if self.handle is not None:
            kernel32, handle = self.handle
            kernel32.ReleaseMutex(handle)
            kernel32.CloseHandle(handle)
            self.handle = None
        return False


def accepted_baseline_projection() -> dict[str, object]:
    """Public baseline facts this successor explicitly adopts, not promotes."""
    return {
        "profile": ACCEPTED_SOURCE_PROFILE,
        "dump_sha256": ACCEPTED_BASELINE_SHA256,
        "source_dump_sha256": epoch.DUMP_SHA256,
        "history_rows": EXPECTED_HISTORY_ROWS,
        "history_last_open_time_ms": EXPECTED_HISTORY_LAST_OPEN_MS,
        "maximum_bars_per_catchup": EXPECTED_CATCHUP_CAP,
        "trading_started": False,
        "orders_submitted": 0,
        "paid_calls": 0,
    }


def validate_source_pins() -> None:
    if (
        epoch.DUMP_SHA256 != ACCEPTED_BASELINE_SHA256
        or epoch.WORKER_IMAGE
        != (
            "ghcr.io/kairos-cryptoai/kairos-runtime-schema-profile-runner@sha256:"
            "2e10e9e936eae3a4a411f65d8b0bd14670ba808368eeff94b4e24021aa291077"
        )
        or epoch.MAX_CATCHUP_BARS != EXPECTED_CATCHUP_CAP
    ):
        raise SuccessorRejected("ACCEPTED_BASELINE_PROFILE_CHANGED")
    if not epoch.DUMP.is_file() or epoch.DUMP.is_symlink():
        raise SuccessorRejected("ACCEPTED_BASELINE_DUMP_REQUIRED")
    if epoch._sha(epoch.DUMP) != ACCEPTED_BASELINE_SHA256:
        raise SuccessorRejected("ACCEPTED_BASELINE_DUMP_HASH_MISMATCH")
    if (
        epoch._sha(epoch.NATIVE_VERIFY) != epoch.NATIVE_VERIFY_SHA256
        or epoch._sha(epoch.primary.TRUSTED_KEY) != epoch.primary.TRUSTED_KEY_SHA256
    ):
        raise SuccessorRejected("PINNED_SIGNED_SOURCE_PROOF_REQUIRED")
    if epoch._sha(epoch.AUX_WHEELHOUSE / epoch.AUX_NUMPY) != epoch.AUX_NUMPY_SHA256:
        raise SuccessorRejected("PINNED_AUXILIARY_WHEEL_REQUIRED")


def _run_git(repo: Path, *args: str, capture: bool = True) -> str:
    try:
        result = subprocess.run(
            [str(epoch.GIT), "-C", str(repo), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            shell=False,
        )
    except Exception:
        raise SuccessorRejected("SIGNED_SOURCE_GIT_CHECK_FAILED") from None
    if result.returncode:
        raise SuccessorRejected("SIGNED_SOURCE_GIT_CHECK_FAILED")
    return result.stdout.decode("ascii", "strict").strip() if capture else ""


def _verify_signed_commit(repo: Path, revision: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SuccessorRejected("EXACT_SIGNED_SOURCE_REVISION_REQUIRED")
    _run_git(repo, "verify-commit", revision, capture=False)
    if _run_git(repo, "log", "-1", "--format=%G? %GF", revision) != (
        "G " + epoch.fresh.SIGNER
    ):
        raise SuccessorRejected("TRUSTED_SOURCE_SIGNER_REQUIRED")


def _verify_repo_identity(repo: Path, *, allow_untracked: bool) -> str:
    """Verify each repo's actual clean, signed main without pinning old HEADs."""
    revision = _run_git(repo, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SuccessorRejected("EXACT_SIGNED_MAIN_IDENTITY_REQUIRED")
    _verify_signed_commit(repo, revision)
    for ref in ("HEAD", "origin/main"):
        if _run_git(repo, "rev-parse", ref) != revision:
            raise SuccessorRejected("EXACT_SIGNED_MAIN_IDENTITY_REQUIRED")
    if _run_git(repo, "branch", "--show-current") != "main":
        raise SuccessorRejected("SIGNED_MAIN_BRANCH_REQUIRED")
    status_args = ["status", "--porcelain"]
    if allow_untracked:
        status_args.append("--untracked-files=no")
    if _run_git(repo, *status_args):
        raise SuccessorRejected("CLEAN_SIGNED_MAIN_REQUIRED")
    return revision


def validate_source_repo_identity(
    repo: Path, historical_revision: str, *, allow_untracked: bool
) -> str:
    """Accept a historical signed archive while requiring today's main clean."""
    current_revision = _verify_repo_identity(repo, allow_untracked=allow_untracked)
    _verify_signed_commit(repo, historical_revision)
    if current_revision == historical_revision:
        return current_revision
    # Confirm the old revision is addressable in this repository without
    # requiring the checkout, branch, or origin to be rewound to it.
    _run_git(repo, "cat-file", "-e", historical_revision + "^{commit}", capture=False)
    return current_revision


def validate_release_identity(expected_revision: str, wheelhouse: Path) -> None:
    """Bind execution to clean signed Deploy main and three pinned source mains."""
    validate_expected_revision(expected_revision)
    validate_source_pins()
    if _run_git(epoch.REPO, "rev-parse", "HEAD") != expected_revision:
        raise SuccessorRejected("EXACT_SIGNED_MAIN_IDENTITY_REQUIRED")
    _verify_repo_identity(epoch.REPO, allow_untracked=False)
    # These older commits are used only for their signed historical source
    # archives. They are never treated as the repositories' current main.
    for repo, revision in SOURCE_REPOSITORIES:
        validate_source_repo_identity(repo, revision, allow_untracked=False)
    for relative in PINNED_DEPLOY_SOURCES:
        committed = subprocess.run(
            [
                str(epoch.GIT),
                "-C",
                str(epoch.REPO),
                "show",
                expected_revision + ":" + relative,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            shell=False,
        )
        path = epoch.REPO / relative
        if (
            committed.returncode
            or path.is_symlink()
            or not path.is_file()
            or hashlib.sha256(committed.stdout).hexdigest() != epoch._sha(path)
        ):
            raise SuccessorRejected("PINNED_DEPLOY_SOURCE_MISMATCH")
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
        check=False,
        shell=False,
    )
    if quant_lock.returncode:
        raise SuccessorRejected("PINNED_QUANT_LOCK_REQUIRED")
    epoch.validate_aux_wheelhouse(epoch.AUX_WHEELHOUSE, quant_lock.stdout)
    safe_wheelhouse = epoch.fresh.safe(wheelhouse)
    epoch.validate_wheelhouse(safe_wheelhouse, epoch.WHEEL_MANIFEST_SHA256)


def validate_no_active_epoch_names(names: list[str]) -> None:
    if any(name.startswith("kairos-epoch-") for name in names):
        raise SuccessorRejected("EXISTING_RUNTIME_EPOCH_MUST_BE_STOPPED")


def validate_expected_revision(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise SuccessorRejected("EXACT_SIGNED_DEPLOY_REVISION_REQUIRED")


def validate_successor_root_is_create_only(root: Path) -> None:
    if root.is_symlink():
        raise SuccessorRejected("SUCCESSOR_ROOT_SYMLINK_REJECTED")
    if root.exists() and any(root.iterdir()):
        raise SuccessorRejected("SUCCESSOR_ROOT_NOT_EMPTY_NO_BLIND_RETRY")


def snapshot_historical_lease(path: Path) -> dict[str, object]:
    """Hash, but never interpret or modify, the old controller's lease bytes."""
    if not path.exists() and not path.is_symlink():
        return {"present": False, "sha256": None, "size": 0}
    if path.is_symlink():
        raise SuccessorRejected("HISTORICAL_LEASE_LINK_REJECTED")
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise SuccessorRejected("HISTORICAL_LEASE_FILE_SHAPE_REJECTED")
        payload = path.read_bytes()
    except SuccessorRejected:
        raise
    except Exception:
        raise SuccessorRejected("HISTORICAL_LEASE_UNREADABLE") from None
    if len(payload) > 4096 or len(payload) != info.st_size:
        raise SuccessorRejected("HISTORICAL_LEASE_FILE_SHAPE_REJECTED")
    return {
        "present": True,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def validate_historical_lease_unchanged(path: Path, before: dict[str, object]) -> None:
    if snapshot_historical_lease(path) != before:
        raise SuccessorRejected("HISTORICAL_LEASE_CHANGED_DURING_SUCCESSOR")


def assert_no_active_epochs() -> None:
    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "--format",
                "{{.Names}}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
            shell=False,
            env=epoch.fresh.supervisor_environment(),
        )
    except Exception:
        raise SuccessorRejected("DOCKER_ACTIVE_EPOCH_INVENTORY_FAILED") from None
    if result.returncode:
        raise SuccessorRejected("DOCKER_ACTIVE_EPOCH_INVENTORY_FAILED")
    names = result.stdout.decode("utf-8", "strict").splitlines()
    validate_no_active_epoch_names(
        [name for name in names if name.startswith("kairos-epoch-")]
    )


def validate_legacy_process_inventory(
    records: list[dict[str, object]], own_pid: int
) -> None:
    for record in records:
        if record.get("pid") == own_pid:
            continue
        if record.get("legacy_runtime_controller") is True:
            raise SuccessorRejected("LEGACY_RUNTIME_CONTROLLER_PROCESS_ACTIVE")


def assert_no_legacy_runtime_processes() -> None:
    """Inspect process identity internally; return no command-line contents."""
    script = r"""
$ErrorActionPreference = 'Stop'
$self = $PID
$own = __OWN_PID__
$rows = @()
$processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
if ($processes.Count -eq 0) { throw 'PROCESS_INVENTORY_UNAVAILABLE' }
foreach ($p in $processes) {
  if ($p.ProcessId -eq $self -or $p.ProcessId -eq $own) { continue }
  $name = [string]$p.Name
  if ($name -notmatch '^(pythonw?\.exe|powershell\.exe|pwsh\.exe)$') { continue }
  $line = [string]$p.CommandLine
  if ([string]::IsNullOrWhiteSpace($line)) { throw 'PROCESS_COMMAND_IDENTITY_UNKNOWN' }
  $kairosPattern = '(?i)(D:\\Kairos|kairos-deploy|' +
    'kairos.*(runtime|boot|cutover)|(runtime|boot|cutover).*kairos)'
  $controllerPattern = '(?i)(runtime_epoch_(?!successor(?:\.py|\b))[a-z0-9_-]+\.py|' +
    'r[4-9]_[a-z0-9_-]*(cutover|resume|recovery|acceptance|postpack)[a-z0-9_-]*\.py|' +
    'Invoke-(NonTradingEpochBoot|LongGapRecovery)\.ps1|' +
    'kairos_native_campaign\.(current_verify|current_liveness))'
  if (($line -match $kairosPattern) -and ($line -match $controllerPattern)) {
    $rows += [pscustomobject]@{ pid=[int]$p.ProcessId; legacy_runtime_controller=$true }
  }
}
$payload = [pscustomobject]@{ inventory_completed=$true; matches=@($rows) }
ConvertTo-Json -InputObject $payload -Compress -Depth 3
""".replace("__OWN_PID__", str(os.getpid()))
    try:
        result = subprocess.run(
            [str(epoch.PS), "-NoProfile", "-NonInteractive", "-Command", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            shell=False,
            env=epoch.fresh.supervisor_environment(),
        )
    except Exception:
        raise SuccessorRejected("LEGACY_RUNTIME_PROCESS_INVENTORY_FAILED") from None
    if result.returncode:
        raise SuccessorRejected("LEGACY_RUNTIME_PROCESS_INVENTORY_FAILED")
    try:
        parsed = json.loads(result.stdout.decode("ascii", "strict"))
        if not isinstance(parsed, dict) or set(parsed) != {
            "inventory_completed",
            "matches",
        }:
            raise ValueError
        if parsed["inventory_completed"] is not True:
            raise ValueError
        records = parsed["matches"]
        if not isinstance(records, list):
            raise ValueError
        if not all(
            isinstance(row, dict)
            and type(row.get("pid")) is int
            and type(row.get("legacy_runtime_controller")) is bool
            for row in records
        ):
            raise ValueError
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, ValueError):
        raise SuccessorRejected("LEGACY_RUNTIME_PROCESS_INVENTORY_MALFORMED") from None
    validate_legacy_process_inventory(records, os.getpid())


def capture_preserved_old_containers() -> dict[str, dict[str, object]]:
    """Read only exact old identities via Docker's allowlisted format fields."""
    snapshot: dict[str, dict[str, object]] = {}
    template = (
        "{{.Id}}|{{.Image}}|{{.State.Status}}|{{.State.ExitCode}}|"
        '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}},{{.Destination}},{{.RW}};{{end}}{{end}}'
    )
    for name, expected in PRESERVED_OLD_CONTAINERS.items():
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", template, name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=20,
                check=False,
                shell=False,
                env=epoch.fresh.supervisor_environment(),
            )
        except Exception:
            raise SuccessorRejected(
                "PRESERVED_OLD_CONTAINER_IDENTITY_UNAVAILABLE"
            ) from None
        if result.returncode:
            raise SuccessorRejected("PRESERVED_OLD_CONTAINER_IDENTITY_UNAVAILABLE")
        try:
            parts = result.stdout.decode("ascii", "strict").strip().split("|")
            if len(parts) != 5:
                raise ValueError
            mounts = []
            for item in filter(None, parts[4].split(";")):
                volume, destination, rw = item.split(",")
                if rw not in {"true", "false"}:
                    raise ValueError
                mounts.append((volume, destination, rw == "true"))
            observed = {
                "id": parts[0],
                "image": parts[1],
                "status": parts[2],
                "exit_code": int(parts[3]),
                "mounts": tuple(mounts),
            }
        except (UnicodeError, ValueError):
            raise SuccessorRejected(
                "PRESERVED_OLD_CONTAINER_IDENTITY_MALFORMED"
            ) from None
        if observed != expected:
            raise SuccessorRejected("PRESERVED_OLD_CONTAINER_IDENTITY_CHANGED")
        snapshot[name] = observed
    return snapshot


def verify_old_container_preservation(before: dict[str, dict[str, object]]) -> None:
    if before != PRESERVED_OLD_CONTAINERS:
        raise SuccessorRejected("PRESERVED_OLD_CONTAINER_INITIAL_PIN_MISMATCH")
    if capture_preserved_old_containers() != before:
        raise SuccessorRejected("PRESERVED_OLD_CONTAINER_IDENTITY_CHANGED")


def private_work_path(owner: str) -> Path:
    epoch.owner_name(owner)
    root = epoch.fresh.safe(SUCCESSOR_ROOT)
    if root.exists() and root.is_symlink():
        raise SuccessorRejected("SUCCESSOR_ROOT_SYMLINK_REJECTED")
    return epoch.fresh.safe(root / ("run-" + owner))


class RetainOwnedClonesController(epoch.EpochController):
    """Preserve stopped, owner-labelled source/restore clones for forensics."""

    def remove_owned_clone(self, container: str, volume: str) -> None:
        if container not in {self.names["source_pg"], self.names["restore_pg"]}:
            raise epoch.Rejected("SUCCESSOR_CLONE_IDENTITY_REQUIRED")
        view = self.inspect_container(container)
        labels = view.get("labels") or {}
        if (
            labels.get(epoch.EPOCH_LABEL) != self.owner
            or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
        ):
            raise epoch.Rejected("SUCCESSOR_OWNED_CLONE_REQUIRED")
        volume_view = json.loads(
            self.docker(["volume", "inspect", "--format", "{{json .}}", volume])
        )
        volume_labels = volume_view.get("Labels") or {}
        if (
            volume_view.get("Name") != volume
            or volume_labels.get(epoch.EPOCH_LABEL) != self.owner
            or volume_labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
        ):
            raise epoch.Rejected("SUCCESSOR_OWNED_VOLUME_REQUIRED")
        if (view.get("state") or {}).get("Status") == "running":
            self.docker(["stop", "--time=15", container], seconds=25)
        final = self.inspect_container(container)
        if (final.get("state") or {}).get("Status") != "exited":
            raise epoch.Rejected("SUCCESSOR_CLONE_STOP_NOT_CONFIRMED")
        self.proofs[
            "source_clone_retained_stopped"
            if container == self.names["source_pg"]
            else "restore_clone_retained_stopped"
        ] = True


def _create_private_work(owner: str) -> Path:
    root = epoch.fresh.safe(SUCCESSOR_ROOT)
    validate_successor_root_is_create_only(root)
    root.mkdir(parents=True, exist_ok=True)
    work = private_work_path(owner)
    if work.exists() or work.is_symlink():
        raise SuccessorRejected("SUCCESSOR_CREATE_ONLY_WORKDIR_REQUIRED")
    epoch._private_directory(work)
    return work


def _run(args: argparse.Namespace) -> dict[str, object]:
    if os.name != "nt":
        raise SuccessorRejected("WINDOWS_RUNTIME_REQUIRED")
    validate_release_identity(args.expected_revision, args.wheelhouse)
    assert_no_legacy_runtime_processes()
    assert_no_active_epochs()
    preserved_before = capture_preserved_old_containers()
    historical_lease_before = snapshot_historical_lease(epoch.ACTIVE_LEASE)
    owner = uuid.uuid4().hex
    work = _create_private_work(owner)
    secrets_map = {
        key: secrets.token_hex(32)
        for key in (
            "admin_password",
            "source_admin_password",
            "restore_admin_password",
            "source_password",
            "history_password",
            "producer_password",
            "consumer_password",
            "redis_admin_password",
            "redis_producer_password",
            "redis_consumer_password",
        )
    }
    epoch.fresh.save(
        work / "epoch-private.json",
        {
            "owner": owner,
            "database": "kairos_epoch_" + owner[:12],
            **secrets_map,
        },
    )
    controller = RetainOwnedClonesController(
        owner,
        expected_revision=args.expected_revision,
        wheelhouse=args.wheelhouse,
        deadline=time.monotonic() + epoch.MAX_SECONDS,
        workdir=work,
    )
    private_ready = True
    try:
        epoch._verify_source_signature(work)
        controller.prepare_snapshots()
        operator_archive = work / "operator.zip"
        quant_archive = work / "quant.zip"
        if (
            operator_archive.is_symlink()
            or not operator_archive.is_file()
            or quant_archive.is_symlink()
            or not quant_archive.is_file()
        ):
            raise SuccessorRejected("PINNED_HISTORICAL_SOURCE_ARCHIVES_REQUIRED")
        end_exclusive_ms = (
            (int(time.time() * 1000) - 5_000) // epoch.MINUTE_MS * epoch.MINUTE_MS
        )
        result = controller.run_epoch(
            end_exclusive_ms=end_exclusive_ms,
            secrets_map=secrets_map,
        )
        verify_old_container_preservation(preserved_before)
        validate_historical_lease_unchanged(epoch.ACTIVE_LEASE, historical_lease_before)
        result.update(
            {
                "successor_scope": ACCEPTED_SOURCE_PROFILE,
                "historical_source_baseline_sha256": ACCEPTED_BASELINE_SHA256,
                "historical_operator_archive_sha256": epoch._sha(operator_archive),
                "historical_quant_archive_sha256": epoch._sha(quant_archive),
                "successor_work_root": str(work),
                "production_qualification": False,
                "root_cause_fixed": False,
                "trading_started": False,
                "orders_submitted": 0,
                "paid_calls": 0,
                "readiness": {
                    "PAPER_QUALIFIED": False,
                    "ALPHA_READY": False,
                    "LIVE_READY": False,
                    "STRATEGY_POLICY": "REJECT_ALL",
                },
            }
        )
        receipt = work / "runtime-epoch-successor-receipt.json"
        epoch.fresh.save(receipt, result)
        return {
            "result": result["result"],
            "owner": owner,
            "receipt": str(receipt),
            "resources": result["resources"],
            "scope": ACCEPTED_SOURCE_PROFILE,
            "trading_started": False,
            "secrets": "private-file-only",
        }
    except BaseException as exc:
        receipt = epoch._persist_failure_receipt(
            work, owner, controller, exc, private_ready=private_ready
        )
        try:
            verify_old_container_preservation(preserved_before)
            validate_historical_lease_unchanged(
                epoch.ACTIVE_LEASE, historical_lease_before
            )
        except SuccessorRejected:
            return {
                "result": "FAILED_CLOSED",
                "owner": owner,
                "receipt": str(receipt) if receipt else None,
                "error_category": "PRESERVED_OLD_CONTAINER_IDENTITY_CHANGED",
                "preserved_forensics": True,
                "trading_started": False,
            }
        return {
            "result": "FAILED_CLOSED",
            "owner": owner,
            "receipt": str(receipt) if receipt else None,
            "error_category": epoch._failure_category(exc),
            "preserved_forensics": True,
            "trading_started": False,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--expected-revision")
    parser.add_argument("--wheelhouse", type=Path, default=epoch.DEFAULT_WHEELHOUSE)
    args = parser.parse_args(argv)
    if not args.execute:
        print(
            json.dumps(
                {
                    "result": "PLAN_ONLY",
                    "operation": "new isolated non-trading successor epoch",
                    "work_root": str(SUCCESSOR_ROOT),
                    "baseline": accepted_baseline_projection(),
                    "writes": False,
                    "legacy_or_old_epoch_mutation": False,
                    "trading_started": False,
                    "orders_submitted": 0,
                    "paid_calls": 0,
                    "readiness": {
                        "PAPER_QUALIFIED": False,
                        "ALPHA_READY": False,
                        "LIVE_READY": False,
                        "STRATEGY_POLICY": "REJECT_ALL",
                    },
                },
                sort_keys=True,
            )
        )
        return 0
    try:
        with WindowsMutex():
            result = _run(args)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("result") == "PASS_NONTRADING_RUNTIME_EPOCH" else 2
    except SuccessorRejected as exc:
        print(
            json.dumps(
                {
                    "result": "FAILED_CLOSED",
                    "error_category": str(exc),
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 2
    except Exception:
        print(
            json.dumps(
                {
                    "result": "FAILED_CLOSED",
                    "error_category": "SUCCESSOR_UNEXPECTED_FAILURE",
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
