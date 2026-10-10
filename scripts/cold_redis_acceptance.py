"""Read-only Redis acceptance evidence from a cold, isolated volume clone.

The default is PLAN_ONLY. Execution never starts or connects to the original
Redis container, never reads container environment/config values, and never
contacts PostgreSQL or publishes. It copies the stopped source volume into a
new owned volume, verifies source immutability, starts Redis only from that
copy on an isolated network namespace, then performs bounded INFO/XRANGE reads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from scripts import buildkit_resource_gate as bounded
else:
    try:
        import buildkit_resource_gate as bounded
    except ModuleNotFoundError:
        # The frozen Linux worker mounts this file alone. It never constructs
        # the Windows Docker adapter, so no sibling script import is required.
        bounded = None


ROOT = Path("D:/Kairos/runtime/cold-redis-acceptance-20261010")
SOURCE_CONTAINER_ID = "cba271ac26764f553cf8319aff992200226c62d02c9c8ca94db4622afd05147a"
SOURCE_IMAGE_ID = (
    "sha256:a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103"
)
SOURCE_VOLUME = "kairos-paper-gate_paper-redis-data"
RUNNER_IMAGE = (
    "ghcr.io/kairos-cryptoai/kairos-runtime-schema-profile-runner@sha256:"
    "2e10e9e936eae3a4a411f65d8b0bd14670ba808368eeff94b4e24021aa291077"
)
OWNER_LABEL = "com.kairos.cold-redis.owner"
SCOPE_LABEL = "com.kairos.cold-redis.scope"
SCOPE = "cold-redis-acceptance-v1"
KIND = "kairos.cold-redis-acceptance.v1"
CONFIRMATION = "COLD_REDIS_ACCEPTANCE_CLONE_ONLY_NO_PRIMARY_ACTIONS"
MAX_SECONDS = 240
CLEANUP_SECONDS = 60
MAX_SOURCE_BYTES = 256 * 1024**2
MAX_SOURCE_FILES = 4096
# The initial 20,000-entry prefix was insufficient for the preserved stream.
# Expand only the isolated read-only search; keep its existing wall-clock and
# memory/CPU/source-copy limits unchanged. Pages are processed incrementally.
MAX_XRANGE_ENTRIES = 120_000
MAX_XRANGE_BYTES = 128 * 1024**2
XRANGE_PAGE_SIZE = 500
MAX_STDOUT = 256 * 1024
WORKER_REJECTION_FIELDS = frozenset(
    {"state", "error", "stage", "exception_class", "error_code", "diagnostic"}
)
WORKER_REJECTION_ERROR = "bounded read-only copy check failed"
WORKER_REJECTION_STAGES = frozenset(
    {
        "prepare_target_mkdir",
        "prepare_target_empty_check",
        "prepare_target_chmod",
        "prepare_target_chown",
        "manifest_source",
        "manifest_bounds",
        "manifest_persistence",
        "copy_source_manifest",
        "copy_persistence_before",
        "copy_bounds",
        "copy_target_empty_check",
        "copy_tree",
        "copy_source_manifest_after",
        "copy_target_manifest",
        "copy_persistence_after",
        "worker_mode",
    }
)
WORKER_EXCEPTION_CLASSES = frozenset(
    {
        "AssertionError",
        "ColdRedisError",
        "FileExistsError",
        "FileNotFoundError",
        "IsADirectoryError",
        "NotADirectoryError",
        "OSError",
        "OverflowError",
        "PermissionError",
        "RuntimeError",
        "TimeoutError",
        "TypeError",
        "ValueError",
        "OtherError",
    }
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PERSISTENCE_ERROR_CODES = frozenset(
    {
        "MANIFEST_INVENTORY_UNSUPPORTED",
        "MANIFEST_TOO_LARGE",
        "MANIFEST_NON_ASCII",
        "MANIFEST_ENTRY_UNSUPPORTED",
        "MANIFEST_SEQUENCE_TYPE_CONFLICT",
        "MANIFEST_OFFSETS_INVALID",
        "COMPONENT_MISSING",
        "BASE_CARDINALITY",
        "UNREFERENCED_COMPONENT",
        "ORPHANED_APPENDONLYDIR",
        "NO_PERSISTENCE_IMAGE",
    }
)
PERSISTENCE_FILENAME = re.compile(
    r"^appendonly\.aof\.[0-9]{1,10}\.(?:base\.rdb|incr\.aof)$"
)
REVISION = re.compile(r"^[0-9a-f]{40}$")
REDIS_RUN_ID = re.compile(r"^[0-9a-f]{40}$")
STREAM_ID = re.compile(r"^[0-9]{1,20}-[0-9]{1,10}$")
TOPIC = re.compile(r"^[A-Za-z0-9._:-]{1,250}$")
MESSAGE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,512}$")
WINDOWS_GIT = Path(r"C:\Program Files\Git\cmd\git.exe")
WINDOWS_GPG = Path(r"C:\Program Files\Git\usr\bin\gpg.exe")


class ColdRedisError(RuntimeError):
    """Sanitized fail-closed operational error."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        diagnostic: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = (
            error_code
            if isinstance(error_code, str) and error_code in PERSISTENCE_ERROR_CODES
            else None
        )
        self.diagnostic = diagnostic if self.error_code is not None else None


def _validate_persistence_diagnostic(value: object) -> dict[str, Any] | None:
    """Accept only bounded metadata, never arbitrary worker-provided strings."""
    if value is None:
        return None
    if not isinstance(value, dict) or len(value) > 6:
        raise ColdRedisError("bounded persistence diagnostic is invalid")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key == "manifest_sha256":
            if not isinstance(item, str) or SHA256.fullmatch(item) is None:
                raise ColdRedisError("bounded persistence diagnostic is invalid")
            result[key] = item
        elif key in {"entry_count", "recognized_file_count", "sequence"}:
            maximum = 9_999_999_999 if key == "sequence" else MAX_SOURCE_FILES
            if type(item) is not int or not 0 <= item <= maximum:
                raise ColdRedisError("bounded persistence diagnostic is invalid")
            result[key] = item
        elif key == "filename":
            if (
                not isinstance(item, str)
                or PERSISTENCE_FILENAME.fullmatch(item) is None
            ):
                raise ColdRedisError("bounded persistence diagnostic is invalid")
            result[key] = item
        elif key == "component_type":
            if not isinstance(item, str) or item not in {"base", "incremental"}:
                raise ColdRedisError("bounded persistence diagnostic is invalid")
            result[key] = item
        else:
            raise ColdRedisError("bounded persistence diagnostic is invalid")
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: object) -> str:
    return _sha256_bytes(_canonical(value))


def _file_sha256(
    path: Path, maximum: int = 64 * 1024**2, *, noatime: bool = False
) -> str:
    if not path.is_file() or path.stat().st_size > maximum:
        raise ColdRedisError(
            "accepted receipt artifact is missing or exceeds its size bound"
        )
    digest = hashlib.sha256()
    with _open_noatime(path) if noatime else path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _open_noatime(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOATIME", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ColdRedisError(
            "source file cannot be opened without changing access metadata"
        ) from None
    return os.fdopen(descriptor, "rb")


def _read_json(path: Path, label: str, maximum: int = 64 * 1024**2) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > maximum:
            raise ColdRedisError(f"{label} exceeds its size bound")
        value = json.loads(raw)
    except ColdRedisError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ColdRedisError(f"{label} is unavailable or invalid JSON") from None
    if not isinstance(value, dict):
        raise ColdRedisError(f"{label} must be a JSON object")
    return value


def _safe_below(path: Path, root: Path, label: str) -> Path:
    _reject_linked_path(path, label)
    _reject_linked_path(root, label)
    resolved = path.resolve(strict=True)
    root_resolved = root.resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        raise ColdRedisError(
            f"{label} must remain under its approved private root"
        ) from None
    for item in (resolved, *resolved.parents):
        if item.is_symlink() or getattr(item.stat(), "st_file_attributes", 0) & 0x400:
            raise ColdRedisError(f"{label} path contains a link or reparse point")
        if item == root_resolved:
            break
    return resolved


def _reject_linked_path(path: Path, label: str) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if current.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ColdRedisError(f"{label} path contains a link or reparse point")


def _target_from_inspection(
    inspection_path: Path, clone_receipt_path: Path, expected_clone_receipt_sha256: str
) -> dict[str, str]:
    if SHA256.fullmatch(expected_clone_receipt_sha256) is None:
        raise ColdRedisError("root-verified accepted clone receipt SHA-256 is required")
    _reject_linked_path(inspection_path, "native inspection")
    _reject_linked_path(clone_receipt_path, "accepted clone receipt")
    clone_receipt_sha256 = _file_sha256(clone_receipt_path)
    if clone_receipt_sha256 != expected_clone_receipt_sha256:
        raise ColdRedisError(
            "accepted clone receipt does not match the root-verified SHA-256"
        )
    receipt = _read_json(clone_receipt_path, "accepted clone receipt")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("kind") != "controlled-runtime-transition-v1"
        or receipt.get("result") != "PASS_CURRENT_CONTROLLED_CLONE"
        or receipt.get("cleanup_verified") is not True
        or receipt.get("primary_mutations") != 0
        or receipt.get("primary_redis_contacted") is not False
    ):
        raise ColdRedisError("accepted signed clone receipt scope or result differs")
    inspection_sha = _file_sha256(inspection_path)
    plan_path = inspection_path.parent / "plan.json"
    rehearsal_path = inspection_path.parent / "native-rehearsal.json"
    artifact_hashes = receipt.get("proofs", {}).get("artifact_sha256")
    if (
        not isinstance(artifact_hashes, dict)
        or artifact_hashes.get("native-inspection.json") != inspection_sha
        or artifact_hashes.get("plan.json") != _file_sha256(plan_path)
        or artifact_hashes.get("native-rehearsal.json") != _file_sha256(rehearsal_path)
        or receipt.get("proofs", {}).get("current_rehearsal_sha256")
        != _file_sha256(rehearsal_path)
    ):
        raise ColdRedisError(
            "inspection, rehearsal and plan are not hash-bound by the accepted clone receipt"
        )
    plan = _read_json(plan_path, "accepted clone plan")
    rehearsal = _read_json(rehearsal_path, "accepted clone rehearsal")
    binding = _digest(
        {key: value for key, value in plan.items() if key != "primary_authorized"}
    )
    if (
        plan.get("schema_version") != 1
        or plan.get("kind") != "controlled-runtime-transition-v1"
        or plan.get("primary_authorized") is not False
        or plan.get("role_provision_authorized") is not True
        or not isinstance(plan.get("reconciliation_id"), str)
        or not plan["reconciliation_id"].strip()
        or rehearsal.get("schema_version") != 1
        or rehearsal.get("kind") != "controlled-runtime-native-rehearsal-v1"
        or rehearsal.get("result") != "PASS"
        or rehearsal.get("state")
        not in {"COMMITTED_ACKNOWLEDGED", "COMMITTED_EXACT_READONLY"}
        or rehearsal.get("plan_binding_sha256") != binding
    ):
        raise ColdRedisError("accepted plan or COMMITTED_EXACT rehearsal proof differs")
    inspection = _read_json(inspection_path, "private native inspection")
    if (
        inspection.get("schema_version") != 1
        or inspection.get("kind") != "controlled-runtime-native-inspection-v1"
        or inspection.get("state") != "INSPECTED"
        or inspection.get("plan_binding_sha256") != binding
        or inspection.get("plan_sha256") != _digest(plan)
    ):
        raise ColdRedisError("private native inspection schema or state differs")
    target = inspection.get("private_target")
    rehearsal_target = rehearsal.get("private_target")
    if not isinstance(target, dict) or not isinstance(rehearsal_target, dict):
        raise ColdRedisError("private native inspection has no exact target")
    identity_fields = (
        "id",
        "producer",
        "message_id",
        "topic",
        "payload_sha256",
        "publish_attempts",
    )
    if any(
        target.get(field) != rehearsal_target.get(field) for field in identity_fields
    ):
        raise ColdRedisError(
            "inspection target does not match the accepted rehearsal legacy identity"
        )
    topic, message_id, expected_hash = (
        target.get("topic"),
        target.get("message_id"),
        target.get("payload_sha256"),
    )
    if not isinstance(topic, str) or TOPIC.fullmatch(topic) is None:
        raise ColdRedisError("private target topic is invalid")
    if not isinstance(message_id, str) or MESSAGE_ID.fullmatch(message_id) is None:
        raise ColdRedisError("private target message identity is invalid")
    if not isinstance(expected_hash, str) or SHA256.fullmatch(expected_hash) is None:
        raise ColdRedisError("private target canonical payload hash is invalid")
    # The inspection is a legacy baseline before schema 018, not proof that the
    # original row is already quarantined. Bind only the approved prospective ID.
    reconciliation_id = plan.get("reconciliation_id")
    if (
        not isinstance(reconciliation_id, str)
        or not reconciliation_id.strip()
        or len(reconciliation_id) > 200
    ):
        raise ColdRedisError("private target reconciliation identity is invalid")
    return {
        "topic": topic,
        "message_id": message_id,
        "canonical_payload_sha256": expected_hash,
        "reconciliation_id": reconciliation_id,
        "native_inspection_sha256": inspection_sha,
        "accepted_clone_receipt_sha256": clone_receipt_sha256,
        "plan_binding_sha256": binding,
        "rehearsal_sha256": _file_sha256(rehearsal_path),
        "prospective_unknown_outcome": "LEGACY_BASELINE_REQUIRES_PRIMARY_QUARANTINE",
    }


def plan() -> dict[str, Any]:
    return {
        "kind": KIND,
        "result": "PLAN_ONLY_NO_NATIVE_CALLS",
        "source": {
            "container_id": SOURCE_CONTAINER_ID,
            "image_id": SOURCE_IMAGE_ID,
            "volume": SOURCE_VOLUME,
            "must_be_stopped": True,
            "environment_or_config_values_read": False,
            "original_container_started": False,
            "original_redis_commands": 0,
        },
        "clone": {
            "network": "none",
            "observer_network": "container:<owned-clone>; loopback only",
            "volume_type": "new owned persistent Docker volume; no tmpfs quota claimed",
            "read_only_root": True,
            "capabilities": "ALL dropped",
            "memory_bytes": 512 * 1024**2,
            "swap_bytes": 0,
            "cpus": 1,
            "pids": 64,
            "tmpfs_bytes": 32 * 1024**2,
            "redis_clone_watchdog_seconds": 150,
            "total_seconds": MAX_SECONDS,
            "xrange_entries_max": MAX_XRANGE_ENTRIES,
            "xrange_response_bytes_max": MAX_XRANGE_BYTES,
        },
        "result_policy": {
            "zero_matches": "INCONCLUSIVE_NO_REPLAY",
            "multiple_matches": "CONFLICT_NO_REPLAY",
            "one_complete_scan_match": "POSITIVE_ACCEPTED_METADATA_ONLY",
            "primary_database_contacted": False,
            "automatic_resolution": False,
            "publishing": False,
        },
        "native_execution_requires": CONFIRMATION,
    }


class BoundedDocker:
    def __init__(
        self,
        work: Path,
        deadline: float,
        native: Any | None = None,
        *,
        script_snapshot: Path | None = None,
        script_sha256: str | None = None,
    ) -> None:
        self.work = work
        self.deadline = deadline
        self.cleanup_deadline = deadline + CLEANUP_SECONDS
        self.script_snapshot = script_snapshot
        self.script_sha256 = script_sha256
        if native is None and bounded is None:
            raise ColdRedisError("bounded Windows Docker adapter is unavailable")
        self.native = native or bounded.Native(work)

    def begin_cleanup(self) -> None:
        # Reserve a bounded cleanup interval even if work exhausted its deadline.
        # No new Linux workers are admitted in this interval: callers only
        # inspect/remove exact owner-labelled resources and recheck source metadata.
        self.deadline = self.cleanup_deadline
        self.script_snapshot = None

    def call(
        self,
        arguments: list[str],
        *,
        seconds: float = 20,
        allow_worker_rejection: bool = False,
    ) -> str:
        if self.script_snapshot is not None:
            _reject_linked_path(
                self.script_snapshot, "immutable cold-clone script snapshot"
            )
            if (
                _file_sha256(self.script_snapshot, maximum=1024 * 1024)
                != self.script_sha256
            ):
                raise ColdRedisError(
                    "cold-clone script snapshot changed before a native call"
                )
        if allow_worker_rejection and (
            len(arguments) != 4
            or arguments[:3] != ["start", "--attach", "--interactive"]
            or re.fullmatch(
                r"kairos-cold-redis-(?:prepare|copy|verify)-[0-9a-f]{12}",
                arguments[3],
            )
            is None
        ):
            raise ColdRedisError(
                "worker rejection capture is only valid for an owned worker start"
            )
        remaining = self.deadline - time.monotonic()
        if remaining <= 4:
            raise ColdRedisError("global cold clone deadline exhausted")
        try:
            exit_code, output = self.native.call(
                arguments,
                self.deadline,
                seconds=min(seconds, remaining - 3),
                allow_failure=allow_worker_rejection,
            )
        except Exception:  # noqa: BLE001 -- sanitize host adapter failures
            raise ColdRedisError(
                "bounded Docker operation failed or exceeded its deadline"
            ) from None
        if len(output.encode("utf-8")) > MAX_STDOUT:
            raise ColdRedisError("bounded Docker output exceeded its size limit")
        if exit_code != 0:
            if not allow_worker_rejection:
                raise ColdRedisError("bounded Docker operation returned nonzero")
            try:
                rejection = json.loads(output)
            except (TypeError, json.JSONDecodeError):
                raise ColdRedisError(
                    "bounded worker rejection record is malformed"
                ) from None
            if (
                not isinstance(rejection, dict)
                or set(rejection) != WORKER_REJECTION_FIELDS
                or rejection.get("state") != "COPY_REJECTED"
                or rejection.get("error") != WORKER_REJECTION_ERROR
                or not isinstance(rejection.get("stage"), str)
                or rejection.get("stage") not in WORKER_REJECTION_STAGES
                or not isinstance(rejection.get("exception_class"), str)
                or rejection.get("exception_class") not in WORKER_EXCEPTION_CLASSES
                or rejection.get("error_code") is not None
                and (
                    not isinstance(rejection.get("error_code"), str)
                    or rejection.get("error_code") not in PERSISTENCE_ERROR_CODES
                )
            ):
                raise ColdRedisError("bounded worker rejection record is invalid")
            diagnostic = _validate_persistence_diagnostic(rejection.get("diagnostic"))
            if rejection.get("error_code") is None and diagnostic is not None:
                raise ColdRedisError("bounded worker rejection record is invalid")
            raise ColdRedisError(
                "WORKER_REJECTED:"
                + rejection["stage"]
                + ":"
                + rejection["exception_class"]
                + (":" + rejection["error_code"] if rejection["error_code"] else ""),
                error_code=rejection["error_code"],
                diagnostic=diagnostic,
            )
        return output


def _inspect_source(docker: BoundedDocker) -> dict[str, Any]:
    # The Go template is deliberately limited to identity, state and mount metadata.
    format_value = (
        "{{.Id}}|{{.Image}}|{{.State.Status}}|{{.State.Running}}|{{.State.Paused}}|"
        "{{.State.Restarting}}|{{.State.Dead}}|{{json .Mounts}}"
    )
    raw = docker.call(["inspect", "--format", format_value, SOURCE_CONTAINER_ID])
    parts = raw.split("|", 7)
    if len(parts) != 8:
        raise ColdRedisError("source Redis metadata is malformed")
    try:
        mounts = json.loads(parts[7])
    except json.JSONDecodeError:
        raise ColdRedisError("source Redis mount metadata is malformed") from None
    if (
        parts[0] != SOURCE_CONTAINER_ID
        or parts[1] != SOURCE_IMAGE_ID
        or parts[2] != "exited"
        or parts[3:7] != ["false", "false", "false", "false"]
        or not isinstance(mounts, list)
    ):
        raise ColdRedisError(
            "the exact original Redis container is not stopped or identity-matched"
        )
    data_mounts = [
        item
        for item in mounts
        if isinstance(item, dict) and item.get("Destination") == "/data"
    ]
    if (
        len(data_mounts) != 1
        or data_mounts[0].get("Type") != "volume"
        or data_mounts[0].get("Name") != SOURCE_VOLUME
    ):
        raise ColdRedisError("the exact Redis source volume is not mounted at /data")
    return {
        "container_id": parts[0],
        "image_id": parts[1],
        "state": parts[2],
        "volume": SOURCE_VOLUME,
        "mount_target": "/data",
    }


def _volume_metadata(docker: BoundedDocker, name: str) -> dict[str, Any]:
    raw = docker.call(
        [
            "volume",
            "inspect",
            "--format",
            "{{.Name}}|{{.Driver}}|{{.Scope}}|{{.CreatedAt}}|{{json .Labels}}|{{json .Options}}",
            name,
        ]
    )
    parts = raw.split("|", 5)
    if len(parts) != 6 or parts[0] != name:
        raise ColdRedisError("Redis volume metadata differs")
    try:
        labels, options = json.loads(parts[4]), json.loads(parts[5])
    except json.JSONDecodeError:
        raise ColdRedisError("Redis volume metadata is malformed") from None
    return {
        "name": parts[0],
        "driver": parts[1],
        "scope": parts[2],
        "created_at": parts[3],
        "labels": labels or {},
        "options": options or {},
    }


def _worker_command(
    mode: str,
    *,
    source: str | None = None,
    target: str | None = None,
    script_path: Path | None = None,
) -> list[str]:
    command = [
        "create",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--memory=512m",
        "--memory-swap=512m",
        "--cpus=1",
        "--pids-limit=64",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=32m",
        "--pull=never",
        "--entrypoint",
        "python",
    ]
    if mode == "prepare-target":
        if (
            source is not None
            or not isinstance(target, str)
            or not re.fullmatch(r"kairos-cold-redis-data-[0-9a-f]{12}", target)
        ):
            raise ColdRedisError("preparation requires only a new owned target volume")
        # The pinned image's default unprivileged UID cannot chmod a new
        # root-owned Docker volume. Only CHOWN is restored, exclusively for
        # transferring this empty owned target to the fixed Redis copy UID.
        # No original volume is mounted and every other capability stays dropped.
        command += ["--user=0:0", "--cap-add=CHOWN"]
    if source:
        command += ["--mount", f"type=volume,src={source},dst=/source,readonly"]
    if target:
        command += ["--mount", f"type=volume,src={target},dst=/data"]
    script_path = script_path or Path(__file__).resolve()
    command += [
        "--mount",
        f"type=bind,src={script_path},dst=/work/cold_redis_acceptance.py,readonly",
    ]
    command += [RUNNER_IMAGE, "-B", "/work/cold_redis_acceptance.py", "--worker", mode]
    return command


def _create_new_owned_volume(
    docker: BoundedDocker, name: str, owner: str, attempted: set[str]
) -> dict[str, Any]:
    """Refuse collisions and verify the new volume before any writable mount."""
    if not re.fullmatch(r"[0-9a-f]{32}", owner) or name != (
        "kairos-cold-redis-data-" + owner[:12]
    ):
        raise ColdRedisError("new snapshot volume identity is invalid")
    existing = docker.call(
        ["volume", "ls", "--format", "{{.Name}}", "--filter", "name=^" + name + "$"]
    )
    if existing.strip():
        raise ColdRedisError("snapshot volume name already exists; never adopt it")
    attempted.add("volume")
    created = docker.call(
        [
            "volume",
            "create",
            "--label",
            f"{OWNER_LABEL}={owner}",
            "--label",
            f"{SCOPE_LABEL}={SCOPE}",
            name,
        ]
    )
    metadata = _volume_metadata(docker, name)
    if (
        created.strip() != name
        or metadata["name"] != name
        or metadata["driver"] != "local"
        or metadata["scope"] != "local"
        or metadata["options"]
        or metadata["labels"] != {OWNER_LABEL: owner, SCOPE_LABEL: SCOPE}
    ):
        raise ColdRedisError("new snapshot volume ownership is unverified")
    return metadata


def _run_worker(
    docker: BoundedDocker,
    *,
    name: str,
    owner: str,
    mode: str,
    source: str | None = None,
    target: str | None = None,
    user: str | None = None,
    script_path: Path | None = None,
) -> dict[str, Any]:
    command = _worker_command(
        mode, source=source, target=target, script_path=script_path
    )
    command[1:1] = [
        "--name",
        name,
        "--label",
        f"{OWNER_LABEL}={owner}",
        "--label",
        f"{SCOPE_LABEL}={SCOPE}",
    ]
    if user:
        command[1:1] = ["--user", user]
    docker.call(command)
    raw = docker.call(
        ["start", "--attach", "--interactive", name],
        seconds=60,
        allow_worker_rejection=True,
    )
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise ColdRedisError(
            "bounded Redis volume worker returned malformed metadata"
        ) from None
    if not isinstance(value, dict) or value.get("state") != "COPY_VERIFIED":
        raise ColdRedisError(
            "bounded Redis volume copy did not pass source/snapshot integrity"
        )
    return value


def _copy_worker(mode: str) -> int:
    """Worker mode runs only in the pinned offline helper image."""
    stage = "worker_mode"
    try:
        if mode == "prepare-target":
            stage = "prepare_target_mkdir"
            data = Path("/data")
            data.mkdir(parents=True, exist_ok=True)
            stage = "prepare_target_empty_check"
            if any(data.iterdir()):
                raise ColdRedisError(
                    "new owned target must be empty before preparation"
                )
            stage = "prepare_target_chmod"
            data.chmod(0o700)
            stage = "prepare_target_chown"
            os.chown(data, 999, 999)
            print(
                json.dumps({"state": "COPY_VERIFIED", "prepared": True}, sort_keys=True)
            )
            return 0
        if mode == "manifest-only":
            stage = "manifest_source"
            source = Path("/source")
            manifest = _manifest_tree(source)
            stage = "manifest_bounds"
            if manifest["file_count"] < 1 or manifest["total_bytes"] > MAX_SOURCE_BYTES:
                raise ColdRedisError(
                    "source Redis volume is empty or exceeds the copy-size bound"
                )
            stage = "manifest_persistence"
            print(
                json.dumps(
                    {
                        "state": "COPY_VERIFIED",
                        **manifest,
                        "persistence": _persistence_layout(source),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if mode != "copy-hash":
            return 2
        stage = "copy_source_manifest"
        source, target = Path("/source"), Path("/data")
        before = _manifest_tree(source)
        stage = "copy_persistence_before"
        persistence = _persistence_layout(source)
        stage = "copy_bounds"
        if before["file_count"] < 1 or before["total_bytes"] > MAX_SOURCE_BYTES:
            raise ColdRedisError(
                "source Redis volume is empty or exceeds the copy-size bound"
            )
        stage = "copy_target_empty_check"
        if any(target.iterdir()):
            raise ColdRedisError("owned snapshot volume is not empty before copy")
        stage = "copy_tree"
        _copy_tree(source, target)
        stage = "copy_source_manifest_after"
        after = _manifest_tree(source)
        stage = "copy_target_manifest"
        copied = _manifest_tree(target)
        stage = "copy_persistence_after"
        if (
            before != after
            or before["content_sha256"] != copied["content_sha256"]
            or persistence != _persistence_layout(source)
        ):
            raise ColdRedisError(
                "source changed during copy or snapshot content differs"
            )
        print(
            json.dumps(
                {
                    "state": "COPY_VERIFIED",
                    "source_manifest_sha256": before["manifest_sha256"],
                    "source_after_manifest_sha256": after["manifest_sha256"],
                    "snapshot_content_sha256": copied["content_sha256"],
                    "file_count": before["file_count"],
                    "total_bytes": before["total_bytes"],
                    "persistence": persistence,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 -- emit only allowlisted diagnostic tokens.
        exception_class = type(exc).__name__
        if exception_class not in WORKER_EXCEPTION_CLASSES:
            exception_class = "OtherError"
        error_code = getattr(exc, "error_code", None)
        if error_code not in PERSISTENCE_ERROR_CODES:
            error_code = None
        try:
            diagnostic = _validate_persistence_diagnostic(
                getattr(exc, "diagnostic", None) if error_code else None
            )
        except ColdRedisError:
            error_code, diagnostic = None, None
        print(
            json.dumps(
                {
                    "state": "COPY_REJECTED",
                    "error": WORKER_REJECTION_ERROR,
                    "stage": stage,
                    "exception_class": exception_class,
                    "error_code": error_code,
                    "diagnostic": diagnostic,
                }
            )
        )
        return 1


def _manifest_tree(root: Path) -> dict[str, Any]:
    if not root.is_dir() or root.is_symlink():
        raise ColdRedisError("volume root is not a plain directory")
    rows: list[dict[str, Any]] = []
    total = 0
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        dirs.sort()
        files.sort()
        for name in dirs:
            path = base / name
            info = path.lstat()
            if path.is_symlink() or not path.is_dir():
                raise ColdRedisError(
                    "Redis volume contains a link or special directory"
                )
            rows.append(_metadata_row(root, path, info, "directory"))
        for name in files:
            path = base / name
            info = path.lstat()
            if path.is_symlink() or not path.is_file():
                raise ColdRedisError("Redis volume contains a link or special file")
            total += info.st_size
            if len(rows) >= MAX_SOURCE_FILES or total > MAX_SOURCE_BYTES:
                raise ColdRedisError("Redis volume exceeds its file or size bound")
            digest = hashlib.sha256()
            with _open_noatime(path) as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
            row = _metadata_row(root, path, info, "file")
            row["sha256"] = digest.hexdigest()
            rows.append(row)
    if len(rows) > MAX_SOURCE_FILES:
        raise ColdRedisError("Redis volume exceeds its file bound")
    content_rows = [
        {key: row[key] for key in ("path", "size", "sha256")}
        for row in rows
        if row["kind"] == "file"
    ]
    return {
        "file_count": sum(row["kind"] == "file" for row in rows),
        "total_bytes": total,
        "manifest_sha256": _sha256_bytes(_canonical(rows)),
        "content_sha256": _sha256_bytes(_canonical(content_rows)),
    }


def _persistence_layout(root: Path) -> dict[str, Any]:
    """Validate Redis persistence lineage using only filenames and AOF manifest metadata."""
    relative_files: set[str] = set()
    for directory, _dirs, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        for name in files:
            relative_files.add((base / name).relative_to(root).as_posix())
    manifests = sorted(path for path in relative_files if path.endswith(".manifest"))
    multipart: list[str] = []
    manifest_sha256 = None
    recognized_count = sum(
        PERSISTENCE_FILENAME.fullmatch(Path(path).name) is not None
        for path in relative_files
    )

    def reject(code: str, message: str, **metadata: Any) -> None:
        diagnostic: dict[str, Any] = {
            "recognized_file_count": min(recognized_count, MAX_SOURCE_FILES),
            **metadata,
        }
        if manifest_sha256 is not None:
            diagnostic["manifest_sha256"] = manifest_sha256
        raise ColdRedisError(message, error_code=code, diagnostic=diagnostic)

    if manifests:
        if manifests != ["appendonlydir/appendonly.aof.manifest"]:
            reject(
                "MANIFEST_INVENTORY_UNSUPPORTED",
                "Redis AOF manifest inventory is ambiguous or unsupported",
            )
        manifest_path = root / manifests[0]
        if manifest_path.stat().st_size > 1024 * 1024:
            reject(
                "MANIFEST_TOO_LARGE", "Redis AOF manifest exceeds its metadata bound"
            )
        with _open_noatime(manifest_path) as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            reject(
                "MANIFEST_TOO_LARGE", "Redis AOF manifest exceeds its metadata bound"
            )
        manifest_sha256 = _sha256_bytes(raw)
        try:
            lines = raw.decode("ascii").splitlines()
        except UnicodeDecodeError:
            reject(
                "MANIFEST_NON_ASCII",
                "Redis AOF manifest metadata is not ASCII",
                entry_count=0,
            )
        seen_sequences: set[tuple[int, str]] = set()
        entry_count = 0
        for line in lines:
            if not line.strip():
                continue
            entry_count += 1
            # Redis 8.2.2 src/aof.c aofInfoFormat/loadAppendOnlyManifest permits
            # optional incremental replication offsets; no payload is exposed.
            # https://raw.githubusercontent.com/redis/redis/8.2.2/src/aof.c
            match = re.fullmatch(
                r"file (appendonly\.aof\."
                r"(?P<filename_sequence>\d+)\.(?P<kind>base\.rdb|incr\.aof)) "
                r"seq (?P<sequence>\d+) type (?P<entry_type>[bi])"
                r"(?: startoffset (?P<startoffset>0|[1-9][0-9]{0,18})"
                r"(?: endoffset (?P<endoffset>0|[1-9][0-9]{0,18}))?)?",
                line,
            )
            if match is None:
                reject(
                    "MANIFEST_ENTRY_UNSUPPORTED",
                    "Redis AOF manifest entry is unsupported",
                    entry_count=min(entry_count, MAX_SOURCE_FILES),
                )
            filename, filename_sequence, kind = match.group(1, 2, 3)
            sequence_text = match.group("sequence")
            entry_type = match.group("entry_type")
            sequence = int(sequence_text)
            expected_type = "b" if kind == "base.rdb" else "i"
            if (
                entry_type != expected_type
                or filename_sequence != sequence_text
                or (sequence, entry_type) in seen_sequences
            ):
                reject(
                    "MANIFEST_SEQUENCE_TYPE_CONFLICT",
                    "Redis AOF manifest sequence or type conflicts",
                    entry_count=min(entry_count, MAX_SOURCE_FILES),
                    filename=filename,
                    component_type="base" if entry_type == "b" else "incremental",
                    sequence=min(sequence, 9_999_999_999),
                )
            seen_sequences.add((sequence, entry_type))
            startoffset = match.group("startoffset")
            endoffset = match.group("endoffset")
            if startoffset is not None:
                start_value = int(startoffset)
                end_value = int(endoffset) if endoffset is not None else None
                if (
                    entry_type != "i"
                    or start_value > 9_223_372_036_854_775_807
                    or end_value is not None
                    and (
                        end_value > 9_223_372_036_854_775_807 or end_value < start_value
                    )
                ):
                    reject(
                        "MANIFEST_OFFSETS_INVALID",
                        "Redis AOF manifest offset metadata conflicts",
                        entry_count=min(entry_count, MAX_SOURCE_FILES),
                        filename=filename,
                        component_type="base" if entry_type == "b" else "incremental",
                        sequence=min(sequence, 9_999_999_999),
                    )
            relative = "appendonlydir/" + filename
            if relative not in relative_files:
                reject(
                    "COMPONENT_MISSING",
                    "Redis AOF manifest references a missing persistence file",
                    entry_count=min(entry_count, MAX_SOURCE_FILES),
                    filename=filename,
                    component_type="base" if kind == "base.rdb" else "incremental",
                    sequence=min(sequence, 9_999_999_999),
                )
            multipart.append(relative)
        if not multipart or sum(path.endswith(".base.rdb") for path in multipart) != 1:
            reject(
                "BASE_CARDINALITY",
                "Redis multipart AOF manifest has no unique base file",
                entry_count=min(entry_count, MAX_SOURCE_FILES),
            )
        listed = set(multipart) | set(manifests)
        aof_named = {
            path for path in relative_files if path.startswith("appendonlydir/")
        }
        if aof_named != listed:
            reject(
                "UNREFERENCED_COMPONENT",
                "Redis multipart AOF directory has unreferenced persistence files",
                entry_count=min(entry_count, MAX_SOURCE_FILES),
            )
        mode = "REDIS_MULTIPART_AOF"
    else:
        legacy = sorted(path for path in relative_files if path == "appendonly.aof")
        appendonly_files = [
            path for path in relative_files if path.startswith("appendonlydir/")
        ]
        if appendonly_files:
            reject(
                "ORPHANED_APPENDONLYDIR",
                "Redis appendonlydir files have no controlling manifest",
            )
        if legacy:
            mode = "REDIS_LEGACY_AOF"
            multipart = legacy
        elif "dump.rdb" in relative_files:
            mode = "REDIS_RDB_FALLBACK"
        else:
            reject(
                "NO_PERSISTENCE_IMAGE",
                "Redis volume has no recognized persistence image",
            )
    return {
        "format": mode,
        "aof_manifest_sha256": manifest_sha256,
        "aof_file_hashes": [
            {
                "relative_path": path,
                "sha256": _file_sha256(
                    root / path, maximum=MAX_SOURCE_BYTES, noatime=True
                ),
            }
            for path in multipart
        ],
        "rdb_present": "dump.rdb" in relative_files,
    }


def _metadata_row(
    root: Path, path: Path, info: os.stat_result, kind: str
) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    if not relative or any(ord(char) < 32 for char in relative):
        raise ColdRedisError("Redis volume has an unsafe path")
    return {
        "path": relative,
        "kind": kind,
        "size": info.st_size,
        "mode": info.st_mode & 0o7777,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "atime_ns": info.st_atime_ns,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _copy_tree(source: Path, target: Path) -> None:
    for directory, _dirs, files in os.walk(source, topdown=True, followlinks=False):
        source_dir = Path(directory)
        relative = source_dir.relative_to(source)
        target_dir = target / relative
        target_dir.mkdir(parents=True, exist_ok=True)
        source_info = source_dir.stat(follow_symlinks=False)
        os.chmod(target_dir, source_info.st_mode & 0o777)
        for name in sorted(files):
            source_file = source_dir / name
            info = source_file.lstat()
            if source_file.is_symlink() or not source_file.is_file():
                raise ColdRedisError("Redis volume contains an unsafe file")
            destination = target_dir / name
            with _open_noatime(source_file) as reader, destination.open("xb") as writer:
                shutil.copyfileobj(reader, writer, 1024 * 1024)
                writer.flush()
                os.fsync(writer.fileno())
            os.chmod(destination, info.st_mode & 0o777)
            os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns))
        os.utime(target_dir, ns=(source_info.st_atime_ns, source_info.st_mtime_ns))


class RESPReader:
    """Tiny RESP2 reader with an aggregate receive cap; only our two reads use it."""

    def __init__(
        self, connection: socket.socket, *, deadline: float, maximum_bytes: int
    ) -> None:
        self.connection = connection
        self.deadline = deadline
        self.maximum_bytes = maximum_bytes
        self.received = 0
        self.buffer = bytearray()

    def _more(self) -> None:
        remaining_time = self.deadline - time.monotonic()
        remaining_bytes = self.maximum_bytes - self.received
        if remaining_time <= 0 or remaining_bytes <= 0:
            raise ColdRedisError(
                "Redis inspection exceeded its time or response-byte bound"
            )
        self.connection.settimeout(min(3.0, remaining_time))
        data = self.connection.recv(min(64 * 1024, remaining_bytes + 1))
        if not data:
            raise ColdRedisError("Redis inspection response ended unexpectedly")
        self.received += len(data)
        if self.received > self.maximum_bytes:
            raise ColdRedisError("Redis inspection exceeded its response-byte bound")
        self.buffer.extend(data)

    def _take(self, count: int) -> bytes:
        while len(self.buffer) < count:
            self._more()
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def _line(self) -> bytes:
        while True:
            position = self.buffer.find(b"\r\n")
            if position >= 0:
                result = bytes(self.buffer[:position])
                del self.buffer[: position + 2]
                return result
            self._more()

    def parse(self, depth: int = 0) -> Any:
        if depth > 8:
            raise ColdRedisError("Redis response nesting exceeded its bound")
        prefix = self._take(1)
        if prefix in {b"+", b"-", b":"}:
            line = self._line()
            if prefix == b"-":
                raise ColdRedisError("Redis returned an error for a read-only probe")
            if prefix == b":":
                try:
                    return int(line)
                except ValueError:
                    raise ColdRedisError(
                        "Redis integer response is malformed"
                    ) from None
            return line
        if prefix == b"$":
            try:
                length = int(self._line())
            except ValueError:
                raise ColdRedisError(
                    "Redis bulk response length is malformed"
                ) from None
            if length == -1:
                return None
            if length < 0 or length > self.maximum_bytes:
                raise ColdRedisError("Redis bulk response length is outside its bound")
            value = self._take(length + 2)
            if value[-2:] != b"\r\n":
                raise ColdRedisError("Redis bulk response terminator is malformed")
            return value[:-2]
        if prefix == b"*":
            try:
                count = int(self._line())
            except ValueError:
                raise ColdRedisError("Redis array count is malformed") from None
            if count == -1:
                return None
            if count < 0 or count > MAX_XRANGE_ENTRIES * 8 + 16:
                raise ColdRedisError("Redis array count is outside its bound")
            return [self.parse(depth + 1) for _ in range(count)]
        raise ColdRedisError("Redis response type is unsupported")


def _resp_command(reader: RESPReader, connection: socket.socket, *parts: str) -> Any:
    encoded = [part.encode("utf-8") for part in parts]
    request = (
        b"*"
        + str(len(encoded)).encode()
        + b"\r\n"
        + b"".join(
            b"$" + str(len(part)).encode() + b"\r\n" + part + b"\r\n"
            for part in encoded
        )
    )
    connection.sendall(request)
    return reader.parse()


def _decode(value: bytes | None) -> str | None:
    if value is None:
        return None
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _inspect_stream(
    topic: str,
    message_id: str,
    payload_sha256: str,
    *,
    deadline: float,
    connect: Any = socket.create_connection,
) -> dict[str, Any]:
    received_total = 0
    probe_run_id = uuid.uuid4().hex
    probed_at_utc = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    matches: list[str] = []
    entries_scanned = 0
    complete = False
    run_id = None
    cursor = "-"
    try:
        connection = None
        connect_deadline = min(deadline, time.monotonic() + 10)
        while connection is None and time.monotonic() < connect_deadline:
            try:
                connection = connect(
                    ("127.0.0.1", 6379),
                    timeout=min(3.0, max(0.1, connect_deadline - time.monotonic())),
                )
            except OSError:
                time.sleep(0.2)
        if connection is None:
            raise ColdRedisError("isolated Redis clone did not become ready")
        with connection:
            reader = RESPReader(
                connection, deadline=deadline, maximum_bytes=MAX_XRANGE_BYTES
            )
            info = _resp_command(reader, connection, "INFO", "server")
            info_text = _decode(info)
            if not isinstance(info_text, str):
                raise ColdRedisError("Redis server identity response is malformed")
            for line in info_text.splitlines():
                if line.startswith("run_id:"):
                    run_id = line.partition(":")[2].strip()
                    break
            if not isinstance(run_id, str) or REDIS_RUN_ID.fullmatch(run_id) is None:
                raise ColdRedisError("isolated Redis clone run_id is malformed")
            while entries_scanned < MAX_XRANGE_ENTRIES:
                count = min(XRANGE_PAGE_SIZE, MAX_XRANGE_ENTRIES - entries_scanned)
                minimum = cursor if cursor == "-" else "(" + cursor
                reply = _resp_command(
                    reader,
                    connection,
                    "XRANGE",
                    topic,
                    minimum,
                    "+",
                    "COUNT",
                    str(count),
                )
                received_total = reader.received
                if not isinstance(reply, list) or len(reply) > count:
                    raise ColdRedisError("Redis XRANGE response shape or count differs")
                if not reply:
                    complete = True
                    break
                for entry in reply:
                    if (
                        not isinstance(entry, list)
                        or len(entry) != 2
                        or not isinstance(entry[0], bytes)
                    ):
                        raise ColdRedisError("Redis stream entry shape differs")
                    stream_id = _decode(entry[0])
                    if (
                        not isinstance(stream_id, str)
                        or STREAM_ID.fullmatch(stream_id) is None
                    ):
                        raise ColdRedisError("Redis stream ID is malformed")
                    fields = entry[1]
                    if not isinstance(fields, list) or len(fields) % 2:
                        raise ColdRedisError("Redis stream fields are malformed")
                    data_fields = []
                    for index in range(0, len(fields), 2):
                        if _decode(fields[index]) == "data":
                            data_fields.append(fields[index + 1])
                    if len(data_fields) != 1 or not isinstance(data_fields[0], bytes):
                        cursor = stream_id
                        entries_scanned += 1
                        continue
                    try:
                        payload = json.loads(data_fields[0])
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        cursor = stream_id
                        entries_scanned += 1
                        continue
                    if (
                        isinstance(payload, dict)
                        and payload.get("message_id") == message_id
                    ):
                        try:
                            digest = _sha256_bytes(_canonical(payload))
                        except (TypeError, ValueError):
                            digest = None
                        if digest == payload_sha256:
                            matches.append(stream_id)
                    cursor = stream_id
                    entries_scanned += 1
                if len(matches) > 1:
                    break
                if len(reply) < count:
                    complete = True
                    break
            state = (
                "CONFLICT"
                if len(matches) > 1
                else "POSITIVE_ACCEPTED"
                if complete and len(matches) == 1
                else "INCONCLUSIVE_ZERO_MATCH"
                if complete
                else "INCONCLUSIVE_SCAN_LIMIT"
            )
    except (OSError, TimeoutError):
        raise ColdRedisError(
            "isolated Redis read-only inspection failed or timed out"
        ) from None
    result: dict[str, Any] = {
        "state": state,
        "redis_server_run_id": run_id,
        "probe_run_id": probe_run_id,
        "probed_at_utc": probed_at_utc,
        "topic": topic,
        "message_id": message_id,
        "canonical_payload_sha256": payload_sha256,
        "match_count": len(matches) if complete or len(matches) > 1 else None,
        "stream_ids": matches[:16],
        "entries_scanned": entries_scanned,
        "scan_complete": complete,
        "response_bytes": received_total,
        "xrange_limit": MAX_XRANGE_ENTRIES,
        "xrange_response_bytes_limit": MAX_XRANGE_BYTES,
    }
    if state == "POSITIVE_ACCEPTED":
        result["evidence"] = {
            "schema": "kairos.redis-acceptance-evidence.v1",
            "redis_server_run_id": run_id,
            "probe_run_id": probe_run_id,
            "probed_at_utc": probed_at_utc,
            "topic": topic,
            "message_id": message_id,
            "canonical_payload_sha256": payload_sha256,
            "match_count": 1,
            "stream_ids": matches,
        }
    return result


def _worker_manifest(
    docker: BoundedDocker,
    *,
    name: str,
    owner: str,
    script_path: Path | None = None,
) -> dict[str, Any]:
    command = _worker_command(
        "manifest-only", source=SOURCE_VOLUME, script_path=script_path
    )
    command[1:1] = [
        "--name",
        name,
        "--label",
        f"{OWNER_LABEL}={owner}",
        "--label",
        f"{SCOPE_LABEL}={SCOPE}",
    ]
    command[1:1] = ["--user", "999:999"]
    docker.call(command)
    raw = docker.call(["start", "--attach", "--interactive", name], seconds=60)
    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        raise ColdRedisError(
            "bounded source manifest worker returned malformed metadata"
        ) from None
    if not isinstance(result, dict) or result.get("state") != "COPY_VERIFIED":
        raise ColdRedisError("bounded source manifest check did not pass")
    return result


def _metadata_only_docker_command(
    owner: str,
    volume: str,
    container: str,
    image: str,
    *,
    watchdog_seconds: int = 150,
) -> list[str]:
    if not 30 <= watchdog_seconds <= MAX_SECONDS:
        raise ColdRedisError(
            "Redis clone watchdog must remain within the global deadline"
        )
    watchdog_script = (
        'redis-server "$@" & redis_pid=$!; '
        f'(sleep {watchdog_seconds}; kill "$redis_pid" 2>/dev/null) & watchdog_pid=$!; '
        'trap \'kill "$redis_pid" 2>/dev/null; kill "$watchdog_pid" 2>/dev/null; '
        'wait "$redis_pid" 2>/dev/null; exit 0\' TERM INT; '
        'wait "$redis_pid"; status=$?; kill "$watchdog_pid" 2>/dev/null; exit "$status"'
    )
    return [
        "create",
        "--name",
        container,
        "--user=999:999",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--stop-timeout=2",
        "--memory=512m",
        "--memory-swap=512m",
        "--cpus=1",
        "--pids-limit=64",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=32m",
        "--mount",
        f"type=volume,src={volume},dst=/data",
        "--label",
        f"{OWNER_LABEL}={owner}",
        "--label",
        f"{SCOPE_LABEL}={SCOPE}",
        "--entrypoint",
        "sh",
        image,
        "-c",
        watchdog_script,
        "cold-redis-watchdog",
        "--bind",
        "127.0.0.1",
        "--protected-mode",
        "yes",
        "--port",
        "6379",
        "--dir",
        "/data",
        "--appendonly",
        "yes",
        "--aof-load-truncated",
        "no",
        "--daemonize",
        "no",
        "--auto-aof-rewrite-percentage",
        "0",
        "--save",
        "",
        "--loglevel",
        "warning",
    ]


def _validate_clone_metadata(
    docker: BoundedDocker, container: str, volume: str, owner: str
) -> dict[str, Any]:
    raw = docker.call(
        [
            "inspect",
            "--format",
            (
                "{{.Id}}|{{.Image}}|{{.State.Running}}|{{.HostConfig.NetworkMode}}|"
                "{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Memory}}|"
                "{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|"
                "{{.HostConfig.PidsLimit}}|{{json .Mounts}}|{{json .Config.Labels}}"
            ),
            container,
        ]
    )
    parts = raw.split("|", 10)
    if len(parts) != 11:
        raise ColdRedisError("owned Redis clone metadata is malformed")
    try:
        mounts, labels = json.loads(parts[9]), json.loads(parts[10])
    except json.JSONDecodeError:
        raise ColdRedisError("owned Redis clone metadata is malformed") from None
    if (
        parts[1] != SOURCE_IMAGE_ID
        or parts[2] != "false"
        or parts[3] != "none"
        or parts[4] != "true"
        or parts[5] != str(512 * 1024**2)
        or parts[6] != str(512 * 1024**2)
        or parts[7] != str(1_000_000_000)
        or parts[8] != "64"
        or not isinstance(mounts, list)
        or not isinstance(labels, dict)
        or labels.get(OWNER_LABEL) != owner
        or labels.get(SCOPE_LABEL) != SCOPE
    ):
        raise ColdRedisError("owned Redis clone security or resource bounds differ")
    data = [item for item in mounts if item.get("Destination") == "/data"]
    if len(data) != 1 or data[0].get("Name") != volume or data[0].get("RW") is not True:
        raise ColdRedisError("owned Redis clone is not using the exact snapshot volume")
    return {
        "container_id": parts[0],
        "image_id": parts[1],
        "network": parts[3],
        "volume": volume,
    }


def _remove_owned(
    docker: BoundedDocker, name: str, owner: str, *, volume: bool = False
) -> None:
    if volume:
        raw = docker.call(
            ["volume", "inspect", "--format", "{{.Name}}|{{json .Labels}}", name],
            seconds=10,
        )
        parts = raw.split("|", 1)
        try:
            labels = json.loads(parts[1])
        except (IndexError, json.JSONDecodeError):
            raise ColdRedisError(
                "owned volume identity cannot be verified for cleanup"
            ) from None
        if parts[0] != name or labels != {OWNER_LABEL: owner, SCOPE_LABEL: SCOPE}:
            raise ColdRedisError(
                "refused cleanup of a volume outside this cold-clone lease"
            )
        docker.call(["volume", "rm", name], seconds=10)
        return
    raw = docker.call(
        ["inspect", "--format", "{{.Name}}|{{json .Config.Labels}}", name], seconds=10
    )
    parts = raw.split("|", 1)
    try:
        labels = json.loads(parts[1])
    except (IndexError, json.JSONDecodeError):
        raise ColdRedisError(
            "owned container identity cannot be verified for cleanup"
        ) from None
    if (
        not isinstance(labels, dict)
        or parts[0] != "/" + name
        or labels.get(OWNER_LABEL) != owner
        or labels.get(SCOPE_LABEL) != SCOPE
    ):
        raise ColdRedisError(
            "refused cleanup of a container outside this cold-clone lease"
        )
    docker.call(["rm", "--force", name], seconds=10)


def _verify_deploy_head(expected_revision: str) -> None:
    repository = Path(__file__).resolve().parents[1]
    git_prefix = _git_command_prefix(repository)
    command_env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH"}
    }
    try:
        completed = subprocess.run(
            [*git_prefix, "rev-parse", "HEAD"],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=5,
            check=False,
            text=True,
            env=command_env,
        )
        branch = subprocess.run(
            [*git_prefix, "branch", "--show-current"],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=5,
            check=False,
            text=True,
            env=command_env,
        )
        signature = subprocess.run(
            [*git_prefix, "verify-commit", "HEAD"],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=10,
            check=False,
            env=command_env,
        )
    except Exception:  # noqa: BLE001 -- subprocess errors are deliberately sanitized
        raise ColdRedisError("current Deploy revision could not be verified") from None
    if (
        completed.returncode != 0
        or completed.stdout.strip() != expected_revision
        or branch.returncode != 0
        or branch.stdout.strip() != "main"
        or signature.returncode != 0
    ):
        raise ColdRedisError(
            "current Deploy source is not the approved signed main revision"
        )
    relative_source = "scripts/cold_redis_acceptance.py"
    try:
        tracked = subprocess.run(
            [*git_prefix, "ls-files", "--error-unmatch", "--", relative_source],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=5,
            check=False,
            env=command_env,
        )
        unchanged = subprocess.run(
            [*git_prefix, "diff", "--quiet", "HEAD", "--", relative_source],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=5,
            check=False,
            env=command_env,
        )
    except Exception:  # noqa: BLE001 -- subprocess errors are deliberately sanitized
        raise ColdRedisError(
            "cold-clone implementation provenance could not be verified"
        ) from None
    if tracked.returncode != 0 or unchanged.returncode != 0:
        raise ColdRedisError(
            "cold-clone implementation is not the exact committed Deploy source"
        )


def _git_command_prefix(repository: Path) -> list[str]:
    """Pin Git/GPG on Windows and scope safe.directory to this exact checkout."""
    resolved_repository = repository.resolve(strict=True).as_posix()
    if os.name == "nt":
        git_executable, gpg_executable = WINDOWS_GIT, WINDOWS_GPG
        if not git_executable.is_file() or not gpg_executable.is_file():
            raise ColdRedisError("pinned Windows Git/GPG executables are unavailable")
    else:
        git_found, gpg_found = shutil.which("git"), shutil.which("gpg")
        if git_found is None or gpg_found is None:
            raise ColdRedisError("Git/GPG executables are unavailable")
        git_executable = Path(git_found).resolve(strict=True)
        gpg_executable = Path(gpg_found).resolve(strict=True)
    return [
        str(git_executable),
        "-c",
        f"safe.directory={resolved_repository}",
        "-c",
        f"gpg.program={gpg_executable.as_posix()}",
    ]


def execute(
    *,
    accepted_clone_receipt: Path,
    accepted_clone_receipt_sha256: str,
    native_inspection: Path,
    expected_deploy_revision: str,
    confirmation: str,
    work_root: Path = ROOT,
    docker_native: Any | None = None,
    clock: Any = time.monotonic,
) -> dict[str, Any]:
    if (
        confirmation != CONFIRMATION
        or REVISION.fullmatch(expected_deploy_revision) is None
    ):
        raise ColdRedisError(
            "explicit cold-clone confirmation and full Deploy revision are required"
        )
    _verify_deploy_head(expected_deploy_revision)
    target = _target_from_inspection(
        native_inspection, accepted_clone_receipt, accepted_clone_receipt_sha256
    )
    if not work_root.is_absolute():
        raise ColdRedisError("artifact root must be an explicit absolute path")
    _reject_linked_path(work_root, "private cold-clone artifact root")
    work_root.mkdir(parents=True, exist_ok=True)
    _reject_linked_path(work_root, "private cold-clone artifact root")
    script_sha = _file_sha256(Path(__file__), maximum=1024 * 1024)
    revision_dir = work_root / ("revision-" + script_sha)
    try:
        revision_dir.mkdir()
    except FileExistsError:
        raise ColdRedisError(
            "create-only execution lease already exists for this script revision"
        ) from None
    owner = uuid.uuid4().hex
    lease = revision_dir / "execution.lock"
    with lease.open("xb") as stream:
        stream.write((owner + "\n").encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    source_script = Path(__file__).resolve()
    _reject_linked_path(source_script, "cold-clone implementation")
    script_snapshot = revision_dir / "script_snapshot.py"
    snapshot_bytes = source_script.read_bytes()
    if len(snapshot_bytes) > 1024 * 1024 or _sha256_bytes(snapshot_bytes) != script_sha:
        raise ColdRedisError("cold-clone implementation changed while snapshotting")
    with script_snapshot.open("xb") as stream:
        stream.write(snapshot_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    if _file_sha256(script_snapshot, maximum=1024 * 1024) != script_sha:
        raise ColdRedisError(
            "immutable cold-clone script snapshot failed its hash check"
        )
    (revision_dir / "docker-config").mkdir()
    (revision_dir / "docker-config" / "config.json").write_text(
        '{"auths":{}}\n', encoding="utf-8"
    )
    deadline = clock() + MAX_SECONDS - CLEANUP_SECONDS
    docker = BoundedDocker(
        revision_dir,
        deadline,
        docker_native,
        script_snapshot=script_snapshot,
        script_sha256=script_sha,
    )
    _verify_deploy_head(expected_deploy_revision)
    if _file_sha256(script_snapshot, maximum=1024 * 1024) != script_sha:
        raise ColdRedisError(
            "cold-clone script snapshot changed before Linux worker invocation"
        )
    names = {
        "volume": "kairos-cold-redis-data-" + owner[:12],
        "redis": "kairos-cold-redis-server-" + owner[:12],
        "prepare": "kairos-cold-redis-prepare-" + owner[:12],
        "copy": "kairos-cold-redis-copy-" + owner[:12],
        "observer": "kairos-cold-redis-observer-" + owner[:12],
        "verify": "kairos-cold-redis-verify-" + owner[:12],
    }
    source_before = _inspect_source(docker)
    volume_before = _volume_metadata(docker, SOURCE_VOLUME)
    attempted: set[str] = set()
    created: set[str] = set()
    clone_metadata: dict[str, Any] | None = None
    copy_proof: dict[str, Any] | None = None
    observation: dict[str, Any] | None = None
    error_category = None
    error_diagnostic: dict[str, Any] | None = None
    try:
        runner_image_id = docker.call(
            ["image", "inspect", "--format", "{{.Id}}", RUNNER_IMAGE]
        )
        if runner_image_id != "sha256:" + RUNNER_IMAGE.rsplit("sha256:", 1)[1]:
            raise ColdRedisError(
                "cached observer runner image differs from the pinned digest"
            )
        _create_new_owned_volume(docker, names["volume"], owner, attempted)
        created.add("volume")
        prepare = _worker_command(
            "prepare-target", target=names["volume"], script_path=script_snapshot
        )
        prepare[1:1] = [
            "--name",
            names["prepare"],
            "--label",
            f"{OWNER_LABEL}={owner}",
            "--label",
            f"{SCOPE_LABEL}={SCOPE}",
        ]
        attempted.add("prepare")
        docker.call(prepare)
        created.add("prepare")
        prepare_result = docker.call(
            ["start", "--attach", "--interactive", names["prepare"]],
            allow_worker_rejection=True,
        )
        if json.loads(prepare_result).get("prepared") is not True:
            raise ColdRedisError("owned snapshot volume preparation did not complete")
        attempted.add("copy")
        copy_proof = _run_worker(
            docker,
            name=names["copy"],
            owner=owner,
            mode="copy-hash",
            source=SOURCE_VOLUME,
            target=names["volume"],
            user="999:999",
            script_path=script_snapshot,
        )
        created.add("copy")
        volume_after = _volume_metadata(docker, SOURCE_VOLUME)
        source_after = _inspect_source(docker)
        if source_after != source_before or volume_after != volume_before:
            raise ColdRedisError(
                "original Redis container or volume metadata changed during clone copy"
            )
        watchdog_seconds = min(150, int(deadline - clock() - 20))
        attempted.add("redis")
        docker.call(
            _metadata_only_docker_command(
                owner,
                names["volume"],
                names["redis"],
                SOURCE_IMAGE_ID,
                watchdog_seconds=watchdog_seconds,
            )
        )
        created.add("redis")
        clone_metadata = _validate_clone_metadata(
            docker, names["redis"], names["volume"], owner
        )
        docker.call(["start", names["redis"]], seconds=30)
        (revision_dir / "target.json").write_bytes(_canonical(target) + b"\n")
        attempted.add("observer")
        docker.call(
            [
                "create",
                "--name",
                names["observer"],
                "--network",
                "container:" + names["redis"],
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--memory=512m",
                "--memory-swap=512m",
                "--cpus=1",
                "--pids-limit=64",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=32m",
                "--pull=never",
                "--entrypoint",
                "python",
                "--mount",
                f"type=bind,src={script_snapshot},dst=/work/cold_redis_acceptance.py,readonly",
                "--mount",
                f"type=bind,src={revision_dir / 'target.json'},dst=/run/target.json,readonly",
                "--label",
                f"{OWNER_LABEL}={owner}",
                "--label",
                f"{SCOPE_LABEL}={SCOPE}",
                RUNNER_IMAGE,
                "-B",
                "/work/cold_redis_acceptance.py",
                "--worker",
                "observe",
                "/run/target.json",
            ],
            seconds=20,
        )
        created.add("observer")
        observer_raw = docker.call(
            ["start", "--attach", "--interactive", names["observer"]], seconds=80
        )
        try:
            observation = json.loads(observer_raw)
        except json.JSONDecodeError:
            raise ColdRedisError(
                "Redis observer returned invalid payload-free evidence"
            ) from None
        if not isinstance(observation, dict) or observation.get("state") not in {
            "POSITIVE_ACCEPTED",
            "CONFLICT",
            "INCONCLUSIVE_ZERO_MATCH",
            "INCONCLUSIVE_SCAN_LIMIT",
        }:
            raise ColdRedisError(
                "Redis observer returned an unsupported evidence classification"
            )
        attempted.add("verify")
        after_probe_manifest = _worker_manifest(
            docker, name=names["verify"], owner=owner, script_path=script_snapshot
        )
        created.add("verify")
        if after_probe_manifest.get("manifest_sha256") != copy_proof.get(
            "source_manifest_sha256"
        ) or after_probe_manifest.get("persistence") != copy_proof.get("persistence"):
            raise ColdRedisError(
                "original Redis volume file or persistence manifest changed after probe"
            )
        copy_proof["source_after_probe_manifest_sha256"] = after_probe_manifest[
            "manifest_sha256"
        ]
        # Re-check the source after Redis clone startup and the complete probe.
        if (
            _inspect_source(docker) != source_before
            or _volume_metadata(docker, SOURCE_VOLUME) != volume_before
        ):
            raise ColdRedisError(
                "original Redis source changed during clone observation"
            )
    except Exception as exc:  # noqa: BLE001 -- fail closed and emit only a category
        error_category = (
            exc.args[0] if isinstance(exc, ColdRedisError) else type(exc).__name__
        )
        if (
            isinstance(exc, ColdRedisError)
            and exc.error_code in PERSISTENCE_ERROR_CODES
        ):
            error_diagnostic = _validate_persistence_diagnostic(exc.diagnostic)
    finally:
        docker.begin_cleanup()
        cleanup_ok = True
        for key in ("verify", "observer", "copy", "prepare", "redis"):
            if key not in attempted:
                continue
            try:
                _remove_owned(docker, names[key], owner)
            except Exception:  # noqa: BLE001 -- cleanup uncertainty must fail closed
                cleanup_ok = False
        if "volume" in attempted:
            try:
                _remove_owned(docker, names["volume"], owner, volume=True)
            except Exception:  # noqa: BLE001 -- cleanup uncertainty must fail closed
                cleanup_ok = False
    if not cleanup_ok:
        error_category = "OWNED_CLONE_CLEANUP_UNVERIFIED"
    source_after = None
    volume_after = None
    if cleanup_ok:
        try:
            source_after = _inspect_source(docker)
            volume_after = _volume_metadata(docker, SOURCE_VOLUME)
        except ColdRedisError:
            error_category = "ORIGINAL_REDIS_SOURCE_UNVERIFIED"
    if cleanup_ok and (source_after != source_before or volume_after != volume_before):
        error_category = "ORIGINAL_REDIS_SOURCE_CHANGED"
    result = {
        "schema_version": 1,
        "kind": KIND,
        "result": observation.get("state")
        if observation and error_category is None
        else "FAILED_CLOSED",
        "owner": owner,
        "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "expected_deploy_revision": expected_deploy_revision,
        "implementation_sha256": script_sha,
        "accepted_clone_receipt_sha256": target["accepted_clone_receipt_sha256"],
        "native_inspection_sha256": target["native_inspection_sha256"],
        "source": {
            **source_before,
            "volume_metadata_sha256_before": _sha256_bytes(_canonical(volume_before)),
            "volume_metadata_sha256_after": _sha256_bytes(_canonical(volume_after))
            if volume_after
            else None,
            "file_manifest_sha256_before_copy": copy_proof.get("source_manifest_sha256")
            if copy_proof
            else None,
            "file_manifest_sha256_after_copy": copy_proof.get(
                "source_after_manifest_sha256"
            )
            if copy_proof
            else None,
            "file_manifest_sha256_after_probe": copy_proof.get(
                "source_after_probe_manifest_sha256"
            )
            if copy_proof
            else None,
            "source_unchanged": bool(
                source_after == source_before and volume_after == volume_before
            ),
        },
        "cold_clone": {
            "snapshot_volume": names["volume"],
            "snapshot_content_sha256": copy_proof.get("snapshot_content_sha256")
            if copy_proof
            else None,
            "snapshot_file_count": copy_proof.get("file_count") if copy_proof else None,
            "snapshot_bytes": copy_proof.get("total_bytes") if copy_proof else None,
            "persistence_lineage": copy_proof.get("persistence")
            if copy_proof
            else None,
            "redis_instance_identity": "ISOLATED_COLD_CLONE_NOT_ORIGINAL_SERVER",
            "clone_container_id": clone_metadata.get("container_id")
            if clone_metadata
            else None,
            "clone_run_id": observation.get("redis_server_run_id")
            if observation
            else None,
            "native_container_removed": cleanup_ok,
            "snapshot_volume_removed": cleanup_ok,
        },
        "redis_server_identity_scope": "ISOLATED_COLD_CLONE_NOT_ORIGINAL_SERVER",
        "cold_redis_sha256": copy_proof.get("snapshot_content_sha256")
        if copy_proof
        else None,
        "target_identity": {
            "topic": target["topic"],
            "message_id": target["message_id"],
            "canonical_payload_sha256": target["canonical_payload_sha256"],
            "reconciliation_id": target["reconciliation_id"],
        },
        "observation": observation,
        "primary_database_contacted": False,
        "original_redis_started": False,
        "original_redis_commands": 0,
        "credentials_read": False,
        "payload_in_receipt": False,
        "publisher_calls": 0,
        "automatic_resolution": False,
        "error_category": error_category,
        "error_diagnostic": error_diagnostic,
    }
    result["receipt_sha256"] = _sha256_bytes(_canonical(result))
    (revision_dir / "receipt.json").write_bytes(
        (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
    )
    return result


def _observer_worker(config_path: Path) -> int:
    try:
        config = _read_json(config_path, "private observer target", 8192)
        topic, message_id, payload_sha256 = (
            config.get("topic"),
            config.get("message_id"),
            config.get("canonical_payload_sha256"),
        )
        if (
            not isinstance(topic, str)
            or TOPIC.fullmatch(topic) is None
            or not isinstance(message_id, str)
            or MESSAGE_ID.fullmatch(message_id) is None
            or not isinstance(payload_sha256, str)
            or SHA256.fullmatch(payload_sha256) is None
        ):
            raise ColdRedisError("observer target metadata is invalid")
        result = _inspect_stream(
            topic, message_id, payload_sha256, deadline=time.monotonic() + 150
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:  # noqa: BLE001 -- observer errors must not expose response payloads
        print(
            json.dumps(
                {
                    "state": "OBSERVER_REJECTED",
                    "error": "bounded Redis read-only probe failed",
                }
            )
        )
        return 1


def _run_worker_bounded(callback: Any, *, seconds: int) -> int:
    def timeout(_signum: int, _frame: Any) -> None:
        raise TimeoutError("bounded clone worker deadline elapsed")

    previous = signal.signal(signal.SIGALRM, timeout)
    signal.alarm(seconds)
    try:
        return callback()
    except Exception:  # noqa: BLE001 -- worker output is sanitized by contract
        print(
            json.dumps(
                {"state": "WORKER_REJECTED", "error": "bounded clone worker failed"}
            )
        )
        return 1
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-cold-clone", action="store_true")
    parser.add_argument("--confirmation")
    parser.add_argument("--expected-deploy-revision")
    parser.add_argument("--accepted-clone-receipt", type=Path)
    parser.add_argument("--accepted-clone-receipt-sha256")
    parser.add_argument("--native-inspection", type=Path)
    parser.add_argument("--work-root", type=Path, default=ROOT)
    parser.add_argument(
        "--worker", choices=("copy-hash", "manifest-only", "prepare-target", "observe")
    )
    parser.add_argument("worker_config", nargs="?", type=Path)
    args = parser.parse_args(argv)
    if args.worker == "copy-hash":
        return _run_worker_bounded(lambda: _copy_worker("copy-hash"), seconds=120)
    if args.worker == "prepare-target":
        return _run_worker_bounded(lambda: _copy_worker("prepare-target"), seconds=30)
    if args.worker == "manifest-only":
        return _run_worker_bounded(lambda: _copy_worker("manifest-only"), seconds=60)
    if args.worker == "observe" and args.worker_config is not None:
        return _run_worker_bounded(
            lambda: _observer_worker(args.worker_config), seconds=150
        )
    if not args.execute_cold_clone:
        print(json.dumps(plan(), sort_keys=True, indent=2))
        return 0
    if any(
        value is None
        for value in (
            args.confirmation,
            args.expected_deploy_revision,
            args.accepted_clone_receipt,
            args.accepted_clone_receipt_sha256,
            args.native_inspection,
        )
    ):
        raise SystemExit(
            "explicit confirmation, revision, receipt hash and native inspection are required"
        )
    try:
        receipt = execute(
            accepted_clone_receipt=args.accepted_clone_receipt,
            accepted_clone_receipt_sha256=args.accepted_clone_receipt_sha256,
            native_inspection=args.native_inspection,
            expected_deploy_revision=args.expected_deploy_revision,
            confirmation=args.confirmation,
            work_root=args.work_root,
        )
        print(
            json.dumps(
                {
                    "result": receipt["result"],
                    "receipt_sha256": receipt["receipt_sha256"],
                }
            )
        )
        return (
            0
            if receipt["result"]
            in {
                "POSITIVE_ACCEPTED",
                "CONFLICT",
                "INCONCLUSIVE_ZERO_MATCH",
                "INCONCLUSIVE_SCAN_LIMIT",
            }
            else 1
        )
    except ColdRedisError as exc:
        print(json.dumps({"result": "FAILED_CLOSED", "error_category": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
