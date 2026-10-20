"""Clone-only AOF recovery qualification for one failed CLOSED_BAR epoch.

The default invocation is a plan.  The explicit qualification mode copies the
one admitted Redis volume into two new owner-labelled volumes, inventories the
AOF read-only, and proves replay against an isolated Redis clone.  It never
starts, stops, writes, or changes ACLs on the admitted Redis container.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import cold_redis_acceptance as cold
    from scripts import runtime_epoch_boot as boot
    from scripts import runtime_epoch_controller as epoch
    from scripts import runtime_epoch_redis_aof as aof
    from scripts.runtime_epoch_redis_aof_clone import (
        AofCloneDependencies,
        AofClonePrimitives,
    )
else:
    import cold_redis_acceptance as cold
    import runtime_epoch_boot as boot
    import runtime_epoch_controller as epoch
    import runtime_epoch_redis_aof as aof
    from runtime_epoch_redis_aof_clone import AofCloneDependencies, AofClonePrimitives

OWNER = "69893dc7b7c647f49967387e7efca9fb"
PREFIX = "kairos-epoch-" + OWNER[:12]
SCOPE = "kairos-nontrading-runtime-epoch-redis-aof-clone-v1"
ROOT = Path("D:/Kairos/runtime/epoch-redis-aof-recovery-20261011")
LEASE = ROOT / "recovery.active"
VERIFY_LEASE = ROOT / "original-verification.active"
BOOT_RUN = "e1e4a133a0f04cdd9ee915720ea9d598"
BOOT_FAILURE_SHA256 = "870b053c163499327ce9888c36ec0aa6bf802b6c4b9647049498505695f1f78a"
BINDING_SHA256 = "62b3ca1224b740683b2f5f59ea1bc1c69bdd739cfdc08abea80aaa4ca2131fc0"
BACKUP_VOLUME = PREFIX + "-redis-aof-backup"
CLONE_VOLUME = PREFIX + "-redis-aof-clone"
CLONE_CONTAINER = PREFIX + "-redisclone"
MAX_SECONDS = 3600
MAX_AOF_BYTES = 8 * 1024 * 1024
EXPECTED_ROWS = 2220
EXPECTED_STREAM = 2221
OPEN_SEGMENT_MANIFEST_SHA256 = (
    "c5ae0c02c2388c4f500bffe3590ba7687884e4ba6ad665bb9f2e8f3a68ce1e65"
)
CLOSED_SEGMENT_MANIFEST_SHA256 = (
    "fb00f2179825f719a7ba600f7b9cf2d4624191af6bc9d90bef0cd8efc1fd1840"
)
EXACT_SEGMENT_FILES = [
    {
        "relative_path": "appendonlydir/appendonly.aof.1.base.rdb",
        "sha256": "21d5885cd631bbc5b955de4e01b0245a85f1d6c66ff5ba68861ccc19bfe7ffdf",
    },
    {
        "relative_path": "appendonlydir/appendonly.aof.1.incr.aof",
        "sha256": "79d2a09bf0e204b92c50a9362566b7cffe67d70b27f6a12465b6d01d7f4183f8",
    },
]


def reject(code: str) -> None:
    raise epoch.Rejected(code)


def _json(path: Path, *, limit: int = 131_072) -> dict:
    return boot.read_json(path, limit=limit)


def _create_only(path: Path, data: bytes) -> None:
    if not isinstance(data, bytes) or path.exists() or path.is_symlink():
        reject("CREATE_ONLY_PRIVATE_EVIDENCE_REQUIRED")
    epoch.fresh.write(path, data)


def _sha_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _bounded_task_state() -> dict:
    """Read Task Scheduler and process state without exposing command lines."""
    command = r"""
$ErrorActionPreference='Stop'
$t=@(Get-ScheduledTask -TaskName 'Kairos-NonTradingEpoch-69893dc7b7c6-Boot' -ErrorAction Stop)
if($t.Count -ne 1){throw 'TASK_IDENTITY'}
$i=Get-ScheduledTaskInfo -TaskName 'Kairos-NonTradingEpoch-69893dc7b7c6-Boot' -ErrorAction Stop
$p=@(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^python(w)?\.exe$' -and $_.CommandLine -match 'runtime_epoch_boot\.py' })
@{state=[string]$t[0].State;last_result=[int]$i.LastTaskResult;boot_python_count=$p.Count} | ConvertTo-Json -Compress
"""
    try:
        result = subprocess.run(
            [str(epoch.PS), "-NoProfile", "-NonInteractive", "-Command", command],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            shell=False,
            env=epoch.fresh.supervisor_environment(),
        )
    except Exception:  # noqa: BLE001 - do not return process details.
        reject("BOOT_TASK_STATE_READ_FAILED")
    if result.returncode or len(result.stdout) > 4096:
        reject("BOOT_TASK_STATE_READ_FAILED")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("BOOT_TASK_STATE_READ_FAILED")
    if (
        not isinstance(value, dict)
        or value.get("state") != "Ready"
        or value.get("last_result") != 1
        or value.get("boot_python_count") != 0
    ):
        reject("FAILED_BOOT_TASK_MUST_BE_READY_AND_IDLE")
    return {"state": "Ready", "last_result": 1, "boot_python_count": 0}


def _failure_paths() -> tuple[Path, Path, Path, Path]:
    boot_root = boot.ROOT
    run = boot_root / "runs" / BOOT_RUN
    return (
        boot_root / "boot.active",
        run / "boot-failure.json",
        run / "output-boot-redis-state-beforestart" / "status.json",
        boot_root / "binding.json",
    )


def validate_failure_evidence(
    *,
    active_path: Path,
    failure_path: Path,
    status_path: Path,
    binding_path: Path,
    task_state: dict,
    allowed_acl_sha256: str | None = None,
) -> dict:
    """Admit only the fixed, hash-bound Redis-publication boot failure."""
    active_bytes = epoch.fresh.safe(active_path).read_bytes()
    try:
        active = json.loads(active_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("EXACT_PREVIOUS_BOOT_LATCH_REQUIRED")
    if (
        not isinstance(active, dict)
        or active.get("owner") != OWNER
        or active.get("run") != BOOT_RUN
        or re.fullmatch(r"[0-9]{15,20}", str(active.get("boot_id", ""))) is None
    ):
        reject("EXACT_PREVIOUS_BOOT_LATCH_REQUIRED")
    if epoch.fresh.sha(failure_path) != BOOT_FAILURE_SHA256:
        reject("EXACT_REVIEWED_BOOT_FAILURE_REQUIRED")
    failure = _json(failure_path)
    status = _json(status_path)
    if (
        failure.get("state") != "FAILED_CLOSED"
        or failure.get("reason") != "WORKER_MODE_FAILED_BOOT-REDIS-STATE"
        or failure.get("owner") != OWNER
        or failure.get("trading_started") is not False
        or status.get("state") != "FAILED_CLOSED"
        or status.get("mode") != "boot-redis-state"
        or status.get("reason") != "BOOT_REDIS_PUBLICATION_RECEIPT_MISSING"
        or status.get("trading_started") is not False
    ):
        reject("EXACT_REVIEWED_PUBLICATION_FAILURE_REQUIRED")
    if epoch.fresh.sha(binding_path) != BINDING_SHA256:
        reject("EXACT_PREVIOUS_BOOT_BINDING_REQUIRED")
    binding = _json(binding_path, limit=1_048_576)
    # Do not run boot.validate_binding here: it deliberately binds the older
    # source-file snapshot.  This recovery binds the fresh signed revision,
    # while requiring the previous private inputs themselves to be unchanged.
    if (
        binding.get("schema_version") != 1
        or binding.get("owner") != OWNER
        or binding.get("scope") != boot.SCOPE
        or binding.get("repo") != epoch.REPO.as_posix()
        or binding.get("python_path") != boot.PYTHON.as_posix()
        or binding.get("containers") != boot.CONTAINERS
        or binding.get("parent_receipt_sha256") != boot.PARENT_RECEIPT_SHA256
        or not isinstance(binding.get("revision"), str)
        or re.fullmatch(r"[0-9a-f]{40}", binding["revision"]) is None
    ):
        reject("EXACT_PREVIOUS_BOOT_BINDING_REQUIRED")
    inputs = binding.get("inputs")
    paths = boot.input_paths()
    if not isinstance(inputs, dict) or set(inputs) != {p.as_posix() for p in paths}:
        reject("PREVIOUS_BOOT_INPUT_INVENTORY_REQUIRED")
    for path in paths:
        current_hash = epoch.fresh.sha(path)
        acl_replacement = (
            path == boot.PARENT / "redis-users.acl"
            and allowed_acl_sha256 is not None
            and current_hash == allowed_acl_sha256
        )
        if inputs.get(path.as_posix()) != current_hash and not acl_replacement:
            reject("PREVIOUS_BOOT_PRIVATE_INPUT_CHANGED")
    if not isinstance(binding.get("source_files"), dict):
        reject("PREVIOUS_BOOT_SOURCE_INVENTORY_REQUIRED")
    return {
        "boot_run": BOOT_RUN,
        "boot_failure_sha256": BOOT_FAILURE_SHA256,
        "boot_failure_reason": failure["reason"],
        "status_reason": status["reason"],
        "binding_sha256": BINDING_SHA256,
        "previous_source_revision": binding["revision"],
        "task_state": task_state,
        "active_latch_sha256": _sha_bytes(active_bytes),
        "active_latch_bytes": active_bytes,
    }


def validate_copy_proof(value: object, *, source_manifest: dict) -> dict:
    if not isinstance(value, dict) or value.get("state") != "COPY_VERIFIED":
        reject("REDIS_AOF_COPY_DID_NOT_PASS")
    if (
        value.get("source_manifest_sha256") != source_manifest.get("manifest_sha256")
        or value.get("source_after_manifest_sha256")
        != source_manifest.get("manifest_sha256")
        or value.get("snapshot_content_sha256") != source_manifest.get("content_sha256")
        or value.get("file_count") != 4
        or type(value.get("total_bytes")) is not int
        or not 0 < value["total_bytes"] <= MAX_AOF_BYTES
    ):
        reject("REDIS_AOF_COPY_MANIFEST_OR_SIZE_CONFLICT")
    return {
        "source_manifest_sha256": value["source_manifest_sha256"],
        "source_after_manifest_sha256": value["source_after_manifest_sha256"],
        "snapshot_content_sha256": value["snapshot_content_sha256"],
        "file_count": value["file_count"],
        "total_bytes": value["total_bytes"],
    }


def validate_authoritative_persistence(current: object, expected: object) -> dict:
    """Bind data bytes; admit only the measured same-segment shutdown endoffset.

    Redis adds exactly `endoffset 3256200` to this frozen manifest on clean
    shutdown. Both raw manifest hashes remain recorded; no other difference
    or any base/increment byte change is admitted, even on another segment.
    """
    if not isinstance(current, dict) or not isinstance(expected, dict):
        reject("REDIS_AOF_AUTHORITATIVE_PERSISTENCE_REQUIRED")
    files = current.get("aof_file_hashes")
    if (
        current.get("format") != "REDIS_MULTIPART_AOF"
        or not isinstance(current.get("aof_manifest_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", current["aof_manifest_sha256"]) is None
        or not isinstance(files, list)
        or len(files) < 2
    ):
        reject("REDIS_AOF_AUTHORITATIVE_PERSISTENCE_CHANGED")
    if current != expected:
        other_current = {k: v for k, v in current.items() if k != "aof_manifest_sha256"}
        other_expected = {
            k: v for k, v in expected.items() if k != "aof_manifest_sha256"
        }
        if (
            other_current != other_expected
            or current.get("rdb_present") is not True
            or files != EXACT_SEGMENT_FILES
            or {current.get("aof_manifest_sha256"), expected.get("aof_manifest_sha256")}
            != {OPEN_SEGMENT_MANIFEST_SHA256, CLOSED_SEGMENT_MANIFEST_SHA256}
        ):
            reject("REDIS_AOF_AUTHORITATIVE_PERSISTENCE_CHANGED")
    return current


def validate_aof_inventory(value: object, *, worker_proof: dict | None = None) -> dict:
    if not isinstance(value, dict) or value.get("status") != "PASS_AOF_INVENTORY":
        reject("REDIS_AOF_INVENTORY_DID_NOT_PASS")
    counts = value.get("subcommand_counts")
    if not isinstance(counts, dict):
        reject("REDIS_AOF_SUBCOMMAND_INVENTORY_REQUIRED")
    if (
        value.get("dbs") != [0]
        or value.get("ledger_fields") != EXPECTED_ROWS
        or value.get("receipt_count") != EXPECTED_ROWS
        or value.get("xadd_count") != EXPECTED_STREAM
        or value.get("publication_message_ids_sha256")
        != (worker_proof or {}).get(
            "publication_message_ids_sha256",
            value.get("publication_message_ids_sha256"),
        )
        or counts.get("select", 0) < 1
        or counts.get("hset") != EXPECTED_ROWS
        or counts.get("xadd") != EXPECTED_STREAM
        or counts.get("xgroup|create") != 1
        or counts.get("xgroup|setid") != 1329
        or counts.get("multi") != counts.get("exec")
        or value.get("transactions_balanced") is not True
        or value.get("actor_format_valid") is not True
        or value.get("matched_receipt_count") != EXPECTED_ROWS
    ):
        reject("REDIS_AOF_INVENTORY_PROOF_CONFLICT")
    for field in ("parsed_source_sha256", "publication_message_ids_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", str(value.get(field, ""))) is None:
            reject("REDIS_AOF_INVENTORY_HASH_REQUIRED")
    if type(value.get("bytes")) is not int or not 0 < value["bytes"] <= MAX_AOF_BYTES:
        reject("REDIS_AOF_INVENTORY_SIZE_REQUIRED")
    return {
        "status": "PASS_AOF_INVENTORY",
        "bytes": value["bytes"],
        "parsed_source_sha256": value["parsed_source_sha256"],
        "publication_message_ids_sha256": value["publication_message_ids_sha256"],
        "dbs": [0],
        "ledger_fields": EXPECTED_ROWS,
        "receipt_count": EXPECTED_ROWS,
        "xadd_count": EXPECTED_STREAM,
        "subcommand_counts": dict(sorted(counts.items())),
        "matched_receipt_count": EXPECTED_ROWS,
        "actor_format_valid": True,
        "transactions_balanced": True,
    }


def validate_readonly_manifest_stability(before: dict, after: dict) -> dict:
    """AOF stays byte-identical; Redis may asynchronously refresh root RDB cache.

    The cold worker admits exactly three authoritative AOF files plus the
    existing root dump.rdb. Only its cache contribution may change; both full
    hashes remain evidence. Pristine backup checks never use this relaxation.
    """
    fields = {
        "state",
        "file_count",
        "total_bytes",
        "manifest_sha256",
        "content_sha256",
        "persistence",
        "cache_stable_metadata_sha256",
    }
    for value in (before, after):
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or value.get("state") != "COPY_VERIFIED"
            or value.get("file_count") != 4
            or type(value.get("total_bytes")) is not int
            or not 0 < value["total_bytes"] <= MAX_AOF_BYTES
            or not isinstance(value.get("persistence"), dict)
            or value["persistence"].get("rdb_present") is not True
            or any(
                re.fullmatch(r"[0-9a-f]{64}", str(value.get(key, ""))) is None
                for key in (
                    "manifest_sha256",
                    "content_sha256",
                    "cache_stable_metadata_sha256",
                )
            )
        ):
            reject("EXACT_READONLY_REDIS_FOUR_FILE_MANIFEST_REQUIRED")
    if (
        before["persistence"] != after["persistence"]
        or before["cache_stable_metadata_sha256"]
        != after["cache_stable_metadata_sha256"]
    ):
        reject("ORIGINAL_REDIS_CHANGED_DURING_READONLY_VERIFICATION")
    return {
        "root_rdb_cache_refreshed": before != after,
        "before_full_manifest_sha256": before["manifest_sha256"],
        "after_full_manifest_sha256": after["manifest_sha256"],
        "before_content_sha256": before["content_sha256"],
        "after_content_sha256": after["content_sha256"],
        "authoritative_aof_byte_identical": True,
        "noncache_tree_and_security_metadata_identical": True,
        "cache_stable_metadata_sha256": before["cache_stable_metadata_sha256"],
    }


def validate_redis_worker_proof(value: object, *, clone: bool) -> dict:
    auth = value.get("auth_proofs") if isinstance(value, dict) else None
    expected_auth = {
        "anonymous_ping_refused": True,
        "default_auth_refused": True,
        "anonymous_write_refused_on_clone": clone,
    }
    if (
        not isinstance(value, dict)
        or value.get("state") != "PASS_BOOT_REDIS_STATE"
        or value.get("owner") != OWNER
        or value.get("mode") != ("boot-redis-clone" if clone else "boot-redis-state")
        or value.get("new_epoch_database") != "kairos_epoch_" + OWNER[:12]
        or value.get("outbox_rows") != EXPECTED_ROWS
        or value.get("completed_inbox") != EXPECTED_ROWS
        or value.get("stream_entries") != EXPECTED_STREAM
        or value.get("publication_receipts") != EXPECTED_ROWS
        or value.get("consumer_groups") != 1
        or value.get("pending_deliveries") != 0
        or re.fullmatch(
            r"[0-9a-f]{64}", str(value.get("publication_message_ids_sha256", ""))
        )
        is None
        or auth != expected_auth
        or value.get("trading_started") is not False
    ):
        reject("BOOT_REDIS_STATE_PROOF_CONFLICT")
    return {
        "state": "PASS_BOOT_REDIS_STATE",
        "owner": OWNER,
        "mode": "boot-redis-clone" if clone else "boot-redis-state",
        "new_epoch_database": "kairos_epoch_" + OWNER[:12],
        "outbox_rows": EXPECTED_ROWS,
        "completed_inbox": EXPECTED_ROWS,
        "stream_entries": EXPECTED_STREAM,
        "publication_receipts": EXPECTED_ROWS,
        "publication_message_ids_sha256": value["publication_message_ids_sha256"],
        "consumer_groups": 1,
        "pending_deliveries": 0,
        "auth_proofs": expected_auth,
        "trading_started": False,
    }


def _worker_json(output: str, *, status: str, limit: int = 32_768) -> dict:
    if not isinstance(output, str) or len(output.encode("utf-8", "replace")) > limit:
        reject("BOUNDED_PRIVATE_WORKER_OUTPUT_REQUIRED")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        reject("PRIVATE_WORKER_JSON_REQUIRED")
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError:
        reject("PRIVATE_WORKER_JSON_REQUIRED")
    if not isinstance(value, dict) or value.get("status", value.get("state")) != status:
        reject("PRIVATE_WORKER_RESULT_NOT_ACCEPTED")
    return value


class RedisAofRecoveryController(boot.BootController):
    def __init__(self, *args, run_id: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.run_id = run_id
        self.names["source_volume"] = BACKUP_VOLUME
        self.names["restore_volume"] = CLONE_VOLUME
        self.cold_snapshot: Path | None = None
        self.aof_snapshot: Path | None = None
        self.original_acl_path: Path | None = None
        self.candidate_acl_path: Path | None = None
        self.lease_bytes: bytes | None = None
        self.verification_lease_bytes: bytes | None = None
        self.preserved: dict | None = None
        self.original_manifest_before: dict | None = None
        self.aof_source: dict | None = None
        self.worker_proof: dict | None = None
        self.offline_helper_ids: dict[str, str] = {}

    def _clone_primitives(self) -> AofClonePrimitives:
        """Inject this run's already-admitted I/O into shared AOF primitives."""
        return AofClonePrimitives(
            AofCloneDependencies(
                owner=OWNER,
                prefix=PREFIX,
                scope_label=epoch.EPOCH_SCOPE,
                epoch_label=epoch.EPOCH_LABEL,
                runner_image=cold.RUNNER_IMAGE,
                worker_image=epoch.WORKER_IMAGE,
                run_id=self.run_id,
                max_aof_bytes=MAX_AOF_BYTES,
                cold_snapshot=self.cold_snapshot,
                aof_snapshot=self.aof_snapshot,
                created=self.created,
                helper_ids=self.offline_helper_ids,
                docker=self.docker,
                inspect_container=self.inspect_container,
                require_mount_set=self.require_mount_set,
                cold_worker_command=cold._worker_command,
                worker_json=_worker_json,
                validate_copy_proof=validate_copy_proof,
                validate_aof_inventory=validate_aof_inventory,
                reject=reject,
            )
        )

    def _assert_absent(self) -> None:
        names = (BACKUP_VOLUME, CLONE_VOLUME)
        for name in names:
            volumes = self.docker(
                [
                    "volume",
                    "ls",
                    "--filter",
                    "name=^" + name + "$",
                    "--format",
                    "{{.Name}}",
                ]
            ).splitlines()
            if volumes:
                reject("REDIS_AOF_NEW_VOLUMES_MUST_BE_ABSENT")
        containers = self.docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=^/" + CLONE_CONTAINER + "$",
                "--format",
                "{{.Names}}",
            ]
        ).splitlines()
        if containers:
            reject("REDIS_AOF_CLONE_CONTAINER_MUST_BE_ABSENT")

    def _owned_labels(self) -> list[str]:
        # Kept as a compatibility seam for callers/tests; implementation lives
        # in the dependency-injected shared primitive.
        return self._clone_primitives()._owned_labels()

    def _create_offline_helper(
        self, name: str, argv: list[str], expected_mounts: dict
    ) -> dict:
        return self._clone_primitives().create_offline_helper(
            name, argv, expected_mounts
        )

    def _finish_offline_helper(self, name: str, output: str, *, status: str) -> dict:
        return self._clone_primitives().finish_offline_helper(
            name, output, status=status
        )

    def cold_manifest(
        self, volume: str, tag: str, *, cache_proof: bool = False
    ) -> dict:
        return self._clone_primitives().cold_manifest(
            volume, tag, cache_proof=cache_proof
        )

    def copy_volume(
        self, source: str, target: str, tag: str, source_manifest: dict
    ) -> dict:
        return self._clone_primitives().copy_volume(
            source, target, tag, source_manifest
        )

    def aof_inventory(
        self, volume: str, tag: str, worker_proof: dict | None = None
    ) -> dict:
        return self._clone_primitives().aof_inventory(
            volume, tag, worker_proof=worker_proof
        )

    def _clone_container_absent(self) -> None:
        output = self.docker(
            [
                "ps",
                "-a",
                "--filter",
                "name=^/" + CLONE_CONTAINER + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        if output.strip():
            reject("REDIS_AOF_CLONE_CONTAINER_MUST_BE_ABSENT")

    def _source_view_fingerprint(self, resources: dict) -> dict:
        value = resources["views"]["redis"]
        if value.get("id") != boot.CONTAINERS["redis"]:
            reject("EXACT_ORIGINAL_EPOCH_REDIS_REQUIRED")
        return {
            "id": value["id"],
            "image": value["image"],
            "state": value.get("state"),
            "mounts": value.get("mounts"),
            "network": value.get("network"),
            "networks": value.get("networks"),
            "labels": value.get("labels"),
        }

    def _make_snapshots(self) -> None:
        self.prepare_snapshots()
        self.cold_snapshot = self.work / "cold_redis_acceptance.py"
        paths = epoch.extract_git_snapshot(
            epoch.REPO,
            self.expected_revision,
            ("scripts/cold_redis_acceptance.py",),
            self.work / "cold-worker-snapshot",
            strip_prefix="scripts",
        )
        if set(paths) != {"cold_redis_acceptance.py"}:
            reject("EXACT_PINNED_COLD_REDIS_WORKER_REQUIRED")
        # The archive extractor's destination is the directory.  Keep a private
        # single-file copy so the Docker helper has an unambiguous readonly bind.
        source = self.work / "cold-worker-snapshot" / "cold_redis_acceptance.py"
        if not source.is_file() or source.is_symlink():
            reject("EXACT_PINNED_COLD_REDIS_WORKER_REQUIRED")
        epoch.fresh.write(self.cold_snapshot, source.read_bytes())
        self.aof_snapshot = self.work / "runtime_epoch_redis_aof.py"
        aof_paths = epoch.extract_git_snapshot(
            epoch.REPO,
            self.expected_revision,
            ("scripts/runtime_epoch_redis_aof.py",),
            self.work / "aof-worker-snapshot",
            strip_prefix="scripts",
        )
        if set(aof_paths) != {"runtime_epoch_redis_aof.py"}:
            reject("EXACT_PINNED_AOF_INVENTORY_MODULE_REQUIRED")
        aof_source = self.work / "aof-worker-snapshot" / "runtime_epoch_redis_aof.py"
        if not aof_source.is_file() or aof_source.is_symlink():
            reject("EXACT_PINNED_AOF_INVENTORY_MODULE_REQUIRED")
        epoch.fresh.write(self.aof_snapshot, aof_source.read_bytes())
        self.proofs["cold_worker_sha256"] = epoch.fresh.sha(self.cold_snapshot)
        self.proofs["aof_inventory_module_sha256"] = epoch.fresh.sha(self.aof_snapshot)

    def _private_acls(self) -> tuple[bytes, bytes]:
        source = boot.PARENT / "redis-users.acl"
        if not source.is_file() or source.is_symlink():
            reject("ORIGINAL_EPOCH_PRIVATE_ACL_REQUIRED")
        original = source.read_bytes()
        self.original_acl_path = self.work / "original-redis-users.acl"
        self.candidate_acl_path = self.work / "candidate-redis-users.acl"
        _create_only(self.original_acl_path, original)
        candidate = aof.candidate_acl(original, OWNER)
        original_suffix = original[original.find(b"\n") + 1 :]
        candidate_suffix = candidate[candidate.find(b"\n") + 1 :]
        if candidate_suffix != original_suffix:
            reject("REDIS_NAMED_ROLE_ACL_BYTES_MUST_BE_IDENTICAL")
        _create_only(self.candidate_acl_path, candidate)
        self.proofs["original_acl_sha256"] = epoch.fresh.sha(self.original_acl_path)
        self.proofs["candidate_acl_sha256"] = epoch.fresh.sha(self.candidate_acl_path)
        self.proofs["named_roles_acl_byte_identical"] = True
        return original, candidate

    def _stop_clone(self) -> None:
        view = self.inspect_container(CLONE_CONTAINER)
        labels = view.get("labels") or {}
        if (
            view.get("id") != self.proofs.get("clone_container_id")
            or labels.get(epoch.EPOCH_LABEL) != OWNER
            or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
        ):
            reject("OWNER_LABELLED_REDIS_AOF_CLONE_REQUIRED_FOR_STOP")
        if (view.get("state") or {}).get("Status") == "running":
            self.docker(["stop", "--time=15", CLONE_CONTAINER], seconds=25)
        stopped = self.inspect_container(CLONE_CONTAINER)
        if (stopped.get("state") or {}).get("Status") != "exited":
            reject("REDIS_AOF_CLONE_MUST_BE_STOPPED_AFTER_READONLY_PROOF")
        self.proofs["clone_stopped"] = True

    def validate_admission(
        self, *, allowed_acl_sha256: str | None = None
    ) -> tuple[dict, dict, dict]:
        task = _bounded_task_state()
        active_path, failure_path, status_path, binding_path = _failure_paths()
        preserved = validate_failure_evidence(
            active_path=active_path,
            failure_path=failure_path,
            status_path=status_path,
            binding_path=binding_path,
            task_state=task,
            allowed_acl_sha256=allowed_acl_sha256,
        )
        resources = self.validate_resources(allow_running=True)
        serve_state = resources["views"]["serve"].get("state") or {}
        if serve_state.get("Status") != "exited" or serve_state.get("ExitCode") != 255:
            reject("EXACT_FAILED_CLOSED_SERVE_EXIT_255_REQUIRED")
        redis_state = resources["views"]["redis"].get("state") or {}
        if redis_state.get("Status") != "running":
            reject("ORIGINAL_EPOCH_REDIS_MUST_REMAIN_RUNNING")
        if resources["views"]["pg"].get("id") != boot.CONTAINERS["pg"]:
            reject("EXACT_NEW_EPOCH_POSTGRES_REQUIRED")
        preserved["resource_metadata"] = {
            "legacy": resources["legacy"],
            "standby": resources["standby"],
            "redis": self._source_view_fingerprint(resources),
        }
        return (
            preserved,
            resources,
            {
                "active_path": active_path,
                "active_bytes": preserved["active_latch_bytes"],
            },
        )

    def _assert_preserved_after(
        self, *, source_fingerprint: dict, source_manifest: dict, task_before: dict
    ) -> dict:
        manifest_after = self.cold_manifest(self.names["redis_volume"], "source-after")
        if manifest_after != self.original_manifest_before:
            reject("ORIGINAL_REDIS_VOLUME_MANIFEST_CHANGED")
        resources = self.validate_resources(allow_running=False)
        if (
            resources["legacy"] != self.preserved["resource_metadata"]["legacy"]
            or resources["standby"] != self.preserved["resource_metadata"]["standby"]
        ):
            reject("LEGACY_OR_STANDBY_METADATA_CHANGED")
        if self._source_view_fingerprint(resources) != source_fingerprint:
            reject("ORIGINAL_REDIS_CONTAINER_METADATA_CHANGED")
        if _bounded_task_state() != task_before:
            reject("BOOT_TASK_STATE_CHANGED_DURING_CLONE_QUALIFICATION")
        _, failure, status, binding = _failure_paths()
        if (
            epoch.fresh.sha(failure) != BOOT_FAILURE_SHA256
            or epoch.fresh.sha(binding) != BINDING_SHA256
        ):
            reject("ORIGINAL_BOOT_FAILURE_EVIDENCE_CHANGED")
        if epoch.fresh.sha(status) != self.proofs["boot_status_sha256"]:
            reject("ORIGINAL_BOOT_STATUS_EVIDENCE_CHANGED")
        active_path, _, _, _ = _failure_paths()
        if epoch.fresh.sha(active_path) != self.preserved["active_latch_sha256"]:
            reject("ORIGINAL_BOOT_LATCH_CHANGED")
        return {
            "manifest": manifest_after,
            "source_container_unchanged": True,
            "legacy_unchanged": True,
            "standby_unchanged": True,
            "task_state_unchanged": True,
            "trading_started": False,
        }

    def _worker_config(self, *, redis_host: str) -> dict:
        config = _json(boot.SERVE_WORK / "config-serve.json", limit=32_768)
        required = {
            "owner",
            "database",
            "pg_host",
            "redis_host",
            "producer_password",
            "consumer_password",
            "redis_producer_password",
            "redis_consumer_password",
        }
        if (
            set(config) != required
            or config.get("owner") != OWNER
            or config.get("pg_host") != self.names["target_pg"]
        ):
            reject("EXACT_EPOCH_SERVE_CONFIG_REQUIRED")
        projected = {key: config[key] for key in required}
        projected["redis_host"] = redis_host
        epoch.validate_worker_config(
            projected,
            mode=(
                "boot-redis-clone"
                if redis_host == CLONE_CONTAINER
                else "boot-redis-state"
            ),
        )
        return projected

    def _run_clone_proof(self) -> dict:
        if self.candidate_acl_path is None:
            reject("PRIVATE_REPLAY_ACL_REQUIRED")
        self._clone_container_absent()
        original_redis_name = self.names["redis"]
        original_redis_volume = self.names["redis_volume"]
        self.names["redis"] = CLONE_CONTAINER
        self.names["redis_volume"] = CLONE_VOLUME
        try:
            command = [
                "redis-server",
                "--appendonly",
                "yes",
                "--appendfsync",
                "always",
                "--aclfile",
                "/run/config/users.acl",
                "--protected-mode",
                "yes",
                "--bind",
                "0.0.0.0",
                "--maxmemory",
                "192mb",
                "--maxmemory-policy",
                "noeviction",
            ]
            options = [
                "--mount",
                f"type=volume,src={CLONE_VOLUME},dst=/data",
                "--mount",
                f"type=bind,src={self.candidate_acl_path},dst=/run/config/users.acl,readonly",
            ]
            self._create_container(
                CLONE_CONTAINER,
                epoch.REDIS_IMAGE,
                options,
                command=command,
                start=False,
                user="999:999",
                memory="256m",
                cpus="0.5",
            )
            view = self.inspect_container(CLONE_CONTAINER)
            self.proofs["clone_container_id"] = view.get("id")
            self.require_mount_set(
                CLONE_CONTAINER,
                {
                    CLONE_VOLUME: ("/data", True),
                    str(self.candidate_acl_path): ("/run/config/users.acl", False),
                },
            )
            policy = json.loads(
                self.docker(
                    [
                        "inspect",
                        "--format",
                        "{{json .HostConfig.RestartPolicy}}",
                        CLONE_CONTAINER,
                    ]
                )
            )
            if policy.get("Name") != "no":
                reject("REDIS_AOF_CLONE_RESTART_POLICY_MUST_BE_OFF")
            self.docker(["start", CLONE_CONTAINER])
            view = self.inspect_container(CLONE_CONTAINER)
            labels = view.get("labels") or {}
            if (
                view.get("id") is None
                or labels.get(epoch.EPOCH_LABEL) != OWNER
                or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
                or view.get("network") != self.names["network"]
                or view.get("ports")
                or (view.get("state") or {}).get("Status") != "running"
            ):
                reject("EXACT_PRIVATE_REDIS_AOF_CLONE_REQUIRED")
            self.proofs["clone_volume"] = CLONE_VOLUME
            self.proofs["backup_volume"] = BACKUP_VOLUME
            config = self._worker_config(redis_host=CLONE_CONTAINER)
            proof = self.phase("boot-redis-clone", config, suffix="aof-clone")
            self.worker_proof = validate_redis_worker_proof(proof, clone=True)
            self.proofs["clone_worker_proof"] = self.worker_proof
            return self.worker_proof
        finally:
            self.names["redis"] = original_redis_name
            self.names["redis_volume"] = original_redis_volume
            if CLONE_CONTAINER in self.created:
                self._stop_clone()

    def load_qualified_receipt(
        self, path: Path | None, expected_sha256: str | None
    ) -> dict:
        if (
            path is None
            or not isinstance(expected_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            or epoch.fresh.safe(path) != path.absolute()
            or ROOT not in path.absolute().parents
            or epoch.fresh.sha(path) != expected_sha256
        ):
            reject("HASH_BOUND_PRIVATE_CLONE_QUALIFICATION_RECEIPT_REQUIRED")
        accepted = _json(path, limit=262_144)
        if (
            accepted.get("schema_version") != 1
            or accepted.get("result") != "PASS_REDIS_AOF_CLONE_QUALIFICATION"
            or accepted.get("owner") != OWNER
            or accepted.get("scope") != SCOPE
            or accepted.get("trading_started") is not False
            or accepted.get("primary_acl_changed") is not False
            or accepted.get("original_redis_stopped_or_restarted") is not False
            or accepted.get("source_container_id") != boot.CONTAINERS["redis"]
            or accepted.get("previous_boot_run") != BOOT_RUN
            or accepted.get("previous_boot_failure_sha256") != BOOT_FAILURE_SHA256
            or accepted.get("previous_boot_binding_sha256") != BINDING_SHA256
            or accepted.get("previous_boot_inputs_unchanged") is not True
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(accepted.get("previous_boot_active_latch_sha256", "")),
            )
            is None
            or accepted.get("backup_volume") != BACKUP_VOLUME
            or accepted.get("clone_volume") != CLONE_VOLUME
            or accepted.get("clone_container") != CLONE_CONTAINER
        ):
            reject("ACCEPTED_CLONE_QUALIFICATION_RECEIPT_REQUIRED")
        proofs = accepted.get("proofs")
        if not isinstance(proofs, dict):
            reject("ACCEPTED_CLONE_QUALIFICATION_PROOFS_REQUIRED")
        if (
            accepted.get("source_revision") != self.expected_revision
            or not isinstance(accepted.get("run_id"), str)
            or re.fullmatch(r"[0-9a-f]{32}", accepted.get("run_id", "")) is None
            or accepted.get("clone_container_id") != proofs.get("clone_container_id")
            or not isinstance(proofs.get("clone_container_id"), str)
            or re.fullmatch(r"[0-9a-f]{64}", proofs.get("clone_container_id", ""))
            is None
            or proofs.get("clone_stopped") is not True
            or proofs.get("backup_volume") != BACKUP_VOLUME
            or proofs.get("clone_volume") != CLONE_VOLUME
            or not isinstance(proofs.get("backup_manifest"), dict)
            or proofs["backup_manifest"].get("file_count") != 4
            or not isinstance(proofs.get("original_source_manifest"), dict)
        ):
            reject("ACCEPTED_CLONE_PRISTINE_BACKUP_IDENTITY_REQUIRED")
        clone_proof = validate_redis_worker_proof(
            proofs.get("clone_worker_proof"), clone=True
        )
        aof_proof = validate_aof_inventory(
            proofs.get("aof_source_before"), worker_proof=clone_proof
        )
        if epoch.fresh.digest(aof_proof) != proofs.get("aof_copy_inventory_sha256"):
            reject("ACCEPTED_CLONE_AOF_INVENTORY_REQUIRED")
        directory_text = accepted.get("working_directory")
        if not isinstance(directory_text, str):
            reject("ACCEPTED_CLONE_PRIVATE_WORK_DIRECTORY_REQUIRED")
        directory = epoch.fresh.safe(Path(directory_text))
        if (
            ROOT not in directory.parents
            or not directory.is_dir()
            or path.absolute() != directory / "redis-aof-clone-qualification.json"
            or directory.name != "run-" + accepted["run_id"]
        ):
            reject("ACCEPTED_CLONE_PRIVATE_WORK_DIRECTORY_REQUIRED")
        failure_path = directory / "redis-aof-recovery-failure.json"
        if failure_path.exists():
            adjudication = accepted.get("retained_evidence_adjudication")
            if (
                not isinstance(adjudication, dict)
                or adjudication.get("result") != "PASS_RETAINED_CLONE_ADJUDICATION"
                or adjudication.get("failure_sha256") != epoch.fresh.sha(failure_path)
                or adjudication.get("clone_restarted") is not False
                or adjudication.get("evidence_rewritten") is not False
                or adjudication.get("source_revision") != self.expected_revision
            ):
                reject("FAILED_CLONE_REQUIRES_EXPLICIT_RETAINED_EVIDENCE_ADJUDICATION")
            clone_view = self.inspect_container(CLONE_CONTAINER)
            if (
                clone_view.get("id") != accepted["clone_container_id"]
                or (clone_view.get("state") or {}).get("Status") != "exited"
                or epoch.fresh.digest(clone_view)
                != adjudication.get("clone_metadata_sha256")
            ):
                reject("ADJUDICATED_STOPPED_CLONE_METADATA_CHANGED")
        original_acl = directory / "original-redis-users.acl"
        candidate_acl = directory / "candidate-redis-users.acl"
        if (
            not original_acl.is_file()
            or original_acl.is_symlink()
            or not candidate_acl.is_file()
            or candidate_acl.is_symlink()
            or epoch.fresh.sha(original_acl) != accepted.get("original_acl_sha256")
            or epoch.fresh.sha(candidate_acl) != accepted.get("candidate_acl_sha256")
            or aof.candidate_acl(original_acl.read_bytes(), OWNER)
            != candidate_acl.read_bytes()
        ):
            reject("ACCEPTED_CLONE_ACL_ARTIFACTS_CHANGED")
        if epoch.fresh.sha(boot.PARENT / "redis-users.acl") != accepted.get(
            "candidate_acl_sha256"
        ):
            reject("ORIGINAL_ACL_MUST_MATCH_REVIEWED_CLONE_CANDIDATE")
        self.proofs["qualification_receipt_sha256"] = expected_sha256
        self.proofs["accepted_clone_proof"] = clone_proof
        self.proofs["accepted_aof_inventory"] = aof_proof
        self.original_acl_path = original_acl
        self.candidate_acl_path = candidate_acl
        return accepted

    def run_verify_original(
        self, *, receipt_path: Path | None, receipt_sha256: str | None
    ) -> dict:
        accepted = self.load_qualified_receipt(receipt_path, receipt_sha256)
        self.preserved, resources, _ = self.validate_admission(
            allowed_acl_sha256=accepted.get("candidate_acl_sha256")
        )
        if self.preserved["active_latch_sha256"] != accepted.get(
            "previous_boot_active_latch_sha256"
        ):
            reject("QUALIFIED_BOOT_ACTIVE_LATCH_CHANGED")
        if (
            (resources["views"]["serve"].get("state") or {}).get("Status") != "exited"
            or (resources["views"]["serve"].get("state") or {}).get("ExitCode") != 255
            or (resources["views"]["redis"].get("state") or {}).get("Status")
            != "running"
        ):
            reject("ORIGINAL_NONTRADING_EPOCH_RESOURCE_STATE_REQUIRED")
        self.proofs["boot_status_sha256"] = epoch.fresh.sha(_failure_paths()[2])
        source_fingerprint = self._source_view_fingerprint(resources)
        task_before = self.preserved["task_state"]
        self._make_snapshots()
        self.original_manifest_before = self.cold_manifest(
            self.names["redis_volume"], "verify-before", cache_proof=True
        )
        if self.original_manifest_before.get("file_count") != 4:
            reject("ORIGINAL_REDIS_VOLUME_DIFFERS_FROM_QUALIFIED_SOURCE")
        original_authority = validate_authoritative_persistence(
            self.original_manifest_before.get("persistence"),
            accepted["proofs"].get("original_source_manifest", {}).get("persistence"),
        )
        backup_manifest = self.cold_manifest(BACKUP_VOLUME, "verify-backup")
        if backup_manifest != accepted["proofs"].get("backup_manifest"):
            reject("PRISTINE_REDIS_AOF_BACKUP_CHANGED")
        current_aof = self.aof_inventory(self.names["redis_volume"], "verify-before")
        if current_aof != self.proofs["accepted_aof_inventory"]:
            reject("ORIGINAL_REDIS_AOF_DIFFERS_FROM_QUALIFIED_CLONE")
        config = self._worker_config(redis_host=self.names["redis"])
        proof = self.phase("boot-redis-state", config, suffix="original-verify")
        original_proof = validate_redis_worker_proof(proof, clone=False)
        clone_proof = self.proofs["accepted_clone_proof"]
        compared = (
            "outbox_rows",
            "completed_inbox",
            "stream_entries",
            "publication_receipts",
            "publication_message_ids_sha256",
            "consumer_groups",
            "pending_deliveries",
        )
        if any(original_proof[key] != clone_proof[key] for key in compared):
            reject("ORIGINAL_REDIS_STATE_DIFFERS_FROM_QUALIFIED_CLONE")
        after_aof = self.aof_inventory(self.names["redis_volume"], "verify-after")
        after_manifest = self.cold_manifest(
            self.names["redis_volume"], "verify-after", cache_proof=True
        )
        validate_authoritative_persistence(
            after_manifest.get("persistence"), original_authority
        )
        if after_aof != current_aof:
            reject("ORIGINAL_REDIS_CHANGED_DURING_READONLY_VERIFICATION")
        cache_proof = validate_readonly_manifest_stability(
            self.original_manifest_before, after_manifest
        )
        resources_after = self.validate_resources(allow_running=True)
        if self._source_view_fingerprint(resources_after) != source_fingerprint:
            reject("ORIGINAL_REDIS_CONTAINER_METADATA_CHANGED")
        if (
            resources_after["legacy"] != self.preserved["resource_metadata"]["legacy"]
            or resources_after["standby"]
            != self.preserved["resource_metadata"]["standby"]
        ):
            reject("LEGACY_OR_STANDBY_METADATA_CHANGED")
        if _bounded_task_state() != task_before:
            reject("BOOT_TASK_STATE_CHANGED_DURING_ORIGINAL_VERIFICATION")
        self.proofs["original_aof_authority"] = original_authority
        self.proofs["backup_manifest"] = backup_manifest
        return {
            "schema_version": 1,
            "result": "PASS_ORIGINAL_REDIS_READONLY_VERIFICATION",
            "owner": OWNER,
            "scope": SCOPE,
            "source_revision": self.expected_revision,
            "qualification_receipt_sha256": receipt_sha256,
            "original_acl_sha256": epoch.fresh.sha(boot.PARENT / "redis-users.acl"),
            "candidate_acl_sha256": accepted["candidate_acl_sha256"],
            "redis_proof": original_proof,
            "aof_inventory": current_aof,
            "original_manifest_cache_proof": cache_proof,
            "original_redis_stopped_or_restarted": False,
            "primary_acl_changed_by_this_run": False,
            "trading_started": False,
        }

    def run_qualification(self) -> dict:
        self.preserved, resources, _latch = self.validate_admission()
        _, _, status_path, _ = _failure_paths()
        self.proofs["boot_status_sha256"] = epoch.fresh.sha(status_path)
        source_fingerprint = self._source_view_fingerprint(resources)
        task_before = self.preserved["task_state"]
        if (
            not LEASE.is_file()
            or LEASE.is_symlink()
            or LEASE.read_bytes() != self.lease_bytes
        ):
            reject("REDIS_AOF_RECOVERY_OWNER_LATCH_REQUIRED")
        self._make_snapshots()
        original_acl, _ = self._private_acls()
        self.original_manifest_before = self.cold_manifest(
            self.names["redis_volume"], "source-before"
        )
        self.proofs["original_source_manifest_sha256"] = (
            self.original_manifest_before.get("manifest_sha256")
        )
        self.proofs["original_source_manifest"] = self.original_manifest_before
        aof_before = self.aof_inventory(self.names["redis_volume"], "source-before")
        authority_before = self.original_manifest_before.get("persistence")
        self.aof_source = aof_before
        self.proofs["aof_source_before"] = aof_before
        self._assert_absent()
        self.create_volume(BACKUP_VOLUME)
        self.initialize_volume(BACKUP_VOLUME, uid=999)
        first_copy = self.copy_volume(
            self.names["redis_volume"],
            BACKUP_VOLUME,
            "source-to-backup",
            self.original_manifest_before,
        )
        backup_manifest = self.cold_manifest(BACKUP_VOLUME, "backup")
        if (
            backup_manifest.get("content_sha256")
            != first_copy["snapshot_content_sha256"]
            or backup_manifest.get("file_count") != 4
            or backup_manifest.get("total_bytes") != first_copy["total_bytes"]
        ):
            reject("REDIS_AOF_BACKUP_MANIFEST_CONFLICT")
        self.create_volume(CLONE_VOLUME)
        self.initialize_volume(CLONE_VOLUME, uid=999)
        second_copy = self.copy_volume(
            BACKUP_VOLUME, CLONE_VOLUME, "backup-to-clone", backup_manifest
        )
        clone_manifest = self.cold_manifest(CLONE_VOLUME, "clone-pristine")
        if (
            clone_manifest.get("content_sha256")
            != second_copy["snapshot_content_sha256"]
            or clone_manifest.get("content_sha256")
            != first_copy["snapshot_content_sha256"]
        ):
            reject("REDIS_AOF_CLONE_MANIFEST_CONFLICT")
        self.proofs["source_to_backup_copy"] = first_copy
        self.proofs["backup_to_clone_copy"] = second_copy
        self.proofs["pristine_clone_manifest_sha256"] = clone_manifest.get(
            "manifest_sha256"
        )
        aof_backup = self.aof_inventory(BACKUP_VOLUME, "backup")
        aof_clone = self.aof_inventory(CLONE_VOLUME, "clone-pristine")
        authority_backup = backup_manifest.get("persistence")
        authority_clone = clone_manifest.get("persistence")
        if (
            aof_before != aof_backup
            or aof_before != aof_clone
            or validate_authoritative_persistence(authority_backup, authority_before)
            != authority_before
            or validate_authoritative_persistence(authority_clone, authority_before)
            != authority_before
        ):
            reject("REDIS_AOF_COPY_INVENTORY_MISMATCH")
        self.proofs["original_aof_authority"] = authority_before
        self.proofs["backup_manifest"] = backup_manifest
        self.proofs["backup_authority"] = authority_backup
        self.proofs["clone_pristine_authority"] = authority_clone
        self.proofs["aof_copy_inventory_sha256"] = epoch.fresh.digest(aof_clone)
        candidate_suffix = self.candidate_acl_path.read_bytes().split(b"\n", 1)[1]
        original_suffix = original_acl.split(b"\n", 1)[1]
        if candidate_suffix != original_suffix:
            reject("REDIS_NAMED_ROLE_ACL_BYTES_MUST_BE_IDENTICAL")
        worker_proof = self._run_clone_proof()
        if (
            aof_before["publication_message_ids_sha256"]
            != worker_proof["publication_message_ids_sha256"]
        ):
            reject("AOF_PUBLICATION_LEDGER_DIFFERS_FROM_FULL_REDIS_PROOF")
        original_after = self.aof_inventory(self.names["redis_volume"], "source-after")
        source_after_manifest = self.cold_manifest(
            self.names["redis_volume"], "source-after"
        )
        authority_after = source_after_manifest.get("persistence")
        if original_after != aof_before or authority_after != authority_before:
            reject("ORIGINAL_REDIS_AOF_INVENTORY_CHANGED")
        unchanged = self._assert_preserved_after(
            source_fingerprint=source_fingerprint,
            source_manifest=self.original_manifest_before,
            task_before=task_before,
        )
        return {
            "schema_version": 1,
            "result": "PASS_REDIS_AOF_CLONE_QUALIFICATION",
            "owner": OWNER,
            "scope": SCOPE,
            "source_revision": self.expected_revision,
            "completed_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "proofs": self.proofs,
            "original_source_unchanged": unchanged,
            "original_acl_sha256": self.proofs["original_acl_sha256"],
            "candidate_acl_sha256": self.proofs["candidate_acl_sha256"],
            "working_directory": str(self.work),
            "source_container_id": boot.CONTAINERS["redis"],
            "previous_boot_run": BOOT_RUN,
            "previous_boot_failure_sha256": BOOT_FAILURE_SHA256,
            "previous_boot_binding_sha256": BINDING_SHA256,
            "previous_boot_active_latch_sha256": self.preserved["active_latch_sha256"],
            "previous_boot_inputs_unchanged": True,
            "backup_volume": BACKUP_VOLUME,
            "clone_volume": CLONE_VOLUME,
            "clone_container": CLONE_CONTAINER,
            "clone_container_id": self.proofs["clone_container_id"],
            "trading_started": False,
            "primary_acl_changed": False,
            "original_redis_stopped_or_restarted": False,
        }

    def fail_closed_cleanup(self) -> None:
        candidates = set(self.created)
        for name in candidates:
            try:
                view = self.inspect_container(name)
                labels = view.get("labels") or {}
                known_id = self.offline_helper_ids.get(name)
                owned_identity_ok = (
                    name != CLONE_CONTAINER
                    or view.get("id") == self.proofs.get("clone_container_id")
                ) and (known_id is None or view.get("id") == known_id)
                if (
                    owned_identity_ok
                    and labels.get(epoch.EPOCH_LABEL) == OWNER
                    and labels.get("com.kairos.runtime-epoch.scope")
                    == epoch.EPOCH_SCOPE
                    and (view.get("state") or {}).get("Status") == "running"
                ):
                    self.docker(["stop", "--time=15", name], seconds=25)
            except Exception:  # noqa: BLE001,S110 - retain owned artifacts and failure evidence.
                pass


def _create_run(
    *,
    verify: bool = False,
    accepted: dict | None = None,
    receipt_sha256: str | None = None,
) -> tuple[str, Path, bytes, bytes | None]:
    if not verify:
        if ROOT.exists() or ROOT.is_symlink():
            reject("REDIS_AOF_RECOVERY_ROOT_MUST_BE_NEW")
        epoch._private_directory(ROOT)
    else:
        if (
            not ROOT.is_dir()
            or ROOT.is_symlink()
            or not LEASE.is_file()
            or LEASE.is_symlink()
        ):
            reject("EXISTING_PRIVATE_QUALIFICATION_LATCH_REQUIRED")
        try:
            latch = json.loads(LEASE.read_bytes())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            reject("EXISTING_PRIVATE_QUALIFICATION_LATCH_REQUIRED")
        if (
            not isinstance(latch, dict)
            or set(latch) != {"owner", "run", "scope"}
            or latch.get("owner") != OWNER
            or latch.get("scope") != SCOPE
            or not isinstance(accepted, dict)
            or latch.get("run") != accepted.get("run_id")
            or LEASE.read_bytes()
            != json.dumps(latch, sort_keys=True).encode("ascii") + b"\n"
        ):
            reject("EXISTING_PRIVATE_QUALIFICATION_LATCH_REQUIRED")
        if VERIFY_LEASE.exists() or VERIFY_LEASE.is_symlink():
            reject("ORIGINAL_VERIFICATION_LATCH_ALREADY_EXISTS")
    run_id = uuid.uuid4().hex
    work = ROOT / ("run-" + run_id)
    epoch._private_directory(work)
    if verify:
        lease = LEASE.read_bytes()
        verification_lease = (
            json.dumps(
                {
                    "owner": OWNER,
                    "run": run_id,
                    "scope": SCOPE + ":original-verification",
                    "qualification_receipt_sha256": receipt_sha256,
                },
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        _create_only(VERIFY_LEASE, verification_lease)
    else:
        lease = (
            json.dumps(
                {"owner": OWNER, "run": run_id, "scope": SCOPE}, sort_keys=True
            ).encode("ascii")
            + b"\n"
        )
        epoch.fresh.write(LEASE, lease)
        verification_lease = None
    return run_id, work, lease, verification_lease


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualify-clone", action="store_true")
    parser.add_argument("--verify-original", action="store_true")
    parser.add_argument("--expected-revision")
    parser.add_argument("--qualification-receipt", type=Path)
    parser.add_argument("--qualification-receipt-sha256")
    args = parser.parse_args(argv)
    if not args.qualify_clone and not args.verify_original:
        print(
            json.dumps(
                {
                    "result": "PLAN_ONLY",
                    "clone_start": False,
                    "original_redis_start_stop": False,
                    "primary_acl_change": False,
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.qualify_clone == args.verify_original:
        reject("SELECT_EXACTLY_ONE_RECOVERY_ACTION")
    run_id = ""
    work = None
    controller = None
    try:
        if re.fullmatch(r"[0-9a-f]{40}", args.expected_revision or "") is None:
            reject("EXPECTED_SIGNED_MAIN_REVISION_REQUIRED")
        boot.verify_source(args.expected_revision)
        accepted = None
        if args.verify_original:
            # Validate the hash and receipt before creating a new private child.
            if (
                args.qualification_receipt is None
                or not isinstance(args.qualification_receipt_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", args.qualification_receipt_sha256)
                is None
                or epoch.fresh.safe(args.qualification_receipt)
                != args.qualification_receipt.absolute()
                or ROOT not in args.qualification_receipt.absolute().parents
                or epoch.fresh.sha(args.qualification_receipt)
                != args.qualification_receipt_sha256
            ):
                reject("HASH_BOUND_PRIVATE_CLONE_QUALIFICATION_RECEIPT_REQUIRED")
            accepted = _json(args.qualification_receipt, limit=262_144)
        run_id, work, lease_bytes, verification_lease_bytes = _create_run(
            verify=args.verify_original,
            accepted=accepted,
            receipt_sha256=args.qualification_receipt_sha256,
        )
        controller = RedisAofRecoveryController(
            OWNER,
            expected_revision=args.expected_revision,
            workdir=work,
            continuation_attempt="aof-" + run_id[:8],
            deadline=time.monotonic() + MAX_SECONDS,
            run_id=run_id,
        )
        controller.lease_bytes = lease_bytes
        controller.verification_lease_bytes = verification_lease_bytes
        if args.qualify_clone:
            result = controller.run_qualification()
        else:
            result = controller.run_verify_original(
                receipt_path=args.qualification_receipt,
                receipt_sha256=args.qualification_receipt_sha256,
            )
        result.update(
            run_id=run_id,
            completed_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
        path = work / (
            "redis-aof-clone-qualification.json"
            if args.qualify_clone
            else "redis-aof-original-verification.json"
        )
        epoch.fresh.save(path, result)
        if LEASE.read_bytes() != lease_bytes:
            reject("REDIS_AOF_RECOVERY_LATCH_CHANGED")
        if (
            args.verify_original
            and VERIFY_LEASE.read_bytes() != verification_lease_bytes
        ):
            reject("ORIGINAL_VERIFICATION_LATCH_CHANGED")
        print(
            json.dumps(
                {
                    "result": result["result"],
                    "receipt": str(path),
                    "sha256": epoch.fresh.sha(path),
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - sanitized diagnostics only.
        reason = (
            str(exc)
            if isinstance(exc, epoch.Rejected)
            else "REDIS_AOF_RECOVERY_FAILED_" + type(exc).__name__.upper()
        )
        if controller:
            controller.fail_closed_cleanup()
        if work is not None:
            try:
                epoch.fresh.save(
                    work / "redis-aof-recovery-failure.json",
                    {
                        "state": "FAILED_CLOSED",
                        "reason": reason,
                        "owner": OWNER,
                        "trading_started": False,
                        "source_revision": args.expected_revision,
                    },
                )
            except Exception:  # noqa: BLE001,S110 - never overwrite forensic evidence.
                pass
        print(
            json.dumps(
                {
                    "result": "FAILED_CLOSED",
                    "reason": reason,
                    "automatic_retry": False,
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
