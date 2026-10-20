"""Dependency-injected, read-only AOF inventory and clone-copy primitives.

This module deliberately contains no admission policy and performs no work at
import time. Callers remain responsible for incident identity, source state,
one-shot claims, and deciding whether a clone may be replayed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class AofCloneDependencies:
    owner: str
    prefix: str
    scope_label: str
    epoch_label: str
    runner_image: str
    worker_image: str
    run_id: str
    max_aof_bytes: int
    cold_snapshot: Path | None
    aof_snapshot: Path | None
    created: list[str]
    helper_ids: dict[str, str]
    docker: Callable[..., str]
    inspect_container: Callable[[str], dict]
    require_mount_set: Callable[[str, dict], None]
    cold_worker_command: Callable[..., list[str]]
    worker_json: Callable[..., dict]
    validate_copy_proof: Callable[..., dict]
    validate_aof_inventory: Callable[..., dict]
    reject: Callable[[str], None]
    # Appended default preserves all existing constructors and their standard
    # 8 MiB copy / 50k inventory behavior.
    aof_profile: str = "standard"


class AofClonePrimitives:
    """Run the existing bounded helper operations using injected runtime I/O."""

    def __init__(self, dependencies: AofCloneDependencies) -> None:
        self.d = dependencies

    def _profile_is_bounded(self) -> bool:
        if type(self.d.aof_profile) is not str or type(self.d.max_aof_bytes) is not int:
            return False
        expected = {
            "standard": 8 * 1024 * 1024,
            "forensic32m": 32 * 1024 * 1024,
        }.get(self.d.aof_profile)
        return expected is not None and self.d.max_aof_bytes == expected

    def _owned_labels(self) -> list[str]:
        return [
            "--label",
            self.d.epoch_label + "=" + self.d.owner,
            "--label",
            "com.kairos.runtime-epoch.scope=" + self.d.scope_label,
        ]

    def create_offline_helper(
        self, name: str, argv: list[str], expected_mounts: dict
    ) -> dict:
        d = self.d
        if not name.startswith(d.prefix + "-") or name in d.created:
            d.reject("UNIQUE_PRIVATE_OFFLINE_HELPER_REQUIRED")
        argv = [argv[0], "--name", name, *self._owned_labels(), *argv[1:]]
        d.docker(argv)
        d.created.append(name)
        view = d.inspect_container(name)
        if (
            not isinstance(view.get("id"), str)
            or re.fullmatch(r"[0-9a-f]{64}", view["id"]) is None
        ):
            d.reject("OFFLINE_HELPER_CONTAINER_ID_REQUIRED")
        d.helper_ids[name] = view["id"]
        labels = view.get("labels") or {}
        if (
            view.get("name") != "/" + name
            or view.get("network") != "none"
            or view.get("ports")
            or view.get("readonly") is not True
            or view.get("privileged")
            or view.get("caps") != ["ALL"]
            or view.get("image")
            not in {
                d.runner_image,
                d.runner_image.split("@", 1)[-1],
                "sha256:" + d.runner_image.rsplit("sha256:", 1)[-1],
            }
            or labels.get(d.epoch_label) != d.owner
            or labels.get("com.kairos.runtime-epoch.scope") != d.scope_label
            or view.get("memory") != 512 * 1024**2
            or view.get("swap") != 512 * 1024**2
            or view.get("cpus") != 1_000_000_000
            or d.docker(
                ["inspect", "--format", "{{json .Config.User}}", name]
            ).strip('"')
            != "999:999"
            or json.loads(
                d.docker(
                    ["inspect", "--format", "{{json .HostConfig.SecurityOpt}}", name]
                )
            )
            != ["no-new-privileges:true"]
            or json.loads(
                d.docker(
                    ["inspect", "--format", "{{json .HostConfig.CapAdd}}", name]
                )
            )
            not in (None, [])
            or json.loads(
                d.docker(["inspect", "--format", "{{json .HostConfig.Tmpfs}}", name])
            )
            != {"/tmp": "rw,noexec,nosuid,nodev,size=32m"}
        ):
            d.reject("OFFLINE_HELPER_SANDBOX_REQUIRED")
        d.require_mount_set(name, expected_mounts)
        return view

    def finish_offline_helper(
        self, name: str, output: str, *, status: str
    ) -> dict:
        d = self.d
        value = d.worker_json(output, status=status)
        view = d.inspect_container(name)
        labels = view.get("labels") or {}
        if (
            view.get("id") != d.helper_ids.get(name)
            or labels.get(d.epoch_label) != d.owner
            or labels.get("com.kairos.runtime-epoch.scope") != d.scope_label
            or (view.get("state") or {}).get("Status") != "exited"
            or (view.get("state") or {}).get("ExitCode") != 0
        ):
            d.reject("OFFLINE_HELPER_EXIT_STATUS_REQUIRED")
        d.docker(["rm", name])
        d.created.remove(name)
        d.helper_ids.pop(name, None)
        return value

    def cold_manifest(
        self, volume: str, tag: str, *, cache_proof: bool = False
    ) -> dict:
        d = self.d
        if not self._profile_is_bounded():
            d.reject("REDIS_AOF_PROFILE_INVALID")
        if d.cold_snapshot is None:
            d.reject("PINNED_COLD_REDIS_WORKER_REQUIRED")
        name = d.prefix + "-manifest-" + tag + "-" + d.run_id[:8]
        argv = d.cold_worker_command(
            "manifest-aof-cache" if cache_proof else "manifest-only",
            source=volume,
            script_path=d.cold_snapshot,
            max_source_bytes=d.max_aof_bytes,
        )
        argv[1:1] = ["--user=999:999"]
        expected = {
            volume: ("/source", False),
            str(d.cold_snapshot): ("/work/cold_redis_acceptance.py", False),
        }
        self.create_offline_helper(name, argv, expected)
        output = d.docker(["start", "--attach", name], seconds=75)
        value = self.finish_offline_helper(name, output, status="COPY_VERIFIED")
        if (
            value.get("file_count") != 4
            or type(value.get("total_bytes")) is not int
            or not 0 < value["total_bytes"] <= d.max_aof_bytes
        ):
            d.reject("REDIS_AOF_SOURCE_MANIFEST_BOUNDS_REQUIRED")
        return value

    def copy_volume(
        self, source: str, target: str, tag: str, source_manifest: dict
    ) -> dict:
        d = self.d
        if not self._profile_is_bounded():
            d.reject("REDIS_AOF_PROFILE_INVALID")
        if d.cold_snapshot is None:
            d.reject("PINNED_COLD_REDIS_WORKER_REQUIRED")
        name = d.prefix + "-copy-" + tag + "-" + d.run_id[:8]
        argv = d.cold_worker_command(
            "copy-hash", source=source, target=target,
            script_path=d.cold_snapshot, max_source_bytes=d.max_aof_bytes
        )
        argv[1:1] = ["--user=999:999"]
        expected = {
            source: ("/source", False),
            target: ("/data", True),
            str(d.cold_snapshot): ("/work/cold_redis_acceptance.py", False),
        }
        self.create_offline_helper(name, argv, expected)
        output = d.docker(["start", "--attach", name], seconds=135)
        raw = self.finish_offline_helper(name, output, status="COPY_VERIFIED")
        return d.validate_copy_proof(
            raw, source_manifest=source_manifest, max_aof_bytes=d.max_aof_bytes
        )

    def aof_inventory(
        self, volume: str, tag: str, worker_proof: dict | None = None
    ) -> dict:
        d = self.d
        if not self._profile_is_bounded():
            d.reject("REDIS_AOF_PROFILE_INVALID")
        if d.aof_snapshot is None:
            d.reject("PINNED_AOF_INVENTORY_SNAPSHOT_REQUIRED")
        name = d.prefix + "-aof-inventory-" + tag + "-" + d.run_id[:8]
        args = [
            "create",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory=512m",
            "--memory-swap=512m",
            "--cpus=1",
            "--pids-limit=64",
            "--user=999:999",
            "--pull=never",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=32m",
            "--mount",
            f"type=volume,src={volume},dst=/source,readonly",
            "--mount",
            f"type=bind,src={d.aof_snapshot},dst=/work/runtime_epoch_redis_aof.py,readonly",
            "--entrypoint",
            "python",
            d.worker_image,
            "-B",
            "/work/runtime_epoch_redis_aof.py",
            "--aof-inventory",
            "--profile",
            d.aof_profile,
        ]
        expected = {
            volume: ("/source", False),
            str(d.aof_snapshot): ("/work/runtime_epoch_redis_aof.py", False),
        }
        self.create_offline_helper(name, args, expected)
        output = d.docker(["start", "--attach", name], seconds=75)
        raw = self.finish_offline_helper(name, output, status="PASS_AOF_INVENTORY")
        return d.validate_aof_inventory(
            raw, worker_proof=worker_proof, profile=d.aof_profile
        )
