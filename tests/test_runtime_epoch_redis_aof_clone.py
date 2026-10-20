"""Offline tests for dependency-injected AOF clone I/O primitives."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.runtime_epoch_redis_aof_clone import (
    AofCloneDependencies,
    AofClonePrimitives,
)


class CloneIoFixture:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.mounts: list[tuple[str, dict]] = []
        self.created: list[str] = []
        self.helper_ids: dict[str, str] = {}
        self.status = "COPY_VERIFIED"
        self.helper_id = "a" * 64
        self.removed: list[str] = []
        self.rejects: list[str] = []
        self.worker_commands: list[tuple[str, dict]] = []

    def docker(self, argv: list[str], **kwargs) -> str:
        self.calls.append((argv, kwargs))
        if argv[0] == "inspect":
            fmt = argv[2]
            if ".Config.User" in fmt:
                return '"999:999"'
            if ".HostConfig.SecurityOpt" in fmt:
                return '["no-new-privileges:true"]'
            if ".HostConfig.CapAdd" in fmt:
                return "[]"
            if ".HostConfig.Tmpfs" in fmt:
                return json.dumps({"/tmp": "rw,noexec,nosuid,nodev,size=32m"})
        if argv[:2] == ["start", "--attach"]:
            return "worker-json"
        if argv[0] == "rm":
            self.removed.append(argv[1])
        return ""

    def inspect_container(self, name: str) -> dict:
        return {
            "id": self.helper_id,
            "name": "/" + name,
            "network": "none",
            "ports": [],
            "readonly": True,
            "privileged": False,
            "caps": ["ALL"],
            "image": "runner@sha256:" + "b" * 64,
            "labels": {
                "kairos.runtime-epoch.owner": "owner",
                "com.kairos.runtime-epoch.scope": "scope",
            },
            "memory": 512 * 1024**2,
            "swap": 512 * 1024**2,
            "cpus": 1_000_000_000,
            "state": {"Status": "exited", "ExitCode": 0},
        }

    def require_mount_set(self, name: str, expected: dict) -> None:
        self.mounts.append((name, expected))

    def worker_command(self, mode: str, **kwargs) -> list[str]:
        self.worker_commands.append((mode, kwargs))
        return ["create", "--mode", mode]

    def reject(self, code: str) -> None:
        self.rejects.append(code)
        raise ValueError(code)

    def make(
        self,
        *,
        max_aof_bytes: int = 8 * 1024 * 1024,
        aof_profile: str = "standard",
    ) -> AofClonePrimitives:
        deps = AofCloneDependencies(
            owner="owner",
            prefix="kairos-epoch-owner",
            scope_label="scope",
            epoch_label="kairos.runtime-epoch.owner",
            runner_image="runner@sha256:" + "b" * 64,
            worker_image="worker@sha256:" + "c" * 64,
            run_id="0123456789abcdef0123456789abcdef",
            max_aof_bytes=max_aof_bytes,
            cold_snapshot=Path("/private/cold.py"),
            aof_snapshot=Path("/private/aof.py"),
            created=self.created,
            helper_ids=self.helper_ids,
            docker=self.docker,
            inspect_container=self.inspect_container,
            require_mount_set=self.require_mount_set,
            cold_worker_command=self.worker_command,
            worker_json=lambda output, *, status: {
                "status": status,
                "file_count": 4,
                "total_bytes": 100,
            },
            validate_copy_proof=lambda value, *, source_manifest, max_aof_bytes: {
                **value,
                "source_manifest": source_manifest,
                "max_aof_bytes": max_aof_bytes,
            },
            validate_aof_inventory=lambda value, *, worker_proof, profile: {
                **value,
                "worker_proof": worker_proof,
                "profile": profile,
            },
            reject=self.reject,
            aof_profile=aof_profile,
        )
        return AofClonePrimitives(deps)


class AofClonePrimitiveTests(unittest.TestCase):
    def test_offline_helper_has_owned_labels_sandbox_and_exact_mount_check(self) -> None:
        fixture = CloneIoFixture()
        primitive = fixture.make()

        view = primitive.create_offline_helper(
            "kairos-epoch-owner-copy-test-01234567",
            ["create", "--network=none"],
            {"source": ("/source", False)},
        )

        self.assertEqual(view["id"], "a" * 64)
        argv = fixture.calls[0][0]
        self.assertIn("--label", argv)
        self.assertIn("kairos.runtime-epoch.owner=owner", argv)
        self.assertIn("com.kairos.runtime-epoch.scope=scope", argv)
        self.assertIn(
            ("kairos-epoch-owner-copy-test-01234567", {"source": ("/source", False)}),
            fixture.mounts,
        )
        self.assertEqual(fixture.helper_ids["kairos-epoch-owner-copy-test-01234567"], "a" * 64)

    def test_collision_and_unowned_name_fail_before_docker(self) -> None:
        fixture = CloneIoFixture()
        primitive = fixture.make()
        fixture.created.append("kairos-epoch-owner-copy-used")

        with self.assertRaisesRegex(ValueError, "UNIQUE_PRIVATE_OFFLINE_HELPER_REQUIRED"):
            primitive.create_offline_helper("kairos-epoch-owner-copy-used", ["create"], {})
        with self.assertRaisesRegex(ValueError, "UNIQUE_PRIVATE_OFFLINE_HELPER_REQUIRED"):
            primitive.create_offline_helper("other-copy", ["create"], {})
        self.assertEqual(fixture.calls, [])

    def test_sandbox_conflict_is_rejected_before_mount_approval(self) -> None:
        fixture = CloneIoFixture()
        fixture.inspect_container = lambda name: {
            **CloneIoFixture().inspect_container(name),
            "network": "unexpected-network",
        }
        primitive = fixture.make()

        with self.assertRaisesRegex(ValueError, "OFFLINE_HELPER_SANDBOX_REQUIRED"):
            primitive.create_offline_helper(
                "kairos-epoch-owner-copy-test-01234567", ["create"], {}
            )
        self.assertEqual(fixture.mounts, [])

    def test_manifest_copy_and_inventory_preserve_injected_validation(self) -> None:
        fixture = CloneIoFixture()
        primitive = fixture.make()

        manifest = primitive.cold_manifest("source-volume", "before")
        copied = primitive.copy_volume("source-volume", "backup-volume", "copy", manifest)
        inventory = primitive.aof_inventory("backup-volume", "backup", worker_proof={"ok": True})

        self.assertEqual(manifest["file_count"], 4)
        self.assertEqual(copied["source_manifest"], manifest)
        self.assertEqual(copied["max_aof_bytes"], 8 * 1024 * 1024)
        self.assertEqual(
            fixture.worker_commands[-1][1]["max_source_bytes"], 8 * 1024 * 1024
        )
        self.assertEqual(inventory["worker_proof"], {"ok": True})
        self.assertEqual(inventory["profile"], "standard")
        self.assertEqual(
            fixture.removed,
            [
                "kairos-epoch-owner-manifest-before-01234567",
                "kairos-epoch-owner-copy-copy-01234567",
                "kairos-epoch-owner-aof-inventory-backup-01234567",
            ],
        )
        create_aof = next(
            argv
            for argv, _ in fixture.calls
            if argv[0] == "create" and "--aof-inventory" in argv
        )
        self.assertIn("--read-only", create_aof)
        self.assertIn("--cap-drop=ALL", create_aof)
        self.assertIn("type=volume,src=backup-volume,dst=/source,readonly", create_aof)

    def test_explicit_forensic_profile_threads_exact_32m_cap_and_name(self) -> None:
        fixture = CloneIoFixture()
        primitive = fixture.make(
            max_aof_bytes=32 * 1024 * 1024, aof_profile="forensic32m"
        )
        manifest = primitive.cold_manifest("source-volume", "before")
        self.assertEqual(
            fixture.worker_commands[-1][1]["max_source_bytes"], 32 * 1024 * 1024
        )
        primitive.aof_inventory("backup-volume", "inventory", worker_proof={"ok": True})
        create_aof = next(
            argv
            for argv, _ in fixture.calls
            if argv[0] == "create" and "--aof-inventory" in argv
        )
        self.assertEqual(
            create_aof[create_aof.index("--profile") + 1], "forensic32m"
        )

    def test_profile_cap_mismatch_rejects_before_helper_creation(self) -> None:
        fixture = CloneIoFixture()
        primitive = fixture.make(
            max_aof_bytes=256 * 1024 * 1024, aof_profile="forensic32m"
        )
        with self.assertRaisesRegex(ValueError, "REDIS_AOF_PROFILE_INVALID"):
            primitive.cold_manifest("source-volume", "before")
        self.assertEqual(fixture.calls, [])

    def test_non_integer_profile_caps_reject_before_helper_creation(self) -> None:
        for cap in (True, float(8 * 1024 * 1024)):
            with self.subTest(cap=cap):
                fixture = CloneIoFixture()
                primitive = fixture.make(max_aof_bytes=cap)
                with self.assertRaisesRegex(ValueError, "REDIS_AOF_PROFILE_INVALID"):
                    primitive.cold_manifest("source-volume", "before")
                self.assertEqual(fixture.calls, [])

    def test_finish_rejects_changed_helper_identity_without_removing_it(self) -> None:
        fixture = CloneIoFixture()
        primitive = fixture.make()
        name = "kairos-epoch-owner-copy-test-01234567"
        fixture.created.append(name)
        fixture.helper_ids[name] = "a" * 64
        fixture.helper_id = "d" * 64

        with self.assertRaisesRegex(ValueError, "OFFLINE_HELPER_EXIT_STATUS_REQUIRED"):
            primitive.finish_offline_helper(name, "worker-json", status="COPY_VERIFIED")
        self.assertEqual(fixture.removed, [])
        self.assertIn(name, fixture.created)


if __name__ == "__main__":
    unittest.main()
