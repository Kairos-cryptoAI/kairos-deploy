"""Non-launching admission tests for the new current-source clone protocol."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts import controlled_runtime_transition as current
from scripts import prepare_controlled_runtime_wheels as wheels


class CurrentControlledTransitionTests(unittest.TestCase):
    def test_cold_before_after_keep_distinct_immutable_observations(self):
        with tempfile.TemporaryDirectory() as root:
            controller = object.__new__(current.Controller)
            controller.work, controller.owner = Path(root), "a" * 32
            lines = ["b" * 64 + "  -", "c" * 64 + "  -", "123"]
            controller.create = mock.Mock()
            controller.remove = mock.Mock()
            controller.docker = mock.Mock(
                side_effect=lambda args, **_kwargs: (
                    "0" if args[0] == "wait" else "\n".join(lines)
                )
            )
            before = controller.current_cold_verify("before")
            before_path = controller.work / "current-cold-verify-before-log.json"
            recorded = before_path.read_bytes()
            after = controller.current_cold_verify("after")
            self.assertEqual(before, after)
            self.assertEqual(before_path.read_bytes(), recorded)
            self.assertEqual(
                json.loads(
                    (controller.work / "current-cold-verify-after-log.json").read_text()
                ),
                lines,
            )
            self.assertNotEqual(
                controller.create.call_args_list[0].args[0],
                controller.create.call_args_list[1].args[0],
            )
            self.assertEqual(controller.remove.call_count, 2)
            with self.assertRaisesRegex(
                current.fresh.Rejected, "CURRENT_COLD_CHECKPOINT_ALREADY_RECORDED"
            ):
                controller.current_cold_verify("before")
            self.assertEqual(controller.create.call_count, 2)

    def test_cold_invalid_checkpoint_refuses_before_remote_operations(self):
        controller = object.__new__(current.Controller)
        controller.create = mock.Mock()
        for checkpoint in ("../after", "repeat", "", 1):
            with (
                self.subTest(checkpoint=checkpoint),
                self.assertRaisesRegex(
                    current.fresh.Rejected, "CURRENT_COLD_CHECKPOINT_INVALID"
                ),
            ):
                controller.current_cold_verify(checkpoint)
        controller.create.assert_not_called()

    def test_cold_default_retains_legacy_create_only_filename(self):
        with tempfile.TemporaryDirectory() as root:
            controller = object.__new__(current.Controller)
            controller.work, controller.owner = Path(root), "a" * 32
            lines = ["b" * 64 + "  -", "c" * 64 + "  -", "123"]
            controller.create, controller.remove = mock.Mock(), mock.Mock()
            controller.docker = mock.Mock(
                side_effect=lambda args, **_kwargs: (
                    "0" if args[0] == "wait" else "\n".join(lines)
                )
            )
            controller.current_cold_verify()
            self.assertTrue(
                (controller.work / "current-cold-verify-log.json").is_file()
            )
            with self.assertRaisesRegex(
                current.fresh.Rejected, "CURRENT_COLD_CHECKPOINT_ALREADY_RECORDED"
            ):
                controller.current_cold_verify()
            self.assertEqual(controller.create.call_count, 1)

    def test_restored_primary_plan_changes_only_authorization_without_mutating_input(
        self,
    ):
        owner = "a" * 32
        plan = {
            "owner": owner,
            "primary_authorized": True,
            "legacy_snapshot_sha256": "b" * 64,
            "package_revisions": {"kairos-core": "c" * 40},
        }
        before = json.dumps(plan, sort_keys=True)
        restored = current.restored_primary_worker_plan(plan, owner)
        self.assertEqual(restored, {**plan, "primary_authorized": False})
        self.assertEqual(json.dumps(plan, sort_keys=True), before)
        self.assertIsNot(restored, plan)

    def test_restored_primary_plan_refuses_unbound_or_nonprimary_input(self):
        owner = "a" * 32
        for plan, candidate in (
            ({"owner": owner, "primary_authorized": False}, owner),
            ({"owner": owner, "primary_authorized": 1}, owner),
            ({"owner": "b" * 32, "primary_authorized": True}, owner),
            ({"owner": owner, "primary_authorized": True}, "not-an-owner"),
            ({"owner": owner}, owner),
            ([], owner),
        ):
            with (
                self.subTest(plan=plan, owner=candidate),
                self.assertRaisesRegex(
                    current.fresh.Rejected,
                    "COMMITTED_PRIMARY_PLAN_REQUIRED_FOR_RESTORE",
                ),
            ):
                current.restored_primary_worker_plan(plan, candidate)

    def test_restore_worker_retains_primary_plan_and_excludes_runtime_credentials(self):
        # Native boundary checks have dedicated tests. This fixture exercises
        # the real create-only phase input/output path without launching Docker.
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            owner = "a" * 32
            plan = {"owner": owner, "primary_authorized": True}
            original = json.dumps(plan).encode()
            (work / "plan.json").write_bytes(original)
            (work / "runtime-auth.json").write_text('{"synthetic": "not-a-key"}')
            wheelhouse = work / "wheelhouse"
            wheelhouse.mkdir()
            (wheelhouse / "manifest.json").write_text("{}")
            operator = work / "operator"
            operator.mkdir()
            target = "owned-test-clone"
            worker = "kairos-controlled-" + owner[:12] + "-verify-restored-primary"
            output = work / ("worker-output-" + worker)
            controller = object.__new__(current.Controller)
            controller.work, controller.owner = work, owner
            controller.owned, controller.workers = {target: []}, {}
            controller.wheelhouse, controller.operator_snapshot = wheelhouse, operator
            controller.operator_manifest = {}
            controller.proofs = {
                "wheel_manifest_sha256": current.fresh.sha(wheelhouse / "manifest.json")
            }
            view = {
                "image": current.RUNNER,
                "network": "container:" + "d" * 64,
                "memory": 512 * 1024**2,
                "swap": 512 * 1024**2,
                "cpus": 10**9,
                "readonly": True,
                "caps": ["ALL"],
                "ports": {},
                "privileged": False,
                "labels": {current.fresh.OWNER_LABEL: owner},
                "mounts": [
                    {
                        "Type": "bind",
                        "Destination": destination,
                        "Source": str(source),
                        "RW": writable,
                    }
                    for destination, source, writable in (
                        ("/operator", operator, False),
                        ("/wheelhouse", wheelhouse, False),
                        ("/output", output, True),
                    )
                ],
            }
            controller.inspect = mock.Mock(
                side_effect=lambda name: {"id": "d" * 64} if name == target else view
            )
            controller.docker = mock.Mock(
                side_effect=lambda args, **_kwargs: "0" if args[0] == "wait" else ""
            )
            with (
                mock.patch.object(current, "require_manifest"),
                mock.patch.object(current, "verify_operator_snapshot"),
                mock.patch.object(current.fresh, "safe", side_effect=lambda path: path),
            ):
                controller.worker(
                    target,
                    "kairos_recovery_" + owner[:12] + "_current_second",
                    "verify-restored-primary",
                )
            self.assertEqual((work / "plan.json").read_bytes(), original)
            self.assertEqual(
                json.loads((output / "plan.json").read_text()),
                {**plan, "primary_authorized": False},
            )
            self.assertFalse((output / "runtime-auth.json").exists())
            self.assertEqual(
                controller.proofs["restored_primary_worker_plan_sha256"],
                current.fresh.sha(output / "plan.json"),
            )
            self.assertEqual(controller.workers, {})

    def test_defaults_never_launch_or_mutate(self):
        for module in (current, wheels):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(module.main([]), 0)
            value = json.loads(output.getvalue())
            self.assertEqual(value["mode"], "PLAN_ONLY")

    def test_current_manifest_binds_two_pure_wheels_and_exact_file_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            packages = []
            for name in ("kairos-core", "kairos-persistence"):
                wheel = name.replace("-", "_") + "-0.3.0-py3-none-any.whl"
                (directory / wheel).write_bytes(b"synthetic wheel fixture")
                packages.append(
                    {
                        "name": name,
                        "revision": "a" * 40,
                        "wheel": wheel,
                        "sha256": hashlib.sha256(
                            b"synthetic wheel fixture"
                        ).hexdigest(),
                        "files": {name.replace("-", "_") + "/__init__.py": "b" * 64},
                    }
                )
            value = {"schema_version": 1, "packages": packages}
            # The fixed Windows native adapter is tested separately. Only
            # manifest policy and owned fixture bytes are under test here.
            with mock.patch.object(
                current.fresh, "safe", side_effect=lambda path: path.absolute()
            ):
                self.assertEqual(current.require_manifest(value, directory), value)
            for bad in (
                value | {"authority": "LIVE"},
                value | {"schema_version": 2},
                value | {"packages": packages[:1]},
            ):
                with self.assertRaises(current.fresh.Rejected):
                    current.require_manifest(bad, directory)
            packages[0]["wheel"] = "../escape.whl"
            with self.assertRaises(current.fresh.Rejected):
                current.require_manifest(value, directory)

    def test_signed_archive_payload_must_match_pure_wheel_payload(self):
        for package in ("kairos-core", "kairos-persistence"):
            package_dir = package.replace("-", "_")
            with tempfile.TemporaryDirectory() as root:
                root = Path(root)
                source = root / "source"
                (source / package_dir).mkdir(parents=True)
                source_file = source / package_dir / "module.py"
                source_file.write_bytes(b"signed bytes")
                archive_files = wheels.source_package_files(source, package)
                self.assertEqual(
                    archive_files,
                    {
                        package_dir + "/module.py": hashlib.sha256(
                            b"signed bytes"
                        ).hexdigest()
                    },
                )
                wheel = root / "fixture.whl"
                with zipfile.ZipFile(wheel, "w") as stream:
                    stream.writestr(package_dir + "/module.py", b"signed bytes")
                    stream.writestr(
                        package_dir.replace("_", "-") + "-0.3.0.dist-info/METADATA",
                        b"metadata is not executable package payload",
                    )
                self.assertEqual(
                    wheels.wheel_package_files(wheel, package), archive_files
                )
                with zipfile.ZipFile(wheel, "a") as stream:
                    stream.writestr(package_dir + "/generated.py", b"not signed")
                self.assertNotEqual(
                    wheels.wheel_package_files(wheel, package), archive_files
                )
                with zipfile.ZipFile(wheel, "a") as stream:
                    stream.writestr("generated_top_level.py", b"not signed")
                with self.assertRaises(current.fresh.Rejected):
                    wheels.wheel_package_files(wheel, package)

    def test_signed_operator_snapshot_is_exact_and_immutable(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            archive = root / "scripts.zip"
            names = {
                "controlled_runtime_transition.py",
                "controlled_runtime_worker.py",
                "controlled_runtime_delivery_probe.py",
                "fresh_runtime_recovery.py",
            }
            with zipfile.ZipFile(archive, "w") as stream:
                for name in names:
                    stream.writestr("scripts/" + name, name.encode())
            snapshot = root / "snapshot"
            manifest = current.extract_operator_archive(archive, snapshot)
            digest = current.verify_operator_snapshot(snapshot, manifest)
            self.assertEqual(len(digest), 64)
            (snapshot / "controlled_runtime_worker.py").write_bytes(b"changed")
            with self.assertRaises(current.fresh.Rejected):
                current.verify_operator_snapshot(snapshot, manifest)
            (snapshot / "extra.py").write_bytes(b"unmanifested")
            with self.assertRaises(current.fresh.Rejected):
                current.verify_operator_snapshot(snapshot, manifest)

    def test_realized_worker_mounts_are_exact_and_least_writable(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            operator, wheelhouse, output = (
                root / name for name in ("operator", "wheelhouse", "output")
            )
            mounts = [
                {
                    "Destination": "/operator",
                    "Source": str(operator),
                    "RW": False,
                    "Type": "bind",
                },
                {
                    "Destination": "/wheelhouse",
                    "Source": str(wheelhouse),
                    "RW": False,
                    "Type": "bind",
                },
                {
                    "Destination": "/output",
                    "Source": str(output),
                    "RW": True,
                    "Type": "bind",
                },
            ]
            view = {"mounts": mounts}
            current.require_worker_mounts(view, operator, wheelhouse, output)
            for invalid in (
                mounts[:-1],
                mounts
                + [
                    {
                        "Destination": "/extra",
                        "Source": str(root),
                        "RW": True,
                        "Type": "bind",
                    }
                ],
                [*mounts[:1], mounts[1] | {"RW": True}, mounts[2]],
                [*mounts[:1], mounts[1], mounts[2] | {"Source": str(root)}],
            ):
                with self.assertRaises(current.fresh.Rejected):
                    current.require_worker_mounts(
                        {"mounts": invalid}, operator, wheelhouse, output
                    )

    def test_execute_requires_explicit_three_way_admission(self):
        with self.assertRaises(current.fresh.Rejected):
            current.main(["--execute-clone"])

    def test_private_directory_is_protected_once_despite_reused_backup_gate(self):
        controller = object.__new__(current.Controller)
        controller.proofs = {"private_backup_acl_verified": True}
        # A second call must not create/overwrite a previous native capture.
        controller.protect_backup_directory()


if __name__ == "__main__":
    unittest.main()
