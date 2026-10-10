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
