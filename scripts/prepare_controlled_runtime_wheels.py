"""Build two pure wheels from clean signed Git archives; no runtime activation."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import time
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import fresh_runtime_recovery as fresh
else:
    import fresh_runtime_recovery as fresh

UV = Path("C:/Users/loval/.local/bin/uv.exe")
ROOT = Path("D:/Kairos/runtime/controlled-runtime-wheels-20261010")
BUILD_CONSTRAINTS = Path(__file__).with_name("controlled_runtime_build-constraints.txt")
EXPECTED_BUILD_CONSTRAINTS = b"hatchling==1.32.0\n"


def source_package_files(source: Path, name: str) -> dict[str, str]:
    """Hash the package payload extracted from the signed source archive."""
    prefix = name.replace("-", "_")
    package = source / prefix
    if not package.is_dir():
        raise fresh.Rejected("SIGNED_SOURCE_PACKAGE_MISSING")
    result = {}
    for path in package.rglob("*"):
        if path.is_symlink() or not path.is_file():
            if path.is_dir() and not path.is_symlink():
                continue
            raise fresh.Rejected("SIGNED_SOURCE_PACKAGE_SPECIAL_FILE")
        relative = path.relative_to(source).as_posix()
        result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not result:
        raise fresh.Rejected("SIGNED_SOURCE_PACKAGE_EMPTY")
    return result


def wheel_package_files(wheel: Path, name: str) -> dict[str, str]:
    """Return the complete runtime payload, excluding the wheel's dist-info."""
    prefix = name.replace("-", "_") + "/"
    with zipfile.ZipFile(wheel) as stream:
        members = [member for member in stream.infolist() if not member.is_dir()]
        metadata_roots = {
            member.filename.split("/", 1)[0]
            for member in members
            if member.filename.split("/", 1)[0].endswith(".dist-info")
        }
        if len(metadata_roots) != 1:
            raise fresh.Rejected("ONE_WHEEL_DIST_INFO_DIRECTORY_REQUIRED")
        runtime = {
            member.filename: hashlib.sha256(stream.read(member)).hexdigest()
            for member in members
            if not any(
                member.filename.startswith(root + "/") for root in metadata_roots
            )
        }
        if any(not path.startswith(prefix) for path in runtime):
            raise fresh.Rejected("UNSIGNED_WHEEL_RUNTIME_FILE_REJECTED")
        return runtime


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    args = parser.parse_args(argv)
    if not args.prepare:
        print(json.dumps({"mode": "PLAN_ONLY", "runtime_operations": 0}))
        return 0
    if BUILD_CONSTRAINTS.read_bytes() != EXPECTED_BUILD_CONSTRAINTS:
        raise fresh.Rejected("PINNED_OFFLINE_BUILD_CONSTRAINT_REQUIRED")
    ROOT.mkdir(parents=True, exist_ok=True)
    directory = fresh.safe(ROOT / uuid.uuid4().hex)
    directory.mkdir()
    controller = object.__new__(fresh.Controller)
    controller.work, controller.proofs = directory, {}
    controller.scratch_directories = []
    controller.deadline = time.monotonic() + 300
    (directory / "docker-config").mkdir()
    fresh.save(directory / "docker-config/config.json", fresh.auth_free_docker_config())
    controller.native = fresh.bounded.Native(directory)
    controller.cleanup_deadline = None
    controller.protect_backup_directory()
    packages = []
    for name in ("kairos-core", "kairos-persistence"):
        repo = Path("D:/Kairos") / name
        for label, command in (
            ("status", ["status", "--porcelain"]),
            ("branch", ["branch", "--show-current"]),
            ("head", ["rev-parse", "HEAD"]),
            ("origin", ["rev-parse", "origin/main"]),
            ("signature", ["log", "-1", "--format=%G? %GF"]),
        ):
            controller.process(
                fresh.GIT, ["-C", str(repo), *command], 20, label=name + "-" + label
            )

        def result(label, package_name=name):
            return (
                (directory / (package_name + "-" + label + ".stdout"))
                .read_text()
                .strip()
            )

        revision = result("head")
        if (
            result("status")
            or result("branch") != "main"
            or result("origin") != revision
            or result("signature") != "G " + fresh.SIGNER
        ):
            raise fresh.Rejected("CURRENT_CLEAN_SIGNED_MAIN_REQUIRED_FOR_WHEEL")
        archive = directory / (name + ".zip")
        controller.process(
            fresh.GIT,
            [
                "-C",
                str(repo),
                "archive",
                "--format=zip",
                "--output=" + str(archive),
                revision,
            ],
            20,
            label=name + "-archive",
        )
        source = directory / name
        source.mkdir()
        archive_bytes = 0
        archive_files = 0
        with zipfile.ZipFile(archive) as stream:
            for member in stream.infolist():
                path = Path(member.filename.replace("/", "\\"))
                mode = member.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or "\\" in member.filename
                    or member.file_size > 16 * 1024**2
                    or member.filename.startswith("/")
                    or kind not in {0, stat.S_IFREG, stat.S_IFDIR}
                ):
                    raise fresh.Rejected("GIT_SOURCE_ARCHIVE_BOUNDARY_REJECTED")
                if not member.is_dir():
                    archive_files += 1
                    archive_bytes += member.file_size
                    if archive_files > 10000 or archive_bytes > 128 * 1024**2:
                        raise fresh.Rejected("GIT_SOURCE_ARCHIVE_SIZE_LIMIT")
            stream.extractall(source)
        expected_files = source_package_files(source, name)
        controller.process(
            UV,
            [
                "build",
                "--wheel",
                "--offline",
                "--build-constraints",
                str(BUILD_CONSTRAINTS),
                "--out-dir",
                str(directory),
                str(source),
            ],
            100,
            label=name + "-build",
        )
        wheels = list(directory.glob(name.replace("-", "_") + "-*.whl"))
        if len(wheels) != 1:
            raise fresh.Rejected("ONE_PURE_WHEEL_PER_SOURCE_REQUIRED")
        wheel = wheels[0]
        files = wheel_package_files(wheel, name)
        if files != expected_files:
            raise fresh.Rejected("WHEEL_PAYLOAD_DIFFERS_FROM_SIGNED_SOURCE")
        packages.append(
            {
                "name": name,
                "revision": revision,
                "wheel": wheel.name,
                "sha256": fresh.sha(wheel),
                "files": files,
            }
        )
    fresh.save(directory / "manifest.json", {"schema_version": 1, "packages": packages})
    fresh.save(
        directory / "build-receipt.json",
        {
            "kind": "current-runtime-wheel-build-v1",
            "result": "PASS",
            "created_at_utc": datetime.now(UTC).isoformat(),
            "manifest_sha256": fresh.sha(directory / "manifest.json"),
            "build_constraints_sha256": fresh.sha(BUILD_CONSTRAINTS),
            "package_revisions": {p["name"]: p["revision"] for p in packages},
            "runtime_operations": 0,
            "windows_cli_tree_proofs": controller.proofs,
        },
    )
    print(
        json.dumps(
            {
                "result": "PASS",
                "wheelhouse": str(directory),
                "manifest_sha256": fresh.sha(directory / "manifest.json"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
