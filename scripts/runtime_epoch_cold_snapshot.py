"""Bounded cold-volume copy, invoked only in an isolated owned helper.

This is a forensic byte snapshot, not a PostgreSQL restore or readiness proof.
The original volume must be mounted read-only and its service must be stopped.
No database/Redis connection, credential parsing, or network is performed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import time
from pathlib import Path

MAX_BYTES = 4 * 1024**3
MAX_FILES = 50_000
MAX_SECONDS = 900


class SnapshotError(RuntimeError):
    """Only fixed public rejection codes leave the helper."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def manifest(root: Path, *, deadline: float) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise SnapshotError("COLD_REGULAR_DIRECTORY_REQUIRED")
    rows = []
    total = 0
    for directory, names, files in os.walk(root, followlinks=False):
        names.sort()
        files.sort()
        if len(rows) + len(names) + len(files) > MAX_FILES:
            raise SnapshotError("COLD_COPY_FILE_BOUND")
        for name in [*names, *files]:
            path = Path(directory) / name
            info = path.lstat()
            if time.monotonic() >= deadline:
                raise SnapshotError("COLD_COPY_DEADLINE")
            if stat.S_ISLNK(info.st_mode) or not (
                stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
            ):
                raise SnapshotError("COLD_LINK_OR_SPECIAL_FILE_REJECTED")
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                rows.append([relative, "d", stat.S_IMODE(info.st_mode)])
                continue
            total += info.st_size
            if total > MAX_BYTES or len(rows) >= MAX_FILES:
                raise SnapshotError("COLD_COPY_SIZE_BOUND")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            # Native Linux requires no-atime support; no fallback reads of the
            # original are allowed if the owner cannot open with O_NOATIME.
            if os.name == "posix":
                if not hasattr(os, "O_NOATIME"):
                    raise SnapshotError("COLD_NOATIME_REQUIRED")
                flags |= os.O_NOATIME
            digest = hashlib.sha256()
            with os.fdopen(os.open(path, flags), "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                ):
                    raise SnapshotError("COLD_SOURCE_CHANGED")
                while block := stream.read(1024**2):
                    if time.monotonic() >= deadline:
                        raise SnapshotError("COLD_COPY_DEADLINE")
                    digest.update(block)
                ended = os.fstat(stream.fileno())
                if (ended.st_size, ended.st_mtime_ns) != (
                    opened.st_size,
                    opened.st_mtime_ns,
                ):
                    raise SnapshotError("COLD_SOURCE_CHANGED")
            rows.append(
                [
                    relative,
                    "f",
                    stat.S_IMODE(info.st_mode),
                    info.st_size,
                    info.st_mtime_ns,
                    digest.hexdigest(),
                ]
            )
        if len(rows) > MAX_FILES:
            raise SnapshotError("COLD_COPY_FILE_BOUND")
    if not rows or not total:
        raise SnapshotError("COLD_NONEMPTY_SOURCE_REQUIRED")
    rows.sort()
    return {"rows": rows, "bytes": total, "entries": len(rows)}


def copy_snapshot(source: Path, target: Path, *, deadline: float) -> dict:
    if (
        source.resolve() == target.resolve()
        or target.is_symlink()
        or not target.is_dir()
    ):
        raise SnapshotError("COLD_SEPARATE_TARGET_REQUIRED")
    if any(target.iterdir()):
        raise SnapshotError("COLD_EMPTY_TARGET_REQUIRED")
    before = manifest(source, deadline=deadline)
    copied_bytes = 0
    for row in before["rows"]:
        src, dst = source / row[0], target / row[0]
        if row[1] == "d":
            dst.mkdir(mode=row[2], parents=True, exist_ok=True)
            os.chmod(dst, row[2])
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        if os.name == "posix":
            flags |= os.O_NOATIME
        with os.fdopen(os.open(src, flags), "rb") as original:
            info = os.fstat(original.fileno())
            if info.st_size != row[3] or info.st_mtime_ns != row[4]:
                raise SnapshotError("COLD_SOURCE_CHANGED")
            file_bytes = 0
            with dst.open("xb") as copied:
                while block := original.read(1024**2):
                    if time.monotonic() >= deadline:
                        raise SnapshotError("COLD_COPY_DEADLINE")
                    file_bytes += len(block)
                    copied_bytes += len(block)
                    if file_bytes > row[3] or copied_bytes > MAX_BYTES:
                        raise SnapshotError("COLD_COPY_SIZE_BOUND")
                    copied.write(block)
                copied.flush()
                os.fsync(copied.fileno())
        os.chmod(dst, row[2])
        os.utime(dst, ns=(row[4], row[4]))
    after = manifest(source, deadline=deadline)
    target_manifest = manifest(target, deadline=deadline)
    if before != after or before != target_manifest:
        raise SnapshotError("COLD_COPY_CONTENT_OR_SOURCE_CONFLICT")
    return {
        "state": "PASS_COLD_BYTE_COPY",
        "content_sha256": hashlib.sha256(canonical(before)).hexdigest(),
        "bytes": before["bytes"],
        "entries": before["entries"],
        "source_unchanged": True,
        "source_readonly": True,
        "restore_proven": False,
        "trading_started": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--copy-owned-cold-volume", action="store_true")
    args = parser.parse_args(argv)
    if not args.copy_owned_cold_volume:
        print(json.dumps({"state": "PLAN_ONLY", "trading_started": False}))
        return 0
    try:
        value = copy_snapshot(
            Path("/source"), Path("/target"), deadline=time.monotonic() + MAX_SECONDS
        )
        print(json.dumps(value, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001 - never emit raw filesystem/native errors.
        print(
            json.dumps(
                {
                    "state": "FAILED_CLOSED",
                    "reason": str(exc)
                    if isinstance(exc, SnapshotError)
                    else "COLD_COPY_OPERATION_FAILED",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
