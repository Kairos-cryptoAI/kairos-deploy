"""Current-source controlled-runtime clone qualification; trading never starts.

This is an additive protocol. The historical recovery workers, receipts and
source locks are not edited or adopted. Default invocation is a dry plan. All
native clone operations reuse the reviewed bounded fresh-recovery primitives.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import stat
import subprocess
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

ROOT = fresh.REPO / "backups/controlled-runtime-transition-20261010"
KIND = "controlled-runtime-transition-v1"
CONFIRM_CLONE = "CURRENT_CONTROLLED_RUNTIME_CLONE_ONLY_NO_TRADING"
RUNNER = "sha256:2e10e9e936eae3a4a411f65d8b0bd14670ba808368eeff94b4e24021aa291077"
MAX_SECONDS = 1800
SCRATCH_CEILING = 256 * 1024**2
REDIS_IMAGE = "sha256:a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103"
OPERATOR_REQUIRED = {
    "controlled_runtime_transition.py",
    "controlled_runtime_worker.py",
    "controlled_runtime_delivery_probe.py",
    "fresh_runtime_recovery.py",
}


def restored_primary_worker_plan(plan: dict, owner: str) -> dict:
    """Derive only the clone authorization bit; never overwrite primary evidence."""
    if (
        not isinstance(plan, dict)
        or not re.fullmatch(r"[0-9a-f]{32}", owner)
        or plan.get("owner") != owner
        or plan.get("primary_authorized") is not True
    ):
        raise fresh.Rejected("COMMITTED_PRIMARY_PLAN_REQUIRED_FOR_RESTORE")
    return {**plan, "primary_authorized": False}


def verify_operator_snapshot(directory: Path, manifest: dict[str, str]) -> str:
    """Require the exact regular-file tree captured from the signed Deploy archive."""
    if not directory.is_dir() or not isinstance(manifest, dict) or not manifest:
        raise fresh.Rejected("SIGNED_OPERATOR_SNAPSHOT_REQUIRED")
    actual = {}
    for path in directory.rglob("*"):
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0) & 0x400
        ):
            raise fresh.Rejected("OPERATOR_SNAPSHOT_LINK_REJECTED")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise fresh.Rejected("OPERATOR_SNAPSHOT_SPECIAL_FILE_REJECTED")
        relative = path.relative_to(directory).as_posix()
        actual[relative] = fresh.sha(path)
    if actual != manifest:
        raise fresh.Rejected("OPERATOR_SNAPSHOT_CONTENT_CHANGED")
    return fresh.digest(actual)


def require_worker_mounts(
    view: dict, operator_snapshot: Path, wheelhouse: Path, output: Path
) -> None:
    """Check Docker's realized mounts, not merely the requested create arguments."""
    expected = {
        "/operator": (operator_snapshot, False),
        "/wheelhouse": (wheelhouse, False),
        "/output": (output, True),
    }
    mounts = view.get("mounts")
    if not isinstance(mounts, list) or len(mounts) != len(expected):
        raise fresh.Rejected("CURRENT_WORKER_MOUNTS_REJECTED")
    actual = {}
    for mount in mounts:
        destination = mount.get("Destination")
        if (
            destination not in expected
            or destination in actual
            or mount.get("Type") != "bind"
        ):
            raise fresh.Rejected("CURRENT_WORKER_MOUNTS_REJECTED")
        source, writable = expected[destination]
        if (
            fresh.mount_identity(mount.get("Source", ""))
            != fresh.mount_identity(str(source))
            or mount.get("RW") is not writable
        ):
            raise fresh.Rejected("CURRENT_WORKER_MOUNTS_REJECTED")
        actual[destination] = True
    if set(actual) != set(expected):
        raise fresh.Rejected("CURRENT_WORKER_MOUNTS_REJECTED")


def extract_operator_archive(archive: Path, directory: Path) -> dict[str, str]:
    """Extract only ordinary files under scripts/ from a signed Git archive."""
    directory.mkdir()
    total_bytes = 0
    file_count = 0
    with zipfile.ZipFile(archive) as stream:
        for member in stream.infolist():
            name = member.filename
            parts = name.rstrip("/").split("/")
            mode = member.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if (
                not name.startswith("scripts/")
                or "\\" in name
                or name.startswith("/")
                or any(part in {"", ".", ".."} for part in parts)
                or member.file_size > 16 * 1024**2
                or kind not in {0, stat.S_IFREG, stat.S_IFDIR}
            ):
                raise fresh.Rejected("SIGNED_OPERATOR_ARCHIVE_BOUNDARY_REJECTED")
            relative = Path(*parts[1:])
            target = directory / relative
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            file_count += 1
            total_bytes += member.file_size
            if file_count > 512 or total_bytes > 64 * 1024**2:
                raise fresh.Rejected("SIGNED_OPERATOR_ARCHIVE_SIZE_LIMIT")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(stream.read(member))
    manifest = {}
    for path in directory.rglob("*"):
        if path.is_file():
            manifest[path.relative_to(directory).as_posix()] = fresh.sha(path)
    if not OPERATOR_REQUIRED.issubset(manifest):
        raise fresh.Rejected("SIGNED_OPERATOR_SCRIPTS_INCOMPLETE")
    verify_operator_snapshot(directory, manifest)
    return manifest


def current_scratch_bytes(directories: list[Path]) -> int:
    """Additive protocol ceiling for two separately retained restored dumps."""
    total = 0
    for directory in directories:
        for item in (directory, *directory.rglob("*")):
            try:
                metadata = item.lstat()
            except FileNotFoundError:
                if item == directory:
                    raise fresh.Rejected("OWN_SCRATCH_DIRECTORY_MISSING") from None
                continue
            if (
                stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x400
            ):
                raise fresh.Rejected("SCRATCH_LINK_REJECTED")
            if stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
            elif not stat.S_ISDIR(metadata.st_mode):
                raise fresh.Rejected("SCRATCH_SPECIAL_FILE_REJECTED")
    if total > SCRATCH_CEILING:
        raise fresh.Rejected("CONTROLLED_SCRATCH_CEILING_EXCEEDED")
    return total


def require_manifest(value: dict, directory: Path) -> dict:
    if set(value) != {"schema_version", "packages"} or value["schema_version"] != 1:
        raise fresh.Rejected("CURRENT_WHEEL_MANIFEST_REQUIRED")
    packages = value["packages"]
    if (
        not isinstance(packages, list)
        or {p.get("name") for p in packages} != {"kairos-core", "kairos-persistence"}
        or len(packages) != 2
    ):
        raise fresh.Rejected("EXACT_TWO_RUNTIME_PACKAGES_REQUIRED")
    for package in packages:
        if set(package) != {"name", "revision", "wheel", "sha256", "files"}:
            raise fresh.Rejected("EXACT_WHEEL_PROVENANCE_REQUIRED")
        if not re.fullmatch(r"[0-9a-f]{40}", package["revision"]):
            raise fresh.Rejected("SIGNED_SOURCE_REVISION_REQUIRED")
        wheel = package["wheel"]
        if not re.fullmatch(
            r"kairos_(core|persistence)-[0-9.]+-py3-none-any\.whl", wheel
        ):
            raise fresh.Rejected("PURE_RUNTIME_WHEEL_REQUIRED")
        if fresh.sha(fresh.safe(directory / wheel)) != package["sha256"]:
            raise fresh.Rejected("WHEEL_BYTES_CHANGED")
        files = package["files"]
        prefix = package["name"].replace("-", "_") + "/"
        if not files or any(
            not name.startswith(prefix)
            or ".." in name.split("/")
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for name, digest in files.items()
        ):
            raise fresh.Rejected("PACKAGE_FILE_PROVENANCE_REQUIRED")
    return value


class Controller(fresh.Controller):
    def __init__(self, wheelhouse: Path, revision: str):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise fresh.Rejected("EXACT_SIGNED_DEPLOY_REVISION_REQUIRED")
        self.owner = uuid.uuid4().hex
        fresh.safe(ROOT).mkdir(parents=True, exist_ok=True)
        self.work = ROOT / ("run-" + self.owner)
        self.work.mkdir()
        self.lease = ROOT / ("controlled-runtime-" + revision[:12] + ".execution.lock")
        fresh.write(self.lease, self.owner.encode())
        self.deadline = time.monotonic() + MAX_SECONDS
        self.native = fresh.bounded.Native(self.work)
        (self.work / "docker-config").mkdir()
        fresh.save(
            self.work / "docker-config/config.json", fresh.auth_free_docker_config()
        )
        self.owned, self.scratch_directories = {}, []
        self.phase, self.proofs, self.cleanup_deadline = "ADMISSION", {}, None
        self.workers = {}
        self.wheelhouse = fresh.safe(wheelhouse)
        self.revision = revision
        self.manifest = require_manifest(
            json.loads((self.wheelhouse / "manifest.json").read_text()), self.wheelhouse
        )

    def protect_backup_directory(self):
        if not self.proofs.get("private_backup_acl_verified"):
            super().protect_backup_directory()

    def check_scratch(self):
        amount = current_scratch_bytes(self.scratch_directories)
        self.proofs["disk_scratch_peak_observed_bytes"] = max(
            amount, self.proofs.get("disk_scratch_peak_observed_bytes", 0)
        )
        self.proofs["disk_scratch_observed_ceiling_bytes"] = SCRATCH_CEILING

    def current_cold_verify(self):
        name = "kairos-recovery-" + self.owner[:12] + "-current-cold-verify"
        self.create(
            name,
            mounts=["type=volume,src=" + fresh.VOLUME + ",dst=/source,readonly"],
            entrypoint="/usr/bin/timeout",
            command=[
                "-s",
                "KILL",
                "170",
                "/bin/sh",
                "-c",
                "fingerprint_root=/source\n" + fresh.FINGERPRINT,
            ],
        )
        code = self.docker(["wait", name], seconds=180)
        lines = self.docker(["logs", name]).splitlines()
        fresh.save(self.work / "current-cold-verify-log.json", lines)
        if (
            code != "0"
            or len(lines) != 3
            or any(not re.fullmatch(r"[0-9a-f]{64}  -", line) for line in lines[:2])
            or not lines[2].isdigit()
        ):
            raise fresh.Rejected("CURRENT_COLD_FINGERPRINT_FAILED")
        self.remove(name)
        return {
            "files_sha256": lines[0][:64],
            "metadata_sha256": lines[1][:64],
            "bytes": int(lines[2]),
        }

    def admit(self):
        self.protect_backup_directory()
        for repo, expected in [(fresh.REPO, self.revision)] + [
            (Path("D:/Kairos") / p["name"], p["revision"])
            for p in self.manifest["packages"]
        ]:
            self.process(
                fresh.GIT,
                ["-C", str(repo), "status", "--porcelain"],
                20,
                label="status-" + repo.name,
            )
            if (self.work / ("status-" + repo.name + ".stdout")).read_text().strip():
                raise fresh.Rejected("CLEAN_SCOPED_MAIN_REQUIRED")
            for suffix, command, wanted in (
                ("head", ["rev-parse", "HEAD"], expected),
                ("origin", ["rev-parse", "origin/main"], expected),
                ("branch", ["branch", "--show-current"], "main"),
                ("signature", ["log", "-1", "--format=%G? %GF"], "G " + fresh.SIGNER),
            ):
                label = suffix + "-" + repo.name
                self.process(fresh.GIT, ["-C", str(repo), *command], 20, label=label)
                if (self.work / (label + ".stdout")).read_text().strip() != wanted:
                    raise fresh.Rejected("SCOPED_MAIN_REVISION_OR_SIGNATURE_CHANGED")
        self.proofs["reviewed_deploy_revision"] = self.revision
        for identifier in self.docker(["ps", "-q"]).splitlines():
            view = self.inspect(identifier)
            if (view["labels"] or {}).get("com.kairos.recovery.scope") == KIND:
                raise fresh.Rejected("OTHER_CURRENT_TRANSITION_RUNNING")
        self.proofs["wheel_manifest_sha256"] = fresh.sha(
            self.wheelhouse / "manifest.json"
        )
        self.proofs["package_revisions"] = {
            p["name"]: p["revision"] for p in self.manifest["packages"]
        }
        archive = self.work / "deploy-scripts.zip"
        self.process(
            fresh.GIT,
            [
                "-C",
                str(fresh.REPO),
                "archive",
                "--format=zip",
                "--output=" + str(archive),
                self.revision,
                "scripts",
            ],
            30,
            label="signed-deploy-scripts-archive",
        )
        self.operator_snapshot = self.work / "operator-snapshot"
        self.operator_manifest = extract_operator_archive(
            archive, self.operator_snapshot
        )
        controller_relative = (
            Path(__file__)
            .resolve()
            .relative_to(fresh.REPO.resolve())
            .as_posix()
            .removeprefix("scripts/")
        )
        if self.operator_manifest.get(controller_relative) != fresh.sha(Path(__file__)):
            raise fresh.Rejected("RUNNING_CONTROLLER_DIFFERS_FROM_SIGNED_SNAPSHOT")
        self.operator_snapshot_sha256 = verify_operator_snapshot(
            self.operator_snapshot, self.operator_manifest
        )
        self.proofs["operator_snapshot_sha256"] = self.operator_snapshot_sha256
        self.proofs["operator_snapshot_files"] = dict(self.operator_manifest)

    def worker(self, target: str, database: str, mode: str, *, primary: bool = False):
        if primary:
            if (
                target != fresh.SOURCE
                or database != "kairos"
                or mode not in {"apply", "verify", "permissions"}
                or self.proofs.get("clone_acceptance_verified") is not True
            ):
                raise fresh.Rejected("EXPLICIT_ACCEPTED_PRIMARY_TARGET_REQUIRED")
            self.assert_primary_target()
        elif target not in self.owned or mode not in {
            "rehearse",
            "verify",
            "delivery",
            "verify-restored-primary",
        }:
            raise fresh.Rejected("CLONE_WORKER_SCOPE_REQUIRED")
        require_manifest(
            json.loads((self.wheelhouse / "manifest.json").read_text()), self.wheelhouse
        )
        verify_operator_snapshot(self.operator_snapshot, self.operator_manifest)
        if (
            fresh.sha(self.wheelhouse / "manifest.json")
            != self.proofs["wheel_manifest_sha256"]
        ):
            raise fresh.Rejected("ADMITTED_WHEEL_MANIFEST_CHANGED")
        if mode == "delivery":
            if database != "kairos_runtime_probe_" + self.owner[:12]:
                raise fresh.Rejected("EMPTY_OWNED_DELIVERY_DATABASE_REQUIRED")
            invocation = (
                "/operator/controlled_runtime_delivery_probe.py --database "
                + shlex.quote(database)
                + " --directory /evidence"
            )
        else:
            invocation = (
                "/operator/controlled_runtime_worker.py --database "
                + shlex.quote(database)
                + " --mode "
                + mode
                + " --directory /evidence --manifest /wheelhouse/manifest.json"
            )
            if primary:
                invocation += " --primary"
        # Nine full rollback snapshots on the preserved non-empty legacy history
        # need a separate clone-only validation budget. Primary mutation and
        # per-snapshot SQL/row/byte guards retain their existing smaller bounds.
        worker_seconds = 960 if mode == "rehearse" and not primary else 600
        name = "kairos-controlled-" + self.owner[:12] + "-" + mode
        if name in self.workers:
            raise fresh.Rejected("DUPLICATE_WORKER_REFUSED")
        output = self.work / ("worker-output-" + name)
        output.mkdir()
        restore_plan = None
        if mode == "verify-restored-primary":
            source_plan = fresh.safe(self.work / "plan.json")
            if not source_plan.is_file():
                raise fresh.Rejected("COMMITTED_PRIMARY_PLAN_FILE_REQUIRED")
            restore_plan = restored_primary_worker_plan(
                json.loads(source_plan.read_text()), self.owner
            )
        for source in self.work.iterdir():
            if not source.is_file() or not (
                source.name == "plan.json"
                or (
                    source.suffix == ".json"
                    and source.name.startswith(("native-", "precommit-"))
                )
                or source.name == "runtime-auth.json"
            ):
                continue
            if source.is_symlink():
                raise fresh.Rejected("WORKER_INPUT_LINK_REJECTED")
            if restore_plan is not None and source.name == "plan.json":
                fresh.save(output / "plan.json", restore_plan)
                continue
            if restore_plan is not None and source.name == "runtime-auth.json":
                # A dump restore proves history, not original-cluster logins.
                continue
            fresh.write(output / source.name, source.read_bytes())
        args = [
            "create",
            "--pull=never",
            "--name",
            name,
            "--network=container:" + target,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory=512m",
            "--memory-swap=512m",
            "--cpus=1",
            "--pids-limit=64",
            "--user=0:0",
            "--label",
            fresh.OWNER_LABEL + "=" + self.owner,
            "--label",
            "com.kairos.recovery.scope=" + KIND,
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=128m,mode=0700",
            "--tmpfs",
            "/evidence:rw,nosuid,nodev,size=32m,mode=0700",
            "--mount",
            "type=bind,src=" + str(self.operator_snapshot) + ",dst=/operator,readonly",
            "--mount",
            "type=bind,src=" + str(self.wheelhouse) + ",dst=/wheelhouse,readonly",
            "--mount",
            "type=bind,src=" + str(output) + ",dst=/output",
            "--entrypoint=/bin/sh",
            RUNNER,
            "-c",
            "set -eu; export PYTHONDONTWRITEBYTECODE=1 PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1; "
            "/usr/local/bin/python -m pip install --no-index --no-deps --no-compile --target /tmp/installed /wheelhouse/*.whl >/tmp/install.log 2>&1; "
            "cp /output/plan.json /evidence/plan.json; chmod 600 /evidence/plan.json; "
            "for f in /output/native-*.json /output/precommit-*.json; do "
            '[ ! -f "$f" ] || { cp "$f" /evidence/; chmod 600 /evidence/"${f##*/}"; }; done; '
            "if [ -f /output/runtime-auth.json ]; then cp /output/runtime-auth.json /evidence/; chmod 600 /evidence/runtime-auth.json; fi; "
            "export PYTHONPATH=/tmp/installed:/operator; set +e; timeout -s KILL "
            + str(worker_seconds)
            + " python -B "
            + invocation
            + "; status=$?; set -e; "
            'for f in /evidence/*.json; do [ ! -f "$f" ] || cp -n "$f" /output/; done; exit "$status"',
        ]
        self.workers[name] = {"target": target, "image": RUNNER}
        self.docker(args)
        view = self.inspect(name)
        if (
            view["image"] != RUNNER
            or view["network"]
            not in {"container:" + self.inspect(target)["id"], "container:" + target}
            or view["memory"] != 512 * 1024**2
            or view["swap"] != 512 * 1024**2
            or view["cpus"] != 10**9
            or view["readonly"] is not True
            or view["caps"] != ["ALL"]
            or view["ports"]
            or view["privileged"]
            or (view["labels"] or {}).get(fresh.OWNER_LABEL) != self.owner
        ):
            raise fresh.Rejected("CURRENT_WORKER_BOUNDARY_CHANGED")
        require_worker_mounts(view, self.operator_snapshot, self.wheelhouse, output)
        verify_operator_snapshot(self.operator_snapshot, self.operator_manifest)
        self.docker(["start", name])
        code = self.docker(["wait", name], seconds=worker_seconds + 10)
        # Logs are private native captures, never copied to public receipts.
        self.docker(["logs", name], allow_failure=True)
        if code != "0":
            raise fresh.Rejected("CURRENT_WORKER_FAILED_PRIVATE_DIAGNOSTIC")
        for artifact in output.iterdir():
            metadata = artifact.lstat()
            if (
                artifact.suffix != ".json"
                or not stat.S_ISREG(metadata.st_mode)
                or artifact.is_symlink()
            ):
                raise fresh.Rejected("CURRENT_WORKER_OUTPUT_BOUNDARY_CHANGED")
            if restore_plan is not None and artifact.name == "plan.json":
                if json.loads(artifact.read_text()) != restore_plan:
                    raise fresh.Rejected("RESTORED_PRIMARY_WORKER_PLAN_CHANGED")
                self.proofs["restored_primary_worker_plan_sha256"] = fresh.sha(artifact)
                # This is an immutable phase-local view, not a replacement for
                # the retained primary-authorized plan in the controller root.
                continue
            destination = self.work / artifact.name
            if destination.exists():
                if not destination.is_file() or fresh.sha(destination) != fresh.sha(
                    artifact
                ):
                    raise fresh.Rejected("CURRENT_WORKER_ARTIFACT_CONFLICT")
            else:
                fresh.write(destination, artifact.read_bytes())
        verify_operator_snapshot(self.operator_snapshot, self.operator_manifest)
        self.docker(["rm", name])
        self.workers.pop(name)

    def assert_primary_target(self):
        raise fresh.Rejected("CLONE_CONTROLLER_HAS_NO_PRIMARY_ADMISSION")

    def delivery_fixture(self, target: str, current_database: str):
        database = "kairos_runtime_probe_" + self.owner[:12]
        if (
            self.sql(
                target,
                current_database,
                "SELECT count(*) FROM pg_database WHERE datname='" + database + "';",
            )
            != "0"
        ):
            raise fresh.Rejected("DELIVERY_DATABASE_ALREADY_EXISTS")
        self.sql(
            target, current_database, "CREATE DATABASE " + database + " OWNER kairos;"
        )
        name = "kairos-controlled-" + self.owner[:12] + "-fixture-redis"
        self.workers[name] = {"target": target, "image": REDIS_IMAGE}
        self.docker(
            [
                "create",
                "--pull=never",
                "--name",
                name,
                "--network=container:" + target,
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--memory=128m",
                "--memory-swap=128m",
                "--cpus=1",
                "--pids-limit=32",
                "--user=redis",
                "--label",
                fresh.OWNER_LABEL + "=" + self.owner,
                "--label",
                "com.kairos.recovery.scope=" + KIND,
                "--tmpfs",
                "/data:rw,nosuid,nodev,size=32m,uid=999,gid=999,mode=0700",
                "--entrypoint=/usr/bin/timeout",
                REDIS_IMAGE,
                "-s",
                "KILL",
                "180",
                "redis-server",
                "--bind",
                "127.0.0.1",
                "--port",
                "6379",
                "--protected-mode",
                "yes",
                "--save",
                "",
                "--appendonly",
                "no",
                "--maxmemory",
                "32mb",
                "--maxmemory-policy",
                "noeviction",
            ]
        )
        value = self.inspect(name)
        if (
            value["image"] != REDIS_IMAGE
            or value["memory"] != 128 * 1024**2
            or value["swap"] != 128 * 1024**2
            or value["cpus"] != 10**9
            or value["network"]
            not in {"container:" + target, "container:" + self.inspect(target)["id"]}
            or value["readonly"] is not True
            or value["caps"] != ["ALL"]
            or value["mounts"]
            or value["ports"]
            or value["privileged"]
            or (value["labels"] or {}).get(fresh.OWNER_LABEL) != self.owner
        ):
            raise fresh.Rejected("FIXTURE_REDIS_BOUNDARY_CHANGED")
        self.docker(["start", name])
        if (
            self.docker(["exec", name, "redis-cli", "-h", "127.0.0.1", "ping"])
            != "PONG"
        ):
            raise fresh.Rejected("EMPTY_FIXTURE_REDIS_NOT_READY")
        self.worker(target, database, "delivery")
        receipt = self.work / (
            "controlled-runtime-delivery-" + self.owner[:12] + ".json"
        )
        if json.loads(receipt.read_text()).get("status") != "PASS":
            raise fresh.Rejected("REAL_DELIVERY_FIXTURE_FAILED")
        self.proofs["fixture_delivery_sha256"] = fresh.sha(receipt)
        self.proofs["fixture_delivery_scope"] = (
            "EMPTY_DISPOSABLE_DATABASE_AND_REDIS_NOT_PRIMARY"
        )
        self.docker(["rm", "-f", name])
        self.workers.pop(name)

    def run(self):
        self.admit()
        # New official backup, complete cold identity check, two legacy restores.
        # The old source and protocol files are used unchanged, never rewritten.
        super().run()
        baseline = self.proofs["snapshot"]
        dump = next(self.work.glob("kairos-recovery-copy-*.dump"))
        name, database = self.restore(dump, "current")
        if self.snapshot(name, database) != baseline:
            raise fresh.Rejected("CURRENT_CLONE_LEGACY_BASELINE_DIFFERS")
        fresh.save(
            self.work / "plan.json",
            {
                "schema_version": 1,
                "kind": KIND,
                "owner": self.owner,
                "primary_authorized": False,
                "role_provision_authorized": True,
                "reconciliation_id": "controlled-runtime-" + self.owner,
                "reason": "expired legacy transport outcome; frozen without replay",
                "accepted_legacy_tables": baseline["tables"],
                "expected_legacy_tables": [p["table"] for p in baseline["tables"]],
                "accepted_legacy_sequences": baseline["sequences"],
                "accepted_migrations": baseline["migrations"],
                "legacy_schema_fingerprint_sha256": baseline["schema_sha256"],
                "legacy_snapshot_sha256": fresh.digest(
                    {
                        "tables": baseline["tables"],
                        "sequences": baseline["sequences"],
                        "migrations": baseline["migrations"],
                        "schema_fingerprint_sha256": baseline["schema_sha256"],
                    }
                ),
                "package_revisions": self.proofs["package_revisions"],
            },
        )
        self.phase = "CURRENT_ATOMIC_CLONE_REHEARSAL"
        self.worker(name, database, "rehearse")
        receipt = json.loads((self.work / "native-rehearsal.json").read_text())
        if receipt.get("result") != "PASS":
            raise fresh.Rejected("CURRENT_CLONE_REHEARSAL_NOT_ACCEPTED")
        self.proofs["current_rehearsal_sha256"] = fresh.sha(
            self.work / "native-rehearsal.json"
        )
        self.phase = "REAL_ISOLATED_DELIVERY_AND_RESTART_FIXTURE"
        self.delivery_fixture(name, database)
        self.phase = "CURRENT_BACKUP_AFTER_AND_SECOND_RESTORE"
        after_dump = self.work / "controlled-after.dump"
        self.docker(
            [
                "exec",
                name,
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-privileges",
                "--username=kairos",
                "--dbname=" + database,
                "--file=/tmp/controlled-after.dump",
            ],
            seconds=120,
        )
        self.docker(["cp", name + ":/tmp/controlled-after.dump", str(after_dump)])
        self.remove(name)
        name, database = self.restore(after_dump, "current_second")
        self.worker(name, database, "verify")
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
        self.proofs["current_backup_after_sha256"] = fresh.sha(after_dump)
        self.proofs["current_restore_verify_sha256"] = fresh.sha(
            self.work / "native-verify.json"
        )
        self.proofs["current_pg_amcheck_exit_code"] = 0
        self.remove(name)
        self.phase = "PRIMARY_STILL_STOPPED_AND_UNCHANGED"
        if self.source() != json.loads(
            (self.work / "source-before.json").read_text()
        ) or self.current_cold_verify() != json.loads(
            (self.work / "cold-fingerprint.json").read_text()
        ):
            raise fresh.Rejected("PRIMARY_CHANGED_DURING_CURRENT_REHEARSAL")

    def finish(self, success: bool, error=None):
        self.cleanup_deadline = time.monotonic() + 60
        cleanup = True
        try:
            final_snapshot_hash = verify_operator_snapshot(
                self.operator_snapshot, self.operator_manifest
            )
            self.proofs["operator_snapshot_sha256_at_finish"] = final_snapshot_hash
            if final_snapshot_hash != self.operator_snapshot_sha256:
                raise fresh.Rejected("OPERATOR_SNAPSHOT_CHANGED_DURING_RUN")
        except Exception:  # noqa: BLE001 -- source uncertainty cannot pass
            success = False
            cleanup = False
        for name, expected in list(self.workers.items()):
            try:
                value = self.inspect(name)
                if (
                    value["image"] != expected["image"]
                    or (value["labels"] or {}).get(fresh.OWNER_LABEL) != self.owner
                ):
                    raise fresh.Rejected("WORKER_CLEANUP_IDENTITY_CONFLICT")
                self.docker(["rm", "-f", name])
                self.workers.pop(name)
            except Exception:  # noqa: BLE001 -- cleanup uncertainty rejects acceptance
                cleanup = False
        for name in list(self.owned):
            try:
                self.remove(name)
            except Exception:  # noqa: BLE001 -- clean only this run's exact resources
                cleanup = False
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
        except Exception:  # noqa: BLE001 -- inventory uncertainty cannot pass
            cleanup = False
        if success:
            self.proofs["artifact_sha256"] = {
                name: fresh.sha(self.work / name)
                for name in (
                    "source-before.json",
                    "cold-fingerprint.json",
                    "plan.json",
                    "native-inspection.json",
                    "native-rehearsal.json",
                    "native-verify.json",
                )
            }
        value = {
            "schema_version": 1,
            "kind": KIND,
            "owner": self.owner,
            "created_at_utc": datetime.now(UTC).isoformat(),
            "result": "PASS_CURRENT_CONTROLLED_CLONE"
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
            "native_operations": self.native.operations,
            "code_sha256": fresh.sha(Path(__file__)),
            "maximum_seconds": MAX_SECONDS,
            "primary_mutations": 0,
            "primary_consumers_started": 0,
            "primary_publisher_calls": 0,
            "primary_redis_contacted": False,
            "isolated_fixture_redis_contacted": bool(
                self.proofs.get("fixture_delivery_sha256")
            ),
            "trading_authority": "NONE",
            "strategy_policy": "REJECT_ALL",
        }
        fresh.save(self.work / "receipt.json", value)
        if success and cleanup and self.lease.read_bytes() == self.owner.encode():
            self.lease.unlink()
        print(
            json.dumps(
                {
                    "result": value["result"],
                    "receipt": str(self.work / "receipt.json"),
                    "error_category": value["error_category"],
                }
            )
        )
        return 0 if success and cleanup else 1


def supervise(args):
    """Hidden Windows owner bounds the complete clone CLI process tree."""
    directory = fresh.safe(Path(args.supervisor_directory))
    if (
        directory.parent != ROOT
        or not re.fullmatch(r"supervisor-[0-9a-f]{32}", directory.name)
        or not directory.is_dir()
        or any(
            p.name not in {"outer.stdout", "outer.stderr"} for p in directory.iterdir()
        )
    ):
        raise fresh.Rejected("PRIVATE_CURRENT_SUPERVISOR_REQUIRED")
    job = fresh.bounded._job_module().WindowsProcessJob()
    child, error, proof = None, None, None
    started = time.monotonic()
    stdout, stderr = directory / "child.stdout", directory / "child.stderr"
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(Path(__file__).absolute()),
                    "--execute-clone",
                    "--confirmation",
                    CONFIRM_CLONE,
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
                    "reviewed_deploy_revision": args.expected_revision,
                    "maximum_seconds": MAX_SECONDS + 90,
                    "assigned_before_resume": True,
                },
            )
            while child.poll() is None:
                if (
                    time.monotonic() - started >= MAX_SECONDS + 90
                    or max(stdout.stat().st_size, stderr.stat().st_size) > 256 * 1024
                ):
                    raise fresh.Rejected("CURRENT_SUPERVISOR_BOUND_EXCEEDED")
                time.sleep(0.1)
    except BaseException as caught:  # noqa: BLE001 -- uncertain interruption never admits primary
        error = (
            str(caught) if isinstance(caught, fresh.Rejected) else type(caught).__name__
        )
    finally:
        try:
            proof = job.finish(child, cancel=child is None or child.poll() is None)
            fresh.require_tree_proof(proof)
        finally:
            job.close()
    child_result, receipt_hash = None, None
    if not error and child is not None and child.returncode == 0:
        try:
            child_result = json.loads(stdout.read_text().strip())
            receipt = fresh.safe(Path(child_result["receipt"]))
            if (
                receipt.name != "receipt.json"
                or receipt.parent.parent != ROOT
                or not re.fullmatch(r"run-[0-9a-f]{32}", receipt.parent.name)
            ):
                raise fresh.Rejected("CURRENT_CHILD_RECEIPT_PATH_REJECTED")
            value = json.loads(receipt.read_text())
            if (
                value.get("result") != "PASS_CURRENT_CONTROLLED_CLONE"
                or value.get("cleanup_verified") is not True
                or value.get("proofs", {}).get("reviewed_deploy_revision")
                != args.expected_revision
            ):
                raise fresh.Rejected("CURRENT_CLONE_NOT_ACCEPTED")
            receipt_hash = fresh.sha(receipt)
        except (ValueError, OSError, KeyError, TypeError, fresh.Rejected) as caught:
            error = (
                str(caught)
                if isinstance(caught, fresh.Rejected)
                else type(caught).__name__
            )
    else:
        error = error or "CURRENT_CLONE_CHILD_FAILED"
    value = {
        "kind": "controlled-runtime-hidden-supervisor-v1",
        "result": "PASS" if not error else "FAILED_CLOSED",
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "cli_tree": proof,
        "child_result": child_result,
        "child_receipt_sha256": receipt_hash,
        "error_category": error,
        "primary_mutations": 0,
        "primary_consumers_started": 0,
    }
    fresh.save(directory / "receipt.json", value)
    print(
        json.dumps(
            {"result": value["result"], "receipt": str(directory / "receipt.json")}
        )
    )
    return 0 if not error else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-clone", action="store_true")
    parser.add_argument("--confirmation")
    parser.add_argument("--expected-revision")
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--supervise", action="store_true")
    parser.add_argument("--supervisor-directory", type=Path)
    args = parser.parse_args(argv)
    if not args.execute_clone:
        print(
            json.dumps(
                {
                    "kind": KIND,
                    "mode": "PLAN_ONLY",
                    "native_operations": 0,
                    "primary_mutations": 0,
                    "trading_authority": "NONE",
                }
            )
        )
        return 0
    if (
        args.confirmation != CONFIRM_CLONE
        or not args.expected_revision
        or not args.wheelhouse
    ):
        raise fresh.Rejected("EXPLICIT_CURRENT_CLONE_ADMISSION_REQUIRED")
    if args.supervise:
        if args.supervisor_directory is None:
            raise fresh.Rejected("PRIVATE_CURRENT_SUPERVISOR_REQUIRED")
        return supervise(args)
    controller = Controller(args.wheelhouse, args.expected_revision)
    error = None
    try:
        controller.run()
    except BaseException as caught:  # noqa: BLE001 -- interrupt/error never authorizes a retry
        error = caught
    return controller.finish(error is None, error)


if __name__ == "__main__":
    sys.exit(main())
