"""Current-source non-trading epoch through the existing native controller.

This does not enable Execution LIVE. It imports only the accepted historical
closed-bar seed into a NEW current-schema database, never the old DB/queue.
All source, image and wheel identities are explicit admission inputs. Existing
historical controller defaults and receipts are not reinterpreted.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import subprocess
import time
import uuid
import zipfile
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_controller as epoch
    from scripts import runtime_epoch_successor as previous
    from scripts.prepare_controlled_runtime_wheels import wheel_package_files
else:
    import runtime_epoch_controller as epoch
    import runtime_epoch_successor as previous
    from prepare_controlled_runtime_wheels import wheel_package_files

ROOT = Path("D:/Kairos/runtime/current-runtime-20261024")
META = Path("D:/Kairos/kairos")
PRIOR_OWNER = "1ec512799b23422190a1f3360ba60996"
PRIOR_IDS = (
    "f915bd6e428320310aaad2357791ca3cc4c1d47da6f73928a796f0b9d1cf8791",
    "3d4b9dac03894c1d5cf37bd5b47076f3dcc6b0fd7591edea2e0e97410901dd41",
    "31d4a1d49461c9bb2924f6e88fd41aacd4d9b3feeb2569d80e17882eb844c874",
)
PROFILE_KEYS = {
    "schema",
    "deploy_revision",
    "runner_recipe_revision",
    "core_revision",
    "persistence_revision",
    "quant_revision",
    "runner_receipt",
    "runner_receipt_sha256",
    "wheelhouse",
    "wheel_manifest_sha256",
    "subnet",
}


class CurrentEpochRejected(RuntimeError):
    """Sanitized current-profile admission failure."""


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise CurrentEpochRejected("DUPLICATE_PROFILE_FIELD")
        value[key] = item
    return value


def read_public_json(path: Path, maximum: int = 262144) -> dict:
    path = epoch.fresh.safe(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise CurrentEpochRejected("BOUNDED_REGULAR_PROFILE_REQUIRED")
    raw = path.read_bytes()
    if len(raw) > maximum:
        raise CurrentEpochRejected("PROFILE_BOUND_EXCEEDED")
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise CurrentEpochRejected("PROFILE_OBJECT_REQUIRED")
    return value


def migration_hashes(revision: str) -> dict[str, str]:
    """Hash Git archive bytes, not platform-converted checkout line endings."""
    prefix = "kairos_persistence/migrations/"
    result = subprocess.run(
        [
            str(epoch.GIT),
            "-C",
            "D:/Kairos/kairos-persistence",
            "archive",
            "--format=zip",
            revision,
            prefix,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
        raise CurrentEpochRejected("SIGNED_MIGRATION_ARCHIVE_REQUIRED")
    values = {}
    with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            if not item.filename.startswith(prefix) or not item.filename.endswith(
                ".sql"
            ):
                raise CurrentEpochRejected("MIGRATION_ARCHIVE_MEMBER_REJECTED")
            name = item.filename.removeprefix(prefix)
            if "/" in name or name in values or item.file_size > 1024 * 1024:
                raise CurrentEpochRejected("MIGRATION_ARCHIVE_MEMBER_REJECTED")
            values[name] = hashlib.sha256(archive.read(item)).hexdigest()
    return values


def validate_profile(
    value: dict, runner: dict, release: dict
) -> epoch.CurrentEpochBuildProfile:
    if (
        set(value) != PROFILE_KEYS
        or value.get("schema") != "kairos.current-nontrading-profile.v1"
    ):
        raise CurrentEpochRejected("EXACT_CURRENT_PROFILE_REQUIRED")
    for key in (
        "deploy_revision",
        "runner_recipe_revision",
        "core_revision",
        "persistence_revision",
        "quant_revision",
    ):
        if not isinstance(value[key], str) or not re.fullmatch(
            r"[0-9a-f]{40}", value[key]
        ):
            raise CurrentEpochRejected("EXACT_SOURCE_REVISION_REQUIRED")
    for key in ("runner_receipt_sha256", "wheel_manifest_sha256"):
        if not isinstance(value[key], str) or not re.fullmatch(
            r"[0-9a-f]{64}", value[key]
        ):
            raise CurrentEpochRejected("EXACT_ARTIFACT_DIGEST_REQUIRED")
    expected = {
        "kairos-deploy": value["deploy_revision"],
        "kairos-core": value["core_revision"],
        "kairos-persistence": value["persistence_revision"],
        "kairos-quant-scouts": value["quant_revision"],
    }
    released = {item["name"]: item["revision"] for item in release["repositories"]}
    if any(released.get(name) != revision for name, revision in expected.items()):
        raise CurrentEpochRejected("BUILD_PROFILE_DIFFERS_FROM_CURRENT_RELEASE")
    if (
        runner.get("schema_version") != 1
        or runner.get("source")
        != {
            "repository": "https://github.com/Kairos-cryptoAI/kairos-persistence",
            "revision": value["persistence_revision"],
        }
        or runner.get("recipe")
        != {
            "repository": "https://github.com/Kairos-cryptoAI/kairos-deploy",
            "revision": value["runner_recipe_revision"],
        }
        or runner.get("workflow", {}).get("repository")
        != "Kairos-cryptoAI/kairos-deploy"
        or runner.get("workflow", {}).get("commit") != value["runner_recipe_revision"]
        or runner.get("runtime")
        != {"python": "3.11.15", "aiohttp": "3.14.5", "multidict": "6.9.1"}
    ):
        raise CurrentEpochRejected("CURRENT_RUNNER_SOURCE_RECEIPT_MISMATCH")
    migrations = migration_hashes(value["persistence_revision"])
    if (
        runner.get("migrations") != migrations
        or "028_news_processing.sql" not in migrations
    ):
        raise CurrentEpochRejected("CURRENT_RUNNER_MIGRATION_PAYLOAD_MISMATCH")
    subnet = ipaddress.ip_network(value["subnet"], strict=True)
    if (
        not isinstance(subnet, ipaddress.IPv4Network)
        or not subnet.is_private
        or subnet.prefixlen != 28
    ):
        raise CurrentEpochRejected("EXPLICIT_PRIVATE_28_SUBNET_REQUIRED")
    return epoch.CurrentEpochBuildProfile(
        worker_image=runner.get("local_image_id", ""),
        wheel_manifest_sha256=value["wheel_manifest_sha256"],
        core_revision=value["core_revision"],
        persistence_revision=value["persistence_revision"],
        quant_revision=value["quant_revision"],
    )


def verify_clean_signed_sources(value: dict) -> None:
    for name, key in (
        ("kairos-deploy", "deploy_revision"),
        ("kairos-core", "core_revision"),
        ("kairos-persistence", "persistence_revision"),
        ("kairos-quant-scouts", "quant_revision"),
    ):
        repo = Path("D:/Kairos") / name
        if (
            previous._run_git(repo, "status", "--porcelain")
            or previous._run_git(repo, "branch", "--show-current") != "main"
            or previous._run_git(repo, "rev-parse", "HEAD") != value[key]
            or previous._run_git(repo, "rev-parse", "origin/main") != value[key]
            or previous._run_git(repo, "remote", "get-url", "origin")
            != f"https://github.com/Kairos-cryptoAI/{name}.git"
        ):
            raise CurrentEpochRejected("CLEAN_EXACT_CURRENT_SOURCE_REQUIRED")
        previous._verify_signed_commit(repo, value[key])
    verify_runner_recipe(value)
    result = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(META / "scripts/Test-CurrentRelease.ps1"),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=180,
        check=False,
    )
    if result.returncode:
        raise CurrentEpochRejected("CURRENT_RELEASE_GATE_FAILED")


RECIPE_INPUT_MODES = {
    ".dockerignore": "100644",
    "docker/Dockerfile": "100644",
    "docker/entrypoint.sh": "100644",
}
MAX_RECIPE_INPUT_BYTES = 1024 * 1024


def _git_recipe_input(repo: Path, revision: str, path: str) -> bytes:
    try:
        tree = subprocess.run(
            [str(epoch.GIT), "-C", str(repo), "ls-tree", "-z", revision, "--", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise CurrentEpochRejected(
            "EXACT_SIGNED_RUNNER_RECIPE_INPUT_REQUIRED"
        ) from None
    records = tree.stdout.split(b"\0") if tree.returncode == 0 else []
    records = [record for record in records if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise CurrentEpochRejected("EXACT_SIGNED_RUNNER_RECIPE_INPUT_REQUIRED")
    metadata, entry_path = records[0].split(b"\t", 1)
    try:
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        decoded_path = entry_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        raise CurrentEpochRejected(
            "EXACT_SIGNED_RUNNER_RECIPE_INPUT_REQUIRED"
        ) from None
    if (
        mode != RECIPE_INPUT_MODES[path]
        or object_type != "blob"
        or decoded_path != path
        or re.fullmatch(r"[0-9a-f]{40}", object_id) is None
    ):
        raise CurrentEpochRejected("EXACT_SIGNED_RUNNER_RECIPE_INPUT_REQUIRED")
    try:
        blob = subprocess.run(
            [str(epoch.GIT), "-C", str(repo), "cat-file", "blob", object_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise CurrentEpochRejected(
            "BOUNDED_SIGNED_RUNNER_RECIPE_INPUT_REQUIRED"
        ) from None
    if blob.returncode or len(blob.stdout) > MAX_RECIPE_INPUT_BYTES:
        raise CurrentEpochRejected("BOUNDED_SIGNED_RUNNER_RECIPE_INPUT_REQUIRED")
    return blob.stdout


def verify_runner_recipe_inputs(
    repo: Path, recipe_revision: str, deploy_revision: str
) -> None:
    if any(
        not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None
        for revision in (recipe_revision, deploy_revision)
    ):
        raise CurrentEpochRejected("EXACT_RUNNER_RECIPE_REVISION_REQUIRED")
    for path in RECIPE_INPUT_MODES:
        if _git_recipe_input(repo, recipe_revision, path) != _git_recipe_input(
            repo, deploy_revision, path
        ):
            raise CurrentEpochRejected(
                "RUNNER_RECIPE_INPUT_DIFFERS_FROM_CURRENT_DEPLOY"
            )


def verify_runner_recipe_ancestor(
    repo: Path, recipe_revision: str, deploy_revision: str
) -> None:
    if any(
        not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None
        for revision in (recipe_revision, deploy_revision)
    ):
        raise CurrentEpochRejected("EXACT_RUNNER_RECIPE_REVISION_REQUIRED")
    try:
        result = subprocess.run(
            [
                str(epoch.GIT),
                "-C",
                str(repo),
                "merge-base",
                "--is-ancestor",
                recipe_revision,
                deploy_revision,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise CurrentEpochRejected("SIGNED_RUNNER_RECIPE_ANCESTRY_REQUIRED") from None
    if result.returncode != 0:
        raise CurrentEpochRejected(
            "SIGNED_RUNNER_RECIPE_NOT_ANCESTOR_OF_CURRENT_DEPLOY"
        )


def verify_runner_recipe(value: dict) -> None:
    repo = Path("D:/Kairos/kairos-deploy")
    recipe_revision = value["runner_recipe_revision"]
    try:
        previous._verify_signed_commit(repo, recipe_revision)
    except previous.SuccessorRejected:
        raise CurrentEpochRejected("TRUSTED_RUNNER_RECIPE_SIGNATURE_REQUIRED") from None
    verify_runner_recipe_ancestor(repo, recipe_revision, value["deploy_revision"])
    verify_runner_recipe_inputs(repo, recipe_revision, value["deploy_revision"])


class CurrentEpochController(previous.RetainOwnedClonesController):
    def __init__(self, *args, subnet: ipaddress.IPv4Network, **kwargs):
        super().__init__(*args, **kwargs)
        if self.build_profile is None:
            raise CurrentEpochRejected("CURRENT_BUILD_PROFILE_REQUIRED")
        self.subnet = subnet

    def create_network(self) -> None:
        previous.validate_subnet_available(
            self.subnet, previous._docker_ipv4_subnets(), previous._host_ipv4_routes()
        )
        self.docker(
            [
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet=" + str(self.subnet),
                "--label",
                epoch.EPOCH_LABEL + "=" + self.owner,
                "--label",
                "com.kairos.runtime-epoch.scope=" + epoch.EPOCH_SCOPE,
                self.names["network"],
            ]
        )
        self.created.append(self.names["network"])
        view = json.loads(
            self.docker(
                ["network", "inspect", "--format", "{{json .}}", self.names["network"]]
            )
        )
        if (
            view.get("Name") != self.names["network"]
            or view.get("Driver") != "bridge"
            or view.get("Internal") is not False
            or view.get("Containers")
            or view.get("Labels", {}).get(epoch.EPOCH_LABEL) != self.owner
            or view.get("IPAM", {}).get("Config")
            != [
                {
                    "Subnet": str(self.subnet),
                    "Gateway": str(self.subnet.network_address + 1),
                }
            ]
        ):
            raise CurrentEpochRejected("CURRENT_NETWORK_IDENTITY_MISMATCH")

    def prepare_snapshots(self) -> None:
        super().prepare_snapshots()
        assert self.build_profile is not None
        for name, revision in self.build_profile.wheel_revisions.items():
            directory = self.work / ("source-" + name)
            expected = epoch.extract_git_snapshot(
                Path("D:/Kairos") / name, revision, (name.replace("-", "_"),), directory
            )
            manifest = read_public_json(self.runtime_wheelhouse / "manifest.json")
            package = next(
                item for item in manifest["packages"] if item["name"] == name
            )
            if (
                package["files"] != expected
                or wheel_package_files(self.runtime_wheelhouse / package["wheel"], name)
                != expected
            ):
                raise CurrentEpochRejected(
                    "WHEEL_PAYLOAD_DIFFERS_FROM_SIGNED_CURRENT_SOURCE"
                )

    def preserved_successor(self) -> dict:
        views = {}
        for identifier in PRIOR_IDS:
            view = self.inspect_container(identifier)
            if (
                view.get("id") != identifier
                or view.get("labels", {}).get(epoch.EPOCH_LABEL) != PRIOR_OWNER
                or view.get("state", {}).get("Status") != "exited"
            ):
                raise CurrentEpochRejected(
                    "PRIOR_SUCCESSOR_MUST_REMAIN_STOPPED_UNCHANGED"
                )
            views[identifier] = view
        return views


def execute(profile_path: Path) -> dict:
    if os.name != "nt":
        raise CurrentEpochRejected("WINDOWS_HOST_REQUIRED")
    value = read_public_json(profile_path)
    if set(value) != PROFILE_KEYS:
        raise CurrentEpochRejected("EXACT_CURRENT_PROFILE_REQUIRED")
    runner_path = epoch.fresh.safe(Path(value["runner_receipt"]))
    runner = read_public_json(runner_path)
    if epoch._sha(runner_path) != value["runner_receipt_sha256"]:
        raise CurrentEpochRejected("RUNNER_RECEIPT_BYTES_CHANGED")
    profile = validate_profile(
        value, runner, read_public_json(META / "config/current-release.json")
    )
    verify_clean_signed_sources(value)
    previous.assert_no_legacy_runtime_processes()
    previous.assert_no_active_epochs()
    previous.validate_source_pins()  # accepted historical seed/verification inputs remain immutable
    subnet = ipaddress.ip_network(value["subnet"], strict=True)
    previous.validate_subnet_available(
        subnet, previous._docker_ipv4_subnets(), previous._host_ipv4_routes()
    )
    owner = uuid.uuid4().hex
    root = epoch.fresh.safe(ROOT)
    root.mkdir(exist_ok=True)
    work = root / ("run-" + owner)
    epoch._private_directory(work)
    controller = CurrentEpochController(
        owner,
        expected_revision=value["deploy_revision"],
        wheelhouse=Path(value["wheelhouse"]),
        deadline=time.monotonic() + epoch.MAX_SECONDS,
        workdir=work,
        build_profile=profile,
        subnet=subnet,
    )
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
    epoch.fresh.save(work / "current-profile.json", value)
    try:
        before = controller.preserved_successor()
        old_before = previous.capture_preserved_old_containers()
        lease_before = previous.snapshot_historical_lease(epoch.ACTIVE_LEASE)
        image = json.loads(
            controller.docker(
                [
                    "image",
                    "inspect",
                    "--format",
                    '{"id":{{json .Id}},"labels":{{json .Config.Labels}},"user":{{json .Config.User}}}',
                    profile.worker_image,
                ]
            )
        )
        if (
            image.get("id") != profile.worker_image
            or image.get("user") != "10001:10001"
            or image.get("labels", {}).get("org.opencontainers.image.revision")
            != profile.persistence_revision
            or image.get("labels", {}).get("org.opencontainers.image.source")
            != "https://github.com/Kairos-cryptoAI/kairos-persistence"
        ):
            raise CurrentEpochRejected("ADMITTED_CURRENT_IMAGE_IDENTITY_MISMATCH")
        controller.prepare_snapshots()
        target_ms = (
            (int(time.time() * 1000) - 5000) // epoch.MINUTE_MS * epoch.MINUTE_MS
        )
        result = controller.run_epoch(
            end_exclusive_ms=target_ms, secrets_map=secrets_map
        )
        if controller.preserved_successor() != before:
            raise CurrentEpochRejected("PRIOR_SUCCESSOR_METADATA_CHANGED")
        previous.verify_old_container_preservation(old_before)
        previous.validate_historical_lease_unchanged(epoch.ACTIVE_LEASE, lease_before)
        status = read_public_json(work / "output-serve/status.json")
        epoch.validate_running_status(status, owner)
        if (
            status.get("schema_profile") != profile.schema_profile
            or status.get("schema_migration_count") != 19
            or status.get("schema_public_table_count") != 33
        ):
            raise CurrentEpochRejected("CURRENT_PROFILE_SERVE_PROOF_REQUIRED")
        result.update(
            {
                "schema_profile": profile.schema_profile,
                "schema_migration_count": 19,
                "schema_public_table_count": 33,
                "source_profile": value,
                "runner_receipt_sha256": value["runner_receipt_sha256"],
                "prior_successor_preserved": True,
                "production_trading_qualified": False,
                "root_cause_fixed": False,
                "trading_started": False,
                "orders_submitted": 0,
                "paid_calls": 0,
            }
        )
        receipt = work / "current-runtime-receipt.json"
        epoch.fresh.save(receipt, result)
        return {
            "result": result["result"],
            "owner": owner,
            "receipt": str(receipt),
            "schema_profile": profile.schema_profile,
            "trading_started": False,
        }
    except BaseException as exc:  # noqa: BLE001 - persist failure evidence on interruption too
        receipt = epoch._persist_failure_receipt(
            work, owner, controller, exc, private_ready=True
        )
        return {
            "result": "FAILED_CLOSED",
            "owner": owner,
            "receipt": str(receipt),
            "error_type": type(exc).__name__,
            "trading_started": False,
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(
            json.dumps(
                {
                    "state": "PLAN_ONLY",
                    "profile": str(args.profile),
                    "trading_started": False,
                }
            )
        )
        return 0
    with previous.WindowsMutex(r"Global\KairosCurrentNonTradingEpoch20261024"):
        result = execute(args.profile)
    print(json.dumps(result))
    return 0 if result["result"] == "PASS_NONTRADING_RUNTIME_EPOCH" else 1


if __name__ == "__main__":
    raise SystemExit(main())
