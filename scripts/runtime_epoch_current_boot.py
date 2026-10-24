"""Signed-receipt-gated boot for one current controlled-runtime epoch.

Plan-only is the default. Execution is owner-bound, create-only latched, and
never adopts the historical successor or the legacy continuation owner.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_controller as epoch
    from scripts import runtime_epoch_current as current
else:
    import runtime_epoch_controller as epoch
    import runtime_epoch_current as current

SCHEMA_PROFILE = "current-controlled-v1"
MIGRATION_COUNT = 19
PUBLIC_TABLE_COUNT = 33
TRUSTED_SIGNER_FINGERPRINT = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
TRUSTED_SIGNER_SHA256 = "3d130656e0fdff59c5efd44cb0779ea89af49b5684a3435863d24d403ccf9358"
TRUSTED_SIGNER = Path(__file__).resolve().parents[1] / (
    "tests/offline_outbox_reconciliation/trusted-signer.asc"
)
GPG = Path("C:/Program Files/Git/usr/bin/gpg.exe")
GPGV = Path("C:/Program Files/Git/usr/bin/gpgv.exe")
SOURCE_LOCK = TRUSTED_SIGNER.with_name("source-lock.json")
RECEIPT_LIMIT = 512 * 1024
STATUS_WAIT_SECONDS = 360
LATCH_LIMIT = 32
HOST_ACCEPTANCE_REPORT = Path(
    "D:/Kairos/runtime/prod-runtime-inputs-20261024/host-acceptance-first/acceptance.report.json"
)
PRIVATE_KEYS = {
    "owner",
    "database",
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
}


class CurrentBootRejected(RuntimeError):
    """Sanitized fail-closed boot-admission or restart refusal."""


def read_bounded_json(path: Path, maximum: int = RECEIPT_LIMIT) -> dict:
    path = epoch.fresh.safe(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise CurrentBootRejected("BOUNDED_REGULAR_JSON_REQUIRED")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=current.unique_object)
    except (OSError, UnicodeError, TypeError, json.JSONDecodeError, current.CurrentEpochRejected):
        raise CurrentBootRejected("BOUNDED_JSON_PARSE_REQUIRED") from None
    if not isinstance(value, dict):
        raise CurrentBootRejected("JSON_OBJECT_REQUIRED")
    return value


def verify_receipt_signature(
    receipt: Path, signature: Path, expected_sha256: str
) -> None:
    signature = epoch.fresh.safe(signature)
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
        or epoch._sha(receipt) != expected_sha256
        or signature.is_symlink()
        or not signature.is_file()
        or not TRUSTED_SIGNER.is_file()
        or epoch._sha(TRUSTED_SIGNER) != TRUSTED_SIGNER_SHA256
    ):
        raise CurrentBootRejected("EXACT_SIGNED_CURRENT_RECEIPT_REQUIRED")
    lock = read_bounded_json(SOURCE_LOCK)
    signer = lock.get("trusted_receipt_signer")
    if signer != {
        "fingerprint": TRUSTED_SIGNER_FINGERPRINT,
        "public_key_file": "tests/offline_outbox_reconciliation/trusted-signer.asc",
        "public_key_sha256": TRUSTED_SIGNER_SHA256,
    }:
        raise CurrentBootRejected("TRUSTED_RECEIPT_SIGNER_PIN_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="kairos-current-boot-gpg-") as directory:
        keyring = Path(directory) / "trusted.gpg"
        env = epoch.fresh.supervisor_environment()
        env["GNUPGHOME"] = directory
        imported = subprocess.run(
            [
                str(GPG),
                "--batch",
                "--no-options",
                "--no-auto-key-retrieve",
                "--no-default-keyring",
                "--keyring",
                str(keyring),
                "--import",
                str(TRUSTED_SIGNER),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=20,
            check=False,
            shell=False,
        )
        verified = subprocess.run(
            [
                str(GPGV),
                "--status-fd",
                "1",
                "--keyring",
                str(keyring),
                str(signature),
                str(receipt),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            timeout=20,
            check=False,
            shell=False,
        )
    status = verified.stdout.decode("utf-8", "replace").splitlines()
    valid = any(
        line.startswith("[GNUPG:] VALIDSIG ")
        and len(line.split()) > 2
        and line.split()[2] == TRUSTED_SIGNER_FINGERPRINT
        for line in status
    )
    if imported.returncode or verified.returncode or not valid:
        raise CurrentBootRejected("CURRENT_RECEIPT_SIGNATURE_NOT_TRUSTED")


def require_host_acceptance(report_path: Path, owner: str, receipt_sha256: str, deploy_revision: str) -> None:
    """Scheduled boot stays inert until signed whole-host acceptance completes."""
    if (
        report_path != HOST_ACCEPTANCE_REPORT
        or (report_path.parent / "acceptance.failure.json").exists()
        or (report_path.parent / "acceptance.failure.json").is_symlink()
        or not report_path.is_file()
        or report_path.is_symlink()
    ):
        raise CurrentBootRejected("SIGNED_HOST_ACCEPTANCE_REQUIRED_BEFORE_SCHEDULED_BOOT")
    report = read_bounded_json(report_path)
    verify_receipt_signature(report_path, report_path.with_name(report_path.name + ".asc"), epoch._sha(report_path))
    if (
        report.get("schema") != "kairos.current-runtime-host-acceptance.v1"
        or report.get("state") != "PASS_CURRENT_NONTRADING_HOST_ACCEPTANCE"
        or report.get("owner") != owner
        or report.get("receipt_sha256") != receipt_sha256
        or report.get("deploy_revision") != deploy_revision
        or report.get("old_resources_preserved") is not True
        or report.get("production_trading_qualified") is not False
        or report.get("trading_started") is not False
        or report.get("orders_submitted") != 0
        or report.get("paid_calls") != 0
    ):
        raise CurrentBootRejected("EXACT_SIGNED_NONTRADING_HOST_ACCEPTANCE_REQUIRED")


def validate_current_receipt(
    receipt: dict, receipt_path: Path, expected_sha256: str
) -> tuple[str, dict, dict, Path]:
    source_profile = receipt.get("source_profile")
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
        or epoch._sha(receipt_path) != expected_sha256
        or receipt.get("result") != "PASS_NONTRADING_RUNTIME_EPOCH"
        or receipt.get("schema_profile") != SCHEMA_PROFILE
        or receipt.get("schema_migration_count") != MIGRATION_COUNT
        or receipt.get("schema_public_table_count") != PUBLIC_TABLE_COUNT
        or receipt.get("trading_started") is not False
        or receipt.get("orders_submitted") != 0
        or receipt.get("paid_calls") != 0
        or receipt.get("production_trading_qualified") is not False
        or receipt.get("root_cause_fixed") is not False
        or receipt.get("prior_successor_preserved") is not True
    ):
        raise CurrentBootRejected("SUCCESSFUL_CURRENT_NONTRADING_RECEIPT_REQUIRED")
    owner = receipt.get("owner")
    if not isinstance(owner, str) or not re.fullmatch(r"[0-9a-f]{32}", owner):
        raise CurrentBootRejected("EXACT_CURRENT_OWNER_REQUIRED")
    work = epoch.fresh.safe(receipt_path.parent)
    if (
        receipt_path.name != "current-runtime-receipt.json"
        or work.parent != current.ROOT
        or work.name != "run-" + owner
        or receipt.get("database") != "kairos_epoch_" + owner[:12]
        or receipt.get("resources") != epoch.resource_names(owner)
        or receipt.get("serve_container") != epoch.resource_names(owner)["serve"]
        or not isinstance(source_profile, dict)
        or receipt.get("runner_receipt_sha256")
        != source_profile.get("runner_receipt_sha256")
    ):
        raise CurrentBootRejected("CURRENT_OWNER_RESOURCE_RECEIPT_MISMATCH")
    profile_path = work / "current-profile.json"
    profile = read_bounded_json(profile_path)
    if profile != receipt.get("source_profile"):
        raise CurrentBootRejected("SIGNED_CURRENT_PROFILE_CHANGED")
    if profile.get("schema") != "kairos.current-nontrading-profile.v1":
        raise CurrentBootRejected("CURRENT_PROFILE_SCHEMA_REQUIRED")
    runner_path = epoch.fresh.safe(Path(profile.get("runner_receipt", "")))
    runner = current.read_public_json(runner_path)
    if epoch._sha(runner_path) != profile.get("runner_receipt_sha256"):
        raise CurrentBootRejected("CURRENT_RUNNER_RECEIPT_CHANGED")
    release = current.read_public_json(current.META / "config/current-release.json")
    build = current.validate_profile(profile, runner, release)
    docker_config = work / "docker-config" / "config.json"
    if docker_config.is_symlink() or not docker_config.is_file():
        raise CurrentBootRejected("EXISTING_AUTH_FREE_OWNER_DOCKER_CONFIG_REQUIRED")
    try:
        if json.loads(docker_config.read_bytes()) != epoch.fresh.auth_free_docker_config():
            raise CurrentBootRejected("EXISTING_AUTH_FREE_OWNER_DOCKER_CONFIG_REQUIRED")
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise CurrentBootRejected("EXISTING_AUTH_FREE_OWNER_DOCKER_CONFIG_REQUIRED") from None
    proofs = receipt.get("proofs")
    if not isinstance(proofs, dict) or not {
        "operator_snapshot_sha256",
        "quant_snapshot_sha256",
        "serve_restart_status",
        "audit_backup_sha256",
    }.issubset(proofs):
        raise CurrentBootRejected("CURRENT_SOURCE_FINGERPRINT_RECEIPTS_REQUIRED")
    baseline = proofs["serve_restart_status"]
    validate_signed_status_baseline(baseline, owner)
    return owner, profile, {"runner": runner, "build": build, "proofs": proofs}, work


def classify_topology(
    states: dict[str, str], active_epoch_names: set[str], expected_names: set[str]
) -> str:
    if set(states) != expected_names or active_epoch_names - expected_names:
        raise CurrentBootRejected("PARTIAL_OR_UNKNOWN_EPOCH_TOPOLOGY")
    values = set(states.values())
    if values == {"running"}:
        if active_epoch_names != expected_names:
            raise CurrentBootRejected("RUNNING_EPOCH_INVENTORY_MISMATCH")
        return "ALREADY_RUNNING"
    if values == {"exited"}:
        if active_epoch_names:
            raise CurrentBootRejected("UNEXPECTED_ACTIVE_EPOCH_PROCESS")
        return "READY_TO_START"
    raise CurrentBootRejected("PARTIAL_OR_UNKNOWN_EPOCH_TOPOLOGY")


def validate_status_profile(status: dict, owner: str, *, previous: dict | None = None) -> dict:
    validated = epoch.validate_running_status(status, owner, previous=previous)
    if (
        status.get("schema_profile") != SCHEMA_PROFILE
        or status.get("schema_migration_count") != MIGRATION_COUNT
        or status.get("schema_public_table_count") != PUBLIC_TABLE_COUNT
        or status.get("trading_started") is not False
    ):
        raise CurrentBootRejected("CURRENT_PROFILE_RUNNING_STATUS_REQUIRED")
    return validated


def validate_signed_status_baseline(status: dict, owner: str) -> dict:
    if (
        not isinstance(status, dict)
        or status.get("state") != "RUNNING_NONTRADING"
        or status.get("owner") != owner
        or status.get("schema_profile") != SCHEMA_PROFILE
        or status.get("schema_migration_count") != MIGRATION_COUNT
        or status.get("schema_public_table_count") != PUBLIC_TABLE_COUNT
        or status.get("trading_started") is not False
        or status.get("PAPER_QUALIFIED") is not False
        or status.get("ALPHA_READY") is not False
        or status.get("LIVE_READY") is not False
        or status.get("STRATEGY_POLICY") != "REJECT_ALL"
        or any(
            status.get(key) != 0
            for key in ("pending_outbox", "unresolved_inbox", "uncompleted_publications")
        )
    ):
        raise CurrentBootRejected("SIGNED_CURRENT_SERVE_BASELINE_REQUIRED")
    watermarks = status.get("watermarks_ms")
    if (
        not isinstance(watermarks, dict)
        or set(watermarks) != set(epoch.SYMBOLS)
        or any(type(value) is not int or value <= 0 for value in watermarks.values())
    ):
        raise CurrentBootRejected("SIGNED_CURRENT_SERVE_BASELINE_REQUIRED")
    try:
        observed = datetime.fromisoformat(status["observed_at_utc"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, TypeError, ValueError):
        raise CurrentBootRejected("SIGNED_CURRENT_SERVE_BASELINE_REQUIRED") from None
    if observed.utcoffset() is None:
        raise CurrentBootRejected("SIGNED_CURRENT_SERVE_BASELINE_REQUIRED")
    return status


def source_manifest(directory: Path) -> dict[str, str]:
    directory = epoch.fresh.safe(directory)
    if not directory.is_dir() or directory.is_symlink():
        raise CurrentBootRejected("CURRENT_SOURCE_SNAPSHOT_REQUIRED")
    result = {}
    total = 0
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise CurrentBootRejected("CURRENT_SOURCE_SNAPSHOT_LINK_REJECTED")
        if path.is_file():
            total += path.stat().st_size
            if len(result) >= 2048 or total > 128 * 1024 * 1024:
                raise CurrentBootRejected("CURRENT_SOURCE_SNAPSHOT_BOUND_EXCEEDED")
            result[path.relative_to(directory).as_posix()] = epoch._sha(path)
    if not result:
        raise CurrentBootRejected("CURRENT_SOURCE_SNAPSHOT_EMPTY")
    return result


class CurrentEpochBootAdapter:
    def __init__(self, receipt_path: Path, expected_sha256: str, signature_path: Path):
        receipt_path = epoch.fresh.safe(receipt_path)
        verify_receipt_signature(receipt_path, signature_path, expected_sha256)
        receipt = read_bounded_json(receipt_path)
        owner, profile, details, self.owner_work = validate_current_receipt(
            receipt, receipt_path, expected_sha256
        )
        current.verify_clean_signed_sources(profile)
        runtime_work = self.owner_work / "runtime-wheelhouse"
        if epoch._sha(Path(profile["wheelhouse"]) / "manifest.json") != profile["wheel_manifest_sha256"]:
            raise CurrentBootRejected("SIGNED_CURRENT_ARTIFACT_FINGERPRINT_CHANGED")
        controller = current.CurrentEpochController(
            owner,
            expected_revision=profile["deploy_revision"],
            wheelhouse=Path(profile["wheelhouse"]),
            deadline=time.monotonic() + epoch.MAX_SECONDS,
            workdir=self.owner_work,
            build_profile=details["build"],
            subnet=ipaddress.ip_network(profile["subnet"], strict=True),
        )
        controller.runtime_wheelhouse = runtime_work
        controller.operator_snapshot = self.owner_work / "operator"
        controller.quant_snapshot = self.owner_work / "quant"
        controller._admin_password = ""  # Set only after private credential admission.
        self.controller = controller
        self.owner = owner
        self.profile = profile
        self.receipt = receipt
        self.receipt_sha256 = expected_sha256
        self.proofs = details["proofs"]
        self.status_path = self.owner_work / "output-serve" / "status.json"
        self.private_path = self.owner_work / "epoch-private.json"
        self.names = epoch.resource_names(owner)
        self.expected = self._validate_sources_and_resources()

    def _validate_sources_and_resources(self) -> dict:
        proofs = self.proofs
        operator = source_manifest(self.owner_work / "operator")
        quant = source_manifest(self.owner_work / "quant")
        if (
            epoch.fresh.digest(operator) != proofs["operator_snapshot_sha256"]
            or epoch.fresh.digest(quant) != proofs["quant_snapshot_sha256"]
        ):
            raise CurrentBootRejected("CURRENT_SOURCE_SNAPSHOT_FINGERPRINT_CHANGED")
        revisions = {
            "kairos-core": self.profile["core_revision"],
            "kairos-persistence": self.profile["persistence_revision"],
        }
        epoch.validate_wheelhouse(
            Path(self.profile["wheelhouse"]),
            self.profile["wheel_manifest_sha256"],
            expected_revisions=revisions,
        )
        epoch.validate_wheelhouse(
            self.controller.runtime_wheelhouse,
            self.profile["wheel_manifest_sha256"],
            exact_files=True,
            expected_revisions=revisions,
        )
        auxiliary_wheel = self.controller.aux_wheelhouse / epoch.AUX_NUMPY
        if (
            auxiliary_wheel.is_symlink()
            or not auxiliary_wheel.is_file()
            or auxiliary_wheel.stat().st_size != epoch.AUX_NUMPY_BYTES
            or epoch._sha(auxiliary_wheel) != epoch.AUX_NUMPY_SHA256
        ):
            raise CurrentBootRejected("PINNED_AUXILIARY_WHEEL_CHANGED")
        if self.private_path.is_symlink() or not self.private_path.is_file():
            raise CurrentBootRejected("OWNER_PRIVATE_CREDENTIAL_FILE_REQUIRED")
        private = json.loads(self.private_path.read_bytes())
        if (
            set(private) != PRIVATE_KEYS
            or private.get("owner") != self.owner
            or private.get("database") != "kairos_epoch_" + self.owner[:12]
            or any(
                not isinstance(private.get(key), str)
                or not re.fullmatch(r"[0-9a-f]{64}", private[key])
                for key in PRIVATE_KEYS - {"owner", "database"}
            )
        ):
            raise CurrentBootRejected("OWNER_PRIVATE_CREDENTIAL_IDENTITY_REQUIRED")
        self.private = private
        self.controller._admin_password = private["admin_password"]
        self._validate_images_and_resources()
        return {"owner": self.owner, "resources": self.names}

    def _validate_images_and_resources(self) -> None:
        c = self.controller
        owner = self.owner
        for image_ref in (epoch.PG_IMAGE, epoch.REDIS_IMAGE):
            image_id = c.docker(["image", "inspect", "--format", "{{json .Id}}", image_ref])
            try:
                parsed = json.loads(image_id)
            except json.JSONDecodeError:
                raise CurrentBootRejected("PINNED_RUNTIME_IMAGE_REQUIRED") from None
            if not isinstance(parsed, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", parsed):
                raise CurrentBootRejected("PINNED_RUNTIME_IMAGE_REQUIRED")
            if image_ref == epoch.PG_IMAGE:
                pg_image_id = parsed
            else:
                redis_image_id = parsed
        image_view = json.loads(
            c.docker(
                [
                    "image",
                    "inspect",
                    "--format",
                    '{"id":{{json .Id}},"labels":{{json .Config.Labels}},"user":{{json .Config.User}}}',
                    self.controller.worker_image,
                ]
            )
        )
        image_labels = image_view.get("labels") or {}
        if (
            image_view.get("id") != self.controller.worker_image
            or image_view.get("user") != "10001:10001"
            or image_labels.get("org.opencontainers.image.revision")
            != self.profile["persistence_revision"]
            or image_labels.get("org.opencontainers.image.source")
            != "https://github.com/Kairos-cryptoAI/kairos-persistence"
        ):
            raise CurrentBootRejected("SIGNED_CURRENT_WORKER_IMAGE_REQUIRED")
        expected_ids = {
            self.names["target_pg"]: pg_image_id,
            self.names["redis"]: redis_image_id,
            self.names["serve"]: self.controller.worker_image,
        }
        limits = {
            self.names["target_pg"]: (4 * 1024**3, 1_000_000_000),
            self.names["redis"]: (256 * 1024**2, 500_000_000),
            self.names["serve"]: (512 * 1024**2, 1_000_000_000),
        }
        states = {}
        container_ids = {}
        container_images = {}
        for name, image_id in expected_ids.items():
            view = c.inspect_container(name)
            labels = view.get("labels") or {}
            memory, cpus = limits[name]
            if (
                view.get("name") != "/" + name
                or not re.fullmatch(r"[0-9a-f]{64}", view.get("id", ""))
                or view.get("image") != image_id
                or labels.get(epoch.EPOCH_LABEL) != owner
                or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
                or view.get("ports") not in (None, {})
                or view.get("privileged") is not False
                or view.get("readonly") is not True
                or view.get("caps") != ["ALL"]
                or view.get("memory") != memory
                or view.get("swap") != memory
                or view.get("cpus") != cpus
                or view.get("network") != self.names["network"]
            ):
                raise CurrentBootRejected("CURRENT_OWNER_CONTAINER_IDENTITY_MISMATCH")
            states[name] = (view.get("state") or {}).get("Status")
            container_ids[name] = view["id"]
            container_images[name] = image_id
        for key in ("target_volume", "redis_volume"):
            volume = self.names[key]
            metadata = json.loads(
                c.docker(["volume", "inspect", "--format", "{{json .}}", volume])
            )
            labels = metadata.get("Labels") or {}
            if (
                metadata.get("Name") != volume
                or labels.get(epoch.EPOCH_LABEL) != owner
                or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
            ):
                raise CurrentBootRejected("CURRENT_OWNER_VOLUME_IDENTITY_MISMATCH")
        network = json.loads(
            c.docker(["network", "inspect", "--format", "{{json .}}", self.names["network"]])
        )
        labels = network.get("Labels") or {}
        if (
            network.get("Name") != self.names["network"]
            or network.get("Driver") != "bridge"
            or labels.get(epoch.EPOCH_LABEL) != owner
            or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
        ):
            raise CurrentBootRejected("CURRENT_OWNER_NETWORK_IDENTITY_MISMATCH")
        secret = self.owner_work / "target-admin-password"
        acl = self.owner_work / "redis-users.acl"
        c.require_mount_set(
            self.names["target_pg"],
            {
                self.names["target_volume"]: ("/var/lib/postgresql/data", True),
                str(secret): ("/run/secrets/epoch_admin_password", False),
            },
        )
        c.require_mount_set(
            self.names["redis"],
            {self.names["redis_volume"]: ("/data", True), str(acl): ("/run/config/users.acl", False)},
        )
        c.require_mount_set(
            self.names["serve"],
            {
                str(self.owner_work / "config-serve.json"): (epoch.CONFIG_PATH_IN_CONTAINER, False),
                str(self.owner_work / "output-serve"): ("/output", True),
                str(self.owner_work / "operator"): ("/operator", False),
                str(self.owner_work / "runtime-wheelhouse"): ("/wheelhouse", False),
                str(self.owner_work / "quant"): ("/quant", False),
                str(c.aux_wheelhouse): ("/aux-wheels", False),
            },
        )
        self.states = states
        self.container_ids = container_ids
        self.container_images = container_images

    def _verify_container_by_id(self, name: str, identifier: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{64}", identifier):
            raise CurrentBootRejected("RECORDED_CONTAINER_ID_REQUIRED")
        view = self.controller.inspect_container(identifier)
        labels = view.get("labels") or {}
        if (
            view.get("id") != identifier
            or view.get("name") != "/" + name
            or view.get("image") != self.container_images.get(name)
            or labels.get(epoch.EPOCH_LABEL) != self.owner
            or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
            or view.get("network") != self.names["network"]
            or view.get("ports") not in (None, {})
            or view.get("privileged") is not False
            or view.get("readonly") is not True
            or view.get("caps") != ["ALL"]
        ):
            raise CurrentBootRejected("RECORDED_CONTAINER_IDENTITY_CHANGED")
        return view

    def _active_epoch_names(self) -> set[str]:
        raw = self.controller.docker(["ps", "--format", "{{.Names}}"])
        names = set(raw.splitlines())
        return {name for name in names if name.startswith("kairos-epoch-")}

    def _check_latches(self, *, exclude_current_work: Path | None = None) -> None:
        boot_dirs = list(self.owner_work.glob("boot-*"))
        if len(boot_dirs) > LATCH_LIMIT:
            raise CurrentBootRejected("BOOT_LATCH_INVENTORY_BOUND_EXCEEDED")
        excluded = None
        if exclude_current_work is not None:
            excluded = epoch.fresh.safe(exclude_current_work)
            if (
                excluded.parent != self.owner_work
                or re.fullmatch(r"boot-[0-9a-f]{32}", excluded.name) is None
                or excluded.is_symlink()
                or not excluded.is_dir()
            ):
                raise CurrentBootRejected("EXACT_CURRENT_BOOT_WORKDIR_REQUIRED")
        for directory in boot_dirs:
            if (
                directory.is_symlink()
                or not directory.is_dir()
                or directory.parent != self.owner_work
                or re.fullmatch(r"boot-[0-9a-f]{32}", directory.name) is None
            ):
                raise CurrentBootRejected("UNKNOWN_PRIOR_BOOT_LATCH")
            path = directory / "boot-latch.json"
            if path.is_symlink() or not path.is_file():
                raise CurrentBootRejected("UNKNOWN_PRIOR_BOOT_LATCH")
            try:
                latch = read_bounded_json(path, 16_384)
            except CurrentBootRejected:
                raise CurrentBootRejected("UNKNOWN_OR_FAILED_PRIOR_BOOT_LATCH") from None
            if (
                latch.get("schema") != "kairos.current-epoch-boot-latch.v1"
                or latch.get("owner") != self.owner
                or latch.get("receipt_sha256") != self.receipt_sha256
            ):
                raise CurrentBootRejected("UNKNOWN_OR_FAILED_PRIOR_BOOT_LATCH")
            if excluded is not None and directory == excluded:
                if (
                    latch.get("state") != "IN_PROGRESS"
                    or latch.get("planned_starts")
                    != [self.names["target_pg"], self.names["redis"]]
                    or (directory / "boot-complete.json").exists()
                    or (directory / "boot-failure.json").exists()
                ):
                    raise CurrentBootRejected("EXACT_CURRENT_IN_PROGRESS_LATCH_REQUIRED")
                continue
            try:
                completed = read_bounded_json(directory / "boot-complete.json", 32_768)
            except CurrentBootRejected:
                raise CurrentBootRejected("UNKNOWN_OR_FAILED_PRIOR_BOOT_LATCH") from None
            if (
                (directory / "boot-failure.json").exists()
                or completed.get("schema") != "kairos.current-epoch-boot-result.v1"
                or latch.get("state") != "IN_PROGRESS"
                or completed.get("receipt_sha256") != self.receipt_sha256
                or completed.get("owner") != self.owner
                or completed.get("state") != "PASS_CURRENT_EPOCH_BOOT"
                or completed.get("boot_id") != directory.name.removeprefix("boot-")
                or completed.get("resources") != self.names
                or not isinstance(completed.get("retained_restore_containers"), list)
                or len(completed["retained_restore_containers"]) != 2
                or len(set(completed["retained_restore_containers"])) != 2
                or any(
                    re.fullmatch(
                        re.escape("kairos-epoch-" + self.owner[:12])
                        + r"-restore-current-[0-9a-f]{14}",
                        name if isinstance(name, str) else "",
                    )
                    is None
                    for name in completed["retained_restore_containers"]
                )
                or completed.get("trading_started") is not False
                or completed.get("orders_submitted") != 0
                or completed.get("paid_calls") != 0
            ):
                raise CurrentBootRejected("UNKNOWN_OR_FAILED_PRIOR_BOOT_LATCH")

    def plan(self) -> dict:
        self._check_latches()
        current.previous.assert_no_legacy_runtime_processes()
        active = self._active_epoch_names()
        state = classify_topology(
            self.states,
            active,
            {self.names["target_pg"], self.names["redis"], self.names["serve"]},
        )
        if state == "ALREADY_RUNNING":
            status = read_bounded_json(self.status_path, 32_768)
            validate_status_profile(status, self.owner)
            return {
                "state": "ALREADY_RUNNING",
                "owner": self.owner,
                "resources": self.expected["resources"],
                "starts": 0,
                "trading_started": False,
            }
        if self.status_path.is_file() and not self.status_path.is_symlink():
            status = read_bounded_json(self.status_path, 32_768)
            if status.get("state") == "FAILED_CLOSED":
                raise CurrentBootRejected("FAILED_CLOSED_OWNER_STATUS_REQUIRES_REVIEW")
            if (
                status.get("owner") != self.owner
                or status.get("schema_profile") != SCHEMA_PROFILE
                or status.get("schema_migration_count") != MIGRATION_COUNT
                or status.get("schema_public_table_count") != PUBLIC_TABLE_COUNT
                or status.get("trading_started") is not False
                or status.get("state")
                not in {
                    "RUNNING_NONTRADING",
                    "STOPPED_NONTRADING",
                    "CATCHING_UP_NONTRADING",
                    "WAITING_SOURCE_NONTRADING",
                }
            ):
                raise CurrentBootRejected("UNKNOWN_OR_MISMATCHED_OWNER_STATUS")
        self._require_unique_restore_host_support()
        return {
            "state": "READY_TO_START",
            "owner": self.owner,
            "resources": self.expected["resources"],
            "starts": 2,
            "trading_started": False,
        }

    def _require_unique_restore_host_support(self) -> None:
        """Refuse pre-start if worker host admission cannot isolate both restores."""
        owner = self.owner
        value = {
            "owner": owner,
            "database": "kairos_epoch_" + owner[:12],
            "pg_host": self.names["target_pg"],
            "redis_host": self.names["redis"],
            "admin_password": "a" * 64,
            "restore_host": "kairos-epoch-"
            + owner[:12]
            + "-restore-current-"
            + "a" * 12
            + "01",
            "restore_database": "kairos_recovery_" + owner[:12] + "_epochrestore",
            "restore_admin_password": "b" * 64,
            "expected_seed": {},
        }
        try:
            epoch.validate_worker_config(
                value,
                mode="boot-verify-restore",
                schema_profile=SCHEMA_PROFILE,
            )
        except TypeError:
            raise CurrentBootRejected(
                "CURRENT_PROFILE_WORKER_ADMISSION_API_REQUIRED"
            ) from None
        except epoch.Rejected:
            raise CurrentBootRejected(
                "CURRENT_WORKER_RESTORE_HOST_ALLOWLIST_BLOCKS_UNIQUE_RETAINED_CLONES"
            ) from None

    def execute(self) -> dict:
        plan = self.plan()
        if plan["state"] == "ALREADY_RUNNING":
            return plan
        boot_id = uuid.uuid4().hex
        work = self.owner_work / ("boot-" + boot_id)
        epoch._private_directory(work)
        latch_path = work / "boot-latch.json"
        epoch.fresh.save(
            latch_path,
            {
                "schema": "kairos.current-epoch-boot-latch.v1",
                "owner": self.owner,
                "receipt_sha256": self.receipt_sha256,
                "state": "IN_PROGRESS",
                "created_at_utc": datetime.now(UTC).isoformat(),
                "planned_starts": [self.names["target_pg"], self.names["redis"]],
            },
        )
        c = current.CurrentEpochController(
            self.owner,
            expected_revision=self.profile["deploy_revision"],
            wheelhouse=Path(self.profile["wheelhouse"]),
            deadline=time.monotonic() + epoch.MAX_SECONDS,
            workdir=work,
            build_profile=current.epoch.CurrentEpochBuildProfile(
                worker_image=self.controller.worker_image,
                wheel_manifest_sha256=self.profile["wheel_manifest_sha256"],
                core_revision=self.profile["core_revision"],
                persistence_revision=self.profile["persistence_revision"],
                quant_revision=self.profile["quant_revision"],
            ),
            subnet=ipaddress.ip_network(self.profile["subnet"], strict=True),
        )
        c.runtime_wheelhouse = self.controller.runtime_wheelhouse
        c.operator_snapshot = self.controller.operator_snapshot
        c.quant_snapshot = self.controller.quant_snapshot
        c._admin_password = self.private["admin_password"]
        started_ids: list[tuple[str, str]] = []
        retained_restores: list[str] = []
        try:
            # All admission is complete before the first state transition.
            for name in (self.names["target_pg"], self.names["redis"]):
                identifier = self.container_ids[name]
                before = self._verify_container_by_id(name, identifier)
                if (before.get("state") or {}).get("Status") != "exited":
                    raise CurrentBootRejected("EXACT_STOPPED_OWNER_CONTAINER_REQUIRED")
                started_ids.append((name, identifier))
                c.docker(["start", identifier])
                after = self._verify_container_by_id(name, identifier)
                if (after.get("state") or {}).get("Status") != "running":
                    raise CurrentBootRejected("OWNER_CONTAINER_START_NOT_VERIFIED")
            c.wait_postgres(self.names["target_pg"])
            common = {
                "owner": self.owner,
                "database": "kairos_epoch_" + self.owner[:12],
                "pg_host": self.names["target_pg"],
                "redis_host": self.names["redis"],
            }
            state = c.phase(
                "boot-state", {**common, "admin_password": self.private["admin_password"]}, suffix=boot_id
            )
            self._verify_profile_receipt(c.proofs["boot-state"])
            retained_restores.append(
                self._backup_restore(c, work, common, state, boot_id + "-01")
            )
            end = ((int(time.time() * 1000) - 5_000) // epoch.MINUTE_MS) * epoch.MINUTE_MS
            c.phase(
                "boot-catchup",
                {
                    **common,
                    "history_password": self.private["history_password"],
                    "end_exclusive_ms": end,
                    "maximum_bars": epoch.MAX_CATCHUP_BARS,
                    "expected_seed": state,
                },
                suffix=boot_id,
            )
            updated = c.phase(
                "boot-state", {**common, "admin_password": self.private["admin_password"]}, suffix=boot_id + "-post"
            )
            if (
                updated["original_prefix"] != state["original_prefix"]
                or updated["queue"] != state["queue"]
                or updated["tables"]["message_outbox"] != state["tables"]["message_outbox"]
                or updated["tables"]["message_inbox"] != state["tables"]["message_inbox"]
            ):
                raise CurrentBootRejected("BOOT_CATCHUP_CHANGED_QUEUE_OR_ORIGINAL_PREFIX")
            retained_restores.append(
                self._backup_restore(c, work, common, updated, boot_id + "-02")
            )
            redis_state = c.phase(
                "boot-redis-state",
                {
                    **common,
                    "producer_password": self.private["producer_password"],
                    "consumer_password": self.private["consumer_password"],
                    "redis_producer_password": self.private["redis_producer_password"],
                    "redis_consumer_password": self.private["redis_consumer_password"],
                },
                suffix=boot_id,
            )
            self._verify_profile_receipt(c.proofs["boot-redis-state"])
            if redis_state.get("state") != "PASS_BOOT_REDIS_STATE":
                raise CurrentBootRejected("EXACT_NONTRADING_REDIS_STATE_REQUIRED")
            self._validate_sources_and_resources()
            self._check_latches(exclude_current_work=work)
            current.previous.assert_no_legacy_runtime_processes()
            if self._active_epoch_names() != {
                self.names["target_pg"],
                self.names["redis"],
            }:
                raise CurrentBootRejected("UNEXPECTED_ACTIVE_EPOCH_BEFORE_SERVE")
            serve_id = self.container_ids[self.names["serve"]]
            serve_before = self._verify_container_by_id(self.names["serve"], serve_id)
            if (serve_before.get("state") or {}).get("Status") != "exited":
                raise CurrentBootRejected("EXACT_STOPPED_OWNER_SERVE_REQUIRED")
            started_ids.append((self.names["serve"], serve_id))
            c.docker(["start", serve_id])
            serve_after = self._verify_container_by_id(self.names["serve"], serve_id)
            if (serve_after.get("state") or {}).get("Status") != "running":
                raise CurrentBootRejected("OWNER_SERVE_START_NOT_VERIFIED")
            status = self._wait_advanced_status(self.proofs["serve_restart_status"])
            completed = {
                "schema": "kairos.current-epoch-boot-result.v1",
                "state": "PASS_CURRENT_EPOCH_BOOT",
                "owner": self.owner,
                "receipt_sha256": self.receipt_sha256,
                "boot_id": boot_id,
                "resources": self.names,
                "status_observed_at_utc": status["observed_at_utc"],
                "trading_started": False,
                "orders_submitted": 0,
                "paid_calls": 0,
                "retained_restore_containers": retained_restores,
            }
            epoch.fresh.save(work / "boot-complete.json", completed)
            return {"state": completed["state"], "owner": self.owner, "receipt_sha256": self.receipt_sha256, "trading_started": False}
        except BaseException as exc:
            cleanup_failures = []
            for name, identifier in reversed(started_ids):
                try:
                    view = self._verify_container_by_id(name, identifier)
                    if (view.get("state") or {}).get("Status") == "running":
                        c.docker(["stop", "--time=15", identifier], seconds=25)
                        stopped = self._verify_container_by_id(name, identifier)
                        if (stopped.get("state") or {}).get("Status") != "exited":
                            raise CurrentBootRejected("RECORDED_OWNER_STOP_NOT_VERIFIED")
                except Exception as cleanup_error:  # noqa: BLE001 - cleanup must continue for other admitted IDs
                    # A changed/unknown identity is retained untouched and fails closed.
                    cleanup_failures.append(type(cleanup_error).__name__)
            failure = {
                "schema": "kairos.current-epoch-boot-result.v1",
                "state": "FAILED_CLOSED",
                "owner": self.owner,
                "receipt_sha256": self.receipt_sha256,
                "error_type": type(exc).__name__,
                "reason": str(exc) if isinstance(exc, (CurrentBootRejected, epoch.Rejected)) else "private diagnostic withheld",
                "trading_started": False,
                "cleanup_incomplete": bool(cleanup_failures),
            }
            epoch.fresh.save(work / "boot-failure.json", failure)
            raise CurrentBootRejected(failure["reason"]) from None

    def _verify_profile_receipt(self, value: dict) -> None:
        if (
            value.get("schema_profile") != SCHEMA_PROFILE
            or value.get("schema_migration_count") != MIGRATION_COUNT
            or value.get("schema_public_table_count") != PUBLIC_TABLE_COUNT
        ):
            raise CurrentBootRejected("CURRENT_SCHEMA_WORKER_RECEIPT_REQUIRED")

    def _backup_restore(self, c, work: Path, common: dict, expected: dict, tag: str) -> str:
        backup = work / ("epoch-history-" + tag + ".dump")
        c.stream_private_pg_dump(backup=backup, database=common["database"])
        if backup.is_symlink() or not backup.is_file():
            raise CurrentBootRejected("BOUNDED_CURRENT_EPOCH_BACKUP_REQUIRED")
        token_match = re.fullmatch(r"([0-9a-f]{32})-(01|02)", tag)
        if token_match is None:
            raise CurrentBootRejected("UNIQUE_RESTORE_BOOT_TOKEN_REQUIRED")
        token = token_match.group(1)[:12] + token_match.group(2)
        prefix = "kairos-epoch-" + self.owner[:12]
        name = prefix + "-restore-current-" + token
        volume = prefix + "-restore-data-current-" + token
        if name in self._container_names(all_states=True) or volume in self._volume_names():
            raise CurrentBootRejected("RETAINED_RESTORE_RESOURCE_ALREADY_EXISTS")
        prior_restore_host, prior_restore_volume = c.names["restore_pg"], c.names["restore_volume"]
        c.names["restore_pg"], c.names["restore_volume"] = name, volume
        restore_id = None
        try:
            c.create_volume(volume)
            c.initialize_volume(volume, uid=70)
            restore_password = self.private["restore_admin_password"]
            password_path = work / ("restore-admin-password-" + tag)
            epoch.fresh.write(password_path, restore_password.encode("ascii"))
            c.create_database(
                name=name,
                volume=volume,
                password_path=password_path,
                database="kairos_recovery_" + self.owner[:12] + "_epochrestore",
                extra_mounts=("--mount", f"type=bind,src={backup},dst=/archive.dump,readonly"),
                watchdog_seconds=1500,
            )
            if name not in c.created:
                raise CurrentBootRejected("RESTORE_CLONE_CREATION_NOT_RECORDED")
            created = c.inspect_container(name)
            labels = created.get("labels") or {}
            restore_id = created.get("id")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", restore_id or "")
                or created.get("name") != "/" + name
                or created.get("image") != self.container_images[self.names["target_pg"]]
                or labels.get(epoch.EPOCH_LABEL) != self.owner
                or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
                or created.get("network") != self.names["network"]
                or created.get("ports") not in (None, {})
                or created.get("privileged") is not False
                or created.get("readonly") is not True
                or created.get("caps") != ["ALL"]
            ):
                raise CurrentBootRejected("CREATED_RESTORE_CLONE_IDENTITY_MISMATCH")
            c.require_mount_set(
                name,
                {
                    volume: ("/var/lib/postgresql/data", True),
                    str(password_path): ("/run/secrets/epoch_admin_password", False),
                    str(backup): ("/archive.dump", False),
                },
            )
            c.wait_postgres(name)
            c.restore_accepted_dump(name, "kairos_recovery_" + self.owner[:12] + "_epochrestore")
            restore_config = {
                **common,
                "admin_password": self.private["admin_password"],
                "restore_host": name,
                "restore_database": "kairos_recovery_" + self.owner[:12] + "_epochrestore",
                "restore_admin_password": restore_password,
                "expected_seed": expected,
            }
            result = c.phase("boot-verify-restore", restore_config, suffix=tag)
            self._verify_profile_receipt(c.proofs["boot-verify-restore"])
            if result.get("state") != "PASS_BOOT_ISOLATED_RESTORE":
                raise CurrentBootRejected("CURRENT_BOOT_RESTORE_VERIFICATION_REQUIRED")
            c.docker(
                [
                    "exec", name, "pg_amcheck", "--install-missing",
                    "--database=kairos_recovery_" + self.owner[:12] + "_epochrestore",
                    "--username=kairos", "--heapallindexed", "--parent-check", "--rootdescend",
                ],
                seconds=240,
            )
        finally:
            try:
                if restore_id is not None:
                    retained = c.inspect_container(restore_id)
                    labels = retained.get("labels") or {}
                    if (
                        retained.get("id") != restore_id
                        or retained.get("name") != "/" + name
                        or retained.get("image") != self.container_images[self.names["target_pg"]]
                        or labels.get(epoch.EPOCH_LABEL) != self.owner
                        or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
                        or retained.get("network") != self.names["network"]
                        or retained.get("ports") not in (None, {})
                        or retained.get("privileged") is not False
                        or retained.get("readonly") is not True
                        or retained.get("caps") != ["ALL"]
                    ):
                        raise CurrentBootRejected("RESTORE_CLONE_IDENTITY_CHANGED")
                    if (retained.get("state") or {}).get("Status") == "running":
                        c.docker(["stop", "--time=15", restore_id], seconds=25)
                    retained = c.inspect_container(restore_id)
                    if (retained.get("state") or {}).get("Status") != "exited":
                        raise CurrentBootRejected("RESTORE_CLONE_NOT_RETAINED_STOPPED")
            finally:
                c.names["restore_pg"], c.names["restore_volume"] = prior_restore_host, prior_restore_volume
        if restore_id is None or name not in c.created:
            raise CurrentBootRejected("RESTORE_CLONE_NOT_RETAINED_STOPPED")
        retained = c.inspect_container(restore_id)
        if (retained.get("state") or {}).get("Status") != "exited":
            raise CurrentBootRejected("RESTORE_CLONE_NOT_RETAINED_STOPPED")
        return name

    def _container_names(self, *, all_states: bool) -> set[str]:
        args = ["ps"]
        if all_states:
            args.append("-a")
        args.extend(["--format", "{{.Names}}"])
        return set(self.controller.docker(args).splitlines())

    def _volume_names(self) -> set[str]:
        return set(
            self.controller.docker(["volume", "ls", "--format", "{{.Name}}"])
            .splitlines()
        )

    def _wait_advanced_status(self, previous: dict) -> dict:
        deadline = time.monotonic() + STATUS_WAIT_SECONDS
        while time.monotonic() < deadline:
            if self.status_path.is_file() and not self.status_path.is_symlink():
                try:
                    status = read_bounded_json(self.status_path, 32_768)
                    if status.get("state") == "FAILED_CLOSED":
                        raise CurrentBootRejected("CURRENT_SERVE_FAILED_CLOSED")
                    if status.get("observed_at_utc") != previous.get("observed_at_utc"):
                        validated = validate_status_profile(status, self.owner, previous=previous)
                        view = self.controller.inspect_container(self.names["serve"])
                        if (view.get("state") or {}).get("Status") != "running":
                            raise CurrentBootRejected("CURRENT_SERVE_NOT_RUNNING")
                        return validated
                except (OSError, json.JSONDecodeError):
                    pass
            time.sleep(2)
        raise CurrentBootRejected("CURRENT_SERVE_FRESH_ADVANCED_STATUS_REQUIRED")

    @classmethod
    def from_inputs(cls, receipt_path: Path, expected_sha256: str, signature_path: Path):
        return cls(receipt_path, expected_sha256, signature_path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        with current.previous.WindowsMutex(r"Global\KairosCurrentNonTradingEpoch20261024"):
            adapter = CurrentEpochBootAdapter.from_inputs(
                args.receipt, args.receipt_sha256, args.signature
            )
            result = adapter.execute() if args.execute else adapter.plan()
        print(json.dumps(result, sort_keys=True))
        return 0 if result["state"] in {"ALREADY_RUNNING", "PASS_CURRENT_EPOCH_BOOT"} else 1
    except (CurrentBootRejected, epoch.Rejected) as exc:
        print(json.dumps({"state": "REFUSED", "reason": str(exc), "trading_started": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
