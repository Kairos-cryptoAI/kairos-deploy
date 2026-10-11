"""Create a separately owned, non-trading runtime epoch (plan-only by default).

This controller intentionally does not call the historical fresh-recovery or
controlled-primary controller entry points.  It reuses only their bounded,
read-only source facts and the Windows-process-bounded Docker CLI primitive.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import time
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import controlled_runtime_primary as primary
    from scripts import controlled_runtime_transition as current
    from scripts import fresh_runtime_recovery as fresh
else:
    import controlled_runtime_primary as primary
    import controlled_runtime_transition as current
    import fresh_runtime_recovery as fresh

REPO = Path("D:/Kairos/kairos-deploy")
ROOT = REPO / "backups/runtime-epoch-20261011"
DUMP = (
    REPO
    / "backups/controlled-runtime-transition-20261010/primary-run-78bf32d0ac9e44ca8d4a7e246136db89/primary-after.dump"
)
DUMP_SHA256 = "2408db1335dc856122750e4604f14a436184f54a7f4ffab22bc35eb69747a7bc"
PG_IMAGE = fresh.IMAGE
REDIS_IMAGE = "redis:8.2.8-alpine3.22@sha256:a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103"
WORKER_IMAGE = "ghcr.io/kairos-cryptoai/kairos-runtime-schema-profile-runner@sha256:2e10e9e936eae3a4a411f65d8b0bd14670ba808368eeff94b4e24021aa291077"
DEFAULT_WHEELHOUSE = Path(
    "D:/Kairos/runtime/controlled-runtime-wheels-20261010/5a552bb299de4638ba083a8cd5e73187"
)
WHEEL_MANIFEST_SHA256 = (
    "716d319327ac65eb522cb954442de7c76a879f802b5fd37a0cd80c7f191a55c6"
)
AUX_WHEELHOUSE = Path("D:/Kairos/runtime/runtime-epoch-aux-wheels-20261011")
AUX_NUMPY = "numpy-2.4.6-cp311-cp311-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"
AUX_NUMPY_BYTES = 16_918_164
AUX_NUMPY_SHA256 = "89cd468399cfd2504718f0ba50e410dca55a170b61a02ad92bb18c8a65186e93"
EPOCH_SCOPE = "kairos-nontrading-runtime-epoch-v1"
EPOCH_LABEL = "com.kairos.runtime-epoch.owner"
ACTIVE_LEASE = ROOT / "runtime-epoch.active"
MAX_SECONDS = 9000
MAX_CATCHUP_BARS = 150_000
WORKER_PATH_IN_IMAGE = "/operator/runtime_epoch_worker.py"
CONFIG_PATH_IN_CONTAINER = "/config/epoch.json"
OUTPUT_PATH_IN_CONTAINER = "/output"
PS = Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
GIT = fresh.GIT
LEGACY_REDIS_ID = "cba271ac26764f553cf8319aff992200226c62d02c9c8ca94db4622afd05147a"
NATIVE_VERIFY = (
    REPO
    / "backups/controlled-runtime-transition-20261010/primary-run-78bf32d0ac9e44ca8d4a7e246136db89/native-verify.json"
)
NATIVE_VERIFY_SHA256 = (
    "d0ccd3b14574d10877bbc488c35155b4ca602e5b65f13ac122d8f2cca5e03930"
)
QUANT_REPO = Path("D:/Kairos/kairos-quant-scouts")
QUANT_REVISION = "77c3d3e813faeb042661dacecd148226d8a25834"
CORE_REVISION = "6937eb4773fc00afaf5ba4e020b28b689f48e377"
PERSISTENCE_REVISION = "11df49ce455b89fd252d5f3d948099a8e9211cb3"
CLOSED_BAR_TOPIC = "kairos.market.closed_bar.v1"
PUBLICATION_KEY_PREFIX = "kairos.runtime."
SYMBOLS = ("BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT")
MINUTE_MS = 60_000


class Rejected(RuntimeError):
    """A sanitized fail-closed admission or operation rejection."""


def _sha(path: Path) -> str:
    return fresh.sha(path)


def owner_name(owner: str) -> str:
    if not isinstance(owner, str) or re.fullmatch(r"[0-9a-f]{32}", owner) is None:
        raise Rejected("EPOCH_OWNER_REQUIRED")
    return owner


def resource_names(owner: str) -> dict[str, str]:
    owner = owner_name(owner)
    prefix = "kairos-epoch-" + owner[:12]
    return {
        "network": prefix + "-private",
        "target_volume": prefix + "-pg-data",
        "source_volume": prefix + "-source-data",
        "restore_volume": prefix + "-restore-data",
        "redis_volume": prefix + "-redis-data",
        "target_pg": prefix + "-pg",
        "source_pg": prefix + "-source",
        "restore_pg": prefix + "-restore",
        "redis": prefix + "-redis",
        "serve": prefix + "-serve",
    }


def validate_worker_config(value: object, *, mode: str) -> dict:
    """Validate narrow, mode-specific worker JSON before private-file creation."""
    common = {"owner", "database", "pg_host", "redis_host"}
    fields = {
        "prepare": common
        | {
            "admin_password",
            "source_host",
            "source_database",
            "source_admin_password",
            "source_password",
            "history_password",
            "producer_password",
            "consumer_password",
        },
        "seed": common
        | {
            "source_host",
            "source_database",
            "source_password",
            "history_password",
            "seed_expectation",
            "source_dump_sha256",
        },
        "catchup": common | {"history_password", "end_exclusive_ms", "maximum_bars"},
        "verify-restore": common
        | {
            "admin_password",
            "restore_host",
            "restore_database",
            "restore_admin_password",
            "expected_seed",
        },
        "qualify": common
        | {
            "producer_password",
            "consumer_password",
            "redis_producer_password",
            "redis_consumer_password",
        },
        "serve": common
        | {
            "producer_password",
            "consumer_password",
            "redis_producer_password",
            "redis_consumer_password",
        },
    }
    if mode not in fields or not isinstance(value, dict) or set(value) != fields[mode]:
        raise Rejected("EXACT_WORKER_CONFIG_FIELDS_REQUIRED")
    if re.fullmatch(r"[0-9a-f]{32}", str(value.get("owner", ""))) is None:
        raise Rejected("EPOCH_OWNER_REQUIRED")
    if value.get("database") != "kairos_epoch_" + value["owner"][:12]:
        raise Rejected("EPOCH_DATABASE_IDENTITY_REQUIRED")
    for key in ("pg_host", "redis_host"):
        if (
            not isinstance(value.get(key), str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value[key]) is None
        ):
            raise Rejected("PRIVATE_EPOCH_HOST_IDENTITY_REQUIRED")
    secret_fields = {key for key in fields[mode] if key.endswith("password")}
    for key in secret_fields:
        if not isinstance(value[key], str) or len(value[key]) < 32:
            raise Rejected("NEW_EPOCH_SECRET_REQUIRED")
    if mode == "catchup":
        if type(value["end_exclusive_ms"]) is not int or value["end_exclusive_ms"] <= 0:
            raise Rejected("CLOSED_END_EXCLUSIVE_REQUIRED")
        if (
            value["end_exclusive_ms"] % 60_000
            or value["maximum_bars"] != MAX_CATCHUP_BARS
        ):
            raise Rejected("FIXED_GLOBAL_CATCHUP_CAP_REQUIRED")
    if mode == "seed" and (
        value["source_dump_sha256"] != DUMP_SHA256
        or not isinstance(value["seed_expectation"], dict)
    ):
        raise Rejected("PINNED_SEED_PROVENANCE_REQUIRED")
    if mode == "verify-restore" and (
        value["restore_host"] != "kairos-epoch-" + value["owner"][:12] + "-restore"
        or value["restore_database"]
        != "kairos_recovery_" + value["owner"][:12] + "_epochrestore"
        or not isinstance(value["expected_seed"], dict)
    ):
        raise Rejected("ISOLATED_RESTORE_IDENTITY_REQUIRED")
    return value


def catchup_end_exclusive_ms(
    seed: dict, target_end_exclusive_ms: int, *, append_limit: int = MAX_CATCHUP_BARS
) -> int:
    """Choose an exact minute boundary that cannot exceed the global append cap."""
    if type(append_limit) is not int or not 1 <= append_limit <= MAX_CATCHUP_BARS:
        raise Rejected("FIXED_GLOBAL_CATCHUP_CAP_REQUIRED")
    if (
        type(target_end_exclusive_ms) is not int
        or target_end_exclusive_ms <= 0
        or target_end_exclusive_ms % MINUTE_MS
    ):
        raise Rejected("CLOSED_END_EXCLUSIVE_REQUIRED")
    anchors = seed.get("anchors") if isinstance(seed, dict) else None
    if not isinstance(anchors, dict) or set(anchors) != set(SYMBOLS):
        raise Rejected("EXACT_FIVE_SYMBOL_SEED_ANCHORS_REQUIRED")
    first_opens: dict[str, int] = {}
    for symbol, record in anchors.items():
        if not isinstance(record, dict):
            raise Rejected("SEED_ANCHOR_SHAPE_REQUIRED")
        last_open = record.get("last_open_time_ms")
        last_close = record.get("last_close_time_ms")
        count = record.get("count")
        if (
            type(last_open) is not int
            or type(last_close) is not int
            or type(count) is not int
            or count < 1
            or last_open % MINUTE_MS
            or last_close != last_open + MINUTE_MS - 1
        ):
            raise Rejected("SEED_ANCHOR_FINALITY_REQUIRED")
        first_opens[symbol] = last_close + 1
    earliest = min(first_opens.values())
    proposed = min(
        target_end_exclusive_ms, earliest + (append_limit // len(SYMBOLS)) * MINUTE_MS
    )
    required = sum(
        max(0, (proposed - start) // MINUTE_MS) for start in first_opens.values()
    )
    while required > append_limit:
        proposed -= MINUTE_MS
        required = sum(
            max(0, (proposed - start) // MINUTE_MS) for start in first_opens.values()
        )
    if proposed <= earliest:
        raise Rejected("CATCHUP_MADE_NO_BOUNDED_PROGRESS")
    return proposed


def redis_acl_text(
    owner: str, *, admin_password: str, producer_password: str, consumer_password: str
) -> str:
    """Build default-off ACLs with separate, key-scoped non-admin roles."""
    owner_name(owner)
    passwords = (admin_password, producer_password, consumer_password)
    if (
        any(
            not isinstance(secret, str) or re.fullmatch(r"[0-9a-f]{64}", secret) is None
            for secret in passwords
        )
        or len(set(passwords)) != 3
    ):
        raise Rejected("DISTINCT_NEW_EPOCH_SECRETS_REQUIRED")
    key = PUBLICATION_KEY_PREFIX + owner + ".publication"

    def rule(
        user: str, password: str, keys: tuple[str, ...], commands: tuple[str, ...]
    ) -> str:
        hashes = " ".join(
            "#" + hashlib.sha256(password.encode("ascii")).hexdigest() for _ in (0,)
        )
        return (
            "user "
            + user
            + " on "
            + hashes
            + " "
            + " ".join(keys)
            + " "
            + " ".join("+" + cmd for cmd in commands)
        )

    admin = rule("kairos_epoch_admin", admin_password, ("~*",), ("@all",))
    producer = rule(
        "kairos_epoch_producer",
        producer_password,
        ("~" + CLOSED_BAR_TOPIC, "~" + key),
        (
            "auth",
            "hello",
            "client|setinfo",
            "ping",
            "eval",
            "hget",
            "hset",
            "xadd",
            "xrange",
            "xlen",
            "xinfo|groups",
        ),
    )
    consumer = rule(
        "kairos_epoch_consumer",
        consumer_password,
        ("~" + CLOSED_BAR_TOPIC,),
        (
            "auth",
            "hello",
            "client|setinfo",
            "ping",
            "xgroup|create",
            "xreadgroup",
            "xautoclaim",
            "xpending",
            "xack",
        ),
    )
    return "user default off\n" + admin + "\n" + producer + "\n" + consumer + "\n"


def build_worker_argv(mode: str, config_path: str, output_path: str) -> list[str]:
    if mode not in {"prepare", "seed", "catchup", "verify-restore", "qualify", "serve"}:
        raise Rejected("WORKER_MODE_REQUIRED")
    if (
        config_path != CONFIG_PATH_IN_CONTAINER
        or output_path != OUTPUT_PATH_IN_CONTAINER
    ):
        raise Rejected("FIXED_WORKER_PATHS_REQUIRED")
    return [
        "python",
        "-B",
        WORKER_PATH_IN_IMAGE,
        "--mode",
        mode,
        "--config",
        config_path,
        "--output",
        output_path,
    ]


def private_worker_projection(owner: str, mode: str, config: dict) -> dict:
    """Return only the fields required by this phase; never mount all credentials."""
    validate_worker_config(config, mode=mode)
    return dict(config)


def extract_git_snapshot(
    repo: Path,
    revision: str,
    paths: tuple[str, ...],
    destination: Path,
    *,
    strip_prefix: str | None = None,
) -> dict[str, str]:
    """Archive only pinned ordinary source files and reject links/escapes."""
    if (
        destination.exists()
        or destination.is_symlink()
        or re.fullmatch(r"[0-9a-f]{40}", revision) is None
    ):
        raise Rejected("CREATE_ONLY_PINNED_SOURCE_SNAPSHOT_REQUIRED")
    archive = destination.parent / (destination.name + ".zip")
    if archive.exists() or archive.is_symlink():
        raise Rejected("CREATE_ONLY_SOURCE_ARCHIVE_REQUIRED")
    command = [
        str(GIT),
        "-C",
        str(repo),
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.eol=lf",
        "archive",
        "--format=zip",
        "--output=" + str(archive),
        revision,
        "--",
        *paths,
    ]
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=False,
        shell=False,
    )
    if result.returncode:
        raise Rejected("PINNED_GIT_ARCHIVE_FAILED")
    destination.mkdir()
    total = count = 0
    with zipfile.ZipFile(archive) as stream:
        for item in stream.infolist():
            name = item.filename
            mode = item.external_attr >> 16
            kind = stat.S_IFMT(mode)
            parts = name.rstrip("/").split("/")
            if (
                "\\" in name
                or name.startswith("/")
                or any(p in {"", ".", ".."} for p in parts)
                or kind not in {0, stat.S_IFREG, stat.S_IFDIR}
            ):
                raise Rejected("PINNED_SOURCE_ARCHIVE_MEMBER_REJECTED")
            relative_parts = (
                parts[1:]
                if strip_prefix is not None and parts[0] == strip_prefix
                else parts
            )
            if strip_prefix is not None and parts[0] != strip_prefix:
                raise Rejected("PINNED_SOURCE_ARCHIVE_PREFIX_REQUIRED")
            target = destination.joinpath(*relative_parts)
            try:
                target.resolve().relative_to(destination.resolve())
            except ValueError:
                raise Rejected("PINNED_SOURCE_ARCHIVE_ESCAPE") from None
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            count += 1
            total += item.file_size
            if count > 2048 or total > 128 * 1024**2 or item.file_size > 16 * 1024**2:
                raise Rejected("PINNED_SOURCE_ARCHIVE_SIZE_LIMIT")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(stream.read(item))
    manifest = {
        file.relative_to(destination).as_posix(): _sha(file)
        for file in destination.rglob("*")
        if file.is_file()
    }
    return manifest


def validate_wheelhouse(
    path: Path, expected_sha256: str, *, exact_files: bool = False
) -> dict:
    if not path.is_dir() or path.is_symlink():
        raise Rejected("PINNED_OFFLINE_WHEELHOUSE_REQUIRED")
    manifest_path = path / "manifest.json"
    if (
        manifest_path.is_symlink()
        or not manifest_path.is_file()
        or _sha(manifest_path) != expected_sha256
        or expected_sha256 != WHEEL_MANIFEST_SHA256
    ):
        raise Rejected("PINNED_OFFLINE_WHEEL_MANIFEST_REQUIRED")
    manifest = current.require_manifest(
        json.loads(manifest_path.read_text(encoding="utf-8")), path
    )
    expected_files = {
        "manifest.json",
        *(item["wheel"] for item in manifest["packages"]),
    }
    if exact_files:
        actual_files = set()
        for item in path.iterdir():
            if item.is_symlink() or not item.is_file():
                raise Rejected("WHEELHOUSE_LINK_OR_DIRECTORY_REJECTED")
            actual_files.add(item.name)
        if actual_files != expected_files:
            raise Rejected("EXACT_OFFLINE_WHEELHOUSE_FILE_SET_REQUIRED")
    revisions = {item["name"]: item["revision"] for item in manifest["packages"]}
    if revisions != {
        "kairos-core": CORE_REVISION,
        "kairos-persistence": PERSISTENCE_REVISION,
    }:
        raise Rejected("EXACT_SIGNED_RUNTIME_WHEEL_REVISIONS_REQUIRED")
    return manifest


def validate_aux_wheelhouse(path: Path, quant_lock: bytes) -> Path:
    if not path.is_dir() or path.is_symlink():
        raise Rejected("PINNED_AUXILIARY_WHEELHOUSE_REQUIRED")
    entries = list(path.iterdir())
    wheel = path / AUX_NUMPY
    if (
        len(entries) != 1
        or entries[0] != wheel
        or wheel.is_symlink()
        or not wheel.is_file()
        or wheel.stat().st_size != AUX_NUMPY_BYTES
        or _sha(wheel) != AUX_NUMPY_SHA256
    ):
        raise Rejected("PINNED_NUMPY_WHEEL_REQUIRED")
    if AUX_NUMPY_SHA256.encode("ascii") not in quant_lock:
        raise Rejected("NUMPY_WHEEL_NOT_BOUND_TO_SIGNED_QUANT_LOCK")
    return wheel


def validate_running_status(
    value: object,
    owner: str,
    *,
    previous: dict | None = None,
    now_ms: int | None = None,
) -> dict:
    if (
        not isinstance(value, dict)
        or value.get("state") != "RUNNING_NONTRADING"
        or value.get("owner") != owner
    ):
        raise Rejected("NONTRADING_SERVE_STATUS_REQUIRED")
    watermarks = value.get("watermarks_ms")
    if (
        not isinstance(watermarks, dict)
        or set(watermarks) != set(SYMBOLS)
        or any(type(item) is not int or item <= 0 for item in watermarks.values())
    ):
        raise Rejected("FIVE_SYMBOL_SERVE_WATERMARKS_REQUIRED")
    if (
        value.get("PAPER_QUALIFIED") is not False
        or value.get("ALPHA_READY") is not False
        or value.get("LIVE_READY") is not False
        or value.get("STRATEGY_POLICY") != "REJECT_ALL"
        or value.get("pending_outbox") != 0
        or value.get("unresolved_inbox") != 0
        or value.get("uncompleted_publications") != 0
    ):
        raise Rejected("NONTRADING_SERVE_HEALTH_BOUNDARY_REQUIRED")
    try:
        observed = datetime.fromisoformat(
            value["observed_at_utc"].replace("Z", "+00:00")
        )
        age = (
            datetime.now(UTC)
            if now_ms is None
            else datetime.fromtimestamp(now_ms / 1000, UTC)
        ) - observed
    except (KeyError, AttributeError, TypeError, ValueError):
        raise Rejected("SERVE_STATUS_TIMESTAMP_REQUIRED") from None
    if age.total_seconds() < -5 or age.total_seconds() > 120:
        raise Rejected("SERVE_STATUS_FRESHNESS_REQUIRED")
    if previous is not None:
        old = previous.get("watermarks_ms")
        if (
            not isinstance(old, dict)
            or set(old) != set(SYMBOLS)
            or any(watermarks[symbol] <= old[symbol] for symbol in SYMBOLS)
        ):
            raise Rejected("SERVE_RESTART_WATERMARK_ADVANCE_REQUIRED")
        try:
            old_time = datetime.fromisoformat(
                previous["observed_at_utc"].replace("Z", "+00:00")
            )
        except (KeyError, AttributeError, TypeError, ValueError):
            raise Rejected("PREVIOUS_SERVE_TIMESTAMP_REQUIRED") from None
        if observed <= old_time:
            raise Rejected("SERVE_RESTART_FRESH_STATUS_REQUIRED")
    return value


def _epoch_config(
    owner: str, database: str, pg_host: str, redis_host: str, secrets_map: dict
) -> dict:
    value = {
        "owner": owner,
        "database": database,
        "pg_host": pg_host,
        "redis_host": redis_host,
        **secrets_map,
    }
    return value


class EpochController:
    """Owner-bound native resource manager; no old-runtime resource is adopted."""

    def __init__(
        self,
        owner: str,
        *,
        expected_revision: str,
        wheelhouse: Path = DEFAULT_WHEELHOUSE,
        deadline: float | None = None,
    ):
        self.owner = owner_name(owner)
        self.names = resource_names(owner)
        self.expected_revision = expected_revision
        self.work = fresh.safe(ROOT / ("run-" + owner))
        self.deadline = deadline or (time.monotonic() + MAX_SECONDS)
        docker_config = self.work / "docker-config"
        if not docker_config.exists():
            docker_config.mkdir()
            fresh.save(docker_config / "config.json", fresh.auth_free_docker_config())
        elif (
            docker_config.is_symlink() or not (docker_config / "config.json").is_file()
        ):
            raise Rejected("AUTH_FREE_OWNER_DOCKER_CONFIG_REQUIRED")
        self.native = fresh.bounded.Native(self.work)
        self.proofs: dict[str, object] = {}
        self.created: list[str] = []
        self.current_phase = "ADMISSION"
        self.phase_index = 0
        self.wheelhouse = fresh.safe(wheelhouse)
        self.runtime_wheelhouse: Path | None = None
        self.operator_snapshot: Path | None = None
        self.quant_snapshot: Path | None = None
        self.aux_wheelhouse = AUX_WHEELHOUSE

    def docker(
        self, arguments: list[str], *, seconds: float = 20, allow_failure: bool = False
    ) -> str:
        if not arguments or any(not isinstance(value, str) for value in arguments):
            raise Rejected("DOCKER_ARGUMENTS_REQUIRED")
        try:
            return self.native.call(
                arguments, self.deadline, seconds=seconds, allow_failure=allow_failure
            )[1]
        except Exception as exc:  # noqa: BLE001 - map arbitrary CLI failures to a sanitized code.
            raise Rejected(
                "BOUNDED_DOCKER_OPERATION_FAILED_" + type(exc).__name__
            ) from None

    def inspect_container(self, name: str) -> dict:
        return json.loads(self.docker(["inspect", "--format", fresh.VIEW, name]))

    def assert_legacy_sources_stopped(self, *, legacy_redis_id: str) -> dict:
        """Read only exact source container metadata; never exec/query/start them."""
        expected = {
            fresh.SOURCE: fresh.SOURCE_ID,
            "kairos-paper-gate-redis-1": legacy_redis_id,
        }
        snapshots = {}
        for name, identifier in expected.items():
            if not re.fullmatch(r"[0-9a-f]{64}", identifier or ""):
                raise Rejected("EXACT_STOPPED_SOURCE_CONTAINER_IDS_REQUIRED")
            view = self.inspect_container(name)
            state = view.get("state") or {}
            labels = view.get("labels") or {}
            mounts = view.get("mounts") or []
            if (
                view.get("id") != identifier
                or view.get("image")
                != (
                    fresh.IMAGE_ID
                    if name == fresh.SOURCE
                    else "sha256:" + REDIS_IMAGE.rsplit("sha256:", 1)[-1]
                )
                or state.get("Status") != "exited"
                or any(
                    state.get(key)
                    for key in ("Running", "Paused", "Restarting", "Dead", "Pid")
                )
                or view.get("ports")
                or view.get("privileged")
                or (
                    name == fresh.SOURCE
                    and (
                        labels.get("com.docker.compose.project") != "kairos-paper-gate"
                        or labels.get("com.docker.compose.service") != "timescaledb"
                        or set((view.get("networks") or {}).keys()) != {fresh.NETWORK}
                        or not any(
                            mount.get("Type") == "volume"
                            and mount.get("Name") == fresh.VOLUME
                            and mount.get("Destination") == "/var/lib/postgresql/data"
                            for mount in mounts
                        )
                    )
                )
            ):
                raise Rejected("EXACT_STOPPED_LEGACY_SOURCE_REQUIRED")
            snapshots[name] = fresh.digest(view)
        return {
            "legacy_pg": expected[fresh.SOURCE],
            "legacy_redis": legacy_redis_id,
            "state": "stopped",
            "metadata_sha256": snapshots,
        }

    def create_network(self) -> None:
        # A private user-defined bridge with no published host ports preserves
        # outbound public Binance market-data access for REST catch-up/live feed.
        self.docker(
            [
                "network",
                "create",
                "--driver",
                "bridge",
                "--label",
                EPOCH_LABEL + "=" + self.owner,
                "--label",
                "com.kairos.runtime-epoch.scope=" + EPOCH_SCOPE,
                self.names["network"],
            ]
        )
        self.created.append(self.names["network"])
        network = json.loads(
            self.docker(
                ["network", "inspect", "--format", "{{json .}}", self.names["network"]]
            )
        )
        labels = network.get("Labels") or {}
        if (
            network.get("Name") != self.names["network"]
            or network.get("Driver") != "bridge"
            or network.get("Internal") is not False
            or labels.get(EPOCH_LABEL) != self.owner
            or labels.get("com.kairos.runtime-epoch.scope") != EPOCH_SCOPE
            or network.get("Containers")
        ):
            raise Rejected("PRIVATE_EPOCH_EGRESS_BRIDGE_REQUIRED")

    def create_volume(self, name: str) -> None:
        if name not in {
            self.names["target_volume"],
            self.names["source_volume"],
            self.names["restore_volume"],
            self.names["redis_volume"],
        }:
            raise Rejected("UNOWNED_VOLUME_NAME")
        self.docker(
            [
                "volume",
                "create",
                "--label",
                EPOCH_LABEL + "=" + self.owner,
                "--label",
                "com.kairos.runtime-epoch.scope=" + EPOCH_SCOPE,
                name,
            ]
        )
        self.created.append(name)
        metadata = json.loads(
            self.docker(["volume", "inspect", "--format", "{{json .}}", name])
        )
        labels = metadata.get("Labels") or {}
        if (
            metadata.get("Name") != name
            or labels.get(EPOCH_LABEL) != self.owner
            or labels.get("com.kairos.runtime-epoch.scope") != EPOCH_SCOPE
        ):
            raise Rejected("CREATED_VOLUME_OWNERSHIP_REQUIRED")

    def initialize_volume(self, name: str, *, uid: int) -> None:
        if name not in {
            self.names["target_volume"],
            self.names["source_volume"],
            self.names["restore_volume"],
            self.names["redis_volume"],
        } or uid not in {70, 999}:
            raise Rejected("NEW_VOLUME_INITIALIZATION_SCOPE_REQUIRED")
        helper = "kairos-epoch-" + self.owner[:12] + "-volume-init-" + str(uid)
        if helper in self.created:
            raise Rejected("UNIQUE_VOLUME_INITIALIZER_REQUIRED")
        self.docker(
            [
                "create",
                "--pull=never",
                "--name",
                helper,
                "--network=none",
                "--user=0",
                "--read-only",
                "--cap-drop=ALL",
                "--cap-add=CHOWN",
                "--security-opt=no-new-privileges:true",
                "--memory=64m",
                "--memory-swap=64m",
                "--cpus=0.25",
                "--pids-limit=16",
                "--label",
                EPOCH_LABEL + "=" + self.owner,
                "--label",
                "com.kairos.runtime-epoch.scope=" + EPOCH_SCOPE,
                "--mount",
                f"type=volume,src={name},dst=/owned",
                "--entrypoint",
                "/bin/sh",
                PG_IMAGE,
                "-c",
                f"chmod 0700 /owned && chown {uid}:{uid} /owned",
            ]
        )
        self.created.append(helper)
        self.docker(["start", "--attach", helper], seconds=20)
        inspection = self.inspect_container(helper)
        if inspection.get("state", {}).get("ExitCode") != 0 or inspection.get(
            "state", {}
        ).get("Running"):
            raise Rejected("VOLUME_INITIALIZER_FAILED")
        self.docker(["rm", helper])
        self.created.remove(helper)

    def _create_container(
        self,
        name: str,
        image: str,
        options: list[str],
        *,
        command: list[str] = (),
        start: bool = True,
        user: str | None = None,
        memory: str = "2g",
        cpus: str = "1",
        tmpfs: str = "/tmp:rw,nosuid,nodev,size=128m",
    ) -> None:
        if not name.startswith("kairos-epoch-" + self.owner[:12] + "-"):
            raise Rejected("OWNER_BOUND_CONTAINER_NAME_REQUIRED")
        args = [
            "create",
            "--pull=never",
            "--name",
            name,
            "--network",
            self.names["network"],
            "--network-alias",
            name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory=" + memory,
            "--memory-swap=" + memory,
            "--cpus=" + cpus,
            "--pids-limit=128",
            "--label",
            EPOCH_LABEL + "=" + self.owner,
            "--label",
            "com.kairos.runtime-epoch.scope=" + EPOCH_SCOPE,
        ]
        if user:
            args += ["--user", user]
        args += ["--tmpfs", tmpfs, *options, image, *command]
        self.docker(args)
        self.created.append(name)
        view = self.inspect_container(name)
        labels = view.get("labels") or {}
        expected_memory = int(memory[:-1]) * (
            1024**3 if memory.endswith("g") else 1024**2
        )
        if (
            view.get("name") != "/" + name
            or view.get("image")
            not in {
                image,
                image.split("@", 1)[-1],
                "sha256:" + image.rsplit("sha256:", 1)[-1],
            }
            or view.get("ports")
            or view.get("network") != self.names["network"]
            or view.get("memory") != expected_memory
            or view.get("swap") != expected_memory
            or view.get("cpus") != int(float(cpus) * 10**9)
            or view.get("readonly") is not True
            or view.get("caps") != ["ALL"]
            or view.get("privileged") is True
            or labels.get(EPOCH_LABEL) != self.owner
            or labels.get("com.kairos.runtime-epoch.scope") != EPOCH_SCOPE
        ):
            raise Rejected("CREATED_CONTAINER_IDENTITY_OR_NO_PORTS_REQUIRED")
        if start:
            self.docker(["start", name])

    def create_database(
        self,
        *,
        name: str,
        volume: str,
        password_path: Path,
        database: str,
        extra_mounts: tuple[str, ...] = (),
        watchdog_seconds: int | None = None,
    ) -> None:
        if (
            password_path.parent != self.work
            or not password_path.is_file()
            or password_path.is_symlink()
        ):
            raise Rejected("PRIVATE_POSTGRES_PASSWORD_FILE_REQUIRED")
        args = [
            "--mount",
            f"type=volume,src={volume},dst=/var/lib/postgresql/data",
            "--mount",
            f"type=bind,src={password_path},dst=/run/secrets/epoch_admin_password,readonly",
            "--env",
            "POSTGRES_USER=kairos",
            "--env",
            "POSTGRES_DB=" + database,
            "--env",
            "POSTGRES_PASSWORD_FILE=/run/secrets/epoch_admin_password",
            "--env",
            "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust",
            "--tmpfs",
            "/var/run/postgresql:rw,nosuid,nodev,size=8m,uid=70,gid=70",
            *extra_mounts,
        ]
        pg_command = [
            "postgres",
            "-c",
            "shared_buffers=64MB",
            "-c",
            "work_mem=4MB",
            "-c",
            "max_connections=20",
            "-c",
            "max_worker_processes=8",
            "-c",
            "timescaledb.max_background_workers=0",
            "-c",
            "timescaledb.telemetry_level=off",
        ]
        if watchdog_seconds is not None:
            if type(watchdog_seconds) is not int or watchdog_seconds not in {1500}:
                raise Rejected("FINITE_DISPOSABLE_POSTGRES_WATCHDOG_REQUIRED")
            args += ["--entrypoint", "/bin/sh"]
            command = [
                "-c",
                f"(sleep {watchdog_seconds}; kill -TERM 1) & exec /usr/local/bin/docker-entrypoint.sh "
                + " ".join(pg_command),
            ]
        else:
            command = pg_command
        self._create_container(
            name,
            PG_IMAGE,
            args,
            command=command,
            user="70:70",
            memory="4g",
            cpus="1",
            tmpfs="/tmp:rw,nosuid,nodev,size=384m,uid=70,gid=70",
        )
        expected_mounts = {
            volume: ("/var/lib/postgresql/data", True),
            str(password_path): ("/run/secrets/epoch_admin_password", False),
        }
        if len(extra_mounts) == 2 and extra_mounts[0] == "--mount":
            fields = extra_mounts[1].split(",")
            values = dict(field.split("=", 1) for field in fields if "=" in field)
            if (
                values.get("type") != "bind"
                or not values.get("src")
                or not values.get("dst")
            ):
                raise Rejected("EXACT_RESTORE_DUMP_MOUNT_REQUIRED")
            expected_mounts[values["src"]] = (values["dst"], "readonly" not in fields)
        self.require_mount_set(name, expected_mounts)

    def wait_postgres(self, name: str, *, seconds: int = 120) -> None:
        end = min(time.monotonic() + seconds, self.deadline - 30)
        while time.monotonic() < end:
            result = self.docker(
                ["exec", name, "pg_isready", "-U", "kairos", "-d", "postgres"],
                seconds=5,
                allow_failure=True,
            )
            if result.strip().endswith("accepting connections"):
                return
            time.sleep(2)
        raise Rejected("NEW_POSTGRES_READINESS_TIMEOUT")

    def restore_accepted_dump(self, container: str, database: str) -> None:
        self.docker(
            [
                "exec",
                container,
                "psql",
                "-U",
                "kairos",
                "-d",
                database,
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "CREATE EXTENSION IF NOT EXISTS timescaledb; SELECT timescaledb_pre_restore();",
            ],
            seconds=30,
        )
        self.docker(
            [
                "exec",
                container,
                "pg_restore",
                "--exit-on-error",
                "--no-owner",
                "--no-privileges",
                "--username=kairos",
                "--dbname=" + database,
                "/archive.dump",
            ],
            seconds=180,
        )
        self.docker(
            [
                "exec",
                container,
                "psql",
                "-U",
                "kairos",
                "-d",
                database,
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                "SELECT timescaledb_post_restore();",
            ],
            seconds=30,
        )
        state = self.docker(
            [
                "exec",
                container,
                "psql",
                "-U",
                "kairos",
                "-d",
                database,
                "-Atqc",
                "SELECT current_setting('timescaledb.restoring')||'|'||current_setting('timescaledb.max_background_workers');",
            ],
            seconds=15,
        )
        if state.strip() != "off|0":
            raise Rejected("SOURCE_RESTORE_BACKGROUND_WORKERS_NOT_DISABLED")

    def create_redis(self, *, acl_path: Path, volume: str) -> None:
        if (
            acl_path.parent != self.work
            or not acl_path.is_file()
            or acl_path.is_symlink()
        ):
            raise Rejected("PRIVATE_REDIS_ACL_FILE_REQUIRED")
        args = [
            "--mount",
            f"type=volume,src={volume},dst=/data",
            "--mount",
            f"type=bind,src={acl_path},dst=/run/config/users.acl,readonly",
        ]
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
        self._create_container(
            self.names["redis"],
            REDIS_IMAGE,
            args,
            command=command,
            user="999:999",
            memory="256m",
            cpus="0.5",
        )
        self.require_mount_set(
            self.names["redis"],
            {volume: ("/data", True), str(acl_path): ("/run/config/users.acl", False)},
        )

    def stop_owned_serve(self) -> None:
        name = self.names["serve"]
        try:
            view = self.inspect_container(name)
        except Rejected:
            return
        labels = view.get("labels") or {}
        if (
            labels.get(EPOCH_LABEL) != self.owner
            or labels.get("com.kairos.runtime-epoch.scope") != EPOCH_SCOPE
        ):
            raise Rejected("OWNER_SERVE_CONTAINER_REQUIRED_FOR_STOP")
        if (view.get("state") or {}).get("Status") == "running":
            self.docker(["stop", "--time=15", name], seconds=25)

    def restart_serve_and_validate(self, status_path: Path, first: dict) -> dict:
        validate_running_status(first, self.owner)
        self.docker(["stop", "--time=15", self.names["serve"]], seconds=25)
        stopped = self.inspect_container(self.names["serve"])
        if (stopped.get("state") or {}).get("Status") != "exited":
            raise Rejected("NONTRADING_SERVE_STOP_FOR_RESTART_FAILED")
        self.docker(["start", self.names["serve"]])
        end = min(time.monotonic() + 180, self.deadline - 15)
        while time.monotonic() < end:
            if status_path.is_file() and not status_path.is_symlink():
                try:
                    current_status = json.loads(status_path.read_text(encoding="utf-8"))
                    if current_status.get("observed_at_utc") != first.get(
                        "observed_at_utc"
                    ):
                        # A restarted producer can finish a healthy zero-bar
                        # cycle before the next minute closes. Validate health
                        # immediately, but wait for natural five-symbol progress
                        # instead of treating that expected timing as failure.
                        validate_running_status(current_status, self.owner)
                        if not all(
                            current_status["watermarks_ms"][symbol]
                            > first["watermarks_ms"][symbol]
                            for symbol in SYMBOLS
                        ):
                            time.sleep(2)
                            continue
                        validated = validate_running_status(
                            current_status, self.owner, previous=first
                        )
                        view = self.inspect_container(self.names["serve"])
                        if (view.get("state") or {}).get("Status") != "running":
                            raise Rejected("NONTRADING_SERVE_RESTART_NOT_RUNNING")
                        return validated
                except (OSError, json.JSONDecodeError):
                    pass
            time.sleep(2)
        raise Rejected("NONTRADING_SERVE_RESTART_FRESHNESS_TIMEOUT")

    def require_mount_set(
        self, container: str, expected: dict[str, tuple[str, bool]]
    ) -> None:
        view = self.inspect_container(container)
        actual = {}
        for mount in view.get("mounts", []):
            source = (
                mount.get("Name")
                if mount.get("Type") == "volume"
                else mount.get("Source")
            )
            destination = mount.get("Destination")
            identity = (
                source
                if mount.get("Type") == "volume"
                else fresh.mount_identity(source or "")
            )
            key = next(
                (
                    candidate
                    for candidate in expected
                    if (
                        candidate
                        if candidate in self.created
                        else fresh.mount_identity(candidate)
                    )
                    == identity
                ),
                None,
            )
            if (
                key is None
                or destination != expected[key][0]
                or mount.get("RW") is not expected[key][1]
                or destination in actual
            ):
                raise Rejected("CREATED_CONTAINER_MOUNT_SET_REJECTED")
            actual[destination] = True
        if set(actual) != {value[0] for value in expected.values()}:
            raise Rejected("CREATED_CONTAINER_MOUNT_SET_REJECTED")

    def run_worker(
        self,
        *,
        mode: str,
        config_path: Path,
        output_dir: Path,
        extra_mounts: tuple[str, ...] = (),
    ) -> dict:
        if config_path.parent != self.work or output_dir.parent != self.work:
            raise Rejected("OWNER_PRIVATE_WORKER_FILES_REQUIRED")
        if (
            not config_path.is_file()
            or config_path.is_symlink()
            or not output_dir.is_dir()
            or output_dir.is_symlink()
        ):
            raise Rejected("WORKER_INPUT_OUTPUT_FILES_REQUIRED")
        name = (
            self.names["serve"]
            if mode == "serve"
            else "kairos-epoch-" + self.owner[:12] + "-" + mode
        )
        if (
            not output_dir.is_dir()
            or output_dir.is_symlink()
            or output_dir == self.work
        ):
            raise Rejected("ISOLATED_PHASE_OUTPUT_DIRECTORY_REQUIRED")
        if self.operator_snapshot is None or self.quant_snapshot is None:
            raise Rejected("SIGNED_OPERATOR_WHEEL_QUANT_SNAPSHOTS_REQUIRED")
        if self.runtime_wheelhouse is None:
            raise Rejected("PRIVATE_OFFLINE_RUNTIME_WHEELHOUSE_REQUIRED")
        for directory in (
            self.operator_snapshot,
            self.quant_snapshot,
            self.runtime_wheelhouse,
            self.aux_wheelhouse,
        ):
            if not directory.is_dir() or directory.is_symlink():
                raise Rejected("READONLY_WORKER_SOURCE_DIRECTORY_REQUIRED")
        extra_mounts = (
            "--mount",
            f"type=bind,src={self.operator_snapshot},dst=/operator,readonly",
            "--mount",
            f"type=bind,src={self.runtime_wheelhouse},dst=/wheelhouse,readonly",
            "--mount",
            f"type=bind,src={self.quant_snapshot},dst=/quant,readonly",
            "--mount",
            f"type=bind,src={self.aux_wheelhouse},dst=/aux-wheels,readonly",
        )
        args = [
            "--mount",
            f"type=bind,src={config_path},dst={CONFIG_PATH_IN_CONTAINER},readonly",
            "--mount",
            f"type=bind,src={output_dir},dst=/output",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            *extra_mounts,
            "--entrypoint",
            "/bin/sh",
        ]
        invocation = build_worker_argv(
            mode, CONFIG_PATH_IN_CONTAINER, OUTPUT_PATH_IN_CONTAINER
        )
        timeout = (
            ""
            if mode == "serve"
            else ("1800" if mode in {"catchup", "qualify"} else "600")
        )
        run = (
            "exec " + " ".join(invocation)
            if not timeout
            else "/usr/bin/timeout -s KILL "
            + timeout
            + " python -B "
            + " ".join(invocation[2:])
        )
        shell = (
            "set -eu; export PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1; /usr/local/bin/python -m pip install --no-index --no-deps --no-compile --target /tmp/installed /wheelhouse/*.whl /aux-wheels/"
            + AUX_NUMPY
            + " >/dev/null 2>&1; export PYTHONPATH=/tmp/installed:/operator:/quant; "
            + run
        )
        command = ["-c", shell]
        self._create_container(
            name,
            WORKER_IMAGE,
            args,
            command=command,
            start=False,
            user="0:0",
            memory="512m",
            cpus="1",
        )
        view = self.inspect_container(name)
        expected_mounts = {
            str(config_path): (CONFIG_PATH_IN_CONTAINER, True),
            str(output_dir): ("/output", False),
        }
        expected_mounts.update(
            {
                str(self.operator_snapshot): ("/operator", True),
                str(self.runtime_wheelhouse): ("/wheelhouse", True),
                str(self.quant_snapshot): ("/quant", True),
                str(self.aux_wheelhouse): ("/aux-wheels", True),
            }
        )
        actual_mounts = {}
        for mount in view.get("mounts", []):
            destination = mount.get("Destination")
            source = fresh.mount_identity(mount.get("Source", ""))
            expected = next(
                (
                    item
                    for host, item in expected_mounts.items()
                    if fresh.mount_identity(host) == source
                ),
                None,
            )
            if (
                expected is None
                or destination != expected[0]
                or mount.get("RW") is not (not expected[1])
                or destination in actual_mounts
            ):
                raise Rejected("WORKER_MOUNT_IDENTITY_OR_ACCESS_REJECTED")
            actual_mounts[destination] = True
        if set(actual_mounts) != {item[0] for item in expected_mounts.values()}:
            raise Rejected("EXACT_WORKER_MOUNT_SET_REQUIRED")
        self.docker(["start", name])
        if mode == "serve":
            self.proofs["serve_container"] = name
            view = self.inspect_container(name)
            if view.get("state", {}).get("Status") != "running":
                raise Rejected("NONTRADING_SERVE_DID_NOT_REMAIN_RUNNING")
            return {"state": "RUNNING_NONTRADING", "container": name}
        result = self.docker(
            ["wait", name], seconds=1810 if mode in {"catchup", "qualify"} else 610
        )
        if result.strip() != "0":
            raise Rejected("WORKER_MODE_FAILED_" + mode.upper())
        output_path = output_dir / (mode + ".json")
        if output_path.is_symlink() or not output_path.is_file():
            raise Rejected("WORKER_RECEIPT_FILE_REQUIRED")
        receipt = json.loads(output_path.read_text(encoding="utf-8"))
        expected_states = {
            "prepare": "PREPARED_EMPTY_NONTRADING_EPOCH",
            "seed": "VERIFIED_HISTORY_SEEDED_AUDIT_ONLY",
            "catchup": "AUDIT_ONLY_CATCHUP_COMPLETE",
            "verify-restore": "PASS_ISOLATED_EPOCH_RESTORE",
            "qualify": "NONTRADING_RUNTIME_QUALIFIED",
        }
        if (
            not isinstance(receipt, dict)
            or receipt.get("owner") != self.owner
            or receipt.get("mode") != mode
            or receipt.get("new_epoch_database") != "kairos_epoch_" + self.owner[:12]
            or receipt.get("state") != expected_states.get(mode)
        ):
            raise Rejected("WORKER_RECEIPT_NOT_ACCEPTED_" + mode.upper())
        if mode == "qualify":
            proofs = receipt.get("qualification_proofs")
            if not isinstance(proofs, dict) or proofs != {
                "redis_acceptance_replay_same_id": True,
                "hash_conflict_refused": True,
                "duplicate_delivery_acked_without_new_inbox": True,
            }:
                raise Rejected("QUALIFICATION_IDEMPOTENCY_PROOFS_REQUIRED")
        self.proofs[mode] = receipt
        self.docker(["rm", name])
        return receipt

    def phase(self, mode: str, config: dict, *, suffix: str = "") -> dict:
        self.current_phase = mode + ("-" + suffix if suffix else "")
        validate_worker_config(config, mode=mode)
        tag = mode + ("-" + suffix if suffix else "")
        self.phase_index += 1
        progress = self.work / ("phase-" + f"{self.phase_index:03d}" + ".json")
        fresh.save(
            progress,
            {"owner": self.owner, "phase": self.current_phase, "state": "IN_PROGRESS"},
        )
        config_path = self.work / ("config-" + tag + ".json")
        output_dir = self.work / ("output-" + tag)
        fresh.save(config_path, config)
        output_dir.mkdir()
        receipt = self.run_worker(
            mode=mode, config_path=config_path, output_dir=output_dir
        )
        completed = self.work / (
            "phase-" + f"{self.phase_index:03d}" + "-complete.json"
        )
        fresh.save(
            completed,
            {"owner": self.owner, "phase": self.current_phase, "state": "COMPLETE"},
        )
        return receipt

    def remove_owned_clone(self, container: str, volume: str) -> None:
        view = self.inspect_container(container)
        labels = view.get("labels") or {}
        if (
            labels.get(EPOCH_LABEL) != self.owner
            or labels.get("com.kairos.runtime-epoch.scope") != EPOCH_SCOPE
        ):
            raise Rejected("OWNED_DISPOSABLE_CLONE_REQUIRED_FOR_CLEANUP")
        self.docker(["rm", "-f", container])
        volume_view = json.loads(
            self.docker(["volume", "inspect", "--format", "{{json .}}", volume])
        )
        labels = volume_view.get("Labels") or {}
        if (
            volume_view.get("Name") != volume
            or labels.get(EPOCH_LABEL) != self.owner
            or labels.get("com.kairos.runtime-epoch.scope") != EPOCH_SCOPE
        ):
            raise Rejected("OWNED_DISPOSABLE_VOLUME_REQUIRED_FOR_CLEANUP")
        self.docker(["volume", "rm", volume])
        key = (
            "temporary_source_cleanup_verified"
            if container == self.names["source_pg"]
            else "temporary_restore_cleanup_verified"
        )
        self.proofs[key] = True

    def stop_owned_after_failure(self) -> None:
        # Keep the fresh target PG/Redis volumes running for forensic review;
        # only stop active workers/serve and disposable source/restore clones.
        candidates = {self.names[key] for key in ("source_pg", "restore_pg", "serve")}
        candidates.update(
            name
            for name in self.created
            if name.startswith("kairos-epoch-" + self.owner[:12] + "-")
        )
        candidates.discard(self.names["target_pg"])
        candidates.discard(self.names["redis"])
        for name in sorted(candidates):
            try:
                view = self.inspect_container(name)
            except Exception:  # noqa: BLE001,S112 - missing containers are already stopped/removed.
                continue
            labels = view.get("labels") or {}
            if (
                labels.get(EPOCH_LABEL) != self.owner
                or labels.get("com.kairos.runtime-epoch.scope") != EPOCH_SCOPE
            ):
                continue
            if (view.get("state") or {}).get("Status") == "running":
                try:
                    self.docker(["stop", "--time=15", name], seconds=25)
                except Exception:  # noqa: BLE001,S110 - preserve the original failure and retain forensics.
                    pass

    def prepare_snapshots(self) -> None:
        manifest = validate_wheelhouse(self.wheelhouse, WHEEL_MANIFEST_SHA256)
        self.runtime_wheelhouse = self.work / "runtime-wheelhouse"
        self.runtime_wheelhouse.mkdir()
        for filename in (
            "manifest.json",
            *(package["wheel"] for package in manifest["packages"]),
        ):
            source = self.wheelhouse / filename
            if source.is_symlink() or not source.is_file():
                raise Rejected("VERIFIED_OFFLINE_WHEEL_INPUT_REQUIRED")
            fresh.write(self.runtime_wheelhouse / filename, source.read_bytes())
        validate_wheelhouse(
            self.runtime_wheelhouse, WHEEL_MANIFEST_SHA256, exact_files=True
        )
        self.operator_snapshot = self.work / "operator"
        self.quant_snapshot = self.work / "quant"
        operator_manifest = extract_git_snapshot(
            REPO,
            self.expected_revision,
            (
                "scripts/runtime_epoch_worker.py",
                "scripts/runtime_epoch_history_seed.py",
                "scripts/controlled_runtime_worker.py",
            ),
            self.operator_snapshot,
            strip_prefix="scripts",
        )
        required = {
            "runtime_epoch_worker.py",
            "runtime_epoch_history_seed.py",
            "controlled_runtime_worker.py",
        }
        if not required.issubset(operator_manifest):
            raise Rejected("EXACT_OPERATOR_WORKER_SNAPSHOT_REQUIRED")
        quant_manifest = extract_git_snapshot(
            QUANT_REPO, QUANT_REVISION, ("kairos_quant",), self.quant_snapshot
        )
        if not any(path.startswith("kairos_quant/") for path in quant_manifest):
            raise Rejected("QUANT_RUNTIME_PACKAGE_SNAPSHOT_REQUIRED")
        self.proofs["operator_snapshot_sha256"] = fresh.digest(operator_manifest)
        self.proofs["quant_snapshot_sha256"] = fresh.digest(quant_manifest)

    def run_epoch(self, *, end_exclusive_ms: int, secrets_map: dict) -> dict:
        owner = self.owner
        database = "kairos_epoch_" + owner[:12]
        source_database = "kairos_recovery_" + owner[:12] + "_epoch"
        restore_database = "kairos_recovery_" + owner[:12] + "_epochrestore"
        target_secret = self.work / "target-admin-password"
        source_secret = self.work / "source-admin-password"
        restore_secret = self.work / "restore-admin-password"
        for path, key in (
            (target_secret, "admin_password"),
            (source_secret, "source_admin_password"),
            (restore_secret, "restore_admin_password"),
        ):
            fresh.write(path, secrets_map[key].encode("ascii"))
        acl_path = self.work / "redis-users.acl"
        fresh.write(
            acl_path,
            redis_acl_text(
                owner,
                admin_password=secrets_map["redis_admin_password"],
                producer_password=secrets_map["redis_producer_password"],
                consumer_password=secrets_map["redis_consumer_password"],
            ).encode("ascii"),
        )

        before = self.assert_legacy_sources_stopped(legacy_redis_id=LEGACY_REDIS_ID)
        self.proofs["legacy_before"] = before
        self.create_network()
        for item in (
            "target_volume",
            "source_volume",
            "restore_volume",
            "redis_volume",
        ):
            self.create_volume(self.names[item])
        for item, uid in (
            ("target_volume", 70),
            ("source_volume", 70),
            ("restore_volume", 70),
            ("redis_volume", 999),
        ):
            self.initialize_volume(self.names[item], uid=uid)

        dump_mount = ("--mount", f"type=bind,src={DUMP},dst=/archive.dump,readonly")
        self.create_database(
            name=self.names["source_pg"],
            volume=self.names["source_volume"],
            password_path=source_secret,
            database=source_database,
            extra_mounts=dump_mount,
            watchdog_seconds=1500,
        )
        self.wait_postgres(self.names["source_pg"])
        self.restore_accepted_dump(self.names["source_pg"], source_database)
        self.create_database(
            name=self.names["target_pg"],
            volume=self.names["target_volume"],
            password_path=target_secret,
            database=database,
        )
        self.wait_postgres(self.names["target_pg"])
        self.create_redis(acl_path=acl_path, volume=self.names["redis_volume"])

        common = {
            "owner": owner,
            "database": database,
            "pg_host": self.names["target_pg"],
            "redis_host": self.names["redis"],
        }
        prepare = {
            **common,
            "admin_password": secrets_map["admin_password"],
            "source_host": self.names["source_pg"],
            "source_database": source_database,
            "source_admin_password": secrets_map["source_admin_password"],
            "source_password": secrets_map["source_password"],
            "history_password": secrets_map["history_password"],
            "producer_password": secrets_map["producer_password"],
            "consumer_password": secrets_map["consumer_password"],
        }
        self.phase("prepare", prepare)
        seed_config = {
            **common,
            "source_host": self.names["source_pg"],
            "source_database": source_database,
            "source_password": secrets_map["source_password"],
            "history_password": secrets_map["history_password"],
            "seed_expectation": {"accepted_dump_sha256": DUMP_SHA256},
            "source_dump_sha256": DUMP_SHA256,
        }
        seed = self.phase("seed", seed_config)
        expected_count = {
            symbol: 34_633 if symbol != "XRPUSDT" else 34_632 for symbol in SYMBOLS
        }
        expected_last = 1_789_832_580_000
        anchors = seed.get("anchors")
        if (
            seed.get("target_outbox_rows_after") != 0
            or seed.get("rows") != sum(expected_count.values())
            or re.fullmatch(r"[0-9a-f]{64}", str(seed.get("ordered_digest_sha256", "")))
            is None
            or not isinstance(anchors, dict)
            or set(anchors) != set(SYMBOLS)
        ):
            raise Rejected("SEEDED_TARGET_OUTBOX_MUST_REMAIN_EMPTY")
        for symbol, anchor in anchors.items():
            expected_first = expected_last - (expected_count[symbol] - 1) * MINUTE_MS
            if (
                anchor.get("count") != expected_count[symbol]
                or anchor.get("first_open_time_ms") != expected_first
                or anchor.get("last_open_time_ms") != expected_last
                or anchor.get("last_close_time_ms") != expected_last + MINUTE_MS - 1
            ):
                raise Rejected("EXACT_ACCEPTED_FIVE_SYMBOL_SEED_REQUIRED")
        self.remove_owned_clone(self.names["source_pg"], self.names["source_volume"])

        rolling = copy.deepcopy(seed)
        batches = 0
        while (
            min(
                anchor["last_close_time_ms"] + 1
                for anchor in rolling["anchors"].values()
            )
            < end_exclusive_ms
        ):
            end = catchup_end_exclusive_ms(rolling, end_exclusive_ms)
            batches += 1
            if batches > 32:
                raise Rejected("FIXED_CATCHUP_BATCH_COUNT_EXCEEDED")
            catchup = self.phase(
                "catchup",
                {
                    **common,
                    "history_password": secrets_map["history_password"],
                    "end_exclusive_ms": end,
                    "maximum_bars": MAX_CATCHUP_BARS,
                },
                suffix=f"{batches:02d}",
            )
            appended = catchup.get("appended")
            if (
                not isinstance(appended, dict)
                or set(appended) != set(SYMBOLS)
                or any(type(n) is not int or n < 0 for n in appended.values())
                or sum(appended.values()) > MAX_CATCHUP_BARS
            ):
                raise Rejected("BOUNDED_CATCHUP_RECEIPT_REQUIRED")
            for symbol, anchor in rolling["anchors"].items():
                anchor["count"] += appended[symbol]
                anchor["last_open_time_ms"] = end - MINUTE_MS
                anchor["last_close_time_ms"] = end - 1
        self.proofs["catchup_batches"] = batches

        backup = self.work / "epoch-history.dump"
        self.docker(
            [
                "exec",
                self.names["target_pg"],
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-privileges",
                "--username=kairos",
                "--dbname=" + database,
                "--file=/tmp/runtime-epoch-history.dump",
            ],
            seconds=180,
        )
        self.docker(
            [
                "cp",
                self.names["target_pg"] + ":/tmp/runtime-epoch-history.dump",
                str(backup),
            ],
            seconds=30,
        )
        if backup.is_symlink() or not backup.is_file() or backup.stat().st_size <= 0:
            raise Rejected("PRIVATE_EPOCH_BACKUP_REQUIRED")
        self.proofs["audit_backup_sha256"] = _sha(backup)
        restore_mount = (
            "--mount",
            f"type=bind,src={backup},dst=/archive.dump,readonly",
        )
        self.create_database(
            name=self.names["restore_pg"],
            volume=self.names["restore_volume"],
            password_path=restore_secret,
            database=restore_database,
            extra_mounts=restore_mount,
            watchdog_seconds=1500,
        )
        self.wait_postgres(self.names["restore_pg"])
        self.restore_accepted_dump(self.names["restore_pg"], restore_database)
        verify_config = {
            **common,
            "admin_password": secrets_map["admin_password"],
            "restore_host": self.names["restore_pg"],
            "restore_database": restore_database,
            "restore_admin_password": secrets_map["restore_admin_password"],
            "expected_seed": seed,
        }
        self.phase("verify-restore", verify_config)
        self.docker(
            [
                "exec",
                self.names["restore_pg"],
                "pg_amcheck",
                "--database=" + restore_database,
                "--username=kairos",
                "--heapallindexed",
                "--parent-check",
                "--rootdescend",
            ],
            seconds=240,
        )
        self.remove_owned_clone(self.names["restore_pg"], self.names["restore_volume"])

        # Qualification may publish only a short live tail (the outbox cap is
        # 100). Bound the final audit-only catch-up to a fresh server-time
        # endpoint immediately before qualification so elapsed restore time does
        # not create an unbounded publish batch.
        final_end = ((int(time.time() * 1000) - 5_000) // MINUTE_MS) * MINUTE_MS
        final_batches = 0
        while (
            min(
                anchor["last_close_time_ms"] + 1
                for anchor in rolling["anchors"].values()
            )
            < final_end
        ):
            end = catchup_end_exclusive_ms(rolling, final_end)
            final_batches += 1
            if final_batches > 32:
                raise Rejected("FINAL_CATCHUP_BATCH_COUNT_EXCEEDED")
            receipt = self.phase(
                "catchup",
                {
                    **common,
                    "history_password": secrets_map["history_password"],
                    "end_exclusive_ms": end,
                    "maximum_bars": MAX_CATCHUP_BARS,
                },
                suffix=f"final-{final_batches:02d}",
            )
            appended = receipt.get("appended")
            if (
                not isinstance(appended, dict)
                or set(appended) != set(SYMBOLS)
                or any(type(n) is not int or n < 0 for n in appended.values())
                or sum(appended.values()) > MAX_CATCHUP_BARS
            ):
                raise Rejected("FINAL_BOUNDED_CATCHUP_RECEIPT_REQUIRED")
            for symbol, anchor in rolling["anchors"].items():
                anchor["count"] += appended[symbol]
                anchor["last_open_time_ms"] = end - MINUTE_MS
                anchor["last_close_time_ms"] = end - 1
        self.proofs["finality_catchup_batches"] = final_batches
        self.proofs["finality_catchup_end_exclusive_ms"] = final_end

        runtime = {
            **common,
            "producer_password": secrets_map["producer_password"],
            "consumer_password": secrets_map["consumer_password"],
            "redis_producer_password": secrets_map["redis_producer_password"],
            "redis_consumer_password": secrets_map["redis_consumer_password"],
        }
        qualified = self.phase("qualify", runtime)
        if qualified.get("state") != "NONTRADING_RUNTIME_QUALIFIED":
            raise Rejected("NONTRADING_RUNTIME_QUALIFICATION_REQUIRED")
        self.phase("serve", runtime)
        status_path = self.work / "output-serve" / "status.json"
        cutoff = min(time.monotonic() + 180, self.deadline - 15)
        status = None
        while time.monotonic() < cutoff:
            if status_path.is_file() and not status_path.is_symlink():
                try:
                    candidate = json.loads(status_path.read_text(encoding="utf-8"))
                    if candidate.get("state") == "RUNNING_NONTRADING":
                        status = candidate
                        break
                except (OSError, json.JSONDecodeError):
                    pass
            time.sleep(2)
        if status is None:
            raise Rejected("PERSISTENT_NONTRADING_SERVE_STATUS_REQUIRED")
        validate_running_status(status, owner)
        restarted_status = self.restart_serve_and_validate(status_path, status)
        after = self.assert_legacy_sources_stopped(legacy_redis_id=LEGACY_REDIS_ID)
        if before != after:
            raise Rejected("PRESERVED_LEGACY_SOURCE_IDENTITY_CHANGED")
        self.proofs["legacy_after"] = after
        self.proofs["serve_restart_status"] = restarted_status
        return {
            "result": "PASS_NONTRADING_RUNTIME_EPOCH",
            "owner": owner,
            "database": database,
            "resources": self.names,
            "catchup_batches": batches,
            "audit_backup_sha256": self.proofs["audit_backup_sha256"],
            "serve_container": self.names["serve"],
            "proofs": self.proofs,
        }


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False)
    quoted = str(path).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; $p='"
        + quoted
        + "'; $acl=[Security.AccessControl.DirectorySecurity]::new(); $acl.SetAccessRuleProtection($true,$false); $ids=@([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')); foreach($id in $ids){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}; [IO.Directory]::SetAccessControl($p,$acl); $got=[IO.Directory]::GetAccessControl($p,[Security.AccessControl.AccessControlSections]::Access); $rules=$got.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]); if(!$got.AreAccessRulesProtected -or $rules.Count -ne 3){throw 'PRIVATE_EPOCH_ACL_REQUIRED'}; foreach($rule in $rules){if($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl' -or $rule.IdentityReference.Value -notin @($ids.Value)){throw 'PRIVATE_EPOCH_EXACT_DACL_REQUIRED'}}"
    )
    result = subprocess.run(
        [str(PS), "-NoProfile", "-NonInteractive", "-Command", command],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
        shell=False,
        env=fresh.supervisor_environment(),
    )
    if result.returncode:
        raise Rejected("PRIVATE_EPOCH_DIRECTORY_ACL_FAILED")


def _verify_source_signature(work: Path) -> None:
    """Use the already-pinned local signer/keyring path; never fetch keys."""

    class Verifier:
        def __init__(self, directory: Path):
            self.work = directory

        def process(self, executable, arguments, seconds, label="source-proof"):
            outpath = self.work / (label + ".stdout")
            errpath = self.work / (label + ".stderr")
            with outpath.open("xb") as out, errpath.open("xb") as err:
                result = subprocess.run(
                    [str(executable), *arguments],
                    cwd=REPO,
                    env=fresh.supervisor_environment(),
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    shell=False,
                    timeout=seconds,
                    check=False,
                )
            if result.returncode:
                raise Rejected("SIGNED_SOURCE_PROOF_VERIFICATION_FAILED")

    primary._verify_signature(
        Verifier(work),
        NATIVE_VERIFY,
        NATIVE_VERIFY.with_suffix(".json.asc"),
        "source-proof",
    )


def _validate_admission(args: argparse.Namespace) -> None:
    if os.name != "nt" or not args.execute:
        raise Rejected("EXACT_WINDOWS_EXECUTE_ADMISSION_REQUIRED")
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_revision or "") is None:
        raise Rejected("EXACT_SIGNED_MAIN_REVISION_REQUIRED")
    if args.expected_legacy_redis_id != LEGACY_REDIS_ID:
        raise Rejected("EXACT_LEGACY_REDIS_ID_REQUIRED")
    if _sha(DUMP) != DUMP_SHA256:
        raise Rejected("PINNED_ACCEPTED_DUMP_REQUIRED")
    if (
        _sha(NATIVE_VERIFY) != NATIVE_VERIFY_SHA256
        or _sha(primary.TRUSTED_KEY) != primary.TRUSTED_KEY_SHA256
    ):
        raise Rejected("PINNED_SIGNED_SOURCE_PROOF_REQUIRED")
    wheelhouse = fresh.safe(args.wheelhouse)
    validate_wheelhouse(wheelhouse, args.expected_wheel_manifest_sha256)
    quant_lock = subprocess.run(
        [str(GIT), "-C", str(QUANT_REPO), "show", QUANT_REVISION + ":uv.lock"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=True,
        shell=False,
    ).stdout
    validate_aux_wheelhouse(AUX_WHEELHOUSE, quant_lock)
    status = subprocess.run(
        [str(GIT), "-C", str(REPO), "status", "--porcelain"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=True,
        shell=False,
    ).stdout
    signer = (
        subprocess.run(
            [str(GIT), "-C", str(REPO), "log", "-1", "--format=%G? %GF"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=True,
            shell=False,
        )
        .stdout.decode()
        .strip()
    )
    if status or signer != "G " + fresh.SIGNER:
        raise Rejected("CLEAN_SIGNED_DEPLOY_HEAD_REQUIRED")
    for ref in ("HEAD", "origin/main"):
        revision = (
            subprocess.run(
                [str(GIT), "-C", str(REPO), "rev-parse", ref],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=True,
                shell=False,
            )
            .stdout.decode()
            .strip()
        )
        if revision != args.expected_revision:
            raise Rejected("EXACT_REVIEWED_MAIN_ORIGIN_REVISION_REQUIRED")
    branch = (
        subprocess.run(
            [str(GIT), "-C", str(REPO), "branch", "--show-current"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=True,
            shell=False,
        )
        .stdout.decode()
        .strip()
    )
    if branch != "main":
        raise Rejected("CLEAN_SIGNED_MAIN_BRANCH_REQUIRED")
    for repo, revision in (
        (Path("D:/Kairos/kairos-core"), CORE_REVISION),
        (Path("D:/Kairos/kairos-persistence"), PERSISTENCE_REVISION),
        (QUANT_REPO, QUANT_REVISION),
    ):
        for ref in ("HEAD", "origin/main"):
            actual = (
                subprocess.run(
                    [str(GIT), "-C", str(repo), "rev-parse", ref],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    check=True,
                    shell=False,
                )
                .stdout.decode()
                .strip()
            )
            if actual != revision:
                raise Rejected("EXACT_SIGNED_SOURCE_MAIN_REQUIRED")
        status_other = subprocess.run(
            [
                str(GIT),
                "-C",
                str(repo),
                "status",
                "--porcelain",
                "--untracked-files=no",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=True,
            shell=False,
        ).stdout
        signer_other = (
            subprocess.run(
                [str(GIT), "-C", str(repo), "log", "-1", "--format=%G? %GF"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=True,
                shell=False,
            )
            .stdout.decode()
            .strip()
        )
        if status_other or signer_other != "G " + fresh.SIGNER:
            raise Rejected("CLEAN_SIGNED_RUNTIME_MAIN_REQUIRED")
        branch_other = (
            subprocess.run(
                [str(GIT), "-C", str(repo), "branch", "--show-current"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=True,
                shell=False,
            )
            .stdout.decode()
            .strip()
        )
        if branch_other != "main":
            raise Rejected("SIGNED_RUNTIME_MAIN_BRANCH_REQUIRED")
    for relative in (
        "scripts/runtime_epoch_controller.py",
        "scripts/fresh_runtime_recovery.py",
        "scripts/buildkit_resource_gate.py",
    ):
        committed = subprocess.run(
            [
                str(GIT),
                "-C",
                str(REPO),
                "show",
                args.expected_revision + ":" + relative,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=True,
            shell=False,
        ).stdout
        if hashlib.sha256(committed).hexdigest() != _sha(REPO / relative):
            raise Rejected("REVIEWED_EPOCH_CONTROLLER_SOURCE_REQUIRED")


def _failure_category(exc: BaseException) -> str:
    """Return only a fixed rejection code or exception type, never driver text."""
    if isinstance(exc, Rejected):
        value = str(exc)
        if re.fullmatch(r"[A-Z0-9_]{1,96}", value):
            return value
    name = type(exc).__name__
    return (
        name if re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,47}", name) else "OperationFailed"
    )


def _persist_failure_receipt(
    work: Path | None,
    owner: str | None,
    controller: EpochController | None,
    exc: BaseException,
    *,
    private_ready: bool,
) -> Path | None:
    """Create a sanitized immutable failure record while preserving owned data."""
    if (
        not private_ready
        or work is None
        or owner is None
        or not work.is_dir()
        or work.is_symlink()
    ):
        return None
    resources = resource_names(owner)
    created = []
    if controller is not None:
        try:
            controller.stop_owned_after_failure()
        except Exception:  # noqa: BLE001,S110 - cleanup is best effort and must not mask the original failure.
            # Cleanup is best effort and fail-closed; receipt generation below
            # deliberately does not include raw Docker/driver output.
            pass
        created = sorted(
            {
                name
                for name in controller.created
                if name in resources.values()
                or name.startswith("kairos-epoch-" + owner[:12] + "-")
            }
        )
    receipt = work / "runtime-epoch-failure.json"
    if receipt.exists() or receipt.is_symlink():
        return None
    try:
        fresh.save(
            receipt,
            {
                "result": "FAILED_CLOSED",
                "owner": owner,
                "phase": controller.current_phase
                if controller is not None
                else "ADMISSION",
                "error_category": _failure_category(exc),
                "resources": resources,
                "created_resources": created,
                "preserved_forensics": True,
                "active_lease_preserved": ACTIVE_LEASE.is_file()
                and not ACTIVE_LEASE.is_symlink(),
                "trading_started": False,
            },
        )
        return receipt
    except Exception:  # noqa: BLE001 - leave a partial failure receipt untouched.
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--expected-revision")
    parser.add_argument("--expected-legacy-redis-id")
    parser.add_argument("--end-exclusive-ms", type=int)
    parser.add_argument("--wheelhouse", type=Path, default=DEFAULT_WHEELHOUSE)
    parser.add_argument(
        "--expected-wheel-manifest-sha256", default=WHEEL_MANIFEST_SHA256
    )
    args = parser.parse_args(argv)
    if not args.execute:
        print(
            json.dumps(
                {
                    "result": "PLAN_ONLY",
                    "writes": False,
                    "legacy_source_start": False,
                    "legacy_source_sql_or_redis_commands": 0,
                    "target": "separate owner-labelled PG/Redis volumes and private bridge",
                    "catchup_cap": MAX_CATCHUP_BARS,
                    "serve": "non-trading consumer-only",
                },
                sort_keys=True,
            )
        )
        return 0
    owner = None
    work = None
    controller = None
    private_ready = False
    try:
        _validate_admission(args)
        if (
            type(args.end_exclusive_ms) is not int
            or args.end_exclusive_ms % 60_000
            or args.end_exclusive_ms > int(time.time() * 1000) - 5_000
        ):
            raise Rejected("FIXED_CLOSED_END_EXCLUSIVE_REQUIRED")
        if ACTIVE_LEASE.exists() or ACTIVE_LEASE.is_symlink():
            raise Rejected("ANOTHER_RUNTIME_EPOCH_ALREADY_ADMITTED")
        owner = uuid.uuid4().hex
        ROOT.mkdir(parents=True, exist_ok=True)
        work = fresh.safe(ROOT / ("run-" + owner))
        _private_directory(work)
        private_ready = True
        _verify_source_signature(work)
        with ACTIVE_LEASE.open("xb") as stream:
            stream.write((owner + "\n").encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        names = resource_names(owner)
        private_secrets = {
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
        fresh.save(
            work / "epoch-private.json",
            {
                "owner": owner,
                "database": "kairos_epoch_" + owner[:12],
                **private_secrets,
            },
        )
        controller = EpochController(
            owner,
            expected_revision=args.expected_revision,
            wheelhouse=args.wheelhouse,
            deadline=time.monotonic() + MAX_SECONDS,
        )
        controller.prepare_snapshots()
        result = controller.run_epoch(
            end_exclusive_ms=args.end_exclusive_ms, secrets_map=private_secrets
        )
        receipt = work / "runtime-epoch-receipt.json"
        fresh.save(receipt, result)
        print(
            json.dumps(
                {
                    "result": result["result"],
                    "owner": owner,
                    "resources": names,
                    "receipt": str(receipt),
                    "secrets": "private-file-only",
                    "native_operations": "bounded-owner-only",
                },
                sort_keys=True,
            )
        )
        return 0
    except BaseException as exc:  # noqa: BLE001 - include cancellation in fail-closed cleanup.
        failure_receipt = _persist_failure_receipt(
            work, owner, controller, exc, private_ready=private_ready
        )
        print(
            json.dumps(
                {
                    "result": "FAILED_CLOSED",
                    "error_category": _failure_category(exc),
                    "owner": owner,
                    "receipt": str(failure_receipt) if failure_receipt else None,
                    "native_operations": "bounded-owner-only",
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
