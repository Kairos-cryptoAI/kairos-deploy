"""Guarded, hash-bound reboot recovery of one existing CLOSED_BAR-only epoch.

No legacy database/queue is addressed. Docker restart policies deliberately
remain off: only this controller may start the three exact admitted resources.
Every ambiguous/failed run leaves a durable latch; there is no automatic retry.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_controller as epoch
else:
    import runtime_epoch_controller as epoch

fresh = epoch.fresh
IS_WINDOWS = os.name == "nt"
OWNER = epoch.CONTINUATION_OWNER
ROOT = Path("D:/Kairos/runtime/epoch-boot-20261011")
PARENT = epoch.ROOT / ("run-" + OWNER)
SERVE_WORK = PARENT / "continuation-05"
SCOPE = "kairos-nontrading-runtime-epoch-boot-v1"
GENERATION = "original"
RECEIPT_NAME = "runtime-epoch-continuation-receipt.json"
PYTHON = Path(
    # Task Scheduler runs outside Codex's packaged AppData virtualization.
    # Pin the physical installation, not its in-app Roaming alias.
    "C:/Users/loval/AppData/Local/Packages/OpenAI.Codex_2p2nqsd0c76g0/"
    "LocalCache/Roaming/uv/python/cpython-3.11.15-windows-x86_64-none/python.exe"
)
PARENT_RECEIPT_SHA256 = (
    "9e5b66868c4e01d1b047d3603eba6fc9673419e838da34e1bd54d579fa70ec4b"
)
CONTAINERS = {
    "pg": epoch.CONTINUATION_04_TARGET_PG_ID,
    "redis": epoch.CONTINUATION_04_REDIS_ID,
    "serve": "f171285853b1ddae798dd11767c2292a133b874ab2928cce8bb8434fe5798981",
}
MAX_SECONDS = 3600
LEASE = ROOT / "boot.active"
STANDBY_NAME = "kairos-shadow-gate-timescaledb-1"
STANDBY_ID = "658849c3945081f628ed2acd78ae85f4a95513f6a72517c533c05a1d3a9f8079"
STANDBY_NETWORK = "kairos-shadow-gate_data"


def stable_standby_metadata(value: dict) -> dict:
    """Canonicalize only natural Docker health-check clock churn.

    This is intentionally pinned to the one reviewed standby identity. Every
    other metadata field remains in the projection; only Start/End strings in
    its bounded health log are removed after validating the complete schema.
    """
    projected = epoch.normalize_container_metadata(json.loads(json.dumps(value)))
    state = projected.get("state")
    health = state.get("Health") if isinstance(state, dict) else None
    logs = health.get("Log") if isinstance(health, dict) else None
    if (
        projected.get("id") != STANDBY_ID
        or (state or {}).get("Status") != "running"
        or not isinstance(health, dict)
        or set(health) != {"Status", "FailingStreak", "Log"}
        or health.get("Status") != "healthy"
        or type(health.get("FailingStreak")) is not int
        or health["FailingStreak"] != 0
        or not isinstance(logs, list)
        or not 1 <= len(logs) <= 5
    ):
        raise epoch.Rejected("BOOT_STANDBY_HEALTH_METADATA_CONFLICT")
    timestamp = re.compile(r"^\d{4}-\d{2}-\d{2}T[^\s]{1,40}Z$")
    for row in logs:
        if (
            not isinstance(row, dict)
            or set(row) != {"Start", "End", "ExitCode", "Output"}
            or not isinstance(row.get("Start"), str)
            or not timestamp.fullmatch(row["Start"])
            or not isinstance(row.get("End"), str)
            or not timestamp.fullmatch(row["End"])
            or type(row.get("ExitCode")) is not int
            or not isinstance(row.get("Output"), str)
            or len(row["Output"]) > 4096
        ):
            raise epoch.Rejected("BOOT_STANDBY_HEALTH_LOG_SHAPE_CONFLICT")
        del row["Start"]
        del row["End"]
    return projected


def configure_generation_r2() -> None:
    """Bind only the accepted new generation; never restart the failed original."""
    global \
        ROOT, \
        SERVE_WORK, \
        SCOPE, \
        GENERATION, \
        RECEIPT_NAME, \
        PARENT_RECEIPT_SHA256, \
        CONTAINERS, \
        LEASE
    ROOT = Path("D:/Kairos/runtime/epoch-boot-r2-20261012")
    SERVE_WORK = Path(
        "D:/Kairos/runtime/runtime-incident-20261012/recovery-46b8f4e6f06841a29bbafc0b271393d2"
    )
    SCOPE = "kairos-nontrading-runtime-epoch-boot-r2-v1"
    GENERATION = "r2"
    RECEIPT_NAME = "receipt.json"
    PARENT_RECEIPT_SHA256 = (
        "095d8965d561851c57aff4e412ee4082422c6026f2f612841c703e4689efc855"
    )
    CONTAINERS = {
        "pg": epoch.CONTINUATION_04_TARGET_PG_ID,
        "redis": epoch.CONTINUATION_04_REDIS_ID,
        "serve": "87b9c085beb1f7666fefc8e3bc2fded72c44397992482fd6efc2a43459a046b0",
    }
    LEASE = ROOT / "boot.active"


def configure_generation_r4() -> None:
    """Bind only the accepted R4 generation and its transport04 restore clone."""
    global \
        ROOT, \
        SERVE_WORK, \
        SCOPE, \
        GENERATION, \
        RECEIPT_NAME, \
        PARENT_RECEIPT_SHA256, \
        CONTAINERS, \
        LEASE
    ROOT = Path("D:/Kairos/runtime/epoch-boot-r4-20261012")
    SERVE_WORK = Path(
        "D:/Kairos/runtime/runtime-incident-20261012/clean-recovery-r4-97469e3b772b4d00b0b531282ba01b55"
    )
    SCOPE = "kairos-nontrading-runtime-epoch-boot-r4-v1"
    GENERATION = "r4"
    RECEIPT_NAME = "receipt.json"
    PARENT_RECEIPT_SHA256 = (
        "0a7a621991a328d9fedb8c203cc0da53a835e0a3c02f6549bacf4ef650dba03f"
    )
    CONTAINERS = {
        "pg": epoch.CONTINUATION_04_TARGET_PG_ID,
        "redis": epoch.CONTINUATION_04_REDIS_ID,
        "serve": "1f9da09121bd509c5aa1d1a698c98334bc1e5378ee4978b65d98885cff19e199",
    }
    LEASE = ROOT / "boot.active"


def read_json(path: Path, *, limit: int = 131_072) -> dict:
    fresh.safe(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise epoch.Rejected("BOUNDED_BOOT_JSON_REQUIRED")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise epoch.Rejected("BOOT_JSON_OBJECT_REQUIRED")
    return value


def git(*args: str) -> str:
    result = subprocess.run(
        [str(epoch.GIT), "-C", str(epoch.REPO), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=False,
        shell=False,
    )
    if result.returncode or len(result.stdout) > 1_048_576:
        raise epoch.Rejected("BOOT_SIGNED_SOURCE_CHECK_FAILED")
    return result.stdout.decode("utf-8").strip()


def verify_source(revision: str) -> None:
    if (
        re.fullmatch(r"[0-9a-f]{40}", revision or "") is None
        or git("branch", "--show-current") != "main"
        or git("status", "--porcelain")
        or any(git("rev-parse", ref) != revision for ref in ("HEAD", "origin/main"))
        or git("log", "-1", "--format=%G? %GF") != "G " + fresh.SIGNER
    ):
        raise epoch.Rejected("BOOT_REQUIRES_CLEAN_EXACT_SIGNED_MAIN")
    git("verify-commit", revision)


def input_paths() -> list[Path]:
    paths = [
        PARENT / "target-admin-password",
        PARENT / "redis-users.acl",
        PARENT / "continuation-04/continuation-private.json",
        SERVE_WORK / "config-serve.json",
        SERVE_WORK / RECEIPT_NAME,
        SERVE_WORK / "operator.zip",
        epoch.AUX_WHEELHOUSE / epoch.AUX_NUMPY,
        epoch.ACTIVE_LEASE,
    ]
    if any(not fresh.safe(path).is_file() for path in paths):
        raise epoch.Rejected("ADMITTED_BOOT_INPUT_MISSING")
    for directory in ("operator", "quant", "runtime-wheelhouse"):
        paths.extend(sorted((SERVE_WORK / directory).rglob("*")))
    return [fresh.safe(path) for path in paths if path.is_file()]


def validate_binding(value: dict) -> None:
    if (
        value.get("schema_version") != 1
        or value.get("owner") != OWNER
        or value.get("scope") != SCOPE
        or value.get("generation", "original") != GENERATION
        or value.get("repo") != epoch.REPO.as_posix()
        or value.get("python_path") != PYTHON.as_posix()
        or value.get("entry_script") != "scripts/runtime_epoch_boot.py"
        or value.get("launcher_script") != "scripts/Invoke-NonTradingEpochBoot.ps1"
        or value.get("containers") != CONTAINERS
        or value.get("parent_receipt_sha256") != PARENT_RECEIPT_SHA256
        or re.fullmatch(r"[0-9a-f]{40}", str(value.get("revision"))) is None
    ):
        raise epoch.Rejected("EXACT_SINGLE_NONTRADING_BOOT_BINDING_REQUIRED")
    sources = value.get("source_files")
    inputs = value.get("inputs")
    if (
        not isinstance(sources, dict)
        or not {value["entry_script"], value["launcher_script"]}.issubset(sources)
        or not isinstance(inputs, dict)
        or set(inputs) != {path.as_posix() for path in input_paths()}
    ):
        raise epoch.Rejected("EXACT_BOOT_FILE_INVENTORY_REQUIRED")
    for name, digest in sources.items():
        if (
            not re.fullmatch(r"scripts/[A-Za-z0-9_./-]+", name)
            or ".." in Path(name).parts
            or re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
            or fresh.sha(fresh.safe(epoch.REPO / name)) != digest
        ):
            raise epoch.Rejected("BOOT_SOURCE_BYTES_CHANGED")
    for name, digest in inputs.items():
        if (
            re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
            or fresh.sha(fresh.safe(Path(name))) != digest
        ):
            raise epoch.Rejected("ADMITTED_EPOCH_PRIVATE_INPUT_CHANGED")
    if epoch.ACTIVE_LEASE.read_text().strip() != OWNER:
        raise epoch.Rejected("EXISTING_EPOCH_OWNER_LEASE_REQUIRED")


def create_binding(revision: str) -> Path:
    verify_source(revision)
    if fresh.sha(SERVE_WORK / RECEIPT_NAME) != PARENT_RECEIPT_SHA256:
        raise epoch.Rejected("ACCEPTED_EPOCH_PARENT_RECEIPT_REQUIRED")
    epoch._private_directory(ROOT)
    path = ROOT / "binding.json"
    sources = {}
    for name in git("ls-files", "scripts").splitlines():
        if name.endswith((".py", ".ps1")):
            sources[name] = fresh.sha(fresh.safe(epoch.REPO / name))
    value = {
        "schema_version": 1,
        "owner": OWNER,
        "scope": SCOPE,
        "generation": GENERATION,
        "revision": revision,
        "repo": epoch.REPO.as_posix(),
        "python_path": PYTHON.as_posix(),
        "entry_script": "scripts/runtime_epoch_boot.py",
        "launcher_script": "scripts/Invoke-NonTradingEpochBoot.ps1",
        "source_files": sources,
        "inputs": {p.as_posix(): fresh.sha(p) for p in input_paths()},
        "containers": CONTAINERS,
        "parent_receipt_sha256": PARENT_RECEIPT_SHA256,
    }
    validate_binding(value)
    fresh.save(path, value)
    return path


def core_snapshot(value: dict) -> dict:
    return {
        k: v
        for k, v in value.items()
        if k not in {"mode", "owner", "new_epoch_database"}
    }


def validate_preserved_state(before: dict, after: dict) -> None:
    if (
        before.get("state") != "PASS_BOOT_STATE"
        or after.get("state") != "PASS_BOOT_STATE"
        or before.get("original_prefix") != after.get("original_prefix")
    ):
        raise epoch.Rejected("BOOT_HISTORY_PREFIX_OR_STATE_CONFLICT")
    old_tables, new_tables = before["tables"], after["tables"]
    if set(old_tables) != set(new_tables) or any(
        old_tables[k] != new_tables[k] for k in old_tables if k != "event_audit"
    ):
        raise epoch.Rejected("BOOT_CHANGED_EXISTING_QUEUES_OR_OTHER_TABLES")
    if before["sequences"] != after["sequences"]:
        raise epoch.Rejected("BOOT_CHANGED_EXISTING_SEQUENCES")
    if new_tables["event_audit"]["count"] < old_tables["event_audit"]["count"]:
        raise epoch.Rejected("BOOT_AUDIT_HISTORY_ROLLBACK")


class BootController(epoch.EpochController):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if GENERATION in {"r2", "r4"}:
            self.names["serve"] += "-" + GENERATION
        if GENERATION == "r2":
            # Original unverified restore resources remain retained and stopped.
            # Reuse only the separate, previously verified disposable names.
            self.names["restore_pg"] += "-incident03"
            self.names["restore_volume"] += "-incident03"
        elif GENERATION == "r4":
            self.names["restore_pg"] += "-transport04"
            self.names["restore_volume"] += "-transport04"

    def validate_isolated_standby(self) -> dict:
        """Leave one already-running, unrelated test DB untouched and isolated."""
        value = self.inspect_container(STANDBY_NAME)
        labels = value.get("labels") or {}
        if (
            value.get("id") != STANDBY_ID
            or value.get("image") != epoch.PG_IMAGE.split("@", 1)[-1]
            or labels.get("com.docker.compose.project") != "kairos-shadow-gate"
            or labels.get("com.docker.compose.service") != "timescaledb"
            or value.get("network") != STANDBY_NETWORK
            or set((value.get("networks") or {}).keys()) != {STANDBY_NETWORK}
            or value.get("ports")
            or value.get("privileged")
            or (value.get("state") or {}).get("Status") != "running"
        ):
            raise epoch.Rejected("BOOT_STANDBY_DATABASE_ISOLATION_CONFLICT")
        self.require_mount_set(
            STANDBY_NAME,
            {
                "kairos-shadow-gate_ts-data": ("/var/lib/postgresql/data", True),
                "D:/Kairos/runtime/shadow-gate/secrets/postgres_password": (
                    "/run/secrets/postgres_password",
                    False,
                ),
                "D:/Kairos/kairos-deploy/timescaledb/schema.sql": (
                    "/docker-entrypoint-initdb.d/001-kairos.sql",
                    False,
                ),
            },
        )
        return {
            "left_untouched": True,
            "metadata": stable_standby_metadata(value),
        }

    def fail_closed_cleanup(self) -> None:
        candidates = set(self.created)
        if self.proofs.get("serve_start_intent"):
            candidates.add(self.names["serve"])
        for name in candidates:
            try:
                view = self.inspect_container(name)
                labels = view.get("labels") or {}
                if (
                    labels.get(epoch.EPOCH_LABEL) == OWNER
                    and labels.get("com.kairos.runtime-epoch.scope")
                    == epoch.EPOCH_SCOPE
                    and (view.get("state") or {}).get("Status") == "running"
                ):
                    self.docker(["stop", "--time=15", name], seconds=25)
            except Exception:  # noqa: BLE001,S110 - retain the original failure and immutable evidence.
                pass

    def validate_resources(self, *, allow_running: bool = False) -> dict:
        legacy = self.assert_legacy_sources_stopped(
            legacy_redis_id=epoch.LEGACY_REDIS_ID
        )
        names = {
            "pg": self.names["target_pg"],
            "redis": self.names["redis"],
            "serve": self.names["serve"],
        }
        images = {
            "pg": epoch.PG_IMAGE,
            "redis": epoch.REDIS_IMAGE,
            "serve": epoch.WORKER_IMAGE,
        }
        views = {}
        for key, name in names.items():
            value = self.inspect_container(name)
            labels = value.get("labels") or {}
            if (
                value.get("id") != CONTAINERS[key]
                or value.get("image") != images[key].split("@", 1)[-1]
                or value.get("network") != self.names["network"]
                or value.get("ports")
                or value.get("readonly") is not True
                or value.get("caps") != ["ALL"]
                or value.get("privileged")
                or set((value.get("networks") or {}).keys()) != {self.names["network"]}
                or value.get("memory")
                != {"pg": 4 * 1024**3, "redis": 256 * 1024**2, "serve": 512 * 1024**2}[
                    key
                ]
                or value.get("swap") != value.get("memory")
                or value.get("cpus")
                != {"pg": 1_000_000_000, "redis": 500_000_000, "serve": 1_000_000_000}[
                    key
                ]
                or labels.get(epoch.EPOCH_LABEL) != OWNER
                or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
                or (value.get("state") or {}).get("Status") not in {"running", "exited"}
            ):
                raise epoch.Rejected("BOOT_EXACT_EXISTING_RESOURCE_REQUIRED")
            policy = json.loads(
                self.docker(
                    ["inspect", "--format", "{{json .HostConfig.RestartPolicy}}", name]
                )
            )
            if policy.get("Name") != "no":
                raise epoch.Rejected("ONLY_GUARDED_BOOT_STARTS_ALLOWED")
            views[key] = value
        allowed = (
            set(names.values()) if allow_running else {names["pg"], names["redis"]}
        )
        running = self.docker(["ps", "--format", "{{.Names}}"])
        standby = {}
        if STANDBY_NAME in running.splitlines():
            standby = self.validate_isolated_standby()
            allowed.add(STANDBY_NAME)
        if any(
            name.startswith("kairos-") and name not in allowed
            for name in running.splitlines()
        ):
            raise epoch.Rejected("BOOT_OTHER_KAIROS_PROCESS_RUNNING")
        self.require_mount_set(
            names["pg"],
            {
                self.names["target_volume"]: ("/var/lib/postgresql/data", True),
                str(PARENT / "target-admin-password"): (
                    "/run/secrets/epoch_admin_password",
                    False,
                ),
            },
        )
        self.require_mount_set(
            names["redis"],
            {
                self.names["redis_volume"]: ("/data", True),
                str(PARENT / "redis-users.acl"): ("/run/config/users.acl", False),
            },
        )
        self.require_mount_set(
            names["serve"],
            {
                str(SERVE_WORK / "config-serve.json"): (
                    epoch.CONFIG_PATH_IN_CONTAINER,
                    False,
                ),
                str(SERVE_WORK / "output-serve"): ("/output", True),
                str(SERVE_WORK / "operator"): ("/operator", False),
                str(SERVE_WORK / "runtime-wheelhouse"): ("/wheelhouse", False),
                str(SERVE_WORK / "quant"): ("/quant", False),
                str(epoch.AUX_WHEELHOUSE): ("/aux-wheels", False),
            },
        )
        return {"legacy": legacy, "views": views, "standby": standby}

    def boot_state(self, tag: str) -> dict:
        return core_snapshot(
            self.phase(
                "boot-state",
                {
                    "owner": OWNER,
                    "database": "kairos_epoch_" + OWNER[:12],
                    "pg_host": self.names["target_pg"],
                    "redis_host": self.names["redis"],
                    "admin_password": self._admin_password,
                },
                suffix=tag,
            )
        )

    def prepare_boot_restore_volume(self, tag: str) -> None:
        """Create only a fresh owned disposable volume for this exact boot backup."""
        if tag not in {"bootbefore", "bootafter"}:
            raise epoch.Rejected("EXACT_BOOT_BACKUP_TAG_REQUIRED")
        volume = self.names["restore_volume"]
        clone = self.names["restore_pg"]
        volumes = self.docker(
            ["volume", "ls", "--filter", "name=" + volume, "--format", "{{.Name}}"]
        ).splitlines()
        clones = self.docker(
            ["ps", "-a", "--filter", "name=^/" + clone + "$", "--format", "{{.Names}}"]
        ).splitlines()
        if volume in volumes or clones:
            raise epoch.Rejected("BOOT_RESTORE_RESOURCES_MUST_BE_ABSENT")
        self.create_volume(volume)
        self.initialize_volume(volume, uid=70)
        self.proofs[tag + "_restore_volume"] = {
            "name": volume,
            "fresh_owner_labelled": True,
            "initialized_uid": 70,
        }

    def run_boot(self) -> dict:
        before_resources = self.validate_resources(allow_running=True)
        self.proofs["isolated_standby"] = before_resources["standby"]
        previous = read_json(SERVE_WORK / "output-serve/status.json")
        state = (before_resources["views"]["serve"].get("state") or {}).get("Status")
        if state == "running":
            epoch.validate_running_status(previous, OWNER)
            if any(
                v["state"]["Status"] != "running"
                for v in before_resources["views"].values()
            ):
                raise epoch.Rejected("BOOT_PARTIAL_RUNNING_EPOCH_REJECTED")
            return {
                "result": "ALREADY_RUNNING_NONTRADING",
                "status": previous,
                "legacy_unchanged": True,
                "trading_started": False,
            }
        if (
            previous.get("state") != "RUNNING_NONTRADING"
            or previous.get("owner") != OWNER
        ):
            raise epoch.Rejected("FAILED_EPOCH_REQUIRES_OPERATOR_REVIEW")
        # A stale timestamp is expected after reboot; all remaining status guards apply.
        observed = datetime.fromisoformat(
            previous["observed_at_utc"].replace("Z", "+00:00")
        )
        epoch.validate_running_status(
            previous, OWNER, now_ms=int(observed.timestamp() * 1000)
        )
        self.validate_resources()
        quant_lock = subprocess.run(
            [
                str(epoch.GIT),
                "-C",
                str(epoch.QUANT_REPO),
                "show",
                epoch.QUANT_REVISION + ":uv.lock",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=True,
            shell=False,
        ).stdout
        epoch.validate_aux_wheelhouse(epoch.AUX_WHEELHOUSE, quant_lock)
        self.prepare_snapshots()
        for key in ("target_pg", "redis"):
            name = self.names[key]
            if self.inspect_container(name)["state"]["Status"] == "exited":
                self.docker(["start", name])
        self.wait_postgres(self.names["target_pg"])
        self._admin_password = (PARENT / "target-admin-password").read_text().strip()
        before = self.boot_state("before")
        self.proofs["before_state"] = before
        self.prepare_boot_restore_volume("bootbefore")
        self.proofs["bootbefore_backup_sha256"] = self.backup_and_verify(
            seed=before,
            restore_password=secrets.token_hex(32),
            tag="bootbefore",
            verification_mode="boot-verify-restore",
        )
        history_secret = epoch.read_attempt_04_rotated_history_secret(
            PARENT / "continuation-04/continuation-private.json", owner=OWNER
        )
        for index in range(3):
            current = self.boot_state("beforecatchup" + str(index))
            end = (
                (int(time.time() * 1000) - 5000) // epoch.MINUTE_MS
            ) * epoch.MINUTE_MS
            required = sum(
                (end - a["last_close_time_ms"] - 1) // epoch.MINUTE_MS
                for a in current["anchors"].values()
            )
            if not 0 <= required <= epoch.MAX_CATCHUP_BARS:
                raise epoch.Rejected("BOOT_FIXED_LONG_GAP_CAP_EXCEEDED")
            if required:
                receipt = self.phase(
                    "boot-catchup",
                    {
                        "owner": OWNER,
                        "database": "kairos_epoch_" + OWNER[:12],
                        "pg_host": self.names["target_pg"],
                        "redis_host": self.names["redis"],
                        "history_password": history_secret,
                        "end_exclusive_ms": end,
                        "maximum_bars": epoch.MAX_CATCHUP_BARS,
                        "expected_seed": current,
                    },
                    suffix=str(index),
                )
                self.proofs["catchup_" + str(index)] = receipt
            after = self.boot_state("aftercatchup" + str(index))
            validate_preserved_state(before, after)
            self.proofs["after_state"] = after
            if index == 0:
                self.prepare_boot_restore_volume("bootafter")
                self.proofs["bootafter_backup_sha256"] = self.backup_and_verify(
                    seed=after,
                    restore_password=secrets.token_hex(32),
                    tag="bootafter",
                    verification_mode="boot-verify-restore",
                )
                continue
            break
        self.phase(
            "boot-redis-state",
            read_json(SERVE_WORK / "config-serve.json"),
            suffix="beforestart",
        )
        self.validate_resources()
        # No container recreation or policy update. Its accepted source/config stay immutable.
        self.proofs["serve_start_intent"] = True
        self.docker(["start", self.names["serve"]])
        self.proofs["serve_started"] = True
        status_path = SERVE_WORK / "output-serve/status.json"
        until = min(self.deadline - 30, time.monotonic() + 180)
        while time.monotonic() < until:
            value = read_json(status_path)
            if value.get("state") == "FAILED_CLOSED":
                raise epoch.Rejected("BOOT_SERVE_FAILED_CLOSED")
            if value.get("observed_at_utc") != previous["observed_at_utc"]:
                epoch.validate_running_status(value, OWNER)
                if all(
                    value["watermarks_ms"][s]
                    > after["anchors"][s]["last_close_time_ms"] + 1
                    for s in epoch.SYMBOLS
                ):
                    final = self.validate_resources(allow_running=True)
                    if any(
                        v["state"]["Status"] != "running"
                        for v in final["views"].values()
                    ):
                        raise epoch.Rejected(
                            "BOOT_ALL_THREE_RESOURCES_MUST_REMAIN_RUNNING"
                        )
                    if final["legacy"] != before_resources["legacy"]:
                        raise epoch.Rejected("BOOT_LEGACY_METADATA_CHANGED")
                    if final["standby"] != before_resources["standby"]:
                        raise epoch.Rejected("BOOT_STANDBY_METADATA_CHANGED")
                    return {
                        "result": "PASS_NONTRADING_EPOCH_BOOT",
                        "status": value,
                        "proofs": self.proofs,
                        "legacy_unchanged": True,
                        "trading_started": False,
                    }
            time.sleep(2)
        raise epoch.Rejected("BOOT_FRESH_FIVE_SYMBOL_STATUS_TIMEOUT")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create-binding", action="store_true")
    parser.add_argument("--expected-revision")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--generation", choices=("original", "r2", "r4"), default="original"
    )
    parser.add_argument("--binding", type=Path)
    parser.add_argument("--binding-sha256")
    parser.add_argument("--boot-id")
    args = parser.parse_args(argv)
    if args.generation == "r2":
        configure_generation_r2()
    elif args.generation == "r4":
        configure_generation_r4()
    args.binding = args.binding or ROOT / "binding.json"
    controller = None
    work = None
    lease_bytes = None
    try:
        if args.create_binding:
            if args.execute:
                raise epoch.Rejected("BOOT_ACTIONS_ARE_EXCLUSIVE")
            path = create_binding(args.expected_revision or "")
            print(
                json.dumps(
                    {
                        "result": "BOOT_BINDING_CREATED",
                        "path": str(path),
                        "sha256": fresh.sha(path),
                    }
                )
            )
            return 0
        if not args.execute:
            print(
                json.dumps(
                    {
                        "result": "PLAN_ONLY",
                        "legacy_start": False,
                        "trading_started": False,
                    }
                )
            )
            return 0
        if not IS_WINDOWS or re.fullmatch(r"[0-9]{15,20}", args.boot_id or "") is None:
            raise epoch.Rejected("WINDOWS_BOOT_ID_REQUIRED")
        if (
            fresh.safe(args.binding) != ROOT / "binding.json"
            or fresh.sha(args.binding) != args.binding_sha256
        ):
            raise epoch.Rejected("HASH_BOUND_LOCAL_BOOT_PLAN_REQUIRED")
        binding = read_json(args.binding)
        validate_binding(binding)
        verify_source(binding["revision"])
        if LEASE.exists():
            raise epoch.Rejected("BOOT_ACTIVE_OR_FAILED_LATCH_REQUIRES_OPERATOR")
        run = uuid.uuid4().hex
        work = ROOT / "runs" / run
        epoch._private_directory(work)
        lease_bytes = (
            json.dumps(
                {"owner": OWNER, "run": run, "boot_id": args.boot_id}, sort_keys=True
            )
            + "\n"
        ).encode()
        fresh.write(LEASE, lease_bytes)
        controller = BootController(
            OWNER,
            expected_revision=binding["revision"],
            workdir=work,
            continuation_attempt="boot-" + run[:8],
            deadline=time.monotonic() + MAX_SECONDS,
        )
        result = controller.run_boot()
        result.update(
            owner=OWNER,
            boot_id=args.boot_id,
            source_revision=binding["revision"],
            binding_sha256=args.binding_sha256,
            completed_at_utc=datetime.now(UTC).isoformat(),
        )
        receipt_path = work / "boot-receipt.json"
        fresh.save(receipt_path, result)
        if LEASE.read_bytes() != lease_bytes:
            raise epoch.Rejected("BOOT_OWNER_LEASE_CHANGED")
        LEASE.unlink()
        print(
            json.dumps(
                {
                    "result": result["result"],
                    "receipt": str(receipt_path),
                    "sha256": fresh.sha(receipt_path),
                }
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - no secret-bearing driver or CLI output.
        category = (
            str(exc)
            if isinstance(exc, epoch.Rejected)
            else "BOOT_OPERATION_FAILED_" + type(exc).__name__.upper()
        )
        if controller:
            # Stop only this run's still-owned workers; preserve their failed
            # artifacts/containers and all database volumes for examination.
            controller.fail_closed_cleanup()
        if work:
            fresh.save(
                work / "boot-failure.json",
                {
                    "state": "FAILED_CLOSED",
                    "reason": category,
                    "owner": OWNER,
                    "trading_started": False,
                    "source_revision": (
                        controller.expected_revision
                        if controller
                        else args.expected_revision
                    ),
                },
            )
        print(
            json.dumps(
                {
                    "result": "FAILED_CLOSED",
                    "reason": category,
                    "automatic_retry": False,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
