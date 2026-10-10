"""Fresh stopped-primary backup and two isolated restore proofs, never activation.

The primary is only mounted read-only by an owner-labelled cold-copy helper.
The unchanged official backup script runs against that COPY, with truthful
copy-project provenance. Historical leases, transports and receipts are not
adopted or rewritten. Default invocation is a non-launching plan.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import buildkit_resource_gate as bounded
else:
    import buildkit_resource_gate as bounded

REPO = Path("D:/Kairos/kairos-deploy")
ROOT = REPO / "backups/fresh-runtime-recovery-20261010"
SOURCE = "kairos-paper-gate-timescaledb-1"
VOLUME = "kairos-paper-gate_paper-ts-data"
NETWORK = "kairos-paper-gate_paper-data"
SOURCE_ID = "dfe9c96b3307f07c7f88bb6cdae46dba903ebb1e7243c2534199da2843229774"
IMAGE = "timescale/timescaledb:2.29.1-pg16@sha256:252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
IMAGE_ID = "sha256:252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
CONFIRM = "FRESH_BACKUP_AND_ISOLATED_RESTORE_NO_PRIMARY_WRITES"
SCOPE = "fresh-stopped-primary-recovery-v1"
OWNER_LABEL = "com.kairos.recovery.owner"
TRANSPORT = Path("D:/Kairos/runtime/archive-clone-20261005/backup_call_contract_v6.py")
TRANSPORT_SHA = "6743819775b1c72b4d8a1eeff66440ae906b127322386178e9203bd1decc264b"
OFFICIAL = REPO / "scripts/Backup-Kairos.ps1"
OFFICIAL_SHA = "35bcec2adaa30043fa44f19daed0c7342bc96c34d0cdee102982c73e5d298908"
PS = Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
GIT = Path("C:/Program Files/Git/cmd/git.exe")
SIGNER = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
CHECKPOINTS = {
    "event_audit",
    "message_inbox",
    "message_outbox",
    "execution_orders",
    "account_snapshots",
    "position_snapshots",
    "source_cursors",
    "source_usage_reservations",
    "execution_effects",
    "execution_effect_events",
    "execution_trades",
    "execution_trade_events",
    "execution_recovery_state",
    "public_execution_events",
    "account_equity_state",
    "paper_canary_arms",
    "execution_runtime_health",
    "execution_mutation_budget_scopes",
    "execution_mutation_reservations",
    "public_execution_events_max_sequence",
}
MIGRATIONS = [
    "001_audit_and_idempotency.sql",
    "002_durable_runtime.sql",
    "003_execution_effect_journal.sql",
    "004_execution_recovery_delay.sql",
    "005_source_state_and_usage.sql",
    "006_paper_trade_lifecycle.sql",
    "007_execution_runtime_health.sql",
    "008_public_execution_events.sql",
    "009_paper_canary_arms.sql",
    "010_runtime_compensation_reserve.sql",
    "011_execution_mutation_budget.sql",
    "012_outbox_producer_order.sql",
]
SECONDS = 1500
VIEW = (
    '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
    '"state":{{json .State}},"labels":{{json .Config.Labels}},'
    '"mounts":{{json .Mounts}},"network":{{json .HostConfig.NetworkMode}},'
    '"networks":{{json .NetworkSettings.Networks}},"privileged":{{json .HostConfig.Privileged}},'
    '"ports":{{json .HostConfig.PortBindings}},"memory":{{json .HostConfig.Memory}},'
    '"swap":{{json .HostConfig.MemorySwap}},"cpus":{{json .HostConfig.NanoCpus}},'
    '"readonly":{{json .HostConfig.ReadonlyRootfs}},"caps":{{json .HostConfig.CapDrop}}}'
)
PG = [
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
FINGERPRINT = r"""set -eu
cd "$fingerprint_root"
[ "$(stat -c %u .)" = "$(id -u)" ]
[ -z "$(find . -type l -print -quit)" ]
[ -z "$(find . ! -type d ! -type f -print -quit)" ]
[ ! -e postmaster.pid ]
[ -f PG_VERSION ] && [ "$(cat PG_VERSION)" = 16 ]
[ "$(pg_controldata . | sed -n 's/^Database cluster state: *//p')" = 'shut down' ]
find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum
find . -print0 | sort -z | xargs -0 stat -c '%n|%a|%u|%g|%Y' | sha256sum
find . -type f -print0 | xargs -0 stat -c %s | awk '{total+=$1} END {printf "%.0f\n",total}'
"""
BARS = """WITH b AS (
 SELECT payload->>'symbol' AS symbol, (payload->>'open_time_ms')::bigint AS t,
 lag((payload->>'open_time_ms')::bigint) OVER (PARTITION BY payload->>'symbol'
 ORDER BY (payload->>'open_time_ms')::bigint) AS prior FROM event_audit
 WHERE topic='kairos.market.closed_bar.v1' AND source='kairos-quant-scouts'
 AND payload->>'venue'='BINANCE_UM')
 SELECT json_build_object('symbol',symbol,'count',count(*),'first',min(t),
 'last',max(t),'gaps',count(*) FILTER(WHERE prior IS NOT NULL AND t-prior<>60000))
 FROM b GROUP BY symbol ORDER BY symbol;"""
STATE = """SELECT json_build_object(
 'inbox_failed',(SELECT count(*) FROM message_inbox WHERE status='FAILED'),
 'inbox_processing',(SELECT count(*) FROM message_inbox WHERE status='PROCESSING'),
 'pending',(SELECT count(*) FROM message_outbox WHERE published_at IS NULL AND dead_lettered_at IS NULL),
 'dead_lettered',(SELECT count(*) FROM message_outbox WHERE dead_lettered_at IS NOT NULL),
 'active_leases',(SELECT count(*) FROM message_outbox WHERE published_at IS NULL AND lease_until>now()),
 'expired_leases',(SELECT count(*) FROM message_outbox WHERE published_at IS NULL AND lease_until<=now()),
 'duplicate_audit',(SELECT count(*) FROM (SELECT message_id FROM event_audit GROUP BY message_id HAVING count(*)>1) x),
 'duplicate_outbox',(SELECT count(*) FROM (SELECT message_id FROM message_outbox GROUP BY message_id HAVING count(*)>1) x),
 'orphan_outbox',(SELECT count(*) FROM message_outbox o LEFT JOIN event_audit a USING(message_id) WHERE a.message_id IS NULL),
 'effects',(SELECT count(*) FROM execution_effects),'trades',(SELECT count(*) FROM execution_trades),
 'invalid_indexes',(SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT i.indisvalid),
 'unvalidated_constraints',(SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public' AND NOT c.convalidated));"""
SCHEMA = """SELECT json_build_object(
 'columns',(SELECT json_agg(x ORDER BY table_name,ordinal_position) FROM
 (SELECT table_name,column_name,ordinal_position,column_default,is_nullable,data_type,udt_schema,udt_name,
 character_maximum_length,numeric_precision,numeric_scale,datetime_precision FROM information_schema.columns WHERE table_schema='public') x),
 'constraints',(SELECT json_agg(x ORDER BY rel,conname) FROM (SELECT r.relname AS rel,c.conname,c.contype,pg_get_constraintdef(c.oid) AS definition FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public') x),
 'indexes',(SELECT json_agg(x ORDER BY tablename,indexname) FROM (SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public') x),
 'functions',(SELECT json_agg(x ORDER BY signature) FROM (SELECT p.oid::regprocedure::text AS signature,pg_get_functiondef(p.oid) AS definition FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind IN ('f','p')) x),
 'extensions',(SELECT json_agg(x ORDER BY extname) FROM (SELECT extname,extversion FROM pg_extension WHERE extname<>'amcheck') x),
 'jobs',(SELECT json_agg(x ORDER BY id) FROM _timescaledb_config.bgw_job x));"""


class Rejected(RuntimeError):
    pass


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024**2), b""):
            h.update(block)
    return h.hexdigest()


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def safe(path: Path) -> Path:
    path = path.absolute()
    for item in (path, *path.parents):
        if item.exists() and item.stat().st_file_attributes & 0x400:
            raise Rejected("REPARSE_PATH_REJECTED")
    return path


def write(path: Path, value: bytes) -> None:
    safe(path)
    with path.open("xb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def save(path: Path, value) -> None:
    write(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def validate_manifest(value, dump: Path, project: str) -> None:
    fields = {
        "schema_version",
        "created_at_utc",
        "compose_project",
        "database",
        "file",
        "bytes",
        "sha256",
        "checkpoints",
        "timescaledb_bgw_owners",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise Rejected("EXACT_OFFICIAL_MANIFEST_FIELDS_REQUIRED")
    try:
        created = datetime.fromisoformat(value["created_at_utc"].replace("Z", "+00:00"))
        age = (datetime.now(UTC) - created).total_seconds()
    except (TypeError, AttributeError, ValueError):
        raise Rejected("FRESH_MANIFEST_UTC_TIMESTAMP_REQUIRED") from None
    with dump.open("rb") as stream:
        magic = stream.read(5)
    if (
        created.utcoffset().total_seconds() != 0
        or not 0 <= age <= 7200
        or not re.fullmatch(re.escape(project) + r"-\d{8}T\d{6}Z\.dump", dump.name)
        or magic != b"PGDMP"
    ):
        raise Rejected("FRESH_CUSTOM_ARCHIVE_MANIFEST_REQUIRED")
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("compose_project") != project
        or value.get("database") != "kairos"
        or value.get("file") != dump.name
        or type(value.get("bytes")) is not int
        or value["bytes"] != dump.stat().st_size
        or value.get("sha256") != sha(dump)
        or value.get("timescaledb_bgw_owners") != ["kairos"]
    ):
        raise Rejected("FRESH_OFFICIAL_MANIFEST_REJECTED")
    values = value.get("checkpoints")
    if (
        not isinstance(values, dict)
        or set(values) != CHECKPOINTS
        or any(type(v) is not int or v < 0 for v in values.values())
        or values["event_audit"] < 1
    ):
        raise Rejected("STRICT_CHECKPOINT_TYPES_REQUIRED")


def validate_state(value) -> None:
    zero = (
        "inbox_failed",
        "inbox_processing",
        "dead_lettered",
        "active_leases",
        "duplicate_audit",
        "duplicate_outbox",
        "orphan_outbox",
        "invalid_indexes",
        "unvalidated_constraints",
    )
    if any(type(v) is not int or v < 0 for v in value.values()) or any(
        value.get(k) != 0 for k in zero
    ):
        raise Rejected("RECOVERY_STATE_INTEGRITY_REJECTED")


def validate_bars(rows) -> None:
    if [r["symbol"] for r in rows] != [
        "BNBUSDT",
        "BTCUSDT",
        "ETHUSDT",
        "SOLUSDT",
        "XRPUSDT",
    ]:
        raise Rejected("FIVE_SYMBOL_ANCHORS_REQUIRED")
    for row in rows:
        if (
            any(type(row[k]) is not int for k in ("count", "first", "last", "gaps"))
            or row["count"] < 1
            or row["gaps"] != 0
            or row["last"] - row["first"] != (row["count"] - 1) * 60000
        ):
            raise Rejected("CONTIGUOUS_BAR_PREFIX_REQUIRED")


def normalize_source(value):
    result = dict(value)
    result["mounts"] = sorted(value["mounts"], key=lambda v: v["Destination"])
    result["state"] = {
        k: value["state"][k]
        for k in (
            "Status",
            "Running",
            "Paused",
            "Restarting",
            "Dead",
            "StartedAt",
            "FinishedAt",
            "ExitCode",
            "Pid",
        )
    }
    return result


def mount_identity(value: str) -> str:
    text = value.replace("\\", "/").casefold()
    if any(part in {".", ".."} for part in text.split("/")):
        raise Rejected("NONCANONICAL_MOUNT_PATH")
    for prefix in ("/run/desktop/mnt/host/", "/host_mnt/"):
        if text.startswith(prefix):
            remainder = text[len(prefix) :]
            if re.match(r"^[a-z]/", remainder):
                return remainder[0] + ":" + remainder[1:]
    return text


def require_tree_proof(value) -> None:
    if (
        not isinstance(value, dict)
        or value.get("assigned_before_resume") is not True
        or value.get("tree_cleanup_verified") is not True
        or type(value.get("active_owned_processes_after")) is not int
        or value["active_owned_processes_after"] != 0
    ):
        raise Rejected("HOST_PROCESS_TREE_CLEANUP_UNPROVEN")


class Controller:
    def __init__(self):
        self.owner = uuid.uuid4().hex
        safe(ROOT).mkdir(parents=True, exist_ok=True)
        self.work = ROOT / ("run-" + self.owner)
        self.work.mkdir()
        self.lease = ROOT / "fresh-recovery.execution.lock"
        write(self.lease, self.owner.encode())
        self.deadline = time.monotonic() + SECONDS
        self.native = bounded.Native(self.work)
        (self.work / "docker-config").mkdir()
        self.owned = {}
        self.phase = "ADMISSION"
        self.proofs = {}
        self.cleanup_deadline = None

    def protect_backup_directory(self):
        # No token/password access: give only this Windows owner, SYSTEM and
        # Administrators inherited full control over this newly owned directory.
        path = str(self.work)
        code = f"$ErrorActionPreference='Stop'; $acl=[Security.AccessControl.DirectorySecurity]::new(); $acl.SetAccessRuleProtection($true,$false); $sids=@([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')); foreach($sid in $sids){{$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}}; Set-Acl -LiteralPath '{path}' -AclObject $acl; $actual=Get-Acl -LiteralPath '{path}'; if(!$actual.AreAccessRulesProtected -or @($actual.Access).Count -ne 3){{throw 'PRIVATE_BACKUP_ACL_REQUIRED'}}; Write-Output 'PRIVATE_BACKUP_ACL_VERIFIED'"
        self.process(
            PS,
            ["-NoProfile", "-NonInteractive", "-Command", code],
            20,
            label="backup-acl",
        )
        self.proofs["private_backup_acl_verified"] = True

    def docker(self, args, seconds=20, allow_failure=False):
        end = self.cleanup_deadline or self.deadline
        return self.native.call(
            args, end, seconds=seconds, allow_failure=allow_failure
        )[1]

    def process(self, exe, args, seconds, label="official"):
        outpath, errpath = (
            self.work / (label + ".stdout"),
            self.work / (label + ".stderr"),
        )
        job = self.native.module.WindowsProcessJob()
        process = None
        try:
            with outpath.open("xb") as out, errpath.open("xb") as err:
                process = subprocess.Popen(
                    [str(exe), *args],
                    cwd=REPO,
                    env={
                        k: v
                        for k, v in os.environ.items()
                        if k.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
                    },
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    shell=False,
                    creationflags=job.creation_flags,
                )
                job.attach_and_resume(process)
                end = min(time.monotonic() + seconds, self.deadline - 10)
                while process.poll() is None:
                    if (
                        time.monotonic() >= end
                        or outpath.stat().st_size > 256 * 1024
                        or errpath.stat().st_size > 256 * 1024
                    ):
                        raise Rejected("OFFICIAL_BACKUP_BOUND_EXCEEDED")
                    time.sleep(0.05)
                if process.returncode != 0:
                    raise Rejected("OFFICIAL_BACKUP_FAILED_PRIVATE_DIAGNOSTIC")
        finally:
            try:
                self.proofs[label + "_cli_tree"] = job.finish(
                    process, cancel=process is None or process.poll() is None
                )
                require_tree_proof(self.proofs[label + "_cli_tree"])
            finally:
                job.close()

    def inspect(self, name):
        return json.loads(self.docker(["inspect", "--format", VIEW, name]))

    def source(self):
        value = self.inspect(SOURCE)
        mounts = value["mounts"]
        data = [m for m in mounts if m.get("Destination") == "/var/lib/postgresql/data"]
        state = value["state"]
        if (
            value["id"] != SOURCE_ID
            or value["image"] != IMAGE_ID
            or (value["labels"] or {}).get("com.docker.compose.project")
            != "kairos-paper-gate"
            or (value["labels"] or {}).get("com.docker.compose.service")
            != "timescaledb"
            or state["Status"] != "exited"
            or any(state[k] for k in ("Running", "Paused", "Restarting", "Dead", "Pid"))
            or state["ExitCode"] != 0
            or value["privileged"]
            or value["ports"]
            or set(value["networks"]) != {NETWORK}
        ):
            raise Rejected("EXACT_STOPPED_PRIMARY_REQUIRED")
        if (
            len(data) != 1
            or data[0].get("Name") != VOLUME
            or data[0].get("Type") != "volume"
        ):
            raise Rejected("PRIMARY_VOLUME_IDENTITY_REQUIRED")
        for m in mounts:
            if m not in data and (
                m.get("Type") != "bind"
                or m.get("RW") is not False
                or m.get("Destination")
                not in {
                    "/docker-entrypoint-initdb.d/001-kairos.sql",
                    "/run/secrets/paper_postgres_password",
                }
            ):
                raise Rejected("UNKNOWN_PRIMARY_MOUNT")
        for identifier in self.docker(["ps", "-q"]).splitlines():
            running = self.inspect(identifier)
            for mount in running["mounts"]:
                if mount.get("Name") == VOLUME and not (
                    running["name"].lstrip("/") in self.owned
                    and mount.get("RW") is False
                ):
                    raise Rejected("PRIMARY_VOLUME_IN_USE")
            if (running["labels"] or {}).get(
                "com.docker.compose.project"
            ) == "kairos-paper-gate" or NETWORK in running["networks"]:
                raise Rejected("PROTECTED_SOURCE_SERVICE_RUNNING")
        value["volume_identity"] = json.loads(
            self.docker(
                [
                    "volume",
                    "inspect",
                    "--format",
                    '{"name":{{json .Name}},"created":{{json .CreatedAt}},"driver":{{json .Driver}},"labels":{{json .Labels}}}',
                    VOLUME,
                ]
            )
        )
        return normalize_source(value)

    def create(
        self, name, *, mounts=(), labels=(), command=(), entrypoint=None, database=None
    ):
        if name in self.owned or not name.startswith(
            "kairos-recovery-" + self.owner[:12] + "-"
        ):
            raise Rejected("FRESH_OWNED_NAME_REQUIRED")
        self.owned[name] = list(mounts)
        args = [
            "create",
            "--pull=never",
            "--name",
            name,
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--user=postgres",
            "--memory=3g",
            "--memory-swap=3g",
            "--cpus=1",
            "--pids-limit=128",
            "--label",
            OWNER_LABEL + "=" + self.owner,
            "--label",
            "com.kairos.recovery.scope=" + SCOPE,
            "--tmpfs",
            "/var/lib/postgresql/data:rw,nosuid,nodev,size=2g,uid=70,gid=70,mode=0700",
            "--tmpfs",
            "/var/run/postgresql:rw,nosuid,nodev,size=8m,uid=70,gid=70",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=128m,uid=70,gid=70",
        ]
        for mount in mounts:
            args += ["--mount", mount]
        for label in labels:
            args += ["--label", label]
        if entrypoint:
            args += ["--entrypoint", entrypoint]
        if database:
            args += [
                "--env",
                "POSTGRES_USER=kairos",
                "--env",
                "POSTGRES_DB=" + database,
                "--env",
                "POSTGRES_HOST_AUTH_METHOD=trust",
            ]
        self.docker([*args, IMAGE, *command])
        self.check_owned(name)
        self.docker(["start", name])
        return name

    def check_owned(self, name):
        value = self.inspect(name)
        mounts = value["mounts"]
        expected = self.owned.get(name)
        if (
            expected is None
            or value["name"] != "/" + name
            or value["image"] != IMAGE_ID
            or (value["labels"] or {}).get(OWNER_LABEL) != self.owner
            or (value["labels"] or {}).get("com.kairos.recovery.scope") != SCOPE
            or value["network"] != "none"
            or value["ports"]
            or value["privileged"]
            or value["memory"] != 3 * 1024**3
            or value["swap"] != 3 * 1024**3
            or value["cpus"] != 10**9
            or value["readonly"] is not True
            or value["caps"] != ["ALL"]
            or len(mounts) != len(expected)
        ):
            raise Rejected("OWNED_CONTAINER_BOUNDARY_REJECTED")
        for mount, spec in zip(
            sorted(mounts, key=lambda m: m["Destination"]),
            sorted(expected, key=lambda m: re.search(r"dst=([^,]+)", m)[1]),
        ):
            target = re.search(r"dst=([^,]+)", spec)[1]
            source = re.search(r"src=([^,]+)", spec)[1]
            if mount["Destination"] != target or mount["RW"] != (
                ",readonly" not in spec
            ):
                raise Rejected("OWNED_MOUNT_MODE_REJECTED")
            if (
                mount.get("Name")
                if spec.startswith("type=volume,")
                else mount_identity(mount["Source"])
            ) != (
                source if spec.startswith("type=volume,") else mount_identity(source)
            ):
                raise Rejected("OWNED_MOUNT_SOURCE_REJECTED")
        return value

    def remove(self, name):
        if not self.docker(["ps", "-aq", "--filter", "name=^/" + name + "$"]):
            self.owned.pop(name, None)
            return
        self.check_owned(name)
        self.docker(["rm", "-f", name])
        self.owned.pop(name)

    def helper(self, copy=False):
        name = "kairos-recovery-" + self.owner[:12] + ("-cold" if copy else "-verify")
        script = "fingerprint_root=/source\n" + FINGERPRINT
        if copy:
            script += "[ $(du -sk /source | awk '{print $1}') -lt 1572864 ]\ntar -cf /evidence/cluster.tar -C /source .\n"
        mounts = ["type=volume,src=" + VOLUME + ",dst=/source,readonly"]
        if copy:
            mounts += ["type=bind,src=" + str(self.work) + ",dst=/evidence"]
        self.create(name, mounts=mounts, entrypoint="/bin/sh", command=["-c", script])
        if self.docker(["wait", name], seconds=120) != "0":
            raise Rejected("COLD_COPY_OR_CONTENT_FINGERPRINT_FAILED")
        lines = self.docker(["logs", name]).splitlines()
        if (
            len(lines) != 3
            or any(not re.fullmatch(r"[0-9a-f]{64}  -", line) for line in lines[:2])
            or not lines[2].isdigit()
        ):
            raise Rejected("COLD_FINGERPRINT_SHAPE_REQUIRED")
        result = {
            "files_sha256": lines[0][:64],
            "metadata_sha256": lines[1][:64],
            "bytes": int(lines[2]),
        }
        self.remove(name)
        return result

    def sql(self, name, database, query, seconds=120):
        if name not in self.owned:
            raise Rejected("SQL_TARGET_NOT_OWNED")
        return self.docker(
            [
                "exec",
                name,
                "psql",
                "-X",
                "--host=127.0.0.1",
                "--username=kairos",
                "--dbname=" + database,
                "--tuples-only",
                "--no-align",
                "--quiet",
                "--set=ON_ERROR_STOP=1",
                "--command=" + query,
            ],
            seconds=seconds,
        )

    def ready(self, name, database):
        count = 0
        end = min(self.deadline - 15, time.monotonic() + 60)
        while count < 3:
            if time.monotonic() > end:
                raise Rejected("CLONE_STARTUP_NOT_READY")
            pid = self.docker(
                ["exec", name, "sh", "-c", "cat /proc/1/comm"], allow_failure=True
            )
            answer = self.docker(
                [
                    "exec",
                    name,
                    "psql",
                    "-X",
                    "--host=127.0.0.1",
                    "-U",
                    "kairos",
                    "-d",
                    database,
                    "-Atqc",
                    "SELECT current_database();",
                ],
                allow_failure=True,
            )
            count = count + 1 if pid == "postgres" and answer == database else 0
            time.sleep(0.5)

    def snapshot(self, name, database):
        rows = self.sql(
            name,
            database,
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;",
        ).splitlines()
        if len(rows) != 27 or any(
            not re.fullmatch(r"[a-z_][a-z0-9_]*", t) for t in rows
        ):
            raise Rejected("EXACT_LEGACY_TABLE_CATALOG_REQUIRED")
        queries = []
        for table in rows:
            queries.append(
                f"SELECT json_build_object('table','{table}','count',count(*),'sha256',encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex')) FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS row_sha FROM public.\"{table}\" t) r;"
            )
        sequence_names = self.sql(
            name,
            database,
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S' ORDER BY c.relname;",
        ).splitlines()
        for seq in sequence_names:
            if not re.fullmatch(r"[a-z_][a-z0-9_]*", seq):
                raise Rejected("UNSAFE_SEQUENCE_NAME")
        transaction = (
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL timezone='UTC'; SET LOCAL statement_timeout='180s'; "
            + "\n".join(queries)
            + " COMMIT;"
        )
        data = [
            json.loads(line)
            for line in self.sql(name, database, transaction, seconds=240).splitlines()
        ]
        schema = json.loads(self.sql(name, database, SCHEMA))
        sequences = {
            seq: self.sql(
                name, database, f'SELECT last_value,is_called FROM public."{seq}";'
            )
            for seq in sequence_names
        }
        migrations = self.sql(
            name, database, "SELECT version FROM schema_migrations ORDER BY version;"
        ).splitlines()
        if migrations != MIGRATIONS:
            raise Rejected("RESTORED_MIGRATION_HISTORY_DIFFERS")
        state = json.loads(self.sql(name, database, STATE))
        validate_state(state)
        bars = [
            json.loads(line) for line in self.sql(name, database, BARS).splitlines()
        ]
        validate_bars(bars)
        for lock in (
            "4907627681104115019",
            "hashtextextended('closed-bar-producer:kairos-quant-scouts',0)",
        ):
            result = self.sql(
                name,
                database,
                f"WITH acquired AS (SELECT pg_try_advisory_lock({lock}) AS value) SELECT value::text||'|'||pg_advisory_unlock({lock})::text FROM acquired;",
            )
            if result != "true|true":
                raise Rejected("CLONE_ADVISORY_GUARD_FAILED")
        return {
            "tables": data,
            "schema_sha256": digest(schema),
            "sequences": sequences,
            "migrations": migrations,
            "state": state,
            "bars": bars,
        }

    def official_backup(self, name, project):
        if sha(OFFICIAL) != OFFICIAL_SHA or sha(TRANSPORT) != TRANSPORT_SHA:
            raise Rejected("PINNED_BACKUP_TRANSPORT_CHANGED")
        spec = importlib.util.spec_from_file_location(
            "kairos_fresh_backup_contract", TRANSPORT
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        journal = self.work / "backup-native-journal"
        journal.mkdir()
        text = module.render_candidate(self.work / "docker-config", journal, self.owner)
        text += "\nfunction docker { Invoke-KairosPublicDocker @args }\n"
        relative = self.work.relative_to(REPO).as_posix()
        compose = (
            f"services:\n  timescaledb:\n    image: {IMAGE}\n    network_mode: none\n"
        )
        write(self.work / "source-compose.yml", compose.encode())
        text += f"& '{OFFICIAL}' -ComposeProject '{project}' -ComposeFile '{relative}/source-compose.yml' -EnvFile 'tests/sim_full_path_gate/empty.env' -OutputDirectory '{relative}' -Database 'kairos' -DatabaseUser 'kairos'\n"
        wrapper = self.work / "official-backup.ps1"
        write(wrapper, text.encode())
        self.process(
            PS,
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(wrapper),
            ],
            240,
        )
        module_guard = module.SequenceGuard()
        for i, category in enumerate(module.EXPECTED, 1):
            for stage in ("start", "complete"):
                value = json.loads(
                    (journal / f"native-{i:03d}.{stage}.json").read_text()
                )
                if (
                    value.get("owner") != self.owner
                    or value.get("source_sha256") != OFFICIAL_SHA
                    or value.get("index") != i
                    or value.get("category") != category
                    or (stage == "complete" and value.get("return_code") != 0)
                ):
                    raise Rejected("OFFICIAL_47_CALL_RECEIPTS_INCOMPLETE")
            module_guard.accept(category)
        module_guard.finalize()
        if len(list(journal.iterdir())) != 94:
            raise Rejected("UNEXPECTED_OFFICIAL_NATIVE_CALL")
        manifests = list(self.work.glob(project + "-*.dump.json"))
        if len(manifests) != 1:
            raise Rejected("ONE_FRESH_OFFICIAL_MANIFEST_REQUIRED")
        manifest_path = manifests[0]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        dump = manifest_path.with_suffix("")
        validate_manifest(manifest, dump, project)
        self.proofs["official_backup"] = {
            "manifest_sha256": sha(manifest_path),
            "dump_sha256": sha(dump),
            "dump_bytes": dump.stat().st_size,
            "native_calls": 47,
            "project": project,
            "source_copy_container_id": self.inspect(name)["id"],
            "wrapper_sha256": sha(wrapper),
            "unchanged_backup_source_sha256": OFFICIAL_SHA,
        }
        return dump, manifest

    def restore(self, dump, suffix):
        name = "kairos-recovery-" + self.owner[:12] + "-" + suffix
        database = "kairos_recovery_" + self.owner[:12] + "_" + suffix
        self.create(
            name,
            mounts=["type=bind,src=" + str(dump) + ",dst=/archive.dump,readonly"],
            database=database,
            command=PG,
        )
        self.ready(name, database)
        self.sql(
            name,
            database,
            "CREATE EXTENSION IF NOT EXISTS timescaledb; SELECT timescaledb_pre_restore();",
        )
        self.docker(
            [
                "exec",
                name,
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
        self.sql(name, database, "SELECT timescaledb_post_restore();")
        if (
            self.sql(
                name,
                database,
                "SELECT current_setting('timescaledb.restoring'),current_setting('timescaledb.max_background_workers');",
            )
            != "off|0"
        ):
            raise Rejected("RESTORE_MODE_OR_BACKGROUND_WORKERS_UNSAFE")
        return name, database

    def run(self):
        self.protect_backup_directory()
        self.phase = "COLD_READONLY_BACKUP"
        before = self.source()
        save(self.work / "source-before.json", before)
        cold = self.helper(copy=True)
        save(self.work / "cold-fingerprint.json", cold)
        self.proofs["cold_archive_sha256"] = sha(self.work / "cluster.tar")
        project = "kairos-recovery-copy-" + self.owner[:12]
        name = "kairos-recovery-" + self.owner[:12] + "-source"
        labels = [
            "com.docker.compose.project=" + project,
            "com.docker.compose.service=timescaledb",
            "com.docker.compose.container-number=1",
            "com.docker.compose.oneoff=False",
        ]
        expected = (
            cold["files_sha256"]
            + "  -\n"
            + cold["metadata_sha256"]
            + "  -\n"
            + str(cold["bytes"])
        )
        # Equality is checked BEFORE postgres is allowed to modify copied WAL.
        script = (
            "set -eu; tar -xf /cold/cluster.tar -C /var/lib/postgresql/data; fingerprint_root=/var/lib/postgresql/data\nfingerprint() {\n"
            + FINGERPRINT
            + '\n}\nactual=$(fingerprint)\n[ "$actual" = '
            + shlex.quote(expected)
            + " ] || exit 91\nprintf '%s\\n' \"$actual\" > /tmp/cold-verified\nprintf 'local all all trust\\nhost all all 127.0.0.1/32 trust\\n' > /tmp/recovery-hba.conf\nexec postgres "
        )
        script += shlex.join(
            PG[1:]
            + [
                "-c",
                "hba_file=/tmp/recovery-hba.conf",
                "-c",
                "default_transaction_read_only=on",
            ]
        )
        self.create(
            name,
            mounts=["type=bind,src=" + str(self.work) + ",dst=/cold,readonly"],
            labels=labels,
            entrypoint="/bin/sh",
            command=["-c", script],
        )
        self.ready(name, "kairos")
        if self.docker(["exec", name, "cat", "/tmp/cold-verified"]) != expected:
            raise Rejected("PRESTART_COLD_COPY_FIDELITY_UNPROVEN")
        self.proofs["cold_copy_fidelity_verified_before_start"] = True
        self.phase = "OFFICIAL_FRESH_BACKUP"
        baseline = self.snapshot(name, "kairos")
        save(self.work / "baseline.json", baseline)
        dump, manifest = self.official_backup(name, project)
        if self.snapshot(name, "kairos") != baseline:
            raise Rejected("COPY_CHANGED_DURING_FRESH_BACKUP")
        for key, number in manifest["checkpoints"].items():
            actual = self.sql(
                name,
                "kairos",
                "SELECT COALESCE(max(event_seq),0) FROM public_execution_events;"
                if key == "public_execution_events_max_sequence"
                else f'SELECT count(*) FROM public."{key}";',
            )
            if actual != str(number):
                raise Rejected("MANIFEST_CHECKPOINT_MISMATCH")
        self.remove(name)
        self.phase = "FIRST_FULL_RESTORE"
        name, database = self.restore(dump, "first")
        restored = self.snapshot(name, database)
        if restored != baseline:
            raise Rejected("FULL_DATA_SCHEMA_SEQUENCE_RESTORE_MISMATCH")
        save(self.work / "first-restored.json", restored)
        self.docker(
            [
                "exec",
                name,
                "pg_amcheck",
                "--database=" + database,
                "--username=kairos",
                "--install-missing",
                "--schema=public",
                "--heapallindexed",
                "--parent-check",
                "--rootdescend",
            ],
            seconds=240,
        )
        self.proofs["pg_amcheck"] = {
            "exit_code": 0,
            "heapallindexed": True,
            "parent_check": True,
            "rootdescend": True,
            "scope": "restored-clone-public",
        }
        if self.snapshot(name, database) != baseline:
            raise Rejected("INTEGRITY_CHECK_CHANGED_PUBLIC_HISTORY")
        after_dump = self.work / "clone-after.dump"
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
                "--file=/tmp/clone-after.dump",
            ],
            seconds=120,
        )
        self.docker(["cp", name + ":/tmp/clone-after.dump", str(after_dump)])
        self.proofs["backup_after_sha256"] = sha(after_dump)
        self.remove(name)
        self.phase = "SECOND_FULL_RESTORE"
        name, database = self.restore(after_dump, "second")
        second = self.snapshot(name, database)
        if second != baseline:
            raise Rejected("BACKUP_AFTER_SECOND_RESTORE_MISMATCH")
        save(self.work / "second-restored.json", second)
        self.docker(
            [
                "exec",
                name,
                "pg_amcheck",
                "--database=" + database,
                "--username=kairos",
                "--schema=public",
                "--heapallindexed",
                "--parent-check",
                "--rootdescend",
            ],
            seconds=240,
        )
        self.remove(name)
        self.phase = "PRIMARY_UNCHANGED_VERIFICATION"
        after = self.source()
        save(self.work / "source-after.json", after)
        if after != before or self.helper() != cold:
            raise Rejected("PRIMARY_IDENTITY_OR_CONTENT_CHANGED")
        self.proofs.update(
            primary_source_sha256=digest(before),
            primary_content_sha256=cold["files_sha256"],
            primary_metadata_sha256=cold["metadata_sha256"],
            restored_history_sha256=digest(baseline),
            snapshot=baseline,
            source_before_equals_after=True,
            full_data_schema_sequence_comparison=True,
        )

    def finish(self, success, error=None):
        self.cleanup_deadline = time.monotonic() + 60
        cleanup = True
        for name in list(self.owned):
            try:
                self.remove(name)
            except Exception:  # noqa: BLE001 -- uncertain cleanup is always fail-closed
                cleanup = False
        try:
            remaining = self.docker(
                ["ps", "-aq", "--filter", "label=" + OWNER_LABEL + "=" + self.owner]
            )
            cleanup = cleanup and not remaining
        except Exception:  # noqa: BLE001 -- no acceptance with an uncertain inventory
            cleanup = False
        value = {
            "schema_version": 1,
            "kind": SCOPE,
            "created_at_utc": datetime.now(UTC).isoformat(),
            "owner": self.owner,
            "result": "PASS_FRESH_BACKUP_TWO_ISOLATED_RESTORES"
            if success and cleanup
            else "FAILED_CLOSED",
            "phase": self.phase,
            "error_category": str(error)
            if isinstance(error, Rejected)
            else type(error).__name__
            if error
            else None,
            "proofs": self.proofs,
            "cleanup_verified": cleanup,
            "native_operations": self.native.operations,
            "code_sha256": sha(Path(__file__)),
            "maximum_seconds": SECONDS,
            "source_database_started": False,
            "primary_mutations": 0,
            "consumer_restart_permitted": False,
            "consumers_started": 0,
            "publisher_calls": 0,
            "external_exactly_once_publication_proven": False,
            "redis_contacted": False,
            "failed_historical_lease_adopted": False,
            "readiness": {
                "TECHNICAL_PAPER_READY": False,
                "PAPER_QUALIFIED": False,
                "ALPHA_READY": False,
                "LIVE_READY": False,
                "STRATEGY_POLICY": "REJECT_ALL",
            },
        }
        save(self.work / "receipt.json", value)
        if success and cleanup and self.lease.read_bytes() == self.owner.encode():
            self.lease.unlink()
        print(
            json.dumps(
                {
                    "result": value["result"],
                    "phase": self.phase,
                    "receipt": str(self.work / "receipt.json"),
                    "error_category": value["error_category"],
                }
            )
        )
        return 0 if success and cleanup else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation")
    parser.add_argument("--expected-revision")
    args = parser.parse_args(argv)
    if not args.execute:
        print(
            json.dumps(
                {
                    "result": "PLAN_ONLY",
                    "source": SOURCE,
                    "original_volume_mount": "READ_ONLY",
                    "primary_start": False,
                    "official_backup_target": "isolated physical copy",
                    "restores": 2,
                    "consumers": False,
                    "maximum_seconds": SECONDS,
                }
            )
        )
        return 0
    if (
        os.name != "nt"
        or args.confirmation != CONFIRM
        or sha(OFFICIAL) != OFFICIAL_SHA
        or sha(TRANSPORT) != TRANSPORT_SHA
        or not re.fullmatch(r"[0-9a-f]{40}", args.expected_revision or "")
    ):
        raise Rejected("EXACT_WINDOWS_CONFIRMATION_SOURCE_REQUIRED")
    state = subprocess.run(
        [str(GIT), "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"],
        capture_output=True,
        check=True,
        timeout=15,
        stdin=subprocess.DEVNULL,
    ).stdout
    signer = (
        subprocess.run(
            [str(GIT), "-C", str(REPO), "log", "-1", "--format=%G? %GF"],
            capture_output=True,
            check=True,
            timeout=15,
            stdin=subprocess.DEVNULL,
        )
        .stdout.decode()
        .strip()
    )
    if state or signer != "G " + SIGNER:
        raise Rejected("CLEAN_SIGNED_DEPLOY_HEAD_REQUIRED")

    def git(*arguments):
        return subprocess.run(
            [str(GIT), "-C", str(REPO), *arguments],
            capture_output=True,
            check=True,
            timeout=15,
            stdin=subprocess.DEVNULL,
        ).stdout

    if git("branch", "--show-current").decode().strip() != "main" or any(
        git("rev-parse", ref).decode().strip() != args.expected_revision
        for ref in ("HEAD", "origin/main")
    ):
        raise Rejected("EXACT_REVIEWED_MAIN_ORIGIN_REVISION_REQUIRED")
    for relative in (
        "scripts/fresh_runtime_recovery.py",
        "scripts/buildkit_resource_gate.py",
    ):
        if hashlib.sha256(
            git("show", args.expected_revision + ":" + relative)
        ).hexdigest() != sha(REPO / relative):
            raise Rejected("REVIEWED_TRACKED_RUNNER_CHANGED")
    controller = Controller()
    controller.proofs["reviewed_deploy_revision"] = args.expected_revision
    try:
        controller.run()
    except BaseException as error:  # noqa: BLE001 -- interrupts must also clean only owned clones
        return controller.finish(False, error)
    return controller.finish(True)


if __name__ == "__main__":
    raise SystemExit(main())
