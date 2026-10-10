"""Bounded native transition worker for an explicitly named local Kairos database.

The worker accepts only a private, controller-authored plan and an explicit
loopback DSN.  It never discovers configuration, reads the Docker socket, or
starts a producer.  The ordinary clone path is restricted to the recovery
clone namespace; touching ``kairos`` requires the separate ``--primary`` gate
and a private temporary-auth document supplied by the controller.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
import re
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote

CLONE_DATABASE = re.compile(r"kairos_recovery_[0-9a-f]{12}_current(?:_second)?\Z")
OWNER = re.compile(r"[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
LEGACY_MIGRATIONS = (
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
)
RUNTIME_PROFILE = LEGACY_MIGRATIONS + (
    "013_campaign_source_budgets.sql",
    "014_bounded_canary_sessions.sql",
    "015_canary_dispatch_claims.sql",
    "016_global_canary_session_guard.sql",
    "018_offline_outbox_reconciliation.sql",
    "026_operator_control.sql",
)
NEW_TABLES = (
    "campaign_source_budgets",
    "operator_control_admissions",
    "operator_control_commands",
    "operator_control_dispatch_claims",
    "operator_controls",
    "paper_canary_attempts",
    "paper_canary_database_identity",
    "paper_canary_dispatch_claims",
    "paper_canary_sessions",
    "paper_readonly_receipts",
    "paper_readonly_runs",
    "paper_readonly_samples",
)
CONTROL_TABLES = frozenset(
    {
        "schema_migrations",
        "paper_canary_database_identity",
        "operator_controls",
        "operator_control_commands",
        "operator_control_admissions",
        "operator_control_dispatch_claims",
    }
)
EXACT_REASON = "expired legacy transport outcome; frozen without replay"
SCHEMA_QUERY = """SELECT json_build_object(
 'columns',(SELECT json_agg(x ORDER BY table_name,ordinal_position) FROM
 (SELECT table_name,column_name,ordinal_position,column_default,is_nullable,data_type,udt_schema,udt_name,
 character_maximum_length,numeric_precision,numeric_scale,datetime_precision FROM information_schema.columns WHERE table_schema='public') x),
 'constraints',(SELECT json_agg(x ORDER BY rel,conname) FROM (SELECT r.relname AS rel,c.conname,c.contype,pg_get_constraintdef(c.oid) AS definition FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public') x),
 'indexes',(SELECT json_agg(x ORDER BY tablename,indexname) FROM (SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public') x),
 'functions',(SELECT json_agg(x ORDER BY signature) FROM (SELECT p.oid::regprocedure::text AS signature,pg_get_functiondef(p.oid) AS definition FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind IN ('f','p')) x),
 'extensions',(SELECT json_agg(x ORDER BY extname) FROM (SELECT extname,extversion FROM pg_extension WHERE extname<>'amcheck') x),
 'jobs',(SELECT json_agg(x ORDER BY id) FROM _timescaledb_config.bgw_job x))"""
MAX_BYTES = 1024 * 1024 * 1024
MAX_ROWS = 1_000_000
MAX_SECONDS = 300


class WorkerError(RuntimeError):
    """Safe failure; database, driver, payload and credential details are hidden."""


class FaultCheckpointError(WorkerError):
    def __init__(self, stage: str) -> None:
        super().__init__("intentional fault checkpoint")
        self.stage = stage


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise WorkerError("document is not canonical JSON") from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe_directory(path: Path) -> Path:
    try:
        if path.is_symlink() or not path.is_dir():
            raise WorkerError("private evidence directory is unavailable")
        resolved = path.resolve(strict=True)
        if resolved != path.absolute() or resolved.is_symlink():
            raise WorkerError("private evidence directory path differs")
        if os.name != "nt" and (resolved.stat().st_mode & 0o077):
            raise WorkerError("private evidence directory permissions are too broad")
        return resolved
    except OSError:
        raise WorkerError("private evidence directory is unavailable") from None


def _read_private_json(path: Path, directory: Path, label: str) -> dict[str, Any]:
    try:
        if path.is_symlink() or path.parent.resolve(strict=True) != directory:
            raise WorkerError(f"{label} path differs")
        if os.name != "nt" and path.exists() and (path.stat().st_mode & 0o077):
            raise WorkerError(f"{label} permissions are too broad")
        value = json.loads(path.read_text(encoding="utf-8"))
    except WorkerError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise WorkerError(f"{label} is unavailable or invalid") from None
    if not isinstance(value, dict):
        raise WorkerError(f"{label} must be an object")
    return value


def _write_private_json(path: Path, directory: Path, value: dict[str, Any]) -> str:
    data = _canonical(value) + b"\n"
    if (
        path.parent.resolve(strict=True) != directory
        or path.is_symlink()
        or len(data) > 16 * 1024 * 1024
    ):
        raise WorkerError("receipt path or size differs")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != data:
            raise WorkerError("private receipt readback differs")
    except FileExistsError:
        raise WorkerError("receipt already exists; refusing overwrite") from None
    except OSError:
        raise WorkerError("private receipt durability is unconfirmed") from None
    return hashlib.sha256(data).hexdigest()


def validate_plan(plan: dict[str, Any], *, database: str, primary: bool) -> None:
    allowed = {
        "schema_version",
        "kind",
        "owner",
        "reconciliation_id",
        "reason",
        "legacy_snapshot_sha256",
        "expected_legacy_tables",
        "accepted_legacy_tables",
        "accepted_legacy_sequences",
        "accepted_migrations",
        "primary_authorized",
        "package_revisions",
        "legacy_schema_fingerprint_sha256",
        "role_provision_authorized",
    }
    if (
        set(plan) - allowed
        or plan.get("schema_version") != 1
        or plan.get("kind") != "controlled-runtime-transition-v1"
    ):
        raise WorkerError("plan schema or fields differ")
    owner = plan.get("owner")
    if not isinstance(owner, str) or OWNER.fullmatch(owner) is None:
        raise WorkerError("plan owner differs")
    if (
        plan.get("reconciliation_id") != "controlled-runtime-" + owner
        or plan.get("reason") != EXACT_REASON
    ):
        raise WorkerError("plan quarantine identity differs")
    if (
        not isinstance(plan.get("legacy_snapshot_sha256"), str)
        or SHA256.fullmatch(plan["legacy_snapshot_sha256"]) is None
    ):
        raise WorkerError("plan accepted snapshot digest differs")
    schema_sha = plan.get("legacy_schema_fingerprint_sha256")
    if not isinstance(schema_sha, str) or SHA256.fullmatch(schema_sha) is None:
        raise WorkerError("plan accepted schema fingerprint differs")
    if plan.get("accepted_migrations") != list(LEGACY_MIGRATIONS):
        raise WorkerError("plan must name the exact 001-012 migration profile")
    tables = plan.get("expected_legacy_tables")
    accepted = plan.get("accepted_legacy_tables")
    if (
        not isinstance(tables, list)
        or len(tables) != 27
        or tables != sorted(set(tables))
        or any(
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name)
            for name in tables
        )
    ):
        raise WorkerError("plan legacy table inventory differs")
    if (
        not isinstance(accepted, list)
        or [item.get("table") for item in accepted if isinstance(item, dict)] != tables
    ):
        raise WorkerError("plan accepted table history differs")
    for item in accepted:
        if (
            set(item) != {"table", "count", "sha256"}
            or type(item["count"]) is not int
            or item["count"] < 0
            or SHA256.fullmatch(str(item["sha256"])) is None
        ):
            raise WorkerError("plan table digest entry differs")
    sequences = plan.get("accepted_legacy_sequences")
    if not isinstance(sequences, dict) or any(
        not isinstance(name, str) or not re.fullmatch(r"-?[0-9]+\|[tf]", str(state))
        for name, state in sequences.items()
    ):
        raise WorkerError("plan sequence history differs")
    if (
        type(plan.get("primary_authorized")) is not bool
        or plan["primary_authorized"] is not primary
    ):
        raise WorkerError("primary authorization gate differs")
    if plan.get("role_provision_authorized") is not True:
        raise WorkerError("separated role provisioning is not explicitly authorized")
    if primary and database != "kairos":
        raise WorkerError("primary mode accepts only literal kairos")
    if not primary and (
        database == "kairos"
        or CLONE_DATABASE.fullmatch(database) is None
        or not database.startswith("kairos_recovery_" + owner[:12] + "_")
    ):
        raise WorkerError(
            "ordinary mode accepts only the owned recovery clone namespace"
        )
    revisions = plan.get("package_revisions")
    if (
        not isinstance(revisions, dict)
        or set(revisions) != {"kairos-core", "kairos-persistence"}
        or revisions.get("kairos-core") != "6937eb4773fc00afaf5ba4e020b28b689f48e377"
    ):
        raise WorkerError("expected package revision manifest differs")
    if any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None
        for value in revisions.values()
    ):
        raise WorkerError("expected package revision format differs")


def verify_wheel_manifest(path: Path, plan: dict[str, Any]) -> str:
    """Bind installed package files to the controller's exact offline wheel manifest."""
    try:
        manifest_bytes = path.read_bytes()
        manifest = json.loads(manifest_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise WorkerError(
            "offline package manifest is unavailable or invalid"
        ) from None
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "packages"}
        or manifest["schema_version"] != 1
        or not isinstance(manifest["packages"], list)
    ):
        raise WorkerError("offline package manifest schema differs")
    packages = {
        item.get("name"): item
        for item in manifest["packages"]
        if isinstance(item, dict)
    }
    if set(packages) != {"kairos-core", "kairos-persistence"} or len(packages) != len(
        manifest["packages"]
    ):
        raise WorkerError("offline package inventory differs")
    expected = plan["package_revisions"]
    for name, item in packages.items():
        if set(item) != {"name", "revision", "wheel", "sha256", "files"}:
            raise WorkerError("offline package entry fields differ")
        if expected.get(name) is not None and item["revision"] != expected[name]:
            raise WorkerError("offline package revision differs")
        if (
            not isinstance(item["revision"], str)
            or re.fullmatch(r"[0-9a-f]{40}", item["revision"]) is None
            or SHA256.fullmatch(str(item["sha256"])) is None
        ):
            raise WorkerError("offline package identity differs")
        if (
            not isinstance(item["wheel"], str)
            or Path(item["wheel"]).name != item["wheel"]
            or not item["wheel"].endswith(".whl")
        ):
            raise WorkerError("offline wheel filename differs")
        files = item["files"]
        if not isinstance(files, dict) or not files:
            raise WorkerError("offline package file inventory is empty")
        try:
            distribution = importlib.metadata.distribution(name)
            observed = {str(entry): entry for entry in (distribution.files or ())}
            prefixes = set()
            for relative, digest in files.items():
                if (
                    not isinstance(relative, str)
                    or relative.startswith(("/", "\\"))
                    or ".." in Path(relative).parts
                    or SHA256.fullmatch(str(digest)) is None
                ):
                    raise WorkerError("offline package file record differs")
                prefixes.add(Path(relative).parts[0])
            package_files = {
                key
                for key in observed
                if Path(key).parts
                and Path(key).parts[0] in prefixes
                and ".dist-info" not in Path(key).parts
                and "__pycache__" not in Path(key).parts
                and not key.endswith((".pyc", ".pyo"))
            }
            if set(files) != package_files:
                raise WorkerError(
                    "offline package source inventory is incomplete or differs"
                )
            for relative, digest in files.items():
                entry = observed.get(relative)
                if entry is None:
                    raise WorkerError("installed package file inventory differs")
                file_path = Path(distribution.locate_file(entry))
                if (
                    file_path.is_symlink()
                    or not file_path.is_file()
                    or hashlib.sha256(file_path.read_bytes()).hexdigest() != digest
                ):
                    raise WorkerError("installed package file hash differs")
            wheel_path = path.parent / item["wheel"]
            if (
                wheel_path.is_symlink()
                or not wheel_path.is_file()
                or hashlib.sha256(wheel_path.read_bytes()).hexdigest() != item["sha256"]
            ):
                raise WorkerError("offline wheel bytes differ from manifest")
        except WorkerError:
            raise
        except Exception:  # noqa: BLE001 -- normalize filesystem/metadata failures without exposing paths.
            raise WorkerError("installed package provenance is unavailable") from None
    return hashlib.sha256(manifest_bytes).hexdigest()


class Budget:
    def __init__(self) -> None:
        self.start = time.monotonic()
        self.rows = 0
        self.bytes = 0

    def add(self, value: str) -> bytes:
        raw = value.encode("utf-8")
        self.rows += 1
        self.bytes += len(raw)
        if (
            self.rows > MAX_ROWS
            or self.bytes > MAX_BYTES
            or len(raw) > 4 * 1024 * 1024
            or time.monotonic() - self.start > MAX_SECONDS
        ):
            raise WorkerError("full-history snapshot exceeded its fixed bound")
        return raw


async def _table_digest(connection: Any, table: str, budget: Budget) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", table):
        raise WorkerError("invalid table identifier")
    query = (
        "SELECT json_build_object('table',$1::text,'count',count(*),'bytes',COALESCE(sum(row_bytes),0),'sha256',"
        "encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex'))::text AS result "
        "FROM (WITH row_hashes AS MATERIALIZED (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS row_sha, octet_length(to_jsonb(t)::text) AS row_bytes "
        'FROM public."' + table + '" t) SELECT row_sha,row_bytes FROM row_hashes) r'
    )
    raw = await connection.fetchval(query, table)
    try:
        result = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, json.JSONDecodeError):
        raise WorkerError("full-table digest result is invalid") from None
    if (
        not isinstance(result, dict)
        or result.get("table") != table
        or type(result.get("count")) is not int
        or type(result.get("bytes")) is not int
        or SHA256.fullmatch(str(result.get("sha256"))) is None
    ):
        raise WorkerError("full-table digest shape differs")
    budget.rows += result["count"]
    budget.bytes += result["bytes"]
    # The database performs row serialization and hash aggregation; the guard
    # bounds total rows/time while the SQL itself is bounded by statement_timeout.
    if (
        budget.rows > MAX_ROWS
        or budget.bytes > MAX_BYTES
        or time.monotonic() - budget.start > MAX_SECONDS
    ):
        raise WorkerError("full-history snapshot exceeded its fixed bound")
    return {"count": result["count"], "sha256": result["sha256"]}


async def _history(
    connection: Any, plan: dict[str, Any], *, runtime: bool
) -> dict[str, Any]:
    table_rows = await connection.fetch(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition ORDER BY c.relname"
    )
    names = tuple(str(item["relname"]) for item in table_rows)
    expected = tuple(plan["expected_legacy_tables"])
    if runtime:
        if names != tuple(sorted((*expected, *NEW_TABLES))):
            raise WorkerError("controlled-runtime table inventory differs")
        migrations = RUNTIME_PROFILE
    else:
        actual_all = tuple(str(item["relname"]) for item in table_rows)
        if actual_all != expected:
            raise WorkerError("legacy table inventory differs")
        migrations = LEGACY_MIGRATIONS
    versions = tuple(
        str(item["version"])
        for item in await connection.fetch(
            "SELECT version FROM schema_migrations ORDER BY version"
        )
    )
    if versions != migrations:
        raise WorkerError("database migration profile differs")
    inventory_json = await connection.fetchval(SCHEMA_QUERY)
    try:
        inventory = (
            json.loads(inventory_json)
            if isinstance(inventory_json, str)
            else inventory_json
        )
    except (TypeError, json.JSONDecodeError):
        raise WorkerError("schema inventory is unavailable") from None
    if not isinstance(inventory, dict):
        raise WorkerError("schema inventory is unavailable")
    budget = Budget()
    tables = {table: await _table_digest(connection, table, budget) for table in names}
    sequences: dict[str, Any] = {}
    for item in await connection.fetch(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S' ORDER BY c.relname"
    ):
        name = str(item["relname"])
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name):
            raise WorkerError("invalid sequence identifier")
        row = await connection.fetchrow(
            'SELECT last_value,is_called FROM public."' + name + '"'
        )
        sequences[name] = (
            str(int(row["last_value"])) + "|" + ("t" if row["is_called"] else "f")
        )
    maximum = int(
        await connection.fetchval(
            "SELECT COALESCE(max(event_seq),0) FROM public_execution_events"
        )
    )
    return {
        "migrations": list(migrations),
        "schema_fingerprint_sha256": _digest(inventory),
        "tables": tables,
        "public_sequences": sequences,
        "public_execution_events_max_sequence": maximum,
    }


def _compare_accepted(history: dict[str, Any], plan: dict[str, Any]) -> None:
    actual = [
        {"table": name, "count": entry["count"], "sha256": entry["sha256"]}
        for name, entry in history["tables"].items()
    ]
    if actual != plan["accepted_legacy_tables"]:
        raise WorkerError("full legacy table history differs from accepted baseline")
    if history["public_sequences"] != plan["accepted_legacy_sequences"]:
        raise WorkerError("legacy sequence state differs from accepted baseline")
    if history["migrations"] != plan["accepted_migrations"]:
        raise WorkerError("legacy migration history differs from accepted baseline")
    if history["schema_fingerprint_sha256"] != plan["legacy_schema_fingerprint_sha256"]:
        raise WorkerError("accepted schema inventory differs")
    if plan["legacy_snapshot_sha256"] != _digest(
        {
            "tables": actual,
            "sequences": history["public_sequences"],
            "migrations": history["migrations"],
            "schema_fingerprint_sha256": history["schema_fingerprint_sha256"],
        }
    ):
        raise WorkerError("accepted full snapshot digest differs")


async def _exact_expired_row(connection: Any) -> dict[str, Any]:
    rows = await connection.fetch(
        "SELECT to_jsonb(t)::text AS row FROM public.message_outbox t WHERE lease_until IS NOT NULL AND lease_until < now() ORDER BY id"
    )
    if len(rows) != 1:
        raise WorkerError("expected exactly one expired legacy outbox lease")
    try:
        row = json.loads(rows[0]["row"])
    except (TypeError, json.JSONDecodeError):
        raise WorkerError("exact expired row is invalid") from None
    required = {
        "id",
        "producer",
        "message_id",
        "topic",
        "payload",
        "payload_sha256",
        "publish_attempts",
        "published_at",
        "dead_lettered_at",
        "lease_owner",
        "lease_until",
        "last_error",
    }
    if not isinstance(row, dict) or not required.issubset(row):
        raise WorkerError("exact expired row identity is incomplete")
    if (
        row["published_at"] is not None
        or row["dead_lettered_at"] is not None
        or not row["lease_owner"]
        or not row["lease_until"]
    ):
        raise WorkerError("exact expired row is already acknowledged or not leased")
    try:
        payload = (
            json.loads(row["payload"])
            if isinstance(row["payload"], str)
            else row["payload"]
        )
        payload_bytes = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, json.JSONDecodeError):
        raise WorkerError("exact expired payload is not canonical JSON") from None
    if hashlib.sha256(payload_bytes).hexdigest() != row["payload_sha256"]:
        raise WorkerError("exact expired payload hash differs")
    return row


async def _other_clients(connection: Any) -> int:
    return int(
        await connection.fetchval(
            "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'"
        )
    )


async def _lock_boundary(connection: Any, tables: tuple[str, ...]) -> None:
    if await _other_clients(connection) != 0:
        raise WorkerError("another database client is connected")
    if not await connection.fetchval(
        "SELECT pg_try_advisory_xact_lock($1)", 4_907_627_681_104_115_019
    ):
        raise WorkerError("schema migration advisory lock is already held")
    if not await connection.fetchval(
        "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
        "closed-bar-producer:kairos-quant-scouts",
    ):
        raise WorkerError("closed-bar producer advisory lease is already held")
    # Migration and quarantine APIs use their own xact advisory keys.  The
    # access-exclusive lock freezes legacy writers before the full scan.
    quoted = ",".join('public."' + table + '"' for table in tables)
    await connection.execute("LOCK TABLE " + quoted + " IN ACCESS EXCLUSIVE MODE")
    if await _other_clients(connection) != 0:
        raise WorkerError("another database client connected during producer freeze")


class ConnectionBoundPool:
    """Expose one real connection through savepoints; never acquire a second."""

    def __init__(
        self, connection: Any, fault: Callable[[str], None] | None = None
    ) -> None:
        self.connection = connection
        self.fault = fault
        self.acquisitions = 0
        self.savepoints = 0
        self.view = _ObservedConnection(self)

    @asynccontextmanager
    async def acquire(self):
        if not self.connection.is_in_transaction():
            raise WorkerError("bound primitive requires the active outer transaction")
        self.acquisitions += 1
        yield self.view
        if not self.connection.is_in_transaction():
            raise WorkerError("nested primitive escaped the outer transaction")


class _ObservedConnection:
    def __init__(self, pool: ConnectionBoundPool) -> None:
        self._pool = pool

    def __getattr__(self, name: str) -> Any:
        return getattr(self._pool.connection, name)

    async def execute(self, query: str, *args: Any) -> Any:
        result = await self._pool.connection.execute(query, *args)
        if (
            self._pool.fault
            and query == "INSERT INTO schema_migrations(version) VALUES ($1)"
            and args
        ):
            self._pool.fault("after_migration_" + str(args[0])[:3])
        return result

    @asynccontextmanager
    async def transaction(self):
        connection = self._pool.connection
        if not connection.is_in_transaction():
            raise WorkerError("migration savepoint has no physical outer transaction")
        backend = int(await connection.fetchval("SELECT pg_backend_pid()"))
        async with connection.transaction():
            self._pool.savepoints += 1
            yield self
        if (
            not connection.is_in_transaction()
            or int(await connection.fetchval("SELECT pg_backend_pid()")) != backend
        ):
            raise WorkerError("migration savepoint changed physical connection")


def _load_primitives(pool: ConnectionBoundPool, database_name: str) -> Any:
    try:
        from kairos_persistence.database import Database, MigrationProfile
        from kairos_persistence.repository import (
            AuditRepository,
            OfflineOutboxExpiredLease,
            OfflineOutboxIdentity,
        )
    except Exception:  # noqa: BLE001 -- normalize driver errors to a sanitized capability failure.
        raise WorkerError(
            "current installed persistence primitives are unavailable"
        ) from None

    if (
        tuple(Database.migration_names(MigrationProfile.CONTROLLED_RUNTIME))
        != RUNTIME_PROFILE
    ):
        raise WorkerError("installed controlled-runtime migration manifest differs")

    class BoundDatabase(Database):
        @property
        def pool(self):  # type: ignore[override]
            return pool

    dsn = "postgresql://kairos@127.0.0.1:5432/" + database_name
    settings = SimpleNamespace(
        database_url=dsn,
        migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
        pool_min_size=1,
        pool_max_size=1,
        command_timeout_s=120,
        _env_file=None,
    )
    return SimpleNamespace(
        database=BoundDatabase(
            settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME
        ),
        repository=AuditRepository,
        identity=OfflineOutboxIdentity,
        lease=OfflineOutboxExpiredLease,
    )


def _runtime_auth(directory: Path) -> dict[str, str]:
    auth = _read_private_json(
        directory / "runtime-auth.json", directory, "runtime auth file"
    )
    password = auth.get("password")
    if (
        set(auth) != {"user", "password"}
        or auth.get("user") != "kairos_runtime"
        or not isinstance(password, str)
        or not 32 <= len(password) <= 256
        or "\x00" in password
    ):
        raise WorkerError("runtime auth identity or password format differs")
    return {"user": "kairos_runtime", "password": password}


async def _grant_roles(
    connection: Any, *, primary: bool, plan: dict[str, Any], directory: Path
) -> dict[str, Any]:
    role_rows = await connection.fetch(
        "SELECT rolname,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication,rolcanlogin FROM pg_roles WHERE rolname=ANY($1::text[])",
        ["kairos_runtime", "kairos_operator"],
    )
    existing = {str(row["rolname"]): row for row in role_rows}
    for name, row in existing.items():
        if name == "kairos_runtime" and (
            not row["rolcanlogin"]
            or row["rolsuper"]
            or row["rolbypassrls"]
            or row["rolcreaterole"]
            or row["rolcreatedb"]
            or row["rolreplication"]
        ):
            raise WorkerError(
                "existing kairos_runtime role conflicts with reviewed policy"
            )
        if name == "kairos_operator" and (
            row["rolcanlogin"]
            or row["rolsuper"]
            or row["rolbypassrls"]
            or row["rolcreaterole"]
            or row["rolcreatedb"]
            or row["rolreplication"]
        ):
            raise WorkerError(
                "existing kairos_operator role conflicts with reviewed policy"
            )
    if not plan.get("role_provision_authorized"):
        raise WorkerError("role provisioning is not in the reviewed transition plan")
    if "kairos_runtime" not in existing:
        if primary:
            auth = _runtime_auth(directory)
            password_literal = await connection.fetchval(
                "SELECT quote_literal($1::text)", auth["password"]
            )
            await connection.execute(
                "CREATE ROLE kairos_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION PASSWORD "
                + str(password_literal)
            )
        else:
            await connection.execute(
                "CREATE ROLE kairos_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION"
            )
    if "kairos_operator" not in existing:
        await connection.execute(
            "CREATE ROLE kairos_operator NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION"
        )
    memberships = await connection.fetchval(
        "SELECT count(*) FROM pg_auth_members m JOIN pg_roles member_role ON member_role.oid=m.member "
        "JOIN pg_roles granted_role ON granted_role.oid=m.roleid "
        "WHERE member_role.rolname='kairos_runtime' OR granted_role.rolname='kairos_operator'"
    )
    if int(memberships or 0) != 0:
        raise WorkerError("runtime/operator role membership must remain empty")
    db_name = str(await connection.fetchval("SELECT current_database()"))
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,62}", db_name):
        raise WorkerError("database identifier is invalid")
    await connection.execute(
        'GRANT CONNECT ON DATABASE "' + db_name + '" TO kairos_runtime'
    )
    await connection.execute("GRANT USAGE ON SCHEMA public TO kairos_runtime")
    runtime_rows = await connection.fetch(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition ORDER BY c.relname"
    )
    runtime_tables = tuple(str(row["relname"]) for row in runtime_rows)
    for table in runtime_tables:
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", table):
            raise WorkerError("runtime table identifier is invalid")
        identifier = 'public."' + table + '"'
        if table in CONTROL_TABLES:
            await connection.execute(
                "GRANT SELECT ON TABLE " + identifier + " TO kairos_runtime"
            )
        else:
            await connection.execute(
                "GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE "
                + identifier
                + " TO kairos_runtime"
            )
    for table in ("operator_control_admissions", "operator_control_dispatch_claims"):
        await connection.execute(
            'GRANT INSERT ON TABLE public."' + table + '" TO kairos_runtime'
        )
    for row in await connection.fetch(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S' ORDER BY c.relname"
    ):
        sequence = str(row["relname"])
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", sequence):
            raise WorkerError("runtime sequence identifier is invalid")
        await connection.execute(
            'GRANT USAGE ON SEQUENCE public."' + sequence + '" TO kairos_runtime'
        )
    return {
        "runtime_tables": len(runtime_tables),
        "role_creation": "only-if-absent",
        "primary": primary,
    }


async def _verify_permissions(connection: Any) -> dict[str, Any]:
    try:
        identity = await connection.fetchrow(
            "SELECT current_user AS role,session_user AS session_role"
        )
        if (
            identity is None
            or identity["role"] != "kairos_runtime"
            or identity["session_role"] != "kairos_runtime"
        ):
            raise WorkerError(
                "runtime privileges must be checked as a real runtime login"
            )
        from kairos_persistence.operator_control import OperatorControlRepository

        # Use the actual startup prerequisite in a read-only transaction.
        class ReadPool:
            def __init__(self, conn: Any) -> None:
                self.connection = conn

            @asynccontextmanager
            async def acquire(self):
                yield self.connection

        await OperatorControlRepository(ReadPool(connection)).verify_runtime_access()
        rejected = 0
        probes = (
            "INSERT INTO public.operator_controls(scope_key,scope_payload,scope_sha256,version,state,audit_head_sha256) VALUES ('forbidden', '{}'::jsonb, repeat('0',64), 1, 'DISARMED', repeat('0',64))",
            "UPDATE public.operator_controls SET state='KILLED' WHERE false",
            "ALTER TABLE public.operator_controls DISABLE TRIGGER ALL",
            "SET ROLE kairos_operator",
            "CREATE TABLE public.kairos_forbidden_probe(id integer)",
        )
        async with connection.transaction():
            await connection.execute("SAVEPOINT kairos_runtime_negative_probe")
            for sql in probes:
                await connection.execute(
                    "ROLLBACK TO SAVEPOINT kairos_runtime_negative_probe"
                )
                try:
                    await connection.execute(sql)
                except Exception as exc:  # noqa: BLE001 -- inspect only the SQLSTATE, reject every other error.
                    if not _is_insufficient_privilege(exc):
                        raise WorkerError(
                            "runtime negative probe failed for a non-privilege reason"
                        ) from None
                    rejected += 1
                else:
                    raise WorkerError(
                        "runtime role unexpectedly passed a forbidden privilege probe"
                    )
            await connection.execute(
                "ROLLBACK TO SAVEPOINT kairos_runtime_negative_probe"
            )
            await connection.execute("RELEASE SAVEPOINT kairos_runtime_negative_probe")
        if rejected != len(probes):
            raise WorkerError(
                "runtime forbidden-capability probe did not reject every operation"
            )
        return {
            "startup_prerequisite": "passed",
            "forbidden_capabilities_rejected": rejected,
        }
    except WorkerError:
        raise
    except Exception:  # noqa: BLE001 -- sanitize driver and database errors.
        raise WorkerError("actual runtime privilege verification failed") from None


def _is_insufficient_privilege(error: BaseException) -> bool:
    return (
        getattr(error, "sqlstate", None) == "42501"
        or type(error).__name__ == "InsufficientPrivilegeError"
    )


async def _verify_runtime_permissions(
    database: str, *, directory: Path, require_auth: bool = False
) -> dict[str, Any]:
    try:
        import asyncpg

        dsn = "postgresql://kairos_runtime@127.0.0.1:5432/" + database
        auth_path = directory / "runtime-auth.json"
        if require_auth and not auth_path.exists():
            raise WorkerError("primary runtime auth file is required")
        if auth_path.exists():
            auth = _runtime_auth(directory)
            dsn = (
                "postgresql://kairos_runtime:"
                + quote(auth["password"], safe="")
                + "@127.0.0.1:5432/"
                + database
            )
        connection = await asyncpg.connect(
            dsn,
            timeout=20,
            command_timeout=120,
            server_settings={
                "application_name": "kairos-controlled-runtime-permission-probe",
                "default_transaction_read_only": "off",
            },
        )
    except Exception:  # noqa: BLE001 -- no connection details or credentials may reach output.
        raise WorkerError(
            "runtime login probe could not connect over loopback"
        ) from None
    try:
        return await _verify_permissions(connection)
    finally:
        await connection.close()


async def _preflight_runtime_login(
    connection: Any, database: str, *, directory: Path
) -> None:
    if database != "kairos":
        raise WorkerError(
            "runtime principal preflight requires the exact primary database"
        )
    exists = await connection.fetchval(
        "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='kairos_runtime')"
    )
    if exists is not False:
        # This is an initial, create-only legacy-to-current transition. Existing
        # ownership or inherited ACLs cannot be proved safe by checking a password
        # or role attributes, and must be reviewed before any primary mutation.
        raise WorkerError(
            "existing or indeterminate runtime principal requires separate ownership and ACL review"
        )
    _runtime_auth(directory)


async def _prepare_exact(
    connection: Any, plan: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    history = await _history(connection, plan, runtime=False)
    row = await _exact_expired_row(connection)
    _compare_accepted(history, plan)
    return history, row


def _private_target(row: dict[str, Any]) -> dict[str, Any]:
    # Private artifact only: payload and lease owner are intentionally retained
    # for exact native API binding, never copied into stdout or sanitized summary.
    return row


async def _quarantined_row(connection: Any) -> dict[str, Any]:
    rows = await connection.fetch(
        "SELECT to_jsonb(t)::text AS row FROM public.message_outbox t WHERE reconciliation_id IS NOT NULL"
    )
    if len(rows) != 1:
        raise WorkerError(
            "controlled-runtime outbox reconciliation row inventory differs"
        )
    row = json.loads(rows[0]["row"])
    if (
        row.get("reconciliation_state") != "PUBLISH_OUTCOME_UNKNOWN"
        or row.get("lease_owner") is not None
        or row.get("lease_until") is not None
    ):
        raise WorkerError("controlled-runtime exact quarantine state differs")
    return row


async def _snapshot_readonly(
    connection: Any, plan: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    async with connection.transaction(isolation="repeatable_read", readonly=True):
        await connection.execute("SET LOCAL statement_timeout='60s'")
        await connection.execute("SET LOCAL lock_timeout='5s'")
        await connection.execute("SET LOCAL work_mem='8MB'")
        await connection.execute("SET LOCAL TIME ZONE 'UTC'")
        history = await _history(connection, plan, runtime=False)
        _compare_accepted(history, plan)
        target = await _exact_expired_row(connection)
        if await _other_clients(connection) != 0:
            raise WorkerError("another database client appeared during snapshot")
        return history, target


async def _atomic_transition(
    connection: Any,
    plan: dict[str, Any],
    *,
    primary: bool,
    directory: Path,
    fault_at: str | None = None,
    expected_runtime_schema_sha256: str | None = None,
) -> dict[str, Any]:
    if connection.is_in_transaction():
        raise WorkerError("worker owns exactly one physical outer transaction")
    outer = connection.transaction(isolation="repeatable_read")
    await outer.start()
    committing = False
    intent: dict[str, Any] | None = None
    hit: list[str] = []

    def fault(stage: str) -> None:
        if fault_at == stage:
            hit.append(stage)
            raise FaultCheckpointError(stage)

    try:
        await connection.execute("SET LOCAL statement_timeout='60s'")
        await connection.execute("SET LOCAL lock_timeout='5s'")
        await connection.execute("SET LOCAL work_mem='8MB'")
        await connection.execute("SET LOCAL TIME ZONE 'UTC'")
        tables = tuple(plan["expected_legacy_tables"])
        await _lock_boundary(connection, tables)
        if await connection.fetchval("SELECT current_user") != "kairos":
            raise WorkerError("effective migration role must be kairos")
        backend = int(await connection.fetchval("SELECT pg_backend_pid()"))
        baseline, original = await _prepare_exact(connection, plan)
        pool = ConnectionBoundPool(connection, fault)
        primitives = _load_primitives(
            pool, str(await connection.fetchval("SELECT current_database()"))
        )
        await primitives.database.migrate()
        fault("after_migrations")
        if int(await connection.fetchval("SELECT pg_backend_pid()")) != backend:
            raise WorkerError("migration changed physical backend")
        lease = primitives.lease(
            owner=original["lease_owner"], until=_utc(original["lease_until"])
        )
        identity = primitives.identity(
            id=original["id"],
            producer=original["producer"],
            message_id=original["message_id"],
            topic=original["topic"],
            payload_sha256=original["payload_sha256"],
            publish_attempts=original["publish_attempts"],
        )
        repository = primitives.repository(pool)
        quarantine = await repository.quarantine_expired_outbox_exact(
            identity,
            expired_lease=lease,
            reconciliation_id=plan["reconciliation_id"],
            reason=plan["reason"],
        )
        if getattr(quarantine.state, "value", quarantine.state) != "QUARANTINED":
            raise WorkerError("native exact quarantine was rejected")
        fault("after_quarantine")
        _check_bound(pool, connection, backend)
        runtime_history = await _history(connection, plan, runtime=True)
        if (
            expected_runtime_schema_sha256 is not None
            and runtime_history["schema_fingerprint_sha256"]
            != expected_runtime_schema_sha256
        ):
            raise WorkerError(
                "primary runtime schema differs from accepted clone rehearsal"
            )
        after = await _quarantined_row(connection)
        _check_exact_quarantine(original, after, plan)
        projected = await _projected_history(connection, plan, original)
        if projected != baseline:
            raise WorkerError(
                "legacy full-history projection changed beyond exact quarantine"
            )
        _check_new_relations(runtime_history)
        role_result = await _grant_roles(
            connection, primary=primary, plan=plan, directory=directory
        )
        fault("after_roles")
        intent = {
            "schema_version": 1,
            "kind": "controlled-runtime-precommit-v1",
            "database": str(await connection.fetchval("SELECT current_database()")),
            "plan_sha256": _digest(plan),
            "plan_binding_sha256": _plan_binding_sha256(plan),
            "legacy_history_sha256": _digest(baseline),
            "runtime_history_sha256": _digest(runtime_history),
            "target_row_id": str(original["id"]),
            "reconciliation_id": plan["reconciliation_id"],
            "prepared_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "backend_pid": backend,
            "quarantine_calls": 1,
            "original_row": original,
        }
        receipt_hash = _write_private_json(
            directory / ("native-precommit-" + _digest(intent) + ".json"),
            directory,
            intent,
        )
        if receipt_hash != hashlib.sha256(_canonical(intent) + b"\n").hexdigest():
            raise WorkerError("precommit intent hash acknowledgement differs")
        fault("before_commit")
        committing = True
        await outer.commit()
        if fault_at == "after_commit_response_loss":
            hit.append(fault_at)
            raise WorkerError("intentional lost commit acknowledgement")
        return {
            "state": "COMMITTED_ACKNOWLEDGED",
            "intent": intent,
            "history": runtime_history,
            "runtime_history_sha256": _digest(runtime_history),
            "private_target": original,
            "roles": role_result,
            "fault_hit": hit,
        }
    except BaseException as exc:
        if committing:
            raise OutcomeUnknown(intent, hit) from None
        try:
            await outer.rollback()
        except BaseException:  # noqa: BLE001 -- cancellation during rollback leaves commit outcome unknown.
            raise OutcomeUnknown(intent, hit) from None
        if isinstance(exc, WorkerError):
            raise
        raise WorkerError(
            "native atomic transition failed; outer rollback acknowledged"
        ) from None


class OutcomeUnknown(WorkerError):
    def __init__(
        self, intent: dict[str, Any] | None, hit: list[str] | None = None
    ) -> None:
        super().__init__(
            "commit acknowledgement unknown; reconnect read-only and classify; never retry"
        )
        self.intent = intent
        self.hit = hit or []


async def _noop() -> None:
    return None


def _utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise WorkerError("expired lease timestamp is not timezone-aware")
        return value.astimezone(UTC)
    if not isinstance(value, str):
        raise WorkerError("expired lease timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise WorkerError("expired lease timestamp is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WorkerError("expired lease timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _plan_binding_sha256(plan: dict[str, Any]) -> str:
    """The primary authorization bit may be added only after clone acceptance."""
    return _digest(
        {key: value for key, value in plan.items() if key != "primary_authorized"}
    )


def _check_bound(pool: ConnectionBoundPool, connection: Any, backend: int) -> None:
    if (
        pool.acquisitions != 2
        or pool.savepoints != 2
        or not connection.is_in_transaction()
    ):
        raise WorkerError(
            "migrate/quarantine did not share one physical outer transaction"
        )


def _check_exact_quarantine(
    before: dict[str, Any], after: dict[str, Any], plan: dict[str, Any]
) -> None:
    for name, value in before.items():
        if name in {
            "lease_owner",
            "lease_until",
            "reconciliation_state",
            "reconciliation_id",
            "reconciliation_started_at",
            "reconciliation_outcome_at",
            "last_error",
        }:
            continue
        if after.get(name) != value:
            raise WorkerError("quarantine altered forbidden legacy outbox fields")
    if (
        after.get("lease_owner") is not None
        or after.get("lease_until") is not None
        or after.get("reconciliation_state") != "PUBLISH_OUTCOME_UNKNOWN"
        or after.get("reconciliation_id") != plan["reconciliation_id"]
    ):
        raise WorkerError("native quarantine durable state differs")
    expected_error = json.dumps(
        {
            "expired_lease_owner_sha256": hashlib.sha256(
                str(before["lease_owner"]).encode("utf-8")
            ).hexdigest(),
            "expired_lease_until": _utc(before["lease_until"]).isoformat(
                timespec="microseconds"
            ),
            "reason": plan["reason"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if after.get("last_error") != expected_error or after.get(
        "reconciliation_started_at"
    ) != after.get("reconciliation_outcome_at"):
        raise WorkerError("native quarantine evidence does not bind reviewed reason")


async def _projected_history(
    connection: Any, plan: dict[str, Any], original: dict[str, Any]
) -> dict[str, Any]:
    """Recompute every legacy table after upgrade with the one allowed row restored."""
    # Use an explicit row projection for schema_migrations and message_outbox;
    # all remaining legacy relations are hashed byte-for-byte as before.
    history = {
        "migrations": list(LEGACY_MIGRATIONS),
        "schema_fingerprint_sha256": plan["legacy_schema_fingerprint_sha256"],
        "tables": {},
        "public_sequences": {},
        "public_execution_events_max_sequence": 0,
    }
    budget = Budget()
    for table in plan["expected_legacy_tables"]:
        if table == "schema_migrations":
            query = (
                "SELECT json_build_object('table',$2::text,'count',count(*),'bytes',COALESCE(sum(row_bytes),0),'sha256',"
                "encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex'))::text AS result "
                "FROM (WITH row_hashes AS MATERIALIZED (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS row_sha, "
                "octet_length(to_jsonb(t)::text) AS row_bytes FROM public.schema_migrations t WHERE version=ANY($1::text[])) SELECT row_sha,row_bytes FROM row_hashes) r"
            )
            params = (list(LEGACY_MIGRATIONS), table)
        elif table == "message_outbox":
            # Exclude the four 018 columns, restore only this exact row's old
            # lease/last_error values, then use the exact accepted SQL hash.
            restore = {
                name: original.get(name)
                for name in ("lease_owner", "lease_until", "last_error")
            }
            expr = "(to_jsonb(t) - ARRAY['reconciliation_state','reconciliation_id','reconciliation_started_at','reconciliation_outcome_at']) || CASE WHEN t.id=$1 THEN $2::jsonb ELSE '{}'::jsonb END"
            query = (
                "SELECT json_build_object('table',$3::text,'count',count(*),'bytes',COALESCE(sum(row_bytes),0),'sha256',"
                "encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex'))::text AS result "
                "FROM (WITH row_hashes AS MATERIALIZED (SELECT encode(sha256(convert_to(("
                + expr
                + ")::text,'UTF8')),'hex') AS row_sha, "
                "octet_length(("
                + expr
                + ")::text) AS row_bytes FROM public.message_outbox t) SELECT row_sha,row_bytes FROM row_hashes) r"
            )
            params = (int(original["id"]), _canonical(restore).decode("utf-8"), table)
        else:
            if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", table):
                raise WorkerError("invalid projected table identifier")
            query = (
                "SELECT json_build_object('table',$1::text,'count',count(*),'bytes',COALESCE(sum(row_bytes),0),'sha256',"
                "encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex'))::text AS result "
                "FROM (WITH row_hashes AS MATERIALIZED (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS row_sha, "
                'octet_length(to_jsonb(t)::text) AS row_bytes FROM public."'
                + table
                + '" t) SELECT row_sha,row_bytes FROM row_hashes) r'
            )
            params = (table,)
        try:
            raw = await connection.fetchval(query, *params)
            entry = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:  # noqa: BLE001 -- suppress database detail and report sanitized digest failure.
            raise WorkerError("projected full-table digest failed") from None
        if (
            not isinstance(entry, dict)
            or entry.get("table") != table
            or type(entry.get("count")) is not int
            or type(entry.get("bytes")) is not int
            or SHA256.fullmatch(str(entry.get("sha256"))) is None
        ):
            raise WorkerError("projected full-table digest shape differs")
        budget.rows += entry["count"]
        budget.bytes += entry["bytes"]
        if (
            budget.rows > MAX_ROWS
            or budget.bytes > MAX_BYTES
            or time.monotonic() - budget.start > MAX_SECONDS
        ):
            raise WorkerError(
                "projected full-history snapshot exceeded its fixed bound"
            )
        history["tables"][table] = {"count": entry["count"], "sha256": entry["sha256"]}
    for row in await connection.fetch(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S' ORDER BY c.relname"
    ):
        name = str(row["relname"])
        state = await connection.fetchrow(
            'SELECT last_value,is_called FROM public."' + name + '"'
        )
        history["public_sequences"][name] = (
            str(int(state["last_value"])) + "|" + ("t" if state["is_called"] else "f")
        )
    history["public_execution_events_max_sequence"] = int(
        await connection.fetchval(
            "SELECT COALESCE(max(event_seq),0) FROM public_execution_events"
        )
    )
    return history


def _check_new_relations(history: dict[str, Any]) -> None:
    for table in NEW_TABLES:
        expected = 1 if table == "paper_canary_database_identity" else 0
        if history["tables"].get(table, {}).get("count") != expected:
            raise WorkerError("new controlled-runtime table has unexpected rows")


async def _classify_readonly(
    connection: Any, plan: dict[str, Any], intent: dict[str, Any]
) -> str:
    if connection.is_in_transaction():
        raise WorkerError("commit classifier requires a fresh read-only connection")
    async with connection.transaction(isolation="repeatable_read", readonly=True):
        await connection.execute("SET LOCAL statement_timeout='60s'")
        await connection.execute("SET LOCAL lock_timeout='5s'")
        await connection.execute("SET LOCAL work_mem='8MB'")
        await connection.execute("SET LOCAL TIME ZONE 'UTC'")
        versions = tuple(
            str(item["version"])
            for item in await connection.fetch(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        )
        if versions == LEGACY_MIGRATIONS:
            history = await _history(connection, plan, runtime=False)
            _compare_accepted(history, plan)
            return "ROLLED_BACK_EXACT"
        if versions != RUNTIME_PROFILE:
            return "INDETERMINATE"
        history = await _history(connection, plan, runtime=True)
        row = await _quarantined_row(connection)
        projected = await _projected_history(
            connection, plan, intent.get("original_row", {})
        )
        if (
            _digest(history) != intent.get("runtime_history_sha256")
            or intent.get("plan_binding_sha256") != _plan_binding_sha256(plan)
            or row.get("reconciliation_id") != plan["reconciliation_id"]
        ):
            return "INDETERMINATE"
        _compare_projection(projected, plan)
        return "COMMITTED_EXACT"


def _compare_projection(projected: dict[str, Any], plan: dict[str, Any]) -> None:
    actual = [
        {"table": name, "count": value["count"], "sha256": value["sha256"]}
        for name, value in projected["tables"].items()
    ]
    if (
        actual != plan["accepted_legacy_tables"]
        or projected["public_sequences"] != plan["accepted_legacy_sequences"]
        or projected["migrations"] != plan["accepted_migrations"]
    ):
        raise WorkerError("full legacy projection differs from accepted baseline")
    digest = _digest(
        {
            "tables": actual,
            "sequences": projected["public_sequences"],
            "migrations": projected["migrations"],
            "schema_fingerprint_sha256": projected["schema_fingerprint_sha256"],
        }
    )
    if digest != plan["legacy_snapshot_sha256"]:
        raise WorkerError("accepted legacy snapshot digest differs")


async def _connect(database: str, *, primary: bool, directory: Path) -> Any:
    try:
        import asyncpg
    except Exception:  # noqa: BLE001 -- normalize missing/broken asyncpg installation.
        raise WorkerError(
            "asyncpg is unavailable in the reviewed worker runtime"
        ) from None
    dsn = "postgresql://kairos@127.0.0.1:5432/" + database
    if primary:
        auth = _read_private_json(
            directory / "native-auth.json", directory, "primary auth file"
        )
        plan = _read_private_json(directory / "plan.json", directory, "transition plan")
        expected_user = "kairos_transition_" + str(plan.get("owner", ""))[:12]
        if (
            set(auth) != {"user", "password", "role"}
            or auth.get("user") != expected_user
            or auth.get("role") != "kairos"
        ):
            raise WorkerError("primary temporary auth identity differs")
        password = auth.get("password")
        if (
            not isinstance(password, str)
            or not 32 <= len(password) <= 256
            or "\n" in password
            or "\r" in password
        ):
            raise WorkerError("primary temporary auth password format differs")
        dsn = (
            "postgresql://"
            + quote(auth["user"], safe="")
            + ":"
            + quote(password, safe="")
            + "@127.0.0.1:5432/kairos"
        )
    try:
        connection = await asyncpg.connect(
            dsn,
            timeout=20,
            command_timeout=120,
            server_settings={
                "application_name": "kairos-controlled-runtime-worker",
                "default_transaction_read_only": "off",
            },
        )
        if primary:
            await connection.execute("SET ROLE kairos")
        if await connection.fetchval("SELECT current_database()") != database:
            await connection.close()
            raise WorkerError("connected database does not match explicit target")
        if await connection.fetchval("SELECT current_user") != "kairos":
            await connection.close()
            raise WorkerError("effective database role is not kairos")
        return connection
    except WorkerError:
        raise
    except Exception:  # noqa: BLE001 -- database connection details must not leave the worker.
        raise WorkerError("loopback database connection failed") from None


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    directory = _safe_directory(args.directory)
    plan_path = directory / "plan.json"
    plan = _read_private_json(plan_path, directory, "transition plan")
    validate_plan(plan, database=args.database, primary=args.primary)
    if (
        not args.primary
        and args.database.endswith("_current_second")
        and args.mode not in {"permissions", "verify", "verify-restored-primary"}
    ):
        raise WorkerError("secondary restored clone is verify-only")
    if args.mode == "verify-restored-primary" and (
        args.primary or not args.database.endswith("_current_second")
    ):
        raise WorkerError(
            "restored-primary verification requires only the secondary owned clone"
        )
    if args.mode == "rehearse" and args.primary:
        raise WorkerError("primary rehearsal is forbidden")
    if args.mode == "apply" and not args.primary:
        raise WorkerError(
            "clone mutations are performed only by the full rehearsal path"
        )
    if args.mode == "apply" and args.primary and not plan["primary_authorized"]:
        raise WorkerError("primary mutation requires accepted authorization in plan")
    manifest_hash = verify_wheel_manifest(args.manifest, plan)
    if args.mode == "rehearse" and args.primary:
        raise WorkerError("fault rehearsal must target only the owned clone")
    async with _loopback_only() as guard:
        connection = await _connect(
            args.database, primary=args.primary, directory=directory
        )
        try:
            if args.primary and args.mode == "apply":
                await _preflight_runtime_login(
                    connection, args.database, directory=directory
                )
            if args.mode in {"inspect", "verify", "verify-restored-primary"}:
                history_only = (
                    args.mode == "verify"
                    and not args.primary
                    and args.database.endswith("_current_second")
                )
                if args.mode == "inspect":
                    history, target = await _snapshot_readonly(connection, plan)
                elif args.mode == "verify-restored-primary":
                    history, target = await _verify_restored_primary(
                        connection, plan, directory, manifest_sha256=manifest_hash
                    )
                else:
                    history, target = await _verify_current(
                        connection,
                        plan,
                        directory,
                        primary=args.primary,
                        manifest_sha256=manifest_hash,
                        history_only=history_only,
                    )
                history_only = history_only or args.mode == "verify-restored-primary"
                safe = {
                    "schema_version": 1,
                    "kind": "controlled-runtime-native-inspection-v1"
                    if args.mode == "inspect"
                    else "controlled-runtime-native-verification-v1",
                    "database": args.database,
                    "plan_sha256": _digest(plan),
                    "plan_binding_sha256": _plan_binding_sha256(plan),
                    "wheel_manifest_sha256": manifest_hash,
                    "snapshot_sha256": _digest(history),
                    "legacy_table_count": len(plan["expected_legacy_tables"]),
                    "legacy_row_count": sum(
                        history["tables"][table]["count"]
                        for table in plan["expected_legacy_tables"]
                    ),
                    "target_row_id_sha256": hashlib.sha256(
                        str(target["id"]).encode()
                    ).hexdigest(),
                    "target_payload_sha256": target.get("payload_sha256"),
                    "expired_lease_until_utc": _utc(target["lease_until"])
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "state": "HISTORY_ONLY_RESTORED_PRIMARY"
                    if args.mode == "verify-restored-primary"
                    else (
                        "VERIFIED_HISTORY_ONLY"
                        if history_only
                        else ("VERIFIED" if args.mode == "verify" else "INSPECTED")
                    ),
                    "runtime_permissions": "NOT_CHECKED_RESTORED_CLUSTER"
                    if history_only
                    else ("VERIFIED" if args.mode == "verify" else "NOT_CHECKED"),
                }
                artifact = {
                    **safe,
                    "history": history,
                    "private_target": _private_target(target),
                }
                path = directory / (
                    "native-inspection.json"
                    if args.mode == "inspect"
                    else "native-verify-restored-primary.json"
                    if args.mode == "verify-restored-primary"
                    else "native-verify.json"
                )
                safe["artifact_sha256"] = _write_private_json(path, directory, artifact)
                return safe | {
                    "primary_mutations": 0,
                    "loopback_connections": guard.connections,
                    "forbidden_network_calls": guard.forbidden,
                }
            if args.mode == "permissions":
                result = await _permissions_only(
                    connection,
                    plan,
                    primary=args.primary,
                    directory=directory,
                    manifest_sha256=manifest_hash,
                )
            else:
                if args.mode == "rehearse":
                    result = await _rehearse(
                        connection,
                        plan,
                        primary=False,
                        directory=directory,
                        manifest_sha256=manifest_hash,
                    )
                elif args.mode == "apply":
                    result = await _apply(
                        connection,
                        plan,
                        primary=args.primary,
                        database=args.database,
                        directory=directory,
                        manifest_sha256=manifest_hash,
                    )
                else:
                    raise WorkerError("unsupported worker mode")
            result["wheel_manifest_sha256"] = manifest_hash
            result["primary_mutations"] = int(args.primary and args.mode == "apply")
            result["loopback_connections"] = guard.connections
            result["forbidden_network_calls"] = guard.forbidden
            return result
        finally:
            await connection.close()


class _loopback_only:
    async def __aenter__(self):
        self.original = asyncio.BaseEventLoop.create_connection
        self.connections = 0
        self.forbidden = 0

        async def guarded(
            loop: Any,
            protocol_factory: Any,
            host: Any = None,
            port: Any = None,
            *args: Any,
            **kwargs: Any,
        ):
            if host != "127.0.0.1" or str(port) != "5432":
                self.forbidden += 1
                raise WorkerError("non-loopback network attempt is forbidden")
            self.connections += 1
            return await self.original(
                loop, protocol_factory, host, port, *args, **kwargs
            )

        asyncio.BaseEventLoop.create_connection = guarded
        return self

    async def __aexit__(self, *args: object):
        asyncio.BaseEventLoop.create_connection = self.original


async def _verify_current(
    connection: Any,
    plan: dict[str, Any],
    directory: Path,
    *,
    primary: bool,
    manifest_sha256: str,
    history_only: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if connection.is_in_transaction():
        raise WorkerError("verification requires a fresh connection")
    async with connection.transaction(isolation="repeatable_read", readonly=True):
        await connection.execute("SET LOCAL statement_timeout='60s'")
        await connection.execute("SET LOCAL lock_timeout='5s'")
        await connection.execute("SET LOCAL work_mem='8MB'")
        await connection.execute("SET LOCAL TIME ZONE 'UTC'")
        history = await _history(connection, plan, runtime=True)
        prior = _read_private_json(
            directory / ("native-apply.json" if primary else "native-rehearsal.json"),
            directory,
            "native transition receipt",
        )
        quarantined = await _quarantined_row(connection)
        original = prior.get("private_target")
        _check_new_relations(history)
        expected_kind = (
            "controlled-runtime-native-apply-v1"
            if primary
            else "controlled-runtime-native-rehearsal-v1"
        )
        if (
            prior.get("kind") != expected_kind
            or (not primary and prior.get("result") != "PASS")
            or prior.get("plan_binding_sha256") != _plan_binding_sha256(plan)
            or prior.get("wheel_manifest_sha256") != manifest_sha256
            or prior.get("state")
            not in {"COMMITTED_ACKNOWLEDGED", "COMMITTED_EXACT_READONLY"}
        ):
            raise WorkerError(
                "native apply receipt does not authorize current verification"
            )
        if (
            not isinstance(original, dict)
            or original.get("id") != quarantined.get("id")
            or original.get("payload_sha256") != quarantined.get("payload_sha256")
        ):
            raise WorkerError("native apply receipt does not bind the quarantined row")
        _check_exact_quarantine(original, quarantined, plan)
        if (
            prior.get("runtime_history_sha256") != _digest(history)
            or quarantined.get("reconciliation_id") != plan["reconciliation_id"]
        ):
            raise WorkerError(
                "current controlled-runtime state differs from committed receipt"
            )
    if not history_only:
        await _verify_runtime_permissions(
            str(await connection.fetchval("SELECT current_database()")),
            directory=directory,
            require_auth=primary,
        )
    return history, original


async def _verify_restored_primary(
    connection: Any, plan: dict[str, Any], directory: Path, *, manifest_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify a no-owner/no-privileges restore of an accepted primary result.

    This is deliberately history-only: the restored database is not the
    primary, and its absent roles/grants are not evidence about primary
    permissions.  The signed/accepted apply artifact remains the authority for
    the exact quarantined target and post-transition history.
    """
    if connection.is_in_transaction():
        raise WorkerError("verification requires a fresh connection")
    async with connection.transaction(isolation="repeatable_read", readonly=True):
        await connection.execute("SET LOCAL statement_timeout='60s'")
        await connection.execute("SET LOCAL lock_timeout='5s'")
        await connection.execute("SET LOCAL work_mem='8MB'")
        await connection.execute("SET LOCAL TIME ZONE 'UTC'")
        history = await _history(connection, plan, runtime=True)
        _check_new_relations(history)
        receipt = _read_private_json(
            directory / "native-apply.json", directory, "accepted primary apply receipt"
        )
        target = await _quarantined_row(connection)
        original = receipt.get("private_target")
        if (
            receipt.get("kind") != "controlled-runtime-native-apply-v1"
            or receipt.get("plan_binding_sha256") != _plan_binding_sha256(plan)
            or receipt.get("wheel_manifest_sha256") != manifest_sha256
            or receipt.get("state")
            not in {"COMMITTED_ACKNOWLEDGED", "COMMITTED_EXACT_READONLY"}
            or receipt.get("runtime_history_sha256") != _digest(history)
        ):
            raise WorkerError(
                "restored primary history differs from accepted apply receipt"
            )
        if (
            not isinstance(original, dict)
            or original.get("id") != target.get("id")
            or original.get("payload_sha256") != target.get("payload_sha256")
        ):
            raise WorkerError(
                "restored primary receipt does not bind the quarantined row"
            )
        _check_exact_quarantine(original, target, plan)
    return history, original


async def _rehearse(
    connection: Any,
    plan: dict[str, Any],
    *,
    primary: bool,
    directory: Path,
    manifest_sha256: str,
) -> dict[str, Any]:
    directory = _safe_directory(directory)
    inspection_path = directory / "native-inspection.json"
    if inspection_path.exists():
        inspection = _read_private_json(
            inspection_path, directory, "native clone inspection"
        )
        if (
            inspection.get("plan_binding_sha256") != _plan_binding_sha256(plan)
            or inspection.get("wheel_manifest_sha256") != manifest_sha256
            or inspection.get("state") != "INSPECTED"
        ):
            raise WorkerError("stored clone inspection does not match rehearsal plan")
        inspection_history = inspection.get("history")
        inspection_target = inspection.get("private_target")
        if not isinstance(inspection_history, dict) or not isinstance(
            inspection_target, dict
        ):
            raise WorkerError("stored clone inspection lacks private baseline evidence")
        _compare_accepted(inspection_history, plan)
    else:
        inspection_history, inspection_target = await _snapshot_readonly(
            connection, plan
        )
        inspection = {
            "schema_version": 1,
            "kind": "controlled-runtime-native-inspection-v1",
            "database": str(await connection.fetchval("SELECT current_database()")),
            "plan_sha256": _digest(plan),
            "plan_binding_sha256": _plan_binding_sha256(plan),
            "wheel_manifest_sha256": manifest_sha256,
            "snapshot_sha256": _digest(inspection_history),
            "legacy_table_count": len(plan["expected_legacy_tables"]),
            "legacy_row_count": sum(
                item["count"] for item in inspection_history["tables"].values()
            ),
            "target_row_id_sha256": hashlib.sha256(
                str(inspection_target["id"]).encode()
            ).hexdigest(),
            "target_payload_sha256": inspection_target.get("payload_sha256"),
            "expired_lease_until_utc": _utc(inspection_target["lease_until"])
            .isoformat()
            .replace("+00:00", "Z"),
            "state": "INSPECTED",
            "history": inspection_history,
            "private_target": _private_target(inspection_target),
        }
        _write_private_json(inspection_path, directory, inspection)
    checkpoints = [
        "after_migration_013",
        "after_migration_014",
        "after_migration_015",
        "after_migration_016",
        "after_migration_018",
        "after_migration_026",
        "after_quarantine",
        "after_roles",
        "before_commit",
    ]
    # Checkpoint wrapper emits migration suffix keys; exercise each point on a
    # freshly restored owned clone supplied by controller. Roll back exact
    # baseline after every injected failure; do not continue on a changed clone.
    rollback_states = []
    for checkpoint in checkpoints:
        try:
            await _atomic_transition(
                connection,
                plan,
                primary=False,
                directory=directory,
                fault_at=checkpoint,
            )
        except FaultCheckpointError as injected:
            if injected.stage != checkpoint:
                raise WorkerError(
                    "fault checkpoint reached an unexpected stage"
                ) from None
            rollback_states.append(checkpoint)
        else:
            raise WorkerError("fault checkpoint did not abort the native transaction")
        observed, _target = await _snapshot_readonly(connection, plan)
        rollback_states[-1] = {
            "checkpoint": checkpoint,
            "rollback_history_sha256": _digest(observed),
        }
    try:
        await _atomic_transition(
            connection,
            plan,
            primary=False,
            directory=directory,
            fault_at="after_commit_response_loss",
        )
    except OutcomeUnknown as unknown:
        if unknown.hit != ["after_commit_response_loss"] or not isinstance(
            unknown.intent, dict
        ):
            raise WorkerError(
                "commit reply was unexpectedly unknown during clone rehearsal"
            ) from None
        await connection.close()
        classifier = await _connect(
            str(inspection["database"]), primary=False, directory=directory
        )
        try:
            if (
                await _classify_readonly(classifier, plan, unknown.intent)
                != "COMMITTED_EXACT"
            ):
                raise WorkerError(
                    "lost clone commit reply was not classified committed-exact"
                )
        finally:
            await classifier.close()
        success = {
            "state": "COMMITTED_EXACT_READONLY",
            "intent": unknown.intent,
            "runtime_history_sha256": unknown.intent["runtime_history_sha256"],
            "private_target": unknown.intent["original_row"],
        }
    else:
        raise WorkerError("lost clone commit reply checkpoint did not fire")
    # API idempotence: a second exact quarantine call and current-profile migrate
    # in a fresh outer transaction must leave the complete current snapshot same.
    probe = await _connect(
        str(inspection["database"]), primary=False, directory=directory
    )
    try:
        post = await _readonly_current(probe, plan)
        before = _digest(post)
        await _idempotence_probe(probe, plan, success)
        after = await _readonly_current(probe, plan)
    finally:
        await probe.close()
    if before != _digest(after):
        raise WorkerError("second migration/quarantine idempotence snapshot changed")
    success["rollback_faults"] = rollback_states
    success["idempotence_history_sha256"] = before
    success["history"] = post
    success["permissions"] = await _verify_runtime_permissions(
        str(inspection["database"]), directory=directory
    )
    receipt = {
        "schema_version": 1,
        "kind": "controlled-runtime-native-rehearsal-v1",
        "result": "PASS",
        "plan_binding_sha256": _plan_binding_sha256(plan),
        "wheel_manifest_sha256": manifest_sha256,
        **success,
        "primary_mutations": 0,
    }
    _write_private_json(directory / "native-rehearsal.json", directory, receipt)
    return {
        "state": "REHEARSAL_PASSED",
        "fault_count": len(rollback_states),
        "history_sha256": before,
        "primary_mutations": 0,
    }


async def _apply(
    connection: Any,
    plan: dict[str, Any],
    *,
    primary: bool,
    database: str,
    directory: Path,
    manifest_sha256: str,
) -> dict[str, Any]:
    if primary:
        rehearsal = _read_private_json(
            directory / "native-rehearsal.json", directory, "clone rehearsal receipt"
        )
        if (
            rehearsal.get("kind") != "controlled-runtime-native-rehearsal-v1"
            or rehearsal.get("result") != "PASS"
            or rehearsal.get("state")
            not in {"COMMITTED_ACKNOWLEDGED", "COMMITTED_EXACT_READONLY"}
        ):
            raise WorkerError(
                "accepted clone rehearsal is required before primary apply"
            )
        if (
            rehearsal.get("plan_binding_sha256") != _plan_binding_sha256(plan)
            or rehearsal.get("wheel_manifest_sha256") != manifest_sha256
        ):
            raise WorkerError("accepted clone rehearsal differs from primary plan")
        inspection = _read_private_json(
            directory / "native-inspection.json", directory, "clone inspection receipt"
        )
        if (
            inspection.get("plan_binding_sha256") != _plan_binding_sha256(plan)
            or inspection.get("wheel_manifest_sha256") != manifest_sha256
        ):
            raise WorkerError("accepted clone inspection differs from primary plan")
        rehearsal_history = rehearsal.get("history")
        if not isinstance(rehearsal_history, dict) or not isinstance(
            rehearsal_history.get("schema_fingerprint_sha256"), str
        ):
            raise WorkerError(
                "accepted clone rehearsal lacks runtime schema fingerprint"
            )
        expected_runtime_schema_sha256 = rehearsal_history["schema_fingerprint_sha256"]
    else:
        expected_runtime_schema_sha256 = None
    try:
        result = await _atomic_transition(
            connection,
            plan,
            primary=primary,
            directory=directory,
            expected_runtime_schema_sha256=expected_runtime_schema_sha256,
        )
    except OutcomeUnknown as unknown:
        if not unknown.intent:
            raise WorkerError(
                "commit outcome unknown without durable intent; stop"
            ) from None
        await connection.close()
        classifier = await _connect(database, primary=primary, directory=directory)
        try:
            classification = await _classify_readonly(classifier, plan, unknown.intent)
            classified_history = (
                await _readonly_current(classifier, plan)
                if classification == "COMMITTED_EXACT"
                else None
            )
        finally:
            await classifier.close()
        if classification != "COMMITTED_EXACT":
            raise WorkerError(
                "lost commit acknowledgement was not classified as committed exact"
            ) from None
        result = {
            "state": "COMMITTED_EXACT_READONLY",
            "intent": unknown.intent,
            "runtime_history_sha256": unknown.intent["runtime_history_sha256"],
            "private_target": unknown.intent["original_row"],
            "history": classified_history,
        }
    result["plan_sha256"] = _digest(plan)
    result["plan_binding_sha256"] = _plan_binding_sha256(plan)
    result["wheel_manifest_sha256"] = manifest_sha256
    _write_private_json(
        directory / "native-apply.json",
        directory,
        {"schema_version": 1, "kind": "controlled-runtime-native-apply-v1", **result},
    )
    permissions = await _verify_runtime_permissions(
        database, directory=directory, require_auth=primary
    )
    return {
        "state": result["state"],
        "runtime_history_sha256": result.get("runtime_history_sha256"),
        "permissions": permissions,
        "primary_mutations": int(primary),
    }


async def _readonly_current(connection: Any, plan: dict[str, Any]) -> dict[str, Any]:
    async with connection.transaction(isolation="repeatable_read", readonly=True):
        await connection.execute("SET LOCAL statement_timeout='60s'")
        await connection.execute("SET LOCAL lock_timeout='5s'")
        await connection.execute("SET LOCAL work_mem='8MB'")
        await connection.execute("SET LOCAL TIME ZONE 'UTC'")
        return await _history(connection, plan, runtime=True)


async def _idempotence_probe(
    connection: Any, plan: dict[str, Any], committed: dict[str, Any]
) -> None:
    # Actual current-profile migrate and exact quarantine API are invoked again
    # within one outer transaction; the API must report ALREADY_QUARANTINED.
    outer = connection.transaction(isolation="repeatable_read")
    await outer.start()
    try:
        pool = ConnectionBoundPool(connection)
        primitives = _load_primitives(
            pool, str(await connection.fetchval("SELECT current_database()"))
        )
        await primitives.database.migrate()
        row = await _quarantined_row(connection)
        lease = primitives.lease(
            owner=committed["private_target"]["lease_owner"],
            until=_utc(committed["private_target"]["lease_until"]),
        )
        identity = primitives.identity(
            id=row["id"],
            producer=row["producer"],
            message_id=row["message_id"],
            topic=row["topic"],
            payload_sha256=row["payload_sha256"],
            publish_attempts=row["publish_attempts"],
        )
        outcome = await primitives.repository(pool).quarantine_expired_outbox_exact(
            identity,
            expired_lease=lease,
            reconciliation_id=plan["reconciliation_id"],
            reason=plan["reason"],
        )
        if getattr(outcome.state, "value", outcome.state) != "ALREADY_QUARANTINED":
            raise WorkerError("native quarantine API was not idempotent")
        await outer.commit()
    except BaseException:
        await outer.rollback()
        raise


async def _permissions_only(
    connection: Any,
    plan: dict[str, Any],
    *,
    primary: bool,
    directory: Path,
    manifest_sha256: str,
) -> dict[str, Any]:
    history = await _readonly_current(connection, plan)
    _check_new_relations(history)
    receipt_path = directory / (
        "native-apply.json" if primary else "native-rehearsal.json"
    )
    receipt = _read_private_json(
        receipt_path, directory, "accepted controlled-runtime receipt"
    )
    accepted_history = receipt.get("history")
    if (
        receipt.get("plan_binding_sha256") != _plan_binding_sha256(plan)
        or receipt.get("wheel_manifest_sha256") != manifest_sha256
        or not isinstance(accepted_history, dict)
        or _digest(history) != _digest(accepted_history)
    ):
        raise WorkerError(
            "permission target full history differs from accepted transition receipt"
        )
    database = str(await connection.fetchval("SELECT current_database()"))
    verification = await _verify_runtime_permissions(
        database, directory=directory, require_auth=primary
    )
    result = {
        "schema_version": 1,
        "kind": "controlled-runtime-native-permissions-v1",
        "state": "PERMISSIONS_VERIFIED",
        "plan_binding_sha256": _plan_binding_sha256(plan),
        "history_sha256": _digest(history),
        "permissions": verification,
        "primary_mutations": 0,
    }
    _write_private_json(directory / "native-permissions.json", directory, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("/evidence"))
    parser.add_argument(
        "--manifest", type=Path, default=Path("/wheelhouse/manifest.json")
    )
    parser.add_argument("--database", required=True)
    parser.add_argument(
        "--mode",
        choices=(
            "inspect",
            "rehearse",
            "apply",
            "verify",
            "verify-restored-primary",
            "permissions",
        ),
        required=True,
    )
    parser.add_argument(
        "--primary",
        action="store_true",
        help="required second gate for literal primary database",
    )
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(asyncio.wait_for(_run(args), timeout=MAX_SECONDS + 30))
    except BaseException as exc:  # noqa: BLE001 -- classify cancellation and keep commit outcome fail-closed.
        # No exception message, DSN, SQL error detail, row, or secret is echoed.
        mutation_state = "unknown" if args.primary and args.mode == "apply" else 0
        print(
            json.dumps(
                {
                    "state": "REJECTED",
                    "error_type": type(exc).__name__,
                    "primary_mutations": mutation_state,
                },
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
