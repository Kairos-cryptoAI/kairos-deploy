"""One bounded read-only PAPER or restored-clone snapshot; no mutation API."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sys
import time
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
MAX_ROW_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_ROWS = 2_000_000
MAX_SECONDS = 300
PREFETCH = 16


class SnapshotError(RuntimeError):
    """Safe failure; driver details, credentials and raw rows are never emitted."""


def _identifier(value: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise SnapshotError("snapshot identifier is invalid")
    return '"' + value + '"'


def _dsn(config: dict[str, Any], secret_text: str | None = None) -> str:
    database = config["physical_database"]
    _identifier(database)
    if config["mode"] == "clone":
        if re.fullmatch(r"kairos_paper_snapshot_[0-9a-f]{12}", database) is None:
            raise SnapshotError("clone database namespace differs")
        return "postgresql://kairos_paper_snapshot@127.0.0.1:5432/" + database
    if config["mode"] != "primary" or database != "kairos":
        raise SnapshotError("only fixed PAPER read-only mode is accepted")
    raw = secret_text if secret_text is not None else Path("/run/secrets/persistence_database_url").read_text(encoding="utf-8")
    raw = raw.strip()
    if "\n" in raw or "\r" in raw or not raw.isascii():
        raise SnapshotError("fixed PAPER secret format differs")
    try:
        value = urlsplit(raw)
        valid = (
            value.scheme in {"postgres", "postgresql"}
            and value.hostname in {"timescaledb", "kairos-paper-gate-timescaledb-1"}
            and value.port == 5432 and value.path == "/kairos"
            and value.username == "kairos" and bool(value.password)
            and not value.query and not value.fragment and "@" in value.netloc
        )
    except ValueError:
        valid = False
    if not valid:
        raise SnapshotError("fixed PAPER secret target differs")
    return urlunsplit((value.scheme, value.netloc.rsplit("@", 1)[0] + "@127.0.0.1:5432", value.path, "", ""))


class LoopbackOnly:
    def __enter__(self) -> "LoopbackOnly":
        self.original = asyncio.BaseEventLoop.create_connection
        self.connections = 0
        self.forbidden = 0

        async def connect(loop: Any, protocol_factory: Any, host: Any = None, port: Any = None, *args: Any, **kwargs: Any) -> Any:
            if host != "127.0.0.1" or str(port) != "5432":
                self.forbidden += 1
                raise SnapshotError("non-loopback connection is forbidden")
            self.connections += 1
            return await self.original(loop, protocol_factory, host, port, *args, **kwargs)

        asyncio.BaseEventLoop.create_connection = connect
        return self

    def __exit__(self, *args: Any) -> None:
        asyncio.BaseEventLoop.create_connection = self.original


def _package(config: dict[str, Any]) -> None:
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != config["worker_sha256"]:
        raise SnapshotError("snapshot worker bytes differ from the reviewed controller")
    root = files("kairos_persistence")
    migrations = root.joinpath("migrations")
    inventory = tuple(sorted(item.name for item in migrations.iterdir() if item.name.endswith(".sql")))
    if inventory != tuple(config["package"]):
        raise SnapshotError("immutable runner package inventory differs")
    for name in inventory:
        if hashlib.sha256(migrations.joinpath(name).read_bytes()).hexdigest() != config["migration_hashes"][name]:
            raise SnapshotError("immutable runner migration bytes differ")
    if hashlib.sha256(root.joinpath("repository.py").read_bytes()).hexdigest() != config["repository_sha256"]:
        raise SnapshotError("immutable repository primitive bytes differ")


class Budget:
    def __init__(self) -> None:
        self.started = time.monotonic()
        self.bytes = 0
        self.rows = 0

    def add(self, raw: str) -> bytes:
        data = raw.encode("utf-8")
        self.bytes += len(data)
        self.rows += 1
        if len(data) > MAX_ROW_BYTES or self.bytes > MAX_TOTAL_BYTES or self.rows > MAX_TOTAL_ROWS or time.monotonic() - self.started > MAX_SECONDS:
            raise SnapshotError("full-history snapshot exceeded its fixed bound")
        return data


async def _table_digest(connection: Any, table: str, budget: Budget) -> dict[str, Any]:
    # Sorting is performed by PostgreSQL with bounded work_mem and statement
    # timeout; the client sees only sixteen rows at a time, never a table array.
    query = "SELECT to_jsonb(t)::text AS row FROM public." + _identifier(table) + ' t ORDER BY (to_jsonb(t)::text) COLLATE "C"'
    digest = hashlib.sha256()
    count = 0
    async for row in connection.cursor(query, prefetch=PREFETCH):
        data = budget.add(row["row"])
        # Length prefixes make framing unambiguous even for newline-bearing data.
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        count += 1
    return {"count": count, "row_digest_sha256": digest.hexdigest()}


async def _roles(connection: Any, tables: tuple[str, ...]) -> dict[str, Any]:
    row = await connection.fetchrow("""SELECT current_user AS role, session_user AS session_role,
        r.rolsuper AS superuser, r.rolbypassrls AS bypass_rls,
        has_schema_privilege(current_user,'public','USAGE') AS schema_usage,
        has_schema_privilege(current_user,'public','CREATE') AS schema_create,
        has_function_privilege(current_user,'gen_random_uuid()','EXECUTE') AS uuid_execute
        FROM pg_roles r WHERE r.rolname=current_user""")
    if row is None or row["role"] != "kairos" or row["session_role"] != "kairos":
        raise SnapshotError("actual PAPER target role differs")
    facts = {key: row[key] for key in ("superuser", "bypass_rls", "schema_usage", "schema_create", "uuid_execute")}
    facts["role"] = "kairos"
    facts["session_role"] = "kairos"
    facts["table_capabilities"] = {}
    for table in tables:
        target = "public." + _identifier(table)
        observed = await connection.fetchrow("""SELECT has_table_privilege(current_user,$1,'SELECT') AS readable,
            has_table_privilege(current_user,$1,'UPDATE') AS updatable,
            (r.rolsuper OR pg_has_role(current_user,c.relowner,'USAGE')) AS owner_capable,
            c.relrowsecurity AS row_security
            FROM pg_class c JOIN pg_roles r ON r.rolname=current_user WHERE c.oid=$1::regclass""", target)
        if observed is None:
            raise SnapshotError("target table capability is missing")
        facts["table_capabilities"][table] = dict(observed)
    capabilities = facts["table_capabilities"]
    facts["sufficient_for_reviewed_next_step"] = (
        all(facts[key] is True for key in ("schema_usage", "schema_create", "uuid_execute"))
        and all(value["readable"] is True and value["updatable"] is True and value["row_security"] is False for value in capabilities.values())
        and all(capabilities[name]["owner_capable"] is True for name in ("message_outbox", "source_usage_reservations", "schema_migrations"))
        and all(capabilities[name]["updatable"] is True for name in ("event_audit", "message_outbox"))
    )
    facts["actual_ddl_executed"] = False
    return facts


async def _snapshot(connection: Any, config: dict[str, Any]) -> dict[str, Any]:
    tables = tuple(config["tables"])
    actual = tuple(item["relname"] for item in await connection.fetch("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition ORDER BY c.relname"))
    if actual != tables:
        raise SnapshotError("legacy public table inventory differs")
    versions = tuple(item["version"] for item in await connection.fetch("SELECT version FROM schema_migrations ORDER BY version"))
    if versions != tuple(config["legacy"]):
        raise SnapshotError("only the exact legacy PAPER source is accepted")
    fingerprint_text = await connection.fetchval(config["inventory_sql"])
    fingerprint = hashlib.sha256(fingerprint_text.encode("utf-8")).hexdigest()
    if fingerprint != config["legacy_fingerprint"]:
        raise SnapshotError("legacy bootstrapped public schema differs")
    roles = await _roles(connection, tables) if config["mode"] == "primary" else None
    if roles is not None and roles["sufficient_for_reviewed_next_step"] is not True:
        raise SnapshotError("actual PAPER target role capabilities are insufficient")
    other_clients = await connection.fetchval("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'")
    if other_clients != 0:
        raise SnapshotError("another database application client is connected")
    budget = Budget()
    digests = {table: await _table_digest(connection, table, budget) for table in tables}
    sequences: dict[str, Any] = {}
    for item in await connection.fetch("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S' ORDER BY c.relname"):
        name = item["relname"]
        state = await connection.fetchrow("SELECT last_value,is_called FROM public." + _identifier(name))
        sequences[name] = {"last_value": int(state["last_value"]), "is_called": state["is_called"]}
    maximum = await connection.fetchval("SELECT COALESCE(max(event_seq),0) FROM public_execution_events")
    if await connection.fetchval("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'") != 0:
        raise SnapshotError("another database client connected during snapshot")
    return {"history": {"database": "kairos", "migrations": list(versions), "schema_fingerprint_sha256": fingerprint, "tables": digests, "public_sequences": sequences, "public_execution_events_max_sequence": int(maximum)}, "target_role": roles, "other_application_clients": 0}


async def _run(config: dict[str, Any]) -> dict[str, Any]:
    import asyncpg  # Supplied only by the reviewed immutable persistence runner.

    _package(config)
    dsn = _dsn(config)
    with LoopbackOnly() as guard:
        connection = await asyncpg.connect(dsn, timeout=20, command_timeout=120, server_settings={"default_transaction_read_only": "on", "application_name": "kairos-paper-readonly-preflight"})
        try:
            if await connection.fetchval("SELECT current_database()") != config["physical_database"]:
                raise SnapshotError("connected database differs")
            async with connection.transaction(isolation="repeatable_read", read_only=True):
                await connection.execute("SET LOCAL statement_timeout='120s'")
                await connection.execute("SET LOCAL lock_timeout='5s'")
                await connection.execute("SET LOCAL work_mem='8MB'")
                await connection.execute("SET LOCAL TIME ZONE 'UTC'")
                result = await asyncio.wait_for(_snapshot(connection, config), timeout=MAX_SECONDS)
        finally:
            await connection.close()
    result.update({"schema_version": 1, "kind": "kairos.paper-readonly-snapshot.v1", "primary_mutations": 0, "forbidden_network_calls": guard.forbidden, "loopback_database_connections": guard.connections})
    return result


def main() -> int:
    try:
        config = json.loads(sys.stdin.readline())
        result = asyncio.run(_run(config))
    except Exception as exc:
        print(json.dumps({"kind": "kairos.paper-readonly-snapshot.v1", "result": "REJECTED", "error_type": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
