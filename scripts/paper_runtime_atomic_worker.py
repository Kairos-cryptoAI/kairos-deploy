"""Clone-only one-connection atomic core; no DSN/primary/consumer CLI.

Callers supply one already-connected disposable clone connection. Production
primitive loading verifies installed bytes from the accepted old runner first.
Unit doubles prove orchestration only, NOT PostgreSQL DDL/savepoint rollback.
"""

from __future__ import annotations

import asyncio
import argparse
import hashlib
import inspect
import json
import os
import re
import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import paper_runtime_atomic_contract as contract
import paper_runtime_history_stream as history_stream
import paper_runtime_snapshot_worker as snapshot


class OutcomeUnknown(contract.AtomicError):
    def __init__(self, intent: dict[str, Any] | None) -> None:
        super().__init__("transaction acknowledgement unknown; read-only inspection required; no retry")
        self.intent = intent


class ConnectionBoundPool:
    """Only acquire is supported: never open, close, release or replace a connection."""

    def __init__(self, connection: Any, fault: Callable[[str], Any] | None = None) -> None:
        self.connection = connection
        self.acquisitions = 0
        self.savepoints = 0
        self.view = _ObservedConnection(self, fault)

    @asynccontextmanager
    async def acquire(self):
        if not self.connection.is_in_transaction():
            raise contract.AtomicError("bound primitive requires the active outer transaction")
        self.acquisitions += 1
        yield self.view
        if not self.connection.is_in_transaction():
            raise contract.AtomicError("nested primitive escaped the outer transaction")


class _ObservedConnection:
    """Forward unchanged SQL to one physical connection; observe only savepoints.

    Faults run AFTER the frozen migrate() inserts an exact suffix marker. No
    hand-written migration loop, SQL rewriting or second connection is used.
    """

    def __init__(self, pool: ConnectionBoundPool, fault: Callable[[str], Any] | None) -> None:
        self._pool = pool
        self._fault = fault

    def __getattr__(self, name: str) -> Any:
        return getattr(self._pool.connection, name)

    async def execute(self, query: str, *args: Any) -> Any:
        result = await self._pool.connection.execute(query, *args)
        if self._fault and query == "INSERT INTO schema_migrations(version) VALUES ($1)" and len(args) == 1 and args[0] in contract.CATALOG.RUNTIME_SUFFIX:
            self._fault("after_migration_" + args[0][:3])
        return result

    @asynccontextmanager
    async def transaction(self):
        connection = self._pool.connection
        if not connection.is_in_transaction():
            raise contract.AtomicError("savepoint requires active physical outer transaction")
        before = int(await connection.fetchval("SELECT pg_backend_pid()"))
        async with connection.transaction():
            self._pool.savepoints += 1
            yield self
        if not connection.is_in_transaction() or int(await connection.fetchval("SELECT pg_backend_pid()")) != before:
            raise contract.AtomicError("savepoint changed/committed physical outer transaction")


def load_frozen_primitives() -> Any:
    root = files("kairos_persistence")
    migrations = root.joinpath("migrations")
    inventory = tuple(sorted(item.name for item in migrations.iterdir() if item.name.endswith(".sql")))
    if inventory != tuple(sorted(contract.CATALOG.ALL_PACKAGE_MIGRATIONS)):
        raise contract.AtomicError("installed immutable migration inventory differs")
    for name in inventory:
        if hashlib.sha256(migrations.joinpath(name).read_bytes()).hexdigest() != contract.CATALOG.MIGRATION_SHA256[name]:
            raise contract.AtomicError("installed immutable migration bytes differ")
    for name, expected in (("repository.py", contract.CATALOG.EXPECTED_PERSISTENCE_REPOSITORY_SHA256), ("database.py", contract.DATABASE_MODULE_SHA256)):
        if hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest() != expected:
            raise contract.AtomicError("installed immutable primitive bytes differ")
    observed_new_tables: set[str] = set()
    for name in contract.CATALOG.RUNTIME_SUFFIX:
        observed_new_tables.update(re.findall(r"CREATE TABLE(?: IF NOT EXISTS)? ([a-z_]+)", migrations.joinpath(name).read_text(encoding="utf-8")))
    if observed_new_tables != set(contract.NEW_TABLES):
        raise contract.AtomicError("reviewed new-table policy differs from frozen SQL")
    from kairos_persistence.database import Database, MigrationProfile
    from kairos_persistence.repository import AuditRepository, OfflineOutboxExpiredLease, OfflineOutboxIdentity

    if Database.migration_names(MigrationProfile.RUNTIME) != contract.RUNTIME_PROFILE:
        raise contract.AtomicError("frozen runtime manifest differs")

    def database(bound_pool: ConnectionBoundPool, name: str) -> Any:
        class BoundDatabase(Database):
            @property
            def pool(self):
                return bound_pool
        # Do not load ambient persistence settings or mutate installed modules.
        return BoundDatabase(SimpleNamespace(database_url="postgresql://kairos@127.0.0.1:5432/" + name), migration_profile=MigrationProfile.RUNTIME)

    return SimpleNamespace(database=database, repository=AuditRepository, identity=OfflineOutboxIdentity, lease=OfflineOutboxExpiredLease)


def persist_precommit_intent(path: Path, intent: dict[str, Any]) -> str:
    """Create-only, bounded, flushed intent. Never overwrite any existing evidence."""
    data = contract.canonical(intent)
    if len(data) > contract.MAX_JSON_BYTES or path.name != "atomic-precommit-" + contract.digest(intent) + ".json" or path.is_symlink():
        raise contract.AtomicError("precommit intent path/bound differs")
    parent = path.parent.resolve(strict=True)
    if parent != path.parent.absolute() or path.parent.is_symlink():
        raise contract.AtomicError("precommit intent directory differs")
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != data:
            raise contract.AtomicError("precommit intent readback differs")
    except OSError:
        raise contract.AtomicError("precommit intent durability acknowledgement missing") from None
    return hashlib.sha256(data).hexdigest()


async def _inventory(connection: Any) -> tuple[str, ...]:
    return tuple(item["relname"] for item in await connection.fetch("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND NOT c.relispartition ORDER BY c.relname"))


async def _other_clients(connection: Any) -> int:
    return int(await connection.fetchval("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'"))


async def _digest_query(connection: Any, query: str, budget: Any, *args: Any) -> dict[str, Any]:
    if not connection.is_in_transaction():
        raise contract.AtomicError("history transport requires the existing physical transaction")
    stream = history_stream.OrderedTextDigest(budget)
    # Keep exact SELECT/arguments/C ordering and length-prefixed row digest.
    # COPY removes repeated16-row cursor round trips, NOT any history scans,
    # locks, rollback checkpoints, provenance checks, or resource/time caps.
    status = await connection.copy_from_query(query, *args, output=stream.write, format="binary", encoding="UTF8", timeout=120)
    return stream.finish(status)


async def _history(connection: Any, *, runtime: bool, original_row: dict[str, Any] | None = None) -> dict[str, Any]:
    projection = original_row is not None
    expected_tables = contract.RUNTIME_TABLES if runtime else contract.LEGACY_TABLES
    if await _inventory(connection) != expected_tables:
        raise contract.AtomicError("public table inventory differs")
    versions = tuple(item["version"] for item in await connection.fetch("SELECT version FROM schema_migrations ORDER BY version"))
    if versions != (contract.RUNTIME_PROFILE if runtime else contract.LEGACY_PROFILE):
        raise contract.AtomicError("physical migration profile differs")
    schema = await connection.fetchval(contract.CATALOG.LEGACY_INVENTORY_QUERY)
    budget = snapshot.Budget()
    tables: dict[str, Any] = {}
    for table in contract.LEGACY_TABLES if projection else expected_tables:
        expression = "to_jsonb(t)"
        args: tuple[Any, ...] = ()
        where = ""
        if projection and table == "message_outbox":
            # New migration018 fields disappear from every old-row projection;
            # ONLY exact row117625 gets its three reviewed old fields restored.
            expression = "(to_jsonb(t) - ARRAY['reconciliation_state','reconciliation_id','reconciliation_started_at','reconciliation_outcome_at']) || CASE WHEN t.id=$1 THEN $2::jsonb ELSE '{}'::jsonb END"
            args = (contract.EXACT_ROW_ID, contract.canonical({name: original_row[name] for name in contract.OLD_QUARANTINE_FIELDS}).decode("utf-8"))
        elif projection and table == "schema_migrations":
            where = " WHERE t.version=ANY($1::text[])"
            args = (list(contract.LEGACY_PROFILE),)
        query = "SELECT (" + expression + ")::text AS row FROM public." + snapshot._identifier(table) + " t" + where + " ORDER BY ((" + expression + ")::text) COLLATE \"C\""
        tables[table] = await _digest_query(connection, query, budget, *args)
    sequences: dict[str, Any] = {}
    for item in await connection.fetch("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S' ORDER BY c.relname"):
        name = item["relname"]
        state = await connection.fetchrow("SELECT last_value,is_called FROM public." + snapshot._identifier(name))
        sequences[name] = {"last_value": int(state["last_value"]), "is_called": state["is_called"]}
    history = {"database": contract.CATALOG.EXPECTED_DATABASE, "migrations": list(contract.LEGACY_PROFILE if projection else versions), "schema_fingerprint_sha256": contract.CATALOG.EXPECTED_LEGACY_FINGERPRINT if projection else hashlib.sha256(schema.encode("utf-8")).hexdigest(), "tables": tables, "public_sequences": sequences, "public_execution_events_max_sequence": int(await connection.fetchval("SELECT COALESCE(max(event_seq),0) FROM public_execution_events"))}
    contract.validate_history(history, runtime=runtime and not projection)
    return history


async def _target(connection: Any) -> dict[str, Any]:
    row = await connection.fetchrow("SELECT to_jsonb(t)::text AS row FROM message_outbox t WHERE id=$1 FOR UPDATE", contract.EXACT_ROW_ID)
    if row is None:
        raise contract.AtomicError("exact signed row is absent")
    return json.loads(row["row"])


def _before_identity(row: dict[str, Any], document: dict[str, Any]) -> None:
    if any(row.get(name) != value for name, value in document["identity"].items()) or row.get("published_at") is not None or row.get("dead_lettered_at") is not None:
        raise contract.AtomicError("signed row identity/ACK state differs")
    owner = row.get("lease_owner")
    if not isinstance(owner, str) or not owner or hashlib.sha256(owner.encode("utf-8")).hexdigest() != document["lease_owner_sha256"] or contract.utc(row.get("lease_until")) != contract.utc(document["lease_until_utc"]):
        raise contract.AtomicError("signed exact expired lease differs")


async def _check_after(connection: Any, before: dict[str, Any], document: dict[str, Any], expected_error: str) -> None:
    after = await _target(connection)
    old_projection = {name: value for name, value in after.items() if name not in contract.NEW_OUTBOX_FIELDS}
    for name in contract.OLD_QUARANTINE_FIELDS:
        old_projection[name] = before[name]
    if old_projection != before or after.get("lease_owner") is not None or after.get("lease_until") is not None or after.get("reconciliation_state") != "PUBLISH_OUTCOME_UNKNOWN" or after.get("reconciliation_id") != document["reconciliation_id"]:
        raise contract.AtomicError("one-row quarantine changed forbidden fields")
    started = contract.utc(after.get("reconciliation_started_at"))
    if contract.utc(after.get("reconciliation_outcome_at")) != started:
        raise contract.AtomicError("quarantine transaction timestamps differ")
    if after.get("last_error") != expected_error:
        raise contract.AtomicError("frozen canonical quarantine evidence differs")
    dirty_defaults = await connection.fetchval("SELECT count(*) FROM message_outbox WHERE id<>$1 AND (reconciliation_state IS DISTINCT FROM 'NONE' OR reconciliation_id IS NOT NULL OR reconciliation_started_at IS NOT NULL OR reconciliation_outcome_at IS NOT NULL)", contract.EXACT_ROW_ID)
    if dirty_defaults != 0:
        raise contract.AtomicError("other outbox rows changed reconciliation fields")


async def _atomic_upgrade_and_quarantine(connection: Any, plan: contract.AtomicPlan, intent_sink: Callable[[dict[str, Any]], Any], *, _primitives: Any = None, _fault: Callable[[str], Any] | None = None) -> dict[str, Any]:
    """Exactly one clone attempt. No reconnect, retry, primary target or transport."""
    plan = contract.AtomicPlan.from_document(plan.document, now=datetime.now(UTC))
    name = await connection.fetchval("SELECT current_database()")
    if not isinstance(name, str) or contract.CLONE_DATABASE.fullmatch(name) is None:
        raise contract.AtomicError("write API accepts only disposable atomic clone database")
    if connection.is_in_transaction():
        raise contract.AtomicError("write API owns exactly one outer transaction")
    primitives = _primitives if _primitives is not None else load_frozen_primitives()
    document = plan.document
    outer = connection.transaction(isolation="repeatable_read")
    await outer.start()
    intent: dict[str, Any] | None = None
    committing = False
    try:
        await connection.execute("SET LOCAL lock_timeout='5s'")
        await connection.execute("SET LOCAL statement_timeout='120s'")
        await connection.execute("SET LOCAL work_mem='8MB'")
        await connection.execute("SET LOCAL TIME ZONE 'UTC'")
        await connection.execute("SELECT pg_advisory_xact_lock($1)", int(contract.CATALOG.SCHEMA_ADVISORY_LOCK))
        if await _inventory(connection) != contract.LEGACY_TABLES or await _other_clients(connection) != 0:
            raise contract.AtomicError("legacy clone inventory/client boundary differs")
        await connection.execute("LOCK TABLE " + ",".join("public." + snapshot._identifier(table) for table in contract.LEGACY_TABLES) + " IN ACCESS EXCLUSIVE MODE")
        roles = await snapshot._roles(connection, contract.LEGACY_TABLES)
        if roles["sufficient_for_reviewed_next_step"] is not True:
            raise contract.AtomicError("clone role is not equivalent to accepted target role")
        backend = int(await connection.fetchval("SELECT pg_backend_pid()"))
        baseline = await _history(connection, runtime=False)
        contract.compare_history(document["legacy_history"], baseline)
        original = await _target(connection)
        _before_identity(original, document)
        pool = ConnectionBoundPool(connection, _fault)
        await primitives.database(pool, name).migrate()
        if _fault:
            _fault("after_migrations")
        if int(await connection.fetchval("SELECT pg_backend_pid()")) != backend:
            raise contract.AtomicError("migration escaped physical connection")
        repository = primitives.repository(pool)
        identity = primitives.identity(**document["identity"])
        lease = primitives.lease(owner=original["lease_owner"], until=contract.utc(document["lease_until_utc"]))
        result = await repository.quarantine_expired_outbox_exact(identity, expired_lease=lease, reconciliation_id=document["reconciliation_id"], reason=document["reason"])
        if result.state.value != "QUARANTINED":
            raise contract.AtomicError("exact quarantine rejected; rollback whole upgrade")
        if _fault:
            _fault("after_quarantine")
        if pool.acquisitions != 2 or pool.savepoints != 2 or not connection.is_in_transaction() or int(await connection.fetchval("SELECT pg_backend_pid()")) != backend:
            raise contract.AtomicError("frozen primitives did not share one outer transaction")
        await _check_after(connection, original, document, repository._quarantine_evidence(document["reason"], lease))
        contract.compare_history(baseline, await _history(connection, runtime=True, original_row=original))
        committed = await _history(connection, runtime=True)
        if committed["schema_fingerprint_sha256"] != document["runtime_schema_fingerprint_sha256"]:
            raise contract.AtomicError("runtime17 schema differs from accepted old clone")
        for table in contract.NEW_TABLES:
            if committed["tables"][table]["count"] != (1 if table == "paper_canary_database_identity" else 0):
                raise contract.AtomicError("new runtime tables contain unexpected rows")
        if await _other_clients(connection) != 0:
            raise contract.AtomicError("another database client appeared")
        contract.AtomicPlan.from_document(document, now=datetime.now(UTC))
        intent = {"schema_version": 1, "kind": contract.INTENT_KIND, "plan_sha256": plan.sha256, "legacy_history_sha256": contract.digest(baseline), "committed_history_sha256": contract.digest(committed), "prepared_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "backend_pid": backend, "quarantine_calls": 1}
        acknowledged = intent_sink(intent)
        if inspect.isawaitable(acknowledged):
            acknowledged = await acknowledged
        if acknowledged != contract.digest(intent):
            raise contract.AtomicError("durable precommit intent was not acknowledged exactly")
        if _fault:
            _fault("before_commit")
        committing = True
        await outer.commit()
        if _fault:
            _fault("after_commit_response_loss")
        return {"state": "COMMITTED_ACKNOWLEDGED", "intent": intent, "history": committed, "quarantine_calls": 1, "bound_acquisitions": pool.acquisitions, "primary_mutations": 0, "consumer_restart_permitted": False}
    except BaseException as error:
        if committing:
            raise OutcomeUnknown(intent) from None
        try:
            await outer.rollback()
        except BaseException:
            raise OutcomeUnknown(intent) from None
        if isinstance(error, contract.AtomicError):
            raise
        raise contract.AtomicError("clone atomic operation failed; outer rollback acknowledged") from None


async def atomic_upgrade_and_quarantine(connection: Any, plan: contract.AtomicPlan, intent_sink: Callable[[dict[str, Any]], Any], *, _primitives: Any = None, _fault: Callable[[str], Any] | None = None) -> dict[str, Any]:
    """Whole-attempt bound; wait_for cancellation still rolls back or reports unknown."""
    return await asyncio.wait_for(_atomic_upgrade_and_quarantine(connection, plan, intent_sink, _primitives=_primitives, _fault=_fault), timeout=snapshot.MAX_SECONDS)


async def inspect_unknown_readonly(connection: Any, plan: contract.AtomicPlan, intent: dict[str, Any]) -> str:
    """New connection only. An expired plan is still usable for inspection, not writes."""
    name = await connection.fetchval("SELECT current_database()")
    if not isinstance(name, str) or contract.CLONE_DATABASE.fullmatch(name) is None or connection.is_in_transaction():
        raise contract.AtomicError("read-only inspector accepts only a fresh clone connection")
    async with connection.transaction(isolation="repeatable_read", readonly=True):
        await connection.execute("SET LOCAL statement_timeout='120s'")
        await connection.execute("SET LOCAL lock_timeout='5s'")
        await connection.execute("SET LOCAL work_mem='8MB'")
        await connection.execute("SET LOCAL TIME ZONE 'UTC'")
        other_clients = await _other_clients(connection)
        versions = tuple(item["version"] for item in await connection.fetch("SELECT version FROM schema_migrations ORDER BY version"))
        if other_clients != 0 or versions not in (contract.LEGACY_PROFILE, contract.RUNTIME_PROFILE):
            return "INDETERMINATE"
        observed = await _history(connection, runtime=versions == contract.RUNTIME_PROFILE)
        return contract.classify_readonly_outcome(plan, intent, observed, other_clients=await _other_clients(connection))


async def _readonly_snapshot(connection: Any) -> dict[str, Any]:
    async with connection.transaction(isolation="repeatable_read", readonly=True):
        await connection.execute("SET LOCAL statement_timeout='120s'")
        await connection.execute("SET LOCAL lock_timeout='5s'")
        await connection.execute("SET LOCAL work_mem='8MB'")
        await connection.execute("SET LOCAL TIME ZONE 'UTC'")
        if await _other_clients(connection) != 0:
            raise contract.AtomicError("another clone application client is connected")
        versions = tuple(item["version"] for item in await connection.fetch("SELECT version FROM schema_migrations ORDER BY version"))
        if versions not in (contract.LEGACY_PROFILE, contract.RUNTIME_PROFILE):
            raise contract.AtomicError("read-only clone snapshot profile differs")
        result = await _history(connection, runtime=versions == contract.RUNTIME_PROFILE)
        if await _other_clients(connection) != 0:
            raise contract.AtomicError("another clone client appeared during snapshot")
        return result


async def _native_cli(args: argparse.Namespace) -> dict[str, Any]:
    """Only local cloned DB + immutable installed primitives, no secret route."""
    if contract.CLONE_DATABASE.fullmatch(args.database) is None:
        raise contract.AtomicError("only fixed disposable clone namespace is accepted")
    plan = contract.AtomicPlan.from_document(contract.read_json(args.plan), now=datetime.now(UTC))
    primitives = load_frozen_primitives()
    import asyncpg
    dsn = "postgresql://kairos@127.0.0.1:5432/" + args.database
    hit: list[str] = []
    def fault(stage: str) -> None:
        if stage == args.fault:
            hit.append(stage)
            raise contract.AtomicError("intentional clone-only transaction response/fault checkpoint")
    with snapshot.LoopbackOnly() as guard:
        connection = await asyncpg.connect(dsn, timeout=20, command_timeout=120, server_settings={"application_name": "kairos-atomic-clone-proof", "default_transaction_read_only": "on" if args.snapshot else "off"})
        try:
            if args.snapshot:
                return {"state": "READ_ONLY_SNAPSHOT", "history": await _readonly_snapshot(connection), "primary_mutations": 0, "forbidden_network_calls": guard.forbidden}
            def sink(prepared: dict[str, Any]) -> str:
                return persist_precommit_intent(args.intent_directory / ("atomic-precommit-" + contract.digest(prepared) + ".json"), prepared)
            try:
                result = await atomic_upgrade_and_quarantine(connection, plan, sink, _primitives=primitives, _fault=fault)
            except OutcomeUnknown as unknown:
                await connection.close()
                connection = await asyncpg.connect(dsn, timeout=20, command_timeout=120, server_settings={"application_name": "kairos-atomic-clone-inspect", "default_transaction_read_only": "on"})
                if hit != ["after_commit_response_loss"] or unknown.intent is None:
                    raise contract.AtomicError("unexpected unknown clone outcome; stop without retry") from None
                classification = await inspect_unknown_readonly(connection, plan, unknown.intent)
                if classification != "COMMITTED_EXACT":
                    raise contract.AtomicError("lost clone commit response was not resolved exactly")
                result = {"state": "COMMITTED_EXACT_READONLY", "intent": unknown.intent, "history": await _readonly_snapshot(connection), "quarantine_calls": 1, "bound_acquisitions": 2, "primary_mutations": 0, "consumer_restart_permitted": False}
            except contract.AtomicError:
                if hit != [args.fault] or args.fault == "after_commit_response_loss":
                    raise
                observed = await _readonly_snapshot(connection)
                contract.compare_history(plan.document["legacy_history"], observed)
                result = {"state": "ROLLBACK_ACKNOWLEDGED", "fault": args.fault, "history": observed, "primary_mutations": 0}
            if guard.forbidden != 0 or guard.connections not in (1, 2):
                raise contract.AtomicError("clone-only loopback network boundary differs")
            result["forbidden_network_calls"] = guard.forbidden
            result["loopback_database_connections"] = guard.connections
            return result
        finally:
            await connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--intent-directory", type=Path, default=Path("/evidence"))
    parser.add_argument("--snapshot", action="store_true")
    parser.add_argument("--fault", choices=[*("after_migration_" + n[:3] for n in contract.CATALOG.RUNTIME_SUFFIX), "after_migrations", "after_quarantine", "before_commit", "after_commit_response_loss"], default="after_commit_response_loss")
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(asyncio.wait_for(_native_cli(args), timeout=snapshot.MAX_SECONDS))
    except BaseException as error:
        print(json.dumps({"state": "REJECTED", "error_type": type(error).__name__, "primary_mutations": 0}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
