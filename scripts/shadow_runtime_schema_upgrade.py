"""Receipt-bound migration of the sole paid-shadow authority; never call a provider.

Default mode restores a fresh verified backup into disposable network-none
containers.  Only an explicit --apply with the exact fresh preflight receipt
may migrate the existing shadow database.  PAPER recovery is a different gate.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "scripts" / "legacy_outbox_quarantine_clone_rehearsal.py"
BACKUP_ROOT = ROOT / "backups"
SOURCE_CONTAINER = "kairos-shadow-gate-timescaledb-1"
SOURCE_PROJECT = "kairos-shadow-gate"
SOURCE_DATABASE = "kairos"
SOURCE_VOLUME = "kairos-shadow-gate_ts-data"
SOURCE_NETWORK = "kairos-shadow-gate_data"
SOURCE_SECRET = ROOT.parent / "runtime" / "shadow-gate" / "secrets" / "persistence_database_url"
TIMESCALE_IMAGE = "timescale/timescaledb:2.29.1-pg16@sha256:252a443e2936039b83dd8da1373d01e59e932d1054fa6adf1bc061f1d56ae60a"
RUNNER_IMAGE = "kairos-runtime-schema-runner-local@sha256:6e076282d8f1df327c90e0255020620aa9aa02cf0518091e6b6fb44621f4d703"
RUNNER_REVISION = "1ca8bf38d265ece7a95f749a268075549f80c043"
DATABASE_MODULE_SHA256 = "44382a74bba25839e76ec8ab2b01f68d58f58ce4510ed8294fb827bce3dc345b"
SCOPE = "shadow-authority-runtime-schema-upgrade"
SCHEMA = "kairos.shadow-runtime-schema-preflight.v1"
MAXIMUM_AGE = timedelta(hours=2)
MAX_DUMP_BYTES = 64 * 1024 * 1024
ARCHIVE_TIMEOUT_SECONDS = 180
CONFIRMATION = "APPLY_AUTHORITATIVE_SHADOW_RUNTIME_SCHEMA"


class UpgradeError(RuntimeError):
    """Safe operational failure; never include credential-bearing stderr."""


def _reviewed_catalog() -> Any:
    path = CATALOG_PATH
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location("kairos_reviewed_legacy_catalog", path)
    if spec is None or spec.loader is None:
        raise UpgradeError("reviewed migration catalog is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if hashlib.sha256(path.read_bytes()).hexdigest() != before:
        raise UpgradeError("reviewed catalog changed while it was loaded")
    module._kairos_loaded_catalog_sha256 = before
    return module


CATALOG = _reviewed_catalog()
LEGACY = tuple(CATALOG.LEGACY_MIGRATIONS)
TARGET = tuple(CATALOG.TARGET_MIGRATIONS)
PACKAGE = tuple(CATALOG.ALL_PACKAGE_MIGRATIONS)
MIGRATION_HASHES = dict(CATALOG.MIGRATION_SHA256)
TABLES = tuple(sorted(CATALOG.CHECKPOINT_TABLES))
NEW_TABLES = ("campaign_source_budgets", "paper_canary_database_identity", "paper_readonly_runs", "paper_readonly_samples", "paper_readonly_receipts", "paper_canary_sessions", "paper_canary_attempts", "paper_canary_dispatch_claims")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _code_identity() -> dict[str, str]:
    identity = {"controller_sha256": _sha(Path(__file__)), "catalog_sha256": _sha(CATALOG_PATH)}
    if identity["catalog_sha256"] != CATALOG._kairos_loaded_catalog_sha256:
        raise UpgradeError("reviewed catalog differs from the loaded runtime catalog")
    return identity


def _assert_code_identity(expected: dict[str, str]) -> None:
    if _code_identity() != expected:
        raise UpgradeError("controller or canonical catalog changed during the operation; receipt refused")


def _utc(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise UpgradeError(f"{name} must be an explicit UTC timestamp")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise UpgradeError(f"{name} must be an explicit UTC timestamp") from None
    if instant.tzinfo is None or instant.utcoffset() != timedelta():
        raise UpgradeError(f"{name} must be an explicit UTC timestamp")
    return instant


def _fresh(value: object, name: str, now: datetime | None = None) -> None:
    instant = _utc(value, name)
    current = now or datetime.now(UTC)
    if current - instant > MAXIMUM_AGE or instant > current + timedelta(minutes=5):
        raise UpgradeError(f"{name} is not a fresh two-hour snapshot")


def _backup(path: Path) -> tuple[dict[str, Any], Path]:
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(BACKUP_ROOT.resolve()):
        raise UpgradeError("backup manifest must remain inside the deployment backup root")
    manifest = json.loads(resolved.read_text(encoding="utf-8-sig"))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise UpgradeError("backup manifest schema is invalid")
    if manifest.get("compose_project") != SOURCE_PROJECT or manifest.get("database") != SOURCE_DATABASE:
        raise UpgradeError("backup is not the sole authoritative shadow database")
    _fresh(manifest.get("created_at_utc"), "backup")
    name = manifest.get("file")
    if not isinstance(name, str) or not re.fullmatch(r"kairos-shadow-gate-[0-9TZ]+\.dump", name):
        raise UpgradeError("backup filename is invalid")
    dump = (resolved.parent / name).resolve(strict=True)
    if dump.parent != resolved.parent:
        raise UpgradeError("backup escaped its manifest directory")
    if type(manifest.get("bytes")) is not int or not 0 < manifest["bytes"] <= MAX_DUMP_BYTES or dump.stat().st_size != manifest["bytes"]:
        raise UpgradeError("backup byte length differs")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("sha256"))) or _sha(dump) != manifest["sha256"]:
        raise UpgradeError("backup SHA-256 differs")
    checkpoints = manifest.get("checkpoints")
    if not isinstance(checkpoints, dict) or set(checkpoints) != set(TABLES) | {"public_execution_events_max_sequence"}:
        raise UpgradeError("backup checkpoint inventory is invalid")
    if any(type(value) is not int or value < 0 for value in checkpoints.values()):
        raise UpgradeError("backup checkpoints must be nonnegative integers")
    if checkpoints["source_usage_reservations"] < 20:
        raise UpgradeError("historical paid-shadow reservations are missing")
    owners = manifest.get("timescaledb_bgw_owners")
    if not isinstance(owners, list) or len(owners) != len(set(owners)) or any(not isinstance(owner, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", owner) for owner in owners):
        raise UpgradeError("backup TimescaleDB owner provenance is invalid")
    return manifest, dump


def _docker(args: list[str], description: str, *, data: str | None = None, missing_ok: bool = False) -> str:
    result = subprocess.run(["docker", *args], input=data, text=True, encoding="utf-8", capture_output=True, shell=False, timeout=300)
    if result.returncode:
        if missing_ok:
            return ""
        raise UpgradeError(f"{description} failed (exit {result.returncode}); raw credential-bearing logs withheld")
    return result.stdout.strip()


def _json(args: list[str], description: str) -> Any:
    try:
        return json.loads(_docker(args, description))
    except json.JSONDecodeError:
        raise UpgradeError(f"{description} returned malformed JSON") from None


def _identity(inspection: dict[str, Any], running: list[dict[str, Any]], image_id: str) -> dict[str, Any]:
    labels = inspection.get("Config", {}).get("Labels", {}) or {}
    if labels.get("com.docker.compose.project") != SOURCE_PROJECT or labels.get("com.docker.compose.service") != "timescaledb":
        raise UpgradeError("source Compose identity differs")
    if inspection.get("Name") != "/" + SOURCE_CONTAINER or inspection.get("Image") != image_id:
        raise UpgradeError("source container name or immutable database image differs")
    if inspection.get("State", {}).get("Running") is not True:
        raise UpgradeError("exact shadow database infrastructure must already be running")
    if inspection.get("HostConfig", {}).get("Privileged") is not False:
        raise UpgradeError("privileged shadow database infrastructure is forbidden")
    if inspection.get("HostConfig", {}).get("PortBindings"):
        raise UpgradeError("authority database must not publish host ports")
    mounts = inspection.get("Mounts", [])
    data = [mount for mount in mounts if mount.get("Destination") == "/var/lib/postgresql/data"]
    if len(data) != 1 or data[0].get("Type") != "volume" or data[0].get("Name") != SOURCE_VOLUME or data[0].get("RW") is not True:
        raise UpgradeError("source persistent volume identity differs")
    networks = inspection.get("NetworkSettings", {}).get("Networks", {})
    if set(networks) != {SOURCE_NETWORK} or not re.fullmatch(r"[0-9a-f]{64}", str(networks[SOURCE_NETWORK].get("NetworkID"))):
        raise UpgradeError("source network identity differs")
    container_id = inspection.get("Id")
    if not isinstance(container_id, str) or not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise UpgradeError("source container ID is invalid")
    for item in running:
        item_labels = item.get("Config", {}).get("Labels", {}) or {}
        if item_labels.get("com.docker.compose.project") == SOURCE_PROJECT and item.get("Id") != container_id:
            raise UpgradeError("all non-database shadow services, including paid producers, must be stopped")
        item_networks = item.get("NetworkSettings", {}).get("Networks", {})
        if SOURCE_NETWORK in item_networks and item.get("Id") != container_id:
            raise UpgradeError("another running container is attached to the authority network")
        if item.get("Id") != container_id and any(mount.get("Name") == SOURCE_VOLUME for mount in item.get("Mounts", [])):
            raise UpgradeError("another running container mounts the authority volume")
    return {"container_id": container_id, "compose_project": SOURCE_PROJECT, "database": SOURCE_DATABASE, "volume": SOURCE_VOLUME, "network": SOURCE_NETWORK, "network_id": networks[SOURCE_NETWORK]["NetworkID"], "image": inspection["Image"]}


def _source_identity() -> dict[str, Any]:
    inspection = _json(["inspect", SOURCE_CONTAINER], "source identity inspection")[0]
    ids = _docker(["ps", "--quiet", "--no-trunc"], "running container inventory").splitlines()
    running = _json(["inspect", *ids], "running container identity inspection") if ids else []
    image = _json(["image", "inspect", TIMESCALE_IMAGE], "pinned database image inspection")[0]
    if not image.get("RepoDigests") or not str(image.get("Id", "")).startswith("sha256:"):
        raise UpgradeError("pinned database image has no immutable local resolution")
    identity = _identity(inspection, running, image["Id"])
    volume = _json(["volume", "inspect", SOURCE_VOLUME], "authority volume inspection")[0]
    network = _json(["network", "inspect", SOURCE_NETWORK], "authority network inspection")[0]
    if volume.get("Labels", {}).get("com.docker.compose.project") != SOURCE_PROJECT or volume.get("Labels", {}).get("com.docker.compose.volume") != "ts-data" or volume.get("Driver") != "local" or volume.get("Name") != SOURCE_VOLUME:
        raise UpgradeError("authority volume provenance differs")
    if network.get("Id") != identity["network_id"] or network.get("Labels", {}).get("com.docker.compose.project") != SOURCE_PROJECT or network.get("Labels", {}).get("com.docker.compose.network") != "data" or network.get("Internal") is not True or network.get("Driver") != "bridge":
        raise UpgradeError("authority network provenance differs")
    identity["volume_driver"] = volume["Driver"]
    identity["network_internal"] = True
    return identity


def _snapshot_sql() -> str:
    table_expressions = []
    for table in TABLES:
        # 018 adds reconciliation metadata.  Hash every original column, not
        # those deliberate new columns; separately prove their pristine state.
        expression = "to_jsonb(t)"
        if table == "message_outbox":
            expression += " - ARRAY['reconciliation_state','reconciliation_id','reconciliation_started_at','reconciliation_outcome_at']::text[]"
        table_expressions.extend((f"'{table}'", f"(SELECT json_build_object('count',count(*),'row_digest',encode(sha256(convert_to(COALESCE(string_agg(({expression})::text,E'\\n' ORDER BY ({expression})::text),''),'UTF8')),'hex')) FROM {table} t)"))
    inventory = CATALOG.LEGACY_INVENTORY_QUERY.strip().removesuffix(";")
    for expression in ("pg_get_viewdef(c.oid, true)", "pg_get_expr(ad.adbin, ad.adrelid, true)", "pg_get_constraintdef(con.oid, true)", "pg_get_indexdef(i.oid)", "pg_get_triggerdef(tg.oid, true)"):
        inventory = inventory.replace(f"md5({expression})", f"encode(sha256(convert_to({expression},'UTF8')),'hex')")
    if "md5(" in inventory:
        raise UpgradeError("reviewed schema inventory contains an unassigned weak fingerprint")
    future_names = ",".join("'" + name + "'" for name in NEW_TABLES)
    sequences = "(SELECT COALESCE(jsonb_object_agg(c.relname,jsonb_build_object('last_value',(xpath('/table/row/last_value/text()',x.state))[1]::text,'is_called',(xpath('/table/row/is_called/text()',x.state))[1]::text)), '{}'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL (SELECT query_to_xml(format('SELECT last_value,is_called FROM %I.%I',n.nspname,c.relname),false,false,'') AS state) x WHERE n.nspname='public' AND c.relkind='S')"
    reconciliation_columns = "(SELECT count(*) FROM pg_attribute WHERE attrelid='public.message_outbox'::regclass AND attnum>0 AND NOT attisdropped AND attname IN ('reconciliation_state','reconciliation_id','reconciliation_started_at','reconciliation_outcome_at'))"
    return "SELECT json_build_object('database',current_database(),'migrations',(SELECT COALESCE(json_agg(version ORDER BY version),'[]'::json) FROM schema_migrations),'tables',json_build_object(" + ",".join(table_expressions) + "),'schema_digest',encode(sha256(convert_to((" + inventory + "),'UTF8')),'hex'),'public_sequences'," + sequences + ",'reconciliation_columns'," + reconciliation_columns + ",'max_sequence',(SELECT COALESCE(max(event_seq),0) FROM public_execution_events),'simulator_relations',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname LIKE 'sim\\_%' ESCAPE '\\'),'runtime_relations',(SELECT COALESCE(json_agg(c.relname ORDER BY c.relname),'[]'::json) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN (" + future_names + ")),'nonpristine_reconciliation',(SELECT count(*) FROM message_outbox t WHERE COALESCE(to_jsonb(t)->>'reconciliation_state','NONE')<>'NONE' OR to_jsonb(t)->>'reconciliation_id' IS NOT NULL OR to_jsonb(t)->>'reconciliation_started_at' IS NOT NULL OR to_jsonb(t)->>'reconciliation_outcome_at' IS NOT NULL))"


def _new_runtime_sql() -> str:
    fields = []
    for table in NEW_TABLES:
        fields.extend((f"'{table}'", f"(SELECT json_build_object('count',count(*),'row_digest',encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),''),'UTF8')),'hex')) FROM {table} t)"))
    return "SELECT json_build_object(" + ",".join(fields) + ")"


def _snapshot(container: str, database: str, user: str = "kairos") -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", database):
        raise UpgradeError("database snapshot identifier is invalid")
    base_expression = _snapshot_sql().removeprefix("SELECT ")
    runtime_expression = _new_runtime_sql().removeprefix("SELECT ")
    sql = "BEGIN READ ONLY; SET LOCAL TIME ZONE 'UTC';\nSELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version='018_offline_outbox_reconciliation.sql') AS runtime_profile \\gset\n\\if :runtime_profile\nSELECT (" + base_expression + ")::jsonb || jsonb_build_object('runtime_rows',(" + runtime_expression + "));\n\\else\n" + _snapshot_sql() + ";\n\\endif\nROLLBACK;\n"
    result = _docker(["exec", "--interactive", container, "psql", "--quiet", "--no-align", "--tuples-only", "--set=ON_ERROR_STOP=1", f"--username={user}", f"--dbname={database}", "--file=-"], "read-only durable snapshot", data=sql)
    try:
        snapshot = json.loads(result)
    except json.JSONDecodeError:
        raise UpgradeError("durable snapshot is malformed") from None
    if snapshot.get("database") != database or snapshot.get("simulator_relations") != 0:
        raise UpgradeError("database snapshot identity or simulator separation differs")
    snapshot["database"] = SOURCE_DATABASE  # Clone physical names deliberately differ.
    return snapshot


def _matches_backup(snapshot: dict[str, Any], manifest: dict[str, Any]) -> None:
    if tuple(snapshot.get("migrations", ())) != LEGACY:
        raise UpgradeError("shadow source must have the exact legacy001-012 profile")
    if snapshot.get("runtime_relations") != [] or snapshot.get("nonpristine_reconciliation") != 0 or snapshot.get("reconciliation_columns") != 0:
        raise UpgradeError("legacy source contains unregistered future runtime DDL/effects")
    for table in TABLES:
        if snapshot.get("tables", {}).get(table, {}).get("count") != manifest["checkpoints"][table]:
            raise UpgradeError("source durable checkpoints differ from verified backup")
    if snapshot.get("max_sequence") != manifest["checkpoints"]["public_execution_events_max_sequence"]:
        raise UpgradeError("source public execution sequence differs from verified backup")


def _preserved(before: dict[str, Any], after: dict[str, Any]) -> None:
    if before.get("tables") != after.get("tables") or before.get("max_sequence") != after.get("max_sequence") or before.get("public_sequences") != after.get("public_sequences"):
        raise UpgradeError("historical reservations or durable rows changed during migration")
    if tuple(after.get("migrations", ())) != TARGET or after.get("simulator_relations") != 0:
        raise UpgradeError("migration did not produce the exact simulator-free runtime profile")
    if after.get("nonpristine_reconciliation") != 0:
        raise UpgradeError("migration changed historical reconciliation effects")
    if after.get("reconciliation_columns") != 4:
        raise UpgradeError("runtime profile does not contain exactly the four reviewed018 columns")
    runtime_rows = after.get("runtime_rows", {})
    if set(runtime_rows) != set(NEW_TABLES) or any(runtime_rows[table].get("count") != (1 if table == "paper_canary_database_identity" else 0) for table in NEW_TABLES):
        raise UpgradeError("new runtime relations are not pristine; campaign adoption is separate")


def _runner_identity(image: str) -> None:
    if image != RUNNER_IMAGE:
        raise UpgradeError("only the reviewed immutable local runner repository digest is accepted")
    image_info = _json(["image", "inspect", image], "immutable runner inspection")[0]
    labels = image_info.get("Config", {}).get("Labels", {}) or {}
    if image not in image_info.get("RepoDigests", []) or labels.get("org.opencontainers.image.revision") != RUNNER_REVISION or labels.get("org.opencontainers.image.source") != "https://github.com/Kairos-cryptoAI/kairos-persistence" or image_info.get("Config", {}).get("User") != "10001:10001":
        raise UpgradeError("immutable runner provenance or unprivileged user differs")


def _runner_program(database: str, before: dict[str, Any], *, apply: bool, expected_schema: str | None = None) -> str:
    payload = {"database": database, "apply": apply, "migration_hashes": MIGRATION_HASHES, "package": PACKAGE, "target": TARGET, "module_sha256": DATABASE_MODULE_SHA256, "before": before, "snapshot_sql": _snapshot_sql(), "runtime_sql": _new_runtime_sql(), "tables": TABLES, "new_tables": NEW_TABLES, "expected_schema": expected_schema}
    # Never inject a DSN/key in argv or source.  Apply loads only its fixed
    # persistence secret inside the exact database container network namespace.
    return "CONFIG=" + repr(payload) + "\n" + r'''
import asyncio,hashlib,json,socket,urllib.parse
from contextlib import asynccontextmanager
from pathlib import Path
from importlib.resources import files
root=files('kairos_persistence')
migrations=root.joinpath('migrations')
names=tuple(sorted(p.name for p in migrations.iterdir() if p.name.endswith('.sql')))
if names != tuple(CONFIG['package']): raise RuntimeError('runner migration inventory differs')
for name in names:
    if hashlib.sha256(migrations.joinpath(name).read_bytes()).hexdigest()!=CONFIG['migration_hashes'][name]: raise RuntimeError('runner migration bytes differ')
if hashlib.sha256(root.joinpath('database.py').read_bytes()).hexdigest()!=CONFIG['module_sha256']: raise RuntimeError('normal migration primitive bytes differ')
from kairos_persistence import Database,MigrationProfile,PersistenceSettings
if Database.migration_names(MigrationProfile.RUNTIME)!=tuple(CONFIG['target']): raise RuntimeError('runner runtime profile differs')
if CONFIG['apply']:
    raw=Path('/run/secrets/persistence_database_url').read_text().strip()
    url=urllib.parse.urlsplit(raw)
    if url.scheme not in ('postgres','postgresql') or url.hostname not in ('timescaledb','kairos-shadow-gate-timescaledb-1') or url.port!=5432 or url.path!='/kairos' or url.query or url.fragment: raise RuntimeError('authority secret target differs')
    credentials=url.netloc.rsplit('@',1)[0]
    if '@' not in url.netloc: raise RuntimeError('authority secret has no explicit credentials')
    dsn=urllib.parse.urlunsplit((url.scheme,credentials+'@127.0.0.1:5432',url.path,'',''))
else:
    dsn='postgresql://kairos_shadow_upgrade@127.0.0.1:5432/'+CONFIG['database']
original_connect=socket.socket.connect
def guarded_connect(sock,address):
    if not isinstance(address,tuple) or address[:2]!=('127.0.0.1',5432): raise RuntimeError('non-loopback network access forbidden')
    return original_connect(sock,address)
socket.socket.connect=guarded_connect
class GuardedDatabase(Database):
    @asynccontextmanager
    async def transaction(self):
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SET LOCAL lock_timeout='5s'")
                await connection.execute("SET LOCAL statement_timeout='120s'")
                await connection.execute("SET LOCAL TIME ZONE 'UTC'")
                await connection.execute('SELECT pg_advisory_xact_lock($1)',4907627681104115019)
                locks=list(CONFIG['tables'])
                if tuple(CONFIG['before']['migrations'])==tuple(CONFIG['target']): locks.extend(CONFIG['new_tables'])
                await connection.execute('LOCK TABLE schema_migrations,'+','.join(locks)+' IN ACCESS EXCLUSIVE MODE')
                if CONFIG['apply'] and await connection.fetchval("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'")!=0: raise RuntimeError('another authority database client is connected')
                actual=json.loads(await connection.fetchval(CONFIG['snapshot_sql']))
                if tuple(actual['migrations'])==tuple(CONFIG['target']): actual['runtime_rows']=json.loads(await connection.fetchval(CONFIG['runtime_sql']))
                actual['database']='kairos'
                if actual!=CONFIG['before']: raise RuntimeError('authority snapshot changed under migration lock')
                yield connection
                if CONFIG['apply'] and await connection.fetchval("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'")!=0: raise RuntimeError('another authority database client connected during migration')
                after=json.loads(await connection.fetchval(CONFIG['snapshot_sql']))
                if after['tables']!=actual['tables'] or after['max_sequence']!=actual['max_sequence'] or after['public_sequences']!=actual['public_sequences'] or after['nonpristine_reconciliation']!=0 or after['simulator_relations']!=0 or after['reconciliation_columns']!=4: raise RuntimeError('durable authority rows changed inside migration transaction')
                if CONFIG['expected_schema'] is not None and after['schema_digest']!=CONFIG['expected_schema']: raise RuntimeError('applied schema differs from reviewed clone before commit')
                runtime_rows=json.loads(await connection.fetchval(CONFIG['runtime_sql']))
                if any(runtime_rows[table]['count']!=(1 if table=='paper_canary_database_identity' else 0) for table in CONFIG['new_tables']): raise RuntimeError('new runtime relations are not pristine before commit')
                if 'runtime_rows' in actual and runtime_rows!=actual['runtime_rows']: raise RuntimeError('idempotent migration changed new runtime rows')
async def main():
    db=GuardedDatabase(PersistenceSettings(database_url=dsn,pool_min_size=1,pool_max_size=1),migration_profile=MigrationProfile.RUNTIME)
    await db.connect()
    try:
        if await db.pool.fetchval('SELECT current_database()')!=CONFIG['database']: raise RuntimeError('connected target differs')
        if await db.pool.fetchval("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname LIKE 'sim\\_%' ESCAPE '\\'")!=0: raise RuntimeError('simulator residue forbidden')
        await db.migrate()
        versions=tuple(r['version'] for r in await db.pool.fetch('SELECT version FROM schema_migrations ORDER BY version'))
        if versions!=tuple(CONFIG['target']): raise RuntimeError('migration result differs')
        print(json.dumps({'result':'PASS_RUNTIME_PROFILE','migration_count':len(versions),'provider_calls':0}))
    finally: await db.close()
asyncio.run(main())
'''


def _migrate(container: str, database: str, suffix: str, before: dict[str, Any], *, apply: bool = False, expected_schema: str | None = None) -> None:
    name = f"kairos-shadow-schema-runner-{suffix}"
    args = ["run", "--rm", "--interactive", "--name", name, "--network", f"container:{container}", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user=10001:10001", "--memory=256m", "--cpus=0.5", "--pids-limit=64", "--label", f"com.kairos.scope={SCOPE}", "--label", f"com.kairos.drill={suffix}", "--env", "PYTHONDONTWRITEBYTECODE=1"]
    if apply:
        if not SOURCE_SECRET.is_file():
            raise UpgradeError("fixed authority persistence secret is unavailable")
        args.extend(("--mount", f"type=bind,src={SOURCE_SECRET.resolve()},dst=/run/secrets/persistence_database_url,readonly"))
    args.extend(("--entrypoint", "python", RUNNER_IMAGE, "-"))
    try:
        result = json.loads(_docker(args, "normal guarded runtime migration", data=_runner_program(database, before, apply=apply, expected_schema=expected_schema)))
        if result != {"result": "PASS_RUNTIME_PROFILE", "migration_count": len(TARGET), "provider_calls": 0}:
            raise UpgradeError("normal guarded migration result is invalid")
    finally:
        _cleanup(name, suffix, runner=True)


def _cleanup(name: str, suffix: str, *, runner: bool = False) -> None:
    text = _docker(["inspect", name], "clone cleanup inspection", missing_ok=True)
    if not text:
        return
    item = json.loads(text)[0]
    labels = item.get("Config", {}).get("Labels", {}) or {}
    expected = f"kairos-shadow-schema-{'runner' if runner else 'clone'}-{suffix}"
    if name != expected or item.get("Name") != "/" + expected or labels.get("com.kairos.scope") != SCOPE or labels.get("com.kairos.drill") != suffix:
        raise UpgradeError("refused cleanup of object outside the exact generated clone identity")
    if not runner:
        if item.get("HostConfig", {}).get("NetworkMode") != "none" or item.get("Mounts"):
            raise UpgradeError("refused cleanup of clone with unexpected mounts/network")
    _docker(["rm", "--force", name], "exact disposable clone cleanup")


def _wait_clone_ready(container: str, database: str) -> None:
    _assert_clone_namespace(container, database)
    # The official PostgreSQL entrypoint temporarily starts a socket-only
    # postmaster for initdb.  A Unix-socket pg_isready can succeed just before
    # that process stops.  TCP plus an authenticated SQL/database check waits
    # for the final postmaster and three consecutive stable observations.
    deadline = time.monotonic() + 60
    successes = 0
    while time.monotonic() < deadline:
        try:
            pid_one = subprocess.run(["docker", "exec", container, "cat", "/proc/1/comm"], capture_output=True, text=True, encoding="utf-8", shell=False, timeout=5)
            ready = pid_one.returncode == 0 and pid_one.stdout.strip() == "postgres"
            if ready:
                result = subprocess.run(["docker", "exec", container, "psql", "--host=127.0.0.1", "--port=5432", "--username=kairos_shadow_upgrade", f"--dbname={database}", "--quiet", "--tuples-only", "--no-align", "--set=ON_ERROR_STOP=1", "--command=SELECT pg_is_in_recovery()::text || '|' || current_database();"], capture_output=True, text=True, encoding="utf-8", shell=False, timeout=5)
                ready = result.returncode == 0 and result.stdout.strip() == "false|" + database
        except subprocess.TimeoutExpired:
            ready = False
        successes = successes + 1 if ready else 0
        if successes == 3:
            return
        time.sleep(0.5)
    raise UpgradeError("disposable clone final TCP postmaster did not become stable within60 seconds")


def _assert_clone_namespace(container: str, database: str) -> None:
    match = re.fullmatch(r"kairos-shadow-schema-clone-([0-9a-f]{12})", container)
    if match is None or database != "kairos_shadow_drill_" + match[1]:
        raise UpgradeError("archive/readiness operation is outside the exact generated clone namespace")


def _restore_stream(container: str, database: str, dump: Path) -> None:
    _assert_clone_namespace(container, database)
    resolved = dump.resolve(strict=True)
    if not resolved.is_relative_to(BACKUP_ROOT.resolve()) or not resolved.is_file() or not 0 < resolved.stat().st_size <= MAX_DUMP_BYTES:
        raise UpgradeError("clone restore archive is outside the protected root or bounded archive size")
    # Docker cp can silently miss a running tmpfs mount on this Windows host.
    # Read only the verified host archive and feed pg_restore's binary stdin;
    # neither database secrets nor an archive staging path enter the container.
    with resolved.open("rb") as archive:
        try:
            result = subprocess.run(["docker", "exec", "--interactive", container, "pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "--username=kairos_shadow_upgrade", f"--dbname={database}"], stdin=archive, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, shell=False, timeout=ARCHIVE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            raise UpgradeError("binary clone restore exceeded its bounded180-second timeout; raw logs withheld") from None
    if result.returncode:
        raise UpgradeError(f"binary verified clone restore failed (exit {result.returncode}); raw logs withheld")


def _dump_stream(container: str, database: str, path: Path) -> None:
    _assert_clone_namespace(container, database)
    parent = path.parent.resolve(strict=True)
    if path.name != "upgraded-shadow.dump" or not parent.is_relative_to(BACKUP_ROOT.resolve()) or not re.fullmatch(r"kairos-shadow-schema-[A-Za-z0-9_-]+", parent.name):
        raise UpgradeError("upgraded archive must remain in its protected generated temporary directory")
    # Exclusive creation prevents overwriting any prior evidence.  The temp
    # directory inherits the already restricted backup directory's ACL.
    with path.open("xb") as archive:
        try:
            result = subprocess.run(["docker", "exec", container, "pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--username=kairos_shadow_upgrade", f"--dbname={database}"], stdout=archive, stderr=subprocess.PIPE, shell=False, timeout=ARCHIVE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            raise UpgradeError("binary clone dump exceeded its bounded180-second timeout; raw logs withheld") from None
    if result.returncode:
        raise UpgradeError(f"binary upgraded clone dump failed (exit {result.returncode}); raw logs withheld")
    if not 0 < path.stat().st_size <= MAX_DUMP_BYTES:
        raise UpgradeError("upgraded clone archive has an invalid or oversized byte length")


def _clone(dump: Path, owners: list[str], suffix: str) -> tuple[str, str]:
    container = f"kairos-shadow-schema-clone-{suffix}"
    database = f"kairos_shadow_drill_{suffix}"
    _docker(["create", "--name", container, "--network=none", "--memory=1g", "--cpus=1", "--pids-limit=256", "--label", f"com.kairos.scope={SCOPE}", "--label", f"com.kairos.drill={suffix}", "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=512m", "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--env", "POSTGRES_USER=kairos_shadow_upgrade", "--env", f"POSTGRES_DB={database}", "--env", "POSTGRES_HOST_AUTH_METHOD=trust", TIMESCALE_IMAGE], "create no-network disposable shadow clone")
    _docker(["start", container], "start no-network disposable shadow clone")
    _wait_clone_ready(container, database)
    for owner in owners:
        if owner != "kairos_shadow_upgrade":
            _docker(["exec", container, "psql", "--set=ON_ERROR_STOP=1", "--username=kairos_shadow_upgrade", f"--dbname={database}", "--command", f'CREATE ROLE "{owner}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;'], "create constrained clone-only TimescaleDB owner placeholder")
    for command in ("CREATE EXTENSION IF NOT EXISTS timescaledb;", "SELECT timescaledb_pre_restore();"):
        _docker(["exec", container, "psql", "--set=ON_ERROR_STOP=1", "--username=kairos_shadow_upgrade", f"--dbname={database}", "--command", command], "enter clone-only restore mode")
    _restore_stream(container, database, dump)
    _docker(["exec", container, "psql", "--set=ON_ERROR_STOP=1", "--username=kairos_shadow_upgrade", f"--dbname={database}", "--command", "SELECT timescaledb_post_restore();"], "leave clone-only restore mode")
    return container, database


def _receipt_valid(receipt: dict[str, Any], manifest_path: Path, manifest: dict[str, Any], source: dict[str, Any], before: dict[str, Any]) -> None:
    identity = _code_identity()
    if receipt.get("schema_version") != SCHEMA or receipt.get("result") != "PASS_CLONE_ONLY" or receipt.get("controller_sha256") != identity["controller_sha256"] or receipt.get("catalog_sha256") != identity["catalog_sha256"]:
        raise UpgradeError("preflight receipt schema/controller/result differs")
    _fresh(receipt.get("created_at_utc"), "preflight receipt")
    if _utc(receipt["created_at_utc"], "preflight receipt") < _utc(manifest["created_at_utc"], "backup") - timedelta(minutes=5):
        raise UpgradeError("preflight receipt predates the verified backup")
    if receipt.get("backup_manifest_sha256") != _sha(manifest_path) or receipt.get("backup_sha256") != manifest["sha256"] or receipt.get("runner_image") != RUNNER_IMAGE or receipt.get("source_identity") != source or receipt.get("before") != before:
        raise UpgradeError("preflight receipt does not bind the exact fresh backup/runner/source/data")
    if receipt.get("runtime_profile") != list(TARGET) or receipt.get("provider_calls") != 0 or receipt.get("primary_mutations") != 0:
        raise UpgradeError("preflight scope or runtime topology differs")
    _preserved(before, receipt.get("after", {}))
    if receipt.get("after") != receipt.get("second_pass") or receipt.get("after") != receipt.get("restore"):
        raise UpgradeError("preflight lacks identical idempotency and restored clone snapshots")


def _write(path: Path, receipt: dict[str, Any], manifest_path: Path) -> None:
    if path.resolve().parent != manifest_path.resolve().parent:
        raise UpgradeError("output receipt must remain beside its protected backup")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")


def run(args: argparse.Namespace) -> dict[str, Any]:
    code_identity = _code_identity()
    if not args.confirm_paid_producers_stopped:
        raise UpgradeError("explicit confirmation that all paid producers are stopped is required")
    if args.apply and (args.confirmation != CONFIRMATION or not args.preflight_receipt_path or not args.expected_preflight_sha256):
        raise UpgradeError("apply requires its exact confirmation and receipt/SHA-256")
    manifest_path = args.manifest_path.resolve(strict=True)
    if args.receipt_path.resolve().parent != manifest_path.parent or args.receipt_path.exists():
        raise UpgradeError("new output receipt must not exist and must remain beside the backup")
    manifest, dump = _backup(manifest_path)
    source = _source_identity()
    before = _snapshot(source["container_id"], SOURCE_DATABASE)
    _matches_backup(before, manifest)
    _runner_identity(args.migration_runner_image)
    if args.apply:
        receipt_path = args.preflight_receipt_path.resolve(strict=True)
        if receipt_path.parent != manifest_path.parent or not re.fullmatch(r"[0-9a-f]{64}", args.expected_preflight_sha256) or _sha(receipt_path) != args.expected_preflight_sha256:
            raise UpgradeError("preflight receipt path or SHA-256 differs")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        _receipt_valid(receipt, manifest_path, manifest, source, before)
        # Reinspect immediately before the only source-changing operation.
        if _source_identity() != source or _snapshot(source["container_id"], SOURCE_DATABASE) != before:
            raise UpgradeError("authority identity or durable data changed before apply")
        _assert_code_identity(code_identity)
        suffix = uuid.uuid4().hex[:12]
        _migrate(source["container_id"], SOURCE_DATABASE, suffix, before, apply=True, expected_schema=receipt["after"]["schema_digest"])
        after = _snapshot(source["container_id"], SOURCE_DATABASE)
        _preserved(before, after)
        if after.get("schema_digest") != receipt["after"].get("schema_digest"):
            raise UpgradeError("applied authority schema differs from its verified clone")
        _assert_code_identity(code_identity)
        result = {"schema_version": "kairos.shadow-runtime-schema-apply.v1", "result": "APPLIED_RUNTIME_PROFILE", "created_at_utc": datetime.now(UTC).isoformat(), **code_identity, "source_identity": source, "preflight_receipt_sha256": args.expected_preflight_sha256, "backup_sha256": manifest["sha256"], "before": before, "after": after, "provider_calls": 0, "consumers_started": 0, "paper_qualified": False, "live_ready": False}
    else:
        suffix = uuid.uuid4().hex[:12]
        restore_suffix = uuid.uuid4().hex[:12]
        with tempfile.TemporaryDirectory(prefix="kairos-shadow-schema-", dir=manifest_path.parent) as temporary:
            upgraded_dump = Path(temporary) / "upgraded-shadow.dump"
            try:
                container, database = _clone(dump, manifest["timescaledb_bgw_owners"], suffix)
                clone_before = _snapshot(container, database, "kairos_shadow_upgrade")
                if clone_before != before:
                    raise UpgradeError("restored backup does not match exact current durable shadow rows")
                _migrate(container, database, suffix, clone_before)
                after = _snapshot(container, database, "kairos_shadow_upgrade")
                _preserved(before, after)
                _migrate(container, database, suffix, after)
                second = _snapshot(container, database, "kairos_shadow_upgrade")
                if second != after:
                    raise UpgradeError("second normal migration changed the durable runtime snapshot")
                _dump_stream(container, database, upgraded_dump)
                owners = sorted(set(manifest["timescaledb_bgw_owners"] + ["kairos_shadow_upgrade"]))
                restore_container, restore_database = _clone(upgraded_dump, owners, restore_suffix)
                restored = _snapshot(restore_container, restore_database, "kairos_shadow_upgrade")
                if restored != after:
                    raise UpgradeError("post-upgrade restore drill changed durable runtime rows")
            finally:
                _cleanup(f"kairos-shadow-schema-clone-{restore_suffix}", restore_suffix)
                _cleanup(f"kairos-shadow-schema-clone-{suffix}", suffix)
        if _sha(dump) != manifest["sha256"] or _source_identity() != source or _snapshot(source["container_id"], SOURCE_DATABASE) != before:
            raise UpgradeError("source or immutable backup changed during clone-only proof")
        _assert_code_identity(code_identity)
        result = {"schema_version": SCHEMA, "result": "PASS_CLONE_ONLY", "created_at_utc": datetime.now(UTC).isoformat(), **code_identity, "backup_manifest_sha256": _sha(manifest_path), "backup_sha256": manifest["sha256"], "runner_image": RUNNER_IMAGE, "runtime_profile": list(TARGET), "source_identity": source, "before": before, "after": after, "second_pass": second, "restore": restored, "provider_calls": 0, "primary_mutations": 0, "paper_qualified": False, "live_ready": False}
    _write(args.receipt_path, result, manifest_path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", type=Path, required=True)
    parser.add_argument("--migration-runner-image", default=RUNNER_IMAGE)
    parser.add_argument("--receipt-path", type=Path, required=True)
    parser.add_argument("--confirm-paid-producers-stopped", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight", action="store_true", help="default: clone-only proof")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--confirmation")
    parser.add_argument("--preflight-receipt-path", type=Path)
    parser.add_argument("--expected-preflight-sha256")
    args = parser.parse_args(argv)
    try:
        result = run(args)
        print(json.dumps({"result": result["result"], "provider_calls": 0, "receipt_path": str(args.receipt_path)}))
        return 0
    except (UpgradeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        boundary = "apply did not return verified success; source DDL may have committed, verify source before any restart" if args.apply else "clone-only operation failed; no source migration was attempted"
        print(f"shadow schema operation stopped: {type(exc).__name__}: {exc}; {boundary}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
