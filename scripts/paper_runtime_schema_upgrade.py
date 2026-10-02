"""Read-only PAPER target-role/full-history and fresh backup restore binding.

There is deliberately no primary apply mode or migration/quarantine function.
Only a generated, network-none clone is restored; existing runtime services
are never started/stopped and no publisher, Redis or exchange client is used.
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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "scripts" / "legacy_outbox_quarantine_clone_rehearsal.py"
WORKER_PATH = ROOT / "scripts" / "paper_runtime_snapshot_worker.py"
SOURCE_PROJECT = "kairos-paper-gate"
SOURCE_CONTAINER = SOURCE_PROJECT + "-timescaledb-1"
SOURCE_DATABASE = "kairos"
SOURCE_VOLUME = SOURCE_PROJECT + "_paper-ts-data"
SOURCE_NETWORK = SOURCE_PROJECT + "_paper-data"
SOURCE_SECRET = ROOT.parent / "runtime" / "paper-gate" / "secrets" / "persistence_database_url"
SCOPE = "paper-runtime-readonly-preflight"
CONFIRMATION = "READ_ONLY_PAPER_TARGET_ROLE_AND_RESTORE_BINDING"
MAX_DUMP_BYTES = 256 * 1024 * 1024
BOOTSTRAP_TABLES = {"market_snapshots", "sentiment_signals", "tactical_commands", "strategic_allocations", "executions", "equity_curve", "llm_calls"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class PreflightError(RuntimeError):
    """Safe operational failure with no raw database/credential logs."""


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _catalog() -> Any:
    before = _sha(CATALOG_PATH)
    specification = importlib.util.spec_from_file_location("kairos_paper_readonly_catalog", CATALOG_PATH)
    if specification is None or specification.loader is None:
        raise PreflightError("reviewed catalog is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    if _sha(CATALOG_PATH) != before:
        raise PreflightError("reviewed catalog changed during load")
    module.loaded_sha256 = before
    return module


CATALOG = _catalog()
TABLES = tuple(sorted(CATALOG.CHECKPOINT_TABLES | BOOTSTRAP_TABLES | {"schema_migrations"}))


def _code_identity() -> dict[str, str]:
    value = {"controller_sha256": _sha(Path(__file__)), "worker_sha256": _sha(WORKER_PATH), "catalog_sha256": _sha(CATALOG_PATH)}
    if value["catalog_sha256"] != CATALOG.loaded_sha256:
        raise PreflightError("loaded catalog differs from its current bytes")
    return value


def _docker(arguments: list[str], *, data: str | None = None, missing_ok: bool = False) -> str:
    result = subprocess.run(["docker", *arguments], input=data, text=True, encoding="utf-8", capture_output=True, shell=False, timeout=360)
    if result.returncode:
        if missing_ok:
            return ""
        raise PreflightError("bounded Docker operation failed; raw output withheld")
    if len(result.stdout) > 1024 * 1024:
        raise PreflightError("Docker response exceeded its bound")
    return result.stdout.strip()


def _json(arguments: list[str]) -> Any:
    try:
        return json.loads(_docker(arguments))
    except json.JSONDecodeError:
        raise PreflightError("Docker response is not structured JSON") from None


def _identity(inspection: dict[str, Any], running: list[dict[str, Any]], image_id: str) -> dict[str, Any]:
    labels = inspection.get("Config", {}).get("Labels", {}) or {}
    identifier = inspection.get("Id")
    if labels.get("com.docker.compose.project") != SOURCE_PROJECT or labels.get("com.docker.compose.service") != "timescaledb" or inspection.get("Name") != "/" + SOURCE_CONTAINER:
        raise PreflightError("fixed PAPER Compose/container identity differs")
    if not SHA256.fullmatch(str(identifier)) or inspection.get("Image") != image_id or inspection.get("State", {}).get("Running") is not True:
        raise PreflightError("PAPER database is absent or has a different immutable image")
    options = inspection.get("HostConfig", {})
    if options.get("Privileged") is not False or options.get("PortBindings"):
        raise PreflightError("PAPER database privileges/host ports differ")
    mounts = inspection.get("Mounts", [])
    volume = [item for item in mounts if item.get("Destination") == "/var/lib/postgresql/data"]
    if len(volume) != 1 or volume[0].get("Type") != "volume" or volume[0].get("Name") != SOURCE_VOLUME or volume[0].get("RW") is not True:
        raise PreflightError("fixed PAPER volume identity differs")
    for item in mounts:
        if item in volume:
            continue
        if item.get("Destination") not in {"/docker-entrypoint-initdb.d/001-kairos.sql", "/run/secrets/paper_postgres_password"} or item.get("Type") != "bind" or item.get("RW") is not False:
            raise PreflightError("unexpected PAPER database mount")
    networks = inspection.get("NetworkSettings", {}).get("Networks", {})
    if set(networks) != {SOURCE_NETWORK} or not SHA256.fullmatch(str(networks[SOURCE_NETWORK].get("NetworkID"))):
        raise PreflightError("fixed PAPER internal network differs")
    for item in running:
        if item.get("Id") == identifier:
            continue
        other = item.get("Config", {}).get("Labels", {}) or {}
        if other.get("com.docker.compose.project") == SOURCE_PROJECT and other.get("com.docker.compose.service") != "redis":
            raise PreflightError("all PAPER application/collector/execution services must remain stopped")
        if SOURCE_NETWORK in item.get("NetworkSettings", {}).get("Networks", {}) or any(mount.get("Name") == SOURCE_VOLUME for mount in item.get("Mounts", [])):
            raise PreflightError("another running container touches PAPER data/network")
    return {"container_id": identifier, "compose_project": SOURCE_PROJECT, "database": SOURCE_DATABASE, "volume": SOURCE_VOLUME, "network": SOURCE_NETWORK, "network_id": networks[SOURCE_NETWORK]["NetworkID"], "image_id": image_id}


def _source_identity() -> dict[str, Any]:
    source = _json(["inspect", SOURCE_CONTAINER])[0]
    ids = _docker(["ps", "--quiet", "--no-trunc"]).splitlines()
    running = _json(["inspect", *ids]) if ids else []
    image = _json(["image", "inspect", CATALOG.EXPECTED_TIMESCALE_IMAGE])[0]
    if not image.get("RepoDigests") or not str(image.get("Id", "")).startswith("sha256:"):
        raise PreflightError("pinned database image is not immutably resolved")
    identity = _identity(source, running, image["Id"])
    volume = _json(["volume", "inspect", SOURCE_VOLUME])[0]
    network = _json(["network", "inspect", SOURCE_NETWORK])[0]
    if volume.get("Name") != SOURCE_VOLUME or volume.get("Driver") != "local" or volume.get("Labels", {}).get("com.docker.compose.project") != SOURCE_PROJECT or volume.get("Labels", {}).get("com.docker.compose.volume") != "paper-ts-data":
        raise PreflightError("PAPER volume provenance differs")
    if network.get("Id") != identity["network_id"] or network.get("Internal") is not True or network.get("Driver") != "bridge" or network.get("Labels", {}).get("com.docker.compose.project") != SOURCE_PROJECT or network.get("Labels", {}).get("com.docker.compose.network") != "paper-data":
        raise PreflightError("PAPER network provenance differs")
    return identity


def _runner_identity() -> None:
    image = _json(["image", "inspect", CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE])[0]
    labels = image.get("Config", {}).get("Labels", {}) or {}
    if CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE not in image.get("RepoDigests", []) or image.get("Config", {}).get("User") != CATALOG.EXPECTED_RUNNER_USER or labels.get("org.opencontainers.image.source") != CATALOG.EXPECTED_PERSISTENCE_REPOSITORY or labels.get("org.opencontainers.image.revision") != CATALOG.EXPECTED_PERSISTENCE_REVISION:
        raise PreflightError("accepted immutable runtime runner provenance differs")


def _verify_clone_receipt(path: Path, signature: Path, inputs: Any) -> str:
    CATALOG._verify_signature(path, signature)
    value = CATALOG._read_json(path, "accepted clone receipt")
    expected_keys = {"schema_version", "classification", "created_at_utc", "source_backup", "migration_runner", "clone", "quarantine", "restore_drill", "original_migration", "readiness", "assertions", "result", "receipt_sha256"}
    if set(value) != expected_keys or type(value.get("schema_version")) is not int or value["schema_version"] != 1 or value.get("result") != "PASS_CLONE_ONLY" or value.get("classification") != "CLONE_ONLY_LEGACY_OUTBOX_QUARANTINE_REHEARSAL":
        raise PreflightError("accepted clone receipt schema/scope differs")
    unsigned = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if value["receipt_sha256"] != CATALOG._sha256_json(unsigned):
        raise PreflightError("accepted clone receipt content hash differs")
    created = CATALOG._utc(value["created_at_utc"], "accepted clone receipt time")
    if not CATALOG._utc(inputs.manifest["created_at_utc"], "backup time") <= created <= datetime.now(UTC) or datetime.now(UTC) - created > CATALOG.MAXIMUM_EVIDENCE_AGE:
        raise PreflightError("accepted clone receipt is not fresh and backup-bound")
    expected_backup = {"sha256": inputs.manifest["sha256"], "manifest_sha256": inputs.manifest_sha256, "recovery_receipt_sha256": inputs.recovery_sha256, "legacy_inspection_receipt_sha256": inputs.inspection_sha256, "legacy_inspection_signature_sha256": inputs.inspection_signature_sha256, "expectation_sha256": inputs.expectation_sha256, "legacy_schema_fingerprint_sha256": CATALOG.EXPECTED_LEGACY_FINGERPRINT, "bytes": inputs.manifest["bytes"]}
    expected_runner = {"persistence_repository": CATALOG.EXPECTED_PERSISTENCE_REPOSITORY, "persistence_revision": CATALOG.EXPECTED_PERSISTENCE_REVISION, "image_digest": CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, "repository_module_sha256": CATALOG.EXPECTED_PERSISTENCE_REPOSITORY_SHA256, "exact_runtime_profile": list(CATALOG.TARGET_MIGRATIONS), "excluded_simulator_migration": "017_simulator_journal.sql"}
    if value["source_backup"] != expected_backup or value["migration_runner"] != expected_runner:
        raise PreflightError("accepted clone receipt binds different evidence/source bytes")
    if value["original_migration"] != {"authorized": False, "original_quarantine_authorized": False, "required_next_gate": "SEPARATE_TARGET_ROLE_AND_PRIMARY_MIGRATION_REVIEW"} or value["readiness"] != {"paper_qualified": False, "alpha_ready": False, "live_ready": False, "strategy_policy": "REJECT_ALL"}:
        raise PreflightError("accepted clone receipt changed its authorization boundary")
    clone = value["clone"]
    if clone.get("network_mode") != "none" or any(clone.get(key) is not False for key in ("original_runtime_contacted", "redis_contacted", "publisher_contacted", "simulator_relations_present")) or type(clone.get("forbidden_network_calls")) is not int or clone["forbidden_network_calls"] != 0:
        raise PreflightError("accepted clone isolation proof differs")
    if value["restore_drill"].get("passed") is not True or SHA256.fullmatch(str(clone.get("first_runtime_schema_fingerprint_sha256"))) is None or clone.get("first_runtime_schema_fingerprint_sha256") != clone.get("second_runtime_schema_fingerprint_sha256") or value["restore_drill"].get("schema_fingerprint_sha256") != clone.get("first_runtime_schema_fingerprint_sha256"):
        raise PreflightError("accepted clone lacks identical runtime/restore schemas")
    CATALOG._verify_worker_result(value["quarantine"], inputs)
    return _sha(path)


def _worker_config(mode: str, database: str) -> dict[str, Any]:
    return {"mode": mode, "physical_database": database, "tables": list(TABLES), "legacy": list(CATALOG.LEGACY_MIGRATIONS), "inventory_sql": CATALOG.LEGACY_INVENTORY_QUERY, "legacy_fingerprint": CATALOG.EXPECTED_LEGACY_FINGERPRINT, "package": list(CATALOG.ALL_PACKAGE_MIGRATIONS), "migration_hashes": CATALOG.MIGRATION_SHA256, "repository_sha256": CATALOG.EXPECTED_PERSISTENCE_REPOSITORY_SHA256, "worker_sha256": _sha(WORKER_PATH)}


def _validate_snapshot(value: Any, *, primary: bool) -> dict[str, Any]:
    required = {"history", "target_role", "other_application_clients", "schema_version", "kind", "primary_mutations", "forbidden_network_calls", "loopback_database_connections"}
    if not isinstance(value, dict) or set(value) != required or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["kind"] != "kairos.paper-readonly-snapshot.v1" or any(type(value[key]) is not int or value[key] != 0 for key in ("primary_mutations", "forbidden_network_calls", "other_application_clients")) or type(value["loopback_database_connections"]) is not int or not 1 <= value["loopback_database_connections"] <= 2:
        raise PreflightError("read-only worker result has an unexpected shape")
    history = value["history"]
    if not isinstance(history, dict) or set(history) != {"database", "migrations", "schema_fingerprint_sha256", "tables", "public_sequences", "public_execution_events_max_sequence"} or history["database"] != SOURCE_DATABASE or history["migrations"] != list(CATALOG.LEGACY_MIGRATIONS) or history["schema_fingerprint_sha256"] != CATALOG.EXPECTED_LEGACY_FINGERPRINT or not isinstance(history["tables"], dict) or set(history["tables"]) != set(TABLES):
        raise PreflightError("full-history source topology differs")
    for fact in history["tables"].values():
        if not isinstance(fact, dict) or set(fact) != {"count", "row_digest_sha256"} or type(fact["count"]) is not int or fact["count"] < 0 or SHA256.fullmatch(str(fact["row_digest_sha256"])) is None:
            raise PreflightError("full-history table digest is malformed")
    if type(history["public_execution_events_max_sequence"]) is not int or history["public_execution_events_max_sequence"] < 0 or not isinstance(history["public_sequences"], dict):
        raise PreflightError("full-history sequence inventory is malformed")
    for name, state in history["public_sequences"].items():
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", name) is None or not isinstance(state, dict) or set(state) != {"last_value", "is_called"} or type(state["last_value"]) is not int or type(state["is_called"]) is not bool:
            raise PreflightError("full-history sequence state is malformed")
    role = value["target_role"]
    if not primary:
        if role is not None:
            raise PreflightError("clone role cannot qualify primary DDL")
    else:
        if not isinstance(role, dict) or set(role) != {"superuser", "bypass_rls", "schema_usage", "schema_create", "uuid_execute", "role", "session_role", "table_capabilities", "sufficient_for_reviewed_next_step", "actual_ddl_executed"} or role["role"] != "kairos" or role["session_role"] != "kairos" or role["actual_ddl_executed"] is not False or role["sufficient_for_reviewed_next_step"] is not True or any(type(role[key]) is not bool for key in ("superuser", "bypass_rls", "schema_usage", "schema_create", "uuid_execute")) or not isinstance(role["table_capabilities"], dict) or set(role["table_capabilities"]) != set(TABLES):
            raise PreflightError("actual primary role proof differs")
        for facts in role["table_capabilities"].values():
            if not isinstance(facts, dict) or set(facts) != {"readable", "updatable", "owner_capable", "row_security"} or any(type(fact) is not bool for fact in facts.values()):
                raise PreflightError("role capability proof is malformed")
        if any(role[key] is not True for key in ("schema_usage", "schema_create", "uuid_execute")) or any(facts["readable"] is not True or facts["updatable"] is not True or facts["row_security"] is not False for facts in role["table_capabilities"].values()) or any(role["table_capabilities"][name]["owner_capable"] is not True for name in ("message_outbox", "source_usage_reservations", "schema_migrations")):
            raise PreflightError("role proof contradicts the required capabilities")
    return value


def _snapshot(container: str, database: str, *, primary: bool) -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:12]
    arguments = ["run", "--rm", "--interactive", "--name", "kairos-paper-snapshot-worker-" + suffix, "--network", "container:" + container, "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user=10001:10001", "--memory=512m", "--cpus=1", "--pids-limit=64", "--label", "com.kairos.scope=" + SCOPE, "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "--env", "PYTHONDONTWRITEBYTECODE=1", "--mount", "type=bind,src=" + str(WORKER_PATH.resolve(strict=True)) + ",dst=/work/snapshot.py,readonly"]
    if primary:
        if container != SOURCE_CONTAINER or database != SOURCE_DATABASE or not SOURCE_SECRET.is_file() or SOURCE_SECRET.resolve(strict=True) != SOURCE_SECRET.absolute():
            raise PreflightError("fixed PAPER secret/container target differs")
        arguments += ["--mount", "type=bind,src=" + str(SOURCE_SECRET.resolve(strict=True)) + ",dst=/run/secrets/persistence_database_url,readonly"]
    elif re.fullmatch(r"kairos-paper-snapshot-clone-[0-9a-f]{12}", container) is None or database != "kairos_paper_snapshot_" + container.rsplit("-", 1)[1]:
        raise PreflightError("snapshot clone namespace differs")
    arguments += ["--entrypoint", "python", CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, "/work/snapshot.py"]
    try:
        value = json.loads(_docker(arguments, data=json.dumps(_worker_config("primary" if primary else "clone", database)) + "\n"))
    except json.JSONDecodeError:
        raise PreflightError("worker did not return one redacted JSON result") from None
    return _validate_snapshot(value, primary=primary)


def _cleanup_clone(container: str, suffix: str) -> None:
    text = _docker(["inspect", container], missing_ok=True)
    if not text:
        return
    value = json.loads(text)[0]
    labels = value.get("Config", {}).get("Labels", {}) or {}
    if container != "kairos-paper-snapshot-clone-" + suffix or value.get("Name") != "/" + container or labels.get("com.kairos.scope") != SCOPE or labels.get("com.kairos.drill") != suffix or value.get("HostConfig", {}).get("NetworkMode") != "none" or value.get("Mounts"):
        raise PreflightError("refused cleanup outside the exact disposable clone identity")
    _docker(["rm", "--force", container])


def _restore_snapshot(inputs: Any) -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:12]
    container = "kairos-paper-snapshot-clone-" + suffix
    database = "kairos_paper_snapshot_" + suffix
    user = "kairos_paper_snapshot"
    try:
        _docker(["create", "--name", container, "--network=none", "--memory=1536m", "--cpus=1", "--pids-limit=256", "--label", "com.kairos.scope=" + SCOPE, "--label", "com.kairos.drill=" + suffix, "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=1g", "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--env", "POSTGRES_USER=" + user, "--env", "POSTGRES_DB=" + database, "--env", "POSTGRES_HOST_AUTH_METHOD=trust", CATALOG.EXPECTED_TIMESCALE_IMAGE])
        _docker(["start", container])
        deadline = time.monotonic() + 60
        ready = 0
        while time.monotonic() < deadline and ready < 3:
            result = subprocess.run(["docker", "exec", container, "psql", "--host=127.0.0.1", "--username=" + user, "--dbname=" + database, "--quiet", "--tuples-only", "--no-align", "--command=SELECT current_database();"], capture_output=True, text=True, shell=False, timeout=5)
            ready = ready + 1 if result.returncode == 0 and result.stdout.strip() == database else 0
            time.sleep(0.5)
        if ready < 3:
            raise PreflightError("disposable clone final TCP database did not become ready")
        CATALOG._ensure_timescaledb_job_owners(container, user, inputs.manifest["timescaledb_bgw_owners"])
        def clone_sql(sql: str) -> None:
            _docker(["exec", container, "psql", "--username=" + user, "--dbname=" + database, "--set=ON_ERROR_STOP=1", "--command=" + sql])
        clone_sql("CREATE EXTENSION IF NOT EXISTS timescaledb; SELECT timescaledb_pre_restore();")
        with inputs.dump_path.open("rb") as stream:
            result = subprocess.run(["docker", "exec", "--interactive", container, "pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "--username=" + user, "--dbname=" + database], stdin=stream, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, shell=False, timeout=300)
        if result.returncode:
            raise PreflightError("bounded disposable clone restore failed; raw output withheld")
        clone_sql("SELECT timescaledb_post_restore();")
        return _snapshot(container, database, primary=False)
    finally:
        _cleanup_clone(container, suffix)


def _checkpoints(snapshot: dict[str, Any], manifest: Any) -> None:
    history = snapshot["history"]
    for table in CATALOG.CHECKPOINT_TABLES:
        if history["tables"][table]["count"] != manifest["checkpoints"][table]:
            raise PreflightError("full-history count differs from the fresh backup")
    if history["public_execution_events_max_sequence"] != manifest["checkpoints"]["public_execution_events_max_sequence"]:
        raise PreflightError("public event sequence differs from the fresh backup")


def _bounded_archive(manifest_path: Path) -> None:
    # Reject oversized input before the reviewed reader copies evidence; its
    # subsequent hash/schema/signature checks remain mandatory and unchanged.
    manifest_path = CATALOG._ensure_below(manifest_path, CATALOG.BACKUP_ROOT, "backup manifest")
    value = CATALOG._read_json(manifest_path, "backup manifest")
    if type(value.get("bytes")) is not int or not 0 < value["bytes"] <= MAX_DUMP_BYTES or re.fullmatch(r"kairos-paper-gate-[0-9]{8}T[0-9]{6}Z\.dump", str(value.get("file"))) is None:
        raise PreflightError("backup input is outside the fixed archive bound")
    archive = (manifest_path.parent / value["file"]).resolve(strict=True)
    if archive.parent != manifest_path.parent or not archive.is_file() or archive.stat().st_size != value["bytes"]:
        raise PreflightError("bounded backup archive identity differs")


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.confirmation != CONFIRMATION:
        raise PreflightError("literal read-only confirmation is required")
    _bounded_archive(Path(args.manifest_path))
    code = _code_identity()
    # Reuse only the existing reviewed evidence reader; never invoke its clone
    # migration/quarantine runner. Its internal literal is not apply authority.
    evidence_args = argparse.Namespace(**vars(args))
    evidence_args.confirmation = "CLONE_ONLY_LEGACY_OUTBOX_QUARANTINE_REHEARSAL"
    inputs = CATALOG._verify_inputs(evidence_args)
    try:
        if inputs.manifest["bytes"] > MAX_DUMP_BYTES:
            raise PreflightError("fresh backup exceeds the fixed 256 MiB archive bound")
        accepted = CATALOG._snapshot_file(Path(args.clone_receipt_path), inputs.staging_directory / "accepted-clone.json", "accepted clone receipt")
        signature = CATALOG._snapshot_file(Path(args.clone_signature_path), inputs.staging_directory / "accepted-clone.json.asc", "accepted clone signature")
        accepted_hash = _verify_clone_receipt(accepted, signature, inputs)
        _runner_identity()
        source = _source_identity()
        before = _snapshot(SOURCE_CONTAINER, SOURCE_DATABASE, primary=True)
        _checkpoints(before, inputs.manifest)
        restored = _restore_snapshot(inputs)
        _checkpoints(restored, inputs.manifest)
        if before["history"] != restored["history"]:
            raise PreflightError("restored fresh backup does not preserve every historical row/sequence")
        if _source_identity() != source or _snapshot(SOURCE_CONTAINER, SOURCE_DATABASE, primary=True) != before or _sha(inputs.dump_path) != inputs.manifest["sha256"] or _code_identity() != code:
            raise PreflightError("source/history/evidence/code changed during read-only proof")
        return {"schema_version": 1, "classification": "PAPER_RUNTIME_READONLY_TARGET_ROLE_AND_RESTORE_BINDING", "result": "PASS_READ_ONLY_PRIMARY_AND_CLONE", "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), **code, "source_identity": source, "source_backup_sha256": inputs.manifest["sha256"], "source_manifest_sha256": inputs.manifest_sha256, "accepted_clone_receipt_sha256": accepted_hash, "accepted_clone_signature_sha256": _sha(signature), "immutable_runner": CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, "source_snapshot": before, "restored_snapshot": restored, "primary_mutations": 0, "primary_apply_implemented": False, "consumers_started": 0, "publisher_calls": 0, "redis_contacted": False, "required_next_gate": "SEPARATE_ATOMIC_PRIMARY_RUNTIME_AND_ONE_ROW_QUARANTINE_PROOF_REVIEW", "consumer_restart_permitted": False, "readiness": {"paper_qualified": False, "alpha_ready": False, "live_ready": False, "strategy_policy": "REJECT_ALL"}}
    finally:
        CATALOG._cleanup_evidence_stage(inputs.staging_directory)


def _write_receipt(value: dict[str, Any], manifest: Path, requested: str | None) -> Path:
    directory = CATALOG._ensure_below(manifest.resolve(strict=True).parent, CATALOG.BACKUP_ROOT, "read-only receipt directory")
    output = Path(requested).absolute() if requested else directory / ("paper-runtime-readonly-preflight-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + ".json")
    if output.parent.resolve(strict=True) != directory or re.fullmatch(r"paper-runtime-readonly-preflight-[0-9]{8}T[0-9]{6}Z\.json", output.name) is None or output.exists() or output.with_suffix(".json.asc").exists():
        raise PreflightError("read-only receipt must be new and beside the protected backup")
    signature = output.with_suffix(".json.asc")
    value = dict(value)
    value["receipt_sha256"] = CATALOG._sha256_json(value)
    content = (CATALOG._canonical_json(value) + "\n").encode("utf-8")
    created: list[tuple[Path, str]] = []
    with tempfile.TemporaryDirectory(prefix=".paper-readonly-sign-", dir=directory) as temporary:
        staged = Path(temporary) / "receipt.json"
        staged.write_bytes(content)
        armored = CATALOG._detached_signature(staged)
        try:
            for path, data in ((output, content), (signature, armored)):
                CATALOG._write_new_file(path, data, "read-only receipt artifact")
                created.append((path, hashlib.sha256(data).hexdigest()))
            CATALOG._verify_signature(output, signature)
        except BaseException:
            for path, expected in reversed(created):
                if path.is_file() and not path.is_symlink() and _sha(path) == expected:
                    path.unlink()
            raise
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest-path", "recovery-receipt-path", "legacy-inspection-receipt-path", "legacy-inspection-signature-path", "expectation-path", "clone-receipt-path", "clone-signature-path", "confirmation"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--receipt-path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = run(args)
        output = _write_receipt(receipt, Path(args.manifest_path), args.receipt_path)
    except Exception as exc:
        print("PAPER read-only preflight rejected: " + type(exc).__name__ + "; no primary apply command exists; raw details withheld", file=sys.stderr)
        return 2
    print(json.dumps({"result": receipt["result"], "primary_mutations": 0, "receipt_path": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
