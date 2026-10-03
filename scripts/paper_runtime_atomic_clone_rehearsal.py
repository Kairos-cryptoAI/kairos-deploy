"""Offline admission plus explicit, bounded native clone-only atomic proof.

Native execution requires separate review/authorization. There is no primary
write path. Offline model receipts are never PostgreSQL rollback proof.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import paper_runtime_atomic_contract as contract


CONFIRMATION = "CLONE_ONLY_ATOMIC_RUNTIME17_AND_EXACT_ROW_PROOF"
FAULTS = (*("after_migration_" + name[:3] for name in contract.CATALOG.RUNTIME_SUFFIX), "after_migrations", "after_quarantine", "before_commit")
SCOPE = "paper-runtime-atomic-clone-proof"
SCRIPTS = Path(__file__).resolve().parent
CODE_FILES = ("paper_runtime_atomic_contract.py", "paper_runtime_atomic_worker.py", "paper_runtime_history_stream.py", "paper_runtime_snapshot_worker.py", "paper_runtime_atomic_clone_rehearsal.py", "validate_paper_runtime_atomic_receipt.py")
MAX_SECONDS = 300


def prepare_plan(args: argparse.Namespace) -> contract.AtomicPlan:
    """Reuse old read-only evidence validation; never run its migration controller."""
    if args.confirmation != CONFIRMATION:
        raise contract.AtomicError("literal clone-only plan confirmation is required")
    reader_args = argparse.Namespace(**vars(args))
    reader_args.confirmation = "CLONE_ONLY_LEGACY_OUTBOX_QUARANTINE_REHEARSAL"
    inputs = contract.CATALOG._verify_inputs(reader_args)
    try:
        preflight = contract.CATALOG._snapshot_file(Path(args.preflight_receipt_path), inputs.staging_directory / "preflight.json", "native read-only receipt")
        signature = contract.CATALOG._snapshot_file(Path(args.preflight_signature_path), inputs.staging_directory / "preflight.json.asc", "native read-only signature")
        contract.CATALOG._verify_signature(preflight, signature)
        value = contract.verify_preflight(contract.read_json(preflight), now=datetime.now(UTC))
        clone = contract.CATALOG._snapshot_file(Path(args.clone_receipt_path), inputs.staging_directory / "clone.json", "accepted old clone receipt")
        clone_signature = contract.CATALOG._snapshot_file(Path(args.clone_signature_path), inputs.staging_directory / "clone.json.asc", "accepted old clone signature")
        clone_hash = contract.readonly._verify_clone_receipt(clone, clone_signature, inputs)
        expected_bindings = {"source_backup_sha256": inputs.manifest["sha256"], "source_manifest_sha256": inputs.manifest_sha256, "accepted_clone_receipt_sha256": clone_hash, "accepted_clone_signature_sha256": contract.readonly._sha(clone_signature)}
        if any(value[name] != expected for name, expected in expected_bindings.items()) or contract.utc(value["created_at_utc"]) < contract.utc(inputs.manifest["created_at_utc"]):
            raise contract.AtomicError("native preflight binds a different evidence chain")
        identity, reconciliation_id = contract.CATALOG._expectation_identity(inputs)
        clone_value = contract.read_json(clone)
        document = {"schema_version": 1, "kind": contract.PLAN_KIND, "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "preflight_created_at_utc": value["created_at_utc"], "preflight_sha256": contract.readonly._sha(preflight), "preflight_signature_sha256": contract.readonly._sha(signature), "source_identity": value["source_identity"], "backup_sha256": inputs.manifest["sha256"], "manifest_sha256": inputs.manifest_sha256, "accepted_clone_receipt_sha256": clone_hash, "identity": identity, "reconciliation_id": reconciliation_id, "lease_owner_sha256": inputs.lease_owner_sha256, "lease_until_utc": inputs.lease_until_utc, "reason": "legacy expired lease clone-only quarantine rehearsal", "legacy_history": value["source_snapshot"]["history"], "runtime_schema_fingerprint_sha256": clone_value["clone"]["first_runtime_schema_fingerprint_sha256"], "runner": contract.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, "persistence_revision": contract.CATALOG.EXPECTED_PERSISTENCE_REVISION, "repository_sha256": contract.CATALOG.EXPECTED_PERSISTENCE_REPOSITORY_SHA256, "database_module_sha256": contract.DATABASE_MODULE_SHA256, "profile": list(contract.RUNTIME_PROFILE), "primary_apply_implemented": False, "consumer_restart_permitted": False, "readiness": dict(contract.READINESS)}
        document.update(backup_created_at_utc=inputs.manifest["created_at_utc"], clone_created_at_utc=clone_value["created_at_utc"], inspection_created_at_utc=inputs.inspection["inspected_at_utc"], recovery_created_at_utc=contract.read_json(inputs.recovery_path)["created_at_utc"])
        return contract.AtomicPlan.from_document(document, now=datetime.now(UTC))
    except contract.AtomicError:
        raise
    except Exception:
        raise contract.AtomicError("offline evidence admission rejected") from None
    finally:
        contract.CATALOG._cleanup_evidence_stage(inputs.staging_directory)


async def run_offline_model(plan: contract.AtomicPlan, backend: Any) -> dict[str, Any]:
    """A fake-only driver contract; no arbitrary 'real proof' switch is accepted.

    backend.run_fault(name) must return the entire legacy snapshot after its
    acknowledged rollback. backend.run_success() returns worker result plus
    backup/restore histories. These are model assertions, not external evidence.
    """
    plan = contract.AtomicPlan.from_document(plan.document, now=datetime.now(UTC))
    if backend.evidence_mode != "offline-model":
        raise contract.AtomicError("real clone launcher is not implemented/reviewed")
    before = await backend.source_snapshot()
    if before != plan.document["legacy_history"]:
        raise contract.AtomicError("model source differs from accepted baseline")
    rollbacks = {}
    for fault in FAULTS:
        observed = await backend.run_fault(fault)
        contract.compare_history(before, observed)
        rollbacks[fault] = contract.digest(observed)
    result = await backend.run_success()
    required = {"worker", "restored_history", "backup_after_sha256", "unknown_after_commit", "unknown_after_rollback", "unknown_mixed", "forbidden_network_calls", "publisher_calls", "redis_contacted", "consumers_started"}
    if not isinstance(result, dict) or set(result) != required:
        raise contract.AtomicError("offline model result shape differs")
    worker = result["worker"]
    if not isinstance(worker, dict) or set(worker) != {"state", "intent", "history", "quarantine_calls", "bound_acquisitions", "primary_mutations", "consumer_restart_permitted"} or worker["state"] != "COMMITTED_ACKNOWLEDGED" or type(worker["quarantine_calls"]) is not int or worker["quarantine_calls"] != 1 or worker["bound_acquisitions"] != 2 or worker["primary_mutations"] != 0 or worker["consumer_restart_permitted"] is not False:
        raise contract.AtomicError("offline worker atomic assertion differs")
    contract.validate_history(worker["history"], runtime=True)
    if worker["history"] != result["restored_history"] or contract.classify_readonly_outcome(plan, worker["intent"], worker["history"]) != "COMMITTED_EXACT":
        raise contract.AtomicError("offline postcommit/restore binding differs")
    contract.require_hash(result["backup_after_sha256"])
    if result["unknown_after_commit"] != "COMMITTED_EXACT" or result["unknown_after_rollback"] != "ROLLED_BACK" or result["unknown_mixed"] != "INDETERMINATE":
        raise contract.AtomicError("offline unknown-outcome classification differs")
    if any(type(result[name]) is not int or result[name] != 0 for name in ("forbidden_network_calls", "publisher_calls", "consumers_started")) or result["redis_contacted"] is not False:
        raise contract.AtomicError("offline model crossed forbidden channel")
    if await backend.source_snapshot() != before:
        raise contract.AtomicError("source changed during offline model")
    receipt = {"schema_version": 1, "kind": contract.RECEIPT_KIND, "result": "PASS_OFFLINE_MODEL_ONLY", "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "evidence_mode": "offline-model", "plan_sha256": plan.sha256, "runner": plan.document["runner"], "profile": list(contract.RUNTIME_PROFILE), "source_before_sha256": contract.digest(before), "source_after_sha256": contract.digest(before), "rollback_snapshots": rollbacks, "worker": worker, "backup_after_sha256": result["backup_after_sha256"], "restored_history_sha256": contract.digest(result["restored_history"]), "unknown_outcomes": {"commit": result["unknown_after_commit"], "rollback": result["unknown_after_rollback"], "mixed": result["unknown_mixed"]}, "actual_postgres_rollback_proven": False, "primary_apply_implemented": False, "primary_quarantine_authorized": False, "primary_mutations": 0, "consumer_restart_permitted": False, "forbidden_network_calls": 0, "publisher_calls": 0, "redis_contacted": False, "consumers_started": 0, "readiness": dict(contract.READINESS), "required_next_gate": contract.NEXT_GATE}
    receipt["receipt_sha256"] = contract.digest(receipt)
    return receipt


class NativeCloneController:
    """One 3GiB DB and one512MiB worker at a time; total300s, no retries."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.deadline = time.monotonic() + MAX_SECONDS
        self.clones: dict[str, str] = {}
        self.workers: dict[str, str] = {}
        self.cleanup_deadline: float | None = None
        self.attempt_directory: Path | None = None
        self.phase = "OFFLINE_ADMISSION"
        self.observed: dict[str, Any] = {"legacy_clone_baseline_verified": False, "rollback_checkpoints": [], "commit_outcome": "NOT_OBSERVED", "runtime_restore_verified": False}

    def remaining(self) -> float:
        seconds = (self.cleanup_deadline or self.deadline) - time.monotonic()
        if seconds <= 0:
            raise contract.AtomicError("native clone total300s bound exhausted; no retry")
        return min(seconds, MAX_SECONDS)

    def docker(self, arguments: list[str], *, stdin: Any = None) -> str:
        result = subprocess.run(["docker", *arguments], stdin=stdin, capture_output=True, shell=False, timeout=self.remaining())
        if result.returncode or len(result.stdout) > 1024 * 1024:
            raise contract.AtomicError("bounded native Docker operation rejected; raw output withheld")
        return result.stdout.decode("utf-8", errors="strict").strip()

    def inspection(self, name: str) -> dict[str, Any]:
        # Do not read Config.Env (which may contain credential values).
        template = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"State":{{json .State}},"Labels":{{json .Config.Labels}},"Mounts":{{json .Mounts}},"Networks":{{json .NetworkSettings.Networks}},"NetworkMode":{{json .HostConfig.NetworkMode}},"Privileged":{{json .HostConfig.Privileged}},"PortBindings":{{json .HostConfig.PortBindings}},"Memory":{{json .HostConfig.Memory}},"NanoCpus":{{json .HostConfig.NanoCpus}}}'
        value = json.loads(self.docker(["inspect", "--format", template, name]))
        if not isinstance(value, dict):
            raise contract.AtomicError("container metadata shape differs")
        return value

    def stopped_source(self, plan: contract.AtomicPlan) -> dict[str, Any]:
        source = self.inspection(contract.readonly.SOURCE_CONTAINER)
        labels = source["Labels"] or {}
        state = source["State"]
        if source["Name"] != "/" + contract.readonly.SOURCE_CONTAINER or labels.get("com.docker.compose.project") != contract.readonly.SOURCE_PROJECT or labels.get("com.docker.compose.service") != "timescaledb" or state.get("Running") is not False or state.get("Paused") is not False or state.get("Restarting") is not False or state.get("Dead") is not False or state.get("Status") != "exited" or source["Privileged"] is not False or source["PortBindings"]:
            raise contract.AtomicError("fixed primary must remain STOPPED and unexposed")
        mounts = source["Mounts"]
        networks = source["Networks"]
        data_mounts = [item for item in mounts if item.get("Destination") == "/var/lib/postgresql/data"] if isinstance(mounts, list) else []
        if len(data_mounts) != 1 or data_mounts[0].get("Type") != "volume" or data_mounts[0].get("Name") != contract.readonly.SOURCE_VOLUME or data_mounts[0].get("RW") is not True or not isinstance(networks, dict) or set(networks) != {contract.readonly.SOURCE_NETWORK}:
            raise contract.AtomicError("fixed stopped primary volume/network differs")
        # Match the unchanged readonly._identity():107–114 policy exactly.
        # These existing read-only binds are inspected, never opened or mounted
        # into the clone worker; secret CONTENTS are not read by this controller.
        for item in mounts:
            if item in data_mounts:
                continue
            if item.get("Destination") not in {"/docker-entrypoint-initdb.d/001-kairos.sql", "/run/secrets/paper_postgres_password"} or item.get("Type") != "bind" or item.get("RW") is not False:
                raise contract.AtomicError("unexpected stopped primary database mount")
        identity = {"compose_project": contract.readonly.SOURCE_PROJECT, "container_id": source["Id"], "database": contract.readonly.SOURCE_DATABASE, "image_id": source["Image"], "network": contract.readonly.SOURCE_NETWORK, "network_id": networks[contract.readonly.SOURCE_NETWORK].get("NetworkID"), "volume": data_mounts[0]["Name"]}
        if identity != plan.document["source_identity"]:
            raise contract.AtomicError("stopped primary differs from accepted signed source")
        for identifier in self.docker(["ps", "--quiet"]).splitlines():
            running = self.inspection(identifier)
            if (running["Labels"] or {}).get("com.docker.compose.project") == contract.readonly.SOURCE_PROJECT or contract.readonly.SOURCE_NETWORK in (running["Networks"] or {}) or any(item.get("Name") == contract.readonly.SOURCE_VOLUME for item in running["Mounts"] or []):
                raise contract.AtomicError("a running container touches protected PAPER source")
        volume_template = '{"Name":{{json .Name}},"Driver":{{json .Driver}},"CreatedAt":{{json .CreatedAt}},"Labels":{{json .Labels}},"Scope":{{json .Scope}}}'
        volume = json.loads(self.docker(["volume", "inspect", "--format", volume_template, contract.readonly.SOURCE_VOLUME]))
        return {"identity": identity, "state": {key: state.get(key) for key in ("Status", "Running", "Paused", "Restarting", "Dead", "StartedAt", "FinishedAt", "ExitCode")}, "volume": {key: volume.get(key) for key in ("Name", "Driver", "CreatedAt", "Labels", "Scope")}}

    def create_clone(self, dump: Path, inputs: Any) -> tuple[str, str]:
        suffix = uuid.uuid4().hex[:12]
        container = "kairos-paper-atomic-clone-" + suffix
        database = "kairos_paper_atomic_" + suffix
        self.clones[container] = suffix
        self.docker(["create", "--pull=never", "--name", container, "--network=none", "--memory=3g", "--cpus=1", "--pids-limit=256", "--label", "com.kairos.scope=" + SCOPE, "--label", "com.kairos.drill=" + suffix, "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=2g", "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--env", "POSTGRES_USER=kairos", "--env", "POSTGRES_DB=" + database, "--env", "POSTGRES_HOST_AUTH_METHOD=trust", contract.CATALOG.EXPECTED_TIMESCALE_IMAGE, "postgres", "-c", "shared_buffers=64MB", "-c", "work_mem=4MB", "-c", "max_connections=20", "-c", "max_worker_processes=8", "-c", "timescaledb.max_background_workers=4"])
        self.docker(["start", container])
        ready = 0
        while ready < 3:
            self.remaining()
            result = subprocess.run(["docker", "exec", container, "psql", "--host=127.0.0.1", "--username=kairos", "--dbname=" + database, "--quiet", "--tuples-only", "--no-align", "--command=SELECT current_database();"], capture_output=True, shell=False, timeout=min(5, self.remaining()))
            ready = ready + 1 if result.returncode == 0 and result.stdout.strip() == database.encode() else 0
            time.sleep(0.5)
        # Same validated Timescale restore ownership procedure as old controller.
        for owner in inputs.manifest["timescaledb_bgw_owners"]:
            if owner != "kairos":
                raise contract.AtomicError("native target role must match accepted owner exactly")
        self.sql(container, database, "CREATE EXTENSION IF NOT EXISTS timescaledb; SELECT timescaledb_pre_restore();")
        with dump.open("rb") as stream:
            self.docker(["exec", "--interactive", container, "pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "--username=kairos", "--dbname=" + database], stdin=stream)
        self.sql(container, database, "SELECT timescaledb_post_restore();")
        return container, database

    def sql(self, container: str, database: str, query: str) -> None:
        if container not in self.clones or contract.CLONE_DATABASE.fullmatch(database) is None:
            raise contract.AtomicError("SQL operation target is not controller-owned clone")
        self.docker(["exec", container, "psql", "--username=kairos", "--dbname=" + database, "--set=ON_ERROR_STOP=1", "--command=" + query])

    def remove_clone(self, container: str) -> None:
        suffix = self.clones.get(container)
        if not self.docker(["ps", "--all", "--quiet", "--filter", "name=^/" + container + "$"]):
            self.clones.pop(container, None)
            return
        value = self.inspection(container)
        labels = value["Labels"] or {}
        if suffix is None or container != "kairos-paper-atomic-clone-" + suffix or value["Name"] != "/" + container or labels.get("com.kairos.scope") != SCOPE or labels.get("com.kairos.drill") != suffix or value["NetworkMode"] != "none" or value["Mounts"] or value["Privileged"] is not False or value["PortBindings"] or value["Memory"] != 3 * 1024**3 or value["NanoCpus"] != 1_000_000_000:
            raise contract.AtomicError("refused cleanup outside exact bounded atomic clone")
        self.docker(["rm", "--force", container])
        del self.clones[container]

    def remove_workers(self) -> None:
        for name, clone in list(self.workers.items()):
            if not self.docker(["ps", "--all", "--quiet", "--filter", "name=^/" + name + "$"]):
                del self.workers[name]
                continue
            value = self.inspection(name)
            labels = value["Labels"] or {}
            clone_identity = self.inspection(clone)
            if value["Name"] != "/" + name or labels.get("com.kairos.scope") != SCOPE or labels.get("com.kairos.drill") != self.clones.get(clone) or value["NetworkMode"] != "container:" + clone_identity["Id"] or value["Privileged"] is not False or value["PortBindings"] or value["Memory"] != 512 * 1024**2 or value["NanoCpus"] != 1_000_000_000:
                raise contract.AtomicError("refused worker cleanup outside exact owned clone scope")
            self.docker(["rm", "--force", name])
            del self.workers[name]

    def worker(self, container: str, database: str, plan_path: Path, intents: Path, *, fault: str | None = None) -> dict[str, Any]:
        if container not in self.clones or contract.CLONE_DATABASE.fullmatch(database) is None:
            raise contract.AtomicError("worker target is not controller-owned clone")
        name = "kairos-paper-atomic-worker-" + uuid.uuid4().hex[:12]
        self.workers[name] = container
        arguments = ["run", "--pull=never", "--rm", "--name", name, "--label", "com.kairos.scope=" + SCOPE, "--label", "com.kairos.drill=" + self.clones[container], "--network", "container:" + container, "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user=" + contract.CATALOG.EXPECTED_RUNNER_USER, "--memory=512m", "--cpus=1", "--pids-limit=64", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "--env", "PYTHONDONTWRITEBYTECODE=1", "--mount", "type=bind,src=" + str(SCRIPTS.resolve(strict=True)) + ",dst=/deploy/scripts,readonly", "--mount", "type=bind,src=" + str(plan_path.resolve(strict=True)) + ",dst=/plan.json,readonly", "--mount", "type=bind,src=" + str(intents.resolve(strict=True)) + ",dst=/evidence", "--entrypoint", "python", contract.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, "/deploy/scripts/paper_runtime_atomic_worker.py", "--plan=/plan.json", "--database=" + database]
        arguments.append("--fault=" + fault if fault else "--snapshot")
        result = json.loads(self.docker(arguments))
        del self.workers[name]
        if not isinstance(result, dict) or result.get("primary_mutations") != 0 or result.get("forbidden_network_calls") != 0:
            raise contract.AtomicError("native worker boundary/result differs")
        return result

    def failure_receipt(self, error: BaseException) -> Path | None:
        """Retain ALL host plan/intent/partial dump artifacts on every native failure."""
        if self.attempt_directory is None:
            return None
        value = {"schema_version": 1, "kind": "kairos.paper-runtime-atomic-clone-failure.v1", "result": "FAILED_NATIVE_CLONE_NO_AUTHORIZATION", "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "phase": self.phase, "error_type": type(error).__name__, "observed": self.observed, "retained_attempt_directory": str(self.attempt_directory), "artifacts": sorted(item.name for item in self.attempt_directory.iterdir()), "primary_apply_implemented": False, "primary_quarantine_authorized": False, "primary_mutations": 0, "consumer_restart_permitted": False, "primary_history_observed_during_rehearsal": False, "readiness": dict(contract.READINESS)}
        value["receipt_sha256"] = contract.digest(value)
        output = self.attempt_directory / ("failure-" + uuid.uuid4().hex[:12] + ".json")
        with output.open("xb") as stream:
            stream.write(contract.canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({"result": value["result"], "failure_receipt": str(output), "retained_attempt_directory": str(self.attempt_directory), "phase": self.phase, "primary_mutations": 0}), file=sys.stderr, flush=True)
        return output

    def run(self) -> tuple[dict[str, Any], Path]:
        plan = prepare_plan(self.args)
        contract.readonly._bounded_archive(Path(self.args.manifest_path))
        runner = json.loads(self.docker(["image", "inspect", "--format", '{"RepoDigests":{{json .RepoDigests}},"User":{{json .Config.User}},"Labels":{{json .Config.Labels}}}', contract.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE]))
        labels = runner["Labels"] or {}
        if contract.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE not in runner["RepoDigests"] or runner["User"] != contract.CATALOG.EXPECTED_RUNNER_USER or labels.get("org.opencontainers.image.source") != contract.CATALOG.EXPECTED_PERSISTENCE_REPOSITORY or labels.get("org.opencontainers.image.revision") != contract.CATALOG.EXPECTED_PERSISTENCE_REVISION:
            raise contract.AtomicError("accepted exact OCI runner provenance differs")
        reader_args = argparse.Namespace(**vars(self.args))
        reader_args.confirmation = "CLONE_ONLY_LEGACY_OUTBOX_QUARANTINE_REHEARSAL"
        inputs = contract.CATALOG._verify_inputs(reader_args)
        output: Path | None = None
        try:
            if inputs.manifest["sha256"] != plan.document["backup_sha256"] or inputs.manifest_sha256 != plan.document["manifest_sha256"]:
                raise contract.AtomicError("native admission backup changed")
            code = {name: contract.readonly._sha(SCRIPTS / name) for name in CODE_FILES}
            source = self.stopped_source(plan)
            root = contract.CATALOG.BACKUP_ROOT.resolve(strict=True)
            self.attempt_directory = root / ("paper-runtime-atomic-attempt-" + uuid.uuid4().hex[:12])
            self.attempt_directory.mkdir(mode=0o700)
            plan_path = self.attempt_directory / "atomic-plan.json"
            with plan_path.open("xb") as stream:
                stream.write(plan.serialized)
                stream.flush()
                os.fsync(stream.fileno())
            intents = self.attempt_directory / "atomic-intents"
            intents.mkdir(mode=0o700)
            # Permanent private parent: not a temporary stage and NEVER removed.
            # Only the child is RW-mounted; host-backed fsync is not power-loss proof.
            os.chmod(intents, 0o777)
            self.phase = "CREATE_LEGACY_CLONE"
            first, database = self.create_clone(inputs.dump_path, inputs)
            initial = self.worker(first, database, plan_path, intents)
            contract.compare_history(plan.document["legacy_history"], initial["history"])
            self.observed["legacy_clone_baseline_verified"] = True
            rollbacks = {}
            for fault in FAULTS:
                self.phase = fault
                print(json.dumps({"phase": fault, "primary_mutations": 0}), file=sys.stderr, flush=True)
                result = self.worker(first, database, plan_path, intents, fault=fault)
                if result.get("state") != "ROLLBACK_ACKNOWLEDGED" or result.get("fault") != fault:
                    raise contract.AtomicError("native fault did not prove an acknowledged rollback")
                contract.compare_history(plan.document["legacy_history"], result["history"])
                rollbacks[fault] = contract.digest(result["history"])
                self.observed["rollback_checkpoints"].append(fault)
            self.phase = "LOST_COMMIT_RESPONSE_AND_READONLY_INSPECTION"
            success = self.worker(first, database, plan_path, intents, fault="after_commit_response_loss")
            if success.get("state") != "COMMITTED_EXACT_READONLY":
                raise contract.AtomicError("native commit response-loss inspection did not resolve exactly")
            contract.validate_history(success["history"], runtime=True)
            if contract.classify_readonly_outcome(plan, success["intent"], success["history"]) != "COMMITTED_EXACT":
                raise contract.AtomicError("native committed intent/history binding differs")
            self.observed["commit_outcome"] = "COMMITTED_EXACT"
            if contract.classify_readonly_outcome(plan, success["intent"], result["history"]) != "ROLLED_BACK":
                raise contract.AtomicError("native rollback baseline did not classify exactly")
            mixed = json.loads(contract.canonical(success["history"]))
            mixed["tables"]["message_outbox"]["row_digest_sha256"] = "0" * 64
            if contract.classify_readonly_outcome(plan, success["intent"], mixed) != "INDETERMINATE":
                raise contract.AtomicError("mixed-metadata classifier negative case failed")
            self.phase = "POSTCOMMIT_DUMP"
            self.docker(["exec", first, "pg_dump", "--username=kairos", "--dbname=" + database, "--format=custom", "--no-owner", "--no-privileges", "--file=/tmp/atomic-after.dump"])
            after_dump = self.attempt_directory / "atomic-after.dump"
            self.docker(["cp", first + ":/tmp/atomic-after.dump", str(after_dump)])
            if after_dump.stat().st_size > contract.readonly.MAX_DUMP_BYTES:
                raise contract.AtomicError("postcommit archive exceeded fixed bound")
            after_dump_hash = contract.readonly._sha(after_dump)
            self.remove_clone(first)
            self.phase = "RUNTIME17_SECOND_RESTORE"
            second, second_database = self.create_clone(after_dump, inputs)
            restored = self.worker(second, second_database, plan_path, intents)
            if restored["history"] != success["history"]:
                raise contract.AtomicError("runtime17 clone restore did not preserve all35 tables/sequence states")
            self.remove_clone(second)
            self.observed["runtime_restore_verified"] = True
            self.phase = "FINAL_STOPPED_SOURCE_CODE_FRESHNESS_CHECK"
            if self.stopped_source(plan) != source or any(contract.readonly._sha(SCRIPTS / name) != value for name, value in code.items()) or contract.readonly._sha(inputs.dump_path) != inputs.manifest["sha256"]:
                raise contract.AtomicError("stopped source/code/archive changed during native proof")
            contract.AtomicPlan.from_document(plan.document, now=datetime.now(UTC))
            baseline = contract.digest(plan.document["legacy_history"])
            worker_record = {name: success[name] for name in ("state", "intent", "history", "quarantine_calls", "bound_acquisitions", "primary_mutations", "consumer_restart_permitted")}
            receipt = {"schema_version": 1, "kind": contract.RECEIPT_KIND, "result": "PASS_NATIVE_ATOMIC_CLONE_ONLY", "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "evidence_mode": "native-postgresql-clone", "plan_sha256": plan.sha256, "runner": plan.document["runner"], "profile": list(contract.RUNTIME_PROFILE), "source_before_sha256": baseline, "source_after_sha256": baseline, "rollback_snapshots": rollbacks, "worker": worker_record, "backup_after_sha256": after_dump_hash, "restored_history_sha256": contract.digest(restored["history"]), "unknown_outcomes": {"commit": "COMMITTED_EXACT", "rollback": "ROLLED_BACK", "mixed": "INDETERMINATE"}, "actual_postgres_rollback_proven": True, "primary_apply_implemented": False, "primary_quarantine_authorized": False, "primary_mutations": 0, "consumer_restart_permitted": False, "forbidden_network_calls": 0, "publisher_calls": 0, "redis_contacted": False, "consumers_started": 0, "readiness": dict(contract.READINESS), "required_next_gate": contract.NEXT_GATE, "primary_history_observed_during_rehearsal": False, "stopped_primary_before": source, "stopped_primary_after": source, "code_sha256": code, "resource_bounds": {"database_memory_bytes": 3 * 1024**3, "database_tmpfs_bytes": 2 * 1024**3, "database_cpus": 1, "worker_memory_bytes": 512 * 1024**2, "maximum_seconds": MAX_SECONDS, "maximum_parallel_databases": 1}, "preflight_sha256": plan.document["preflight_sha256"], "unknown_outcome_proof": {"commit": "native injected lost response after COMMIT; fresh read-only connection", "rollback": "native fault rollback full baseline; read-only classifier", "mixed": "offline metadata-only negative classifier; no mixed DB mutation"}}
            receipt["retained_attempt_directory"] = str(self.attempt_directory)
            receipt["receipt_sha256"] = contract.digest(receipt)
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            output = inputs.receipt_directory / ("paper-runtime-atomic-clone-proof-" + stamp + ".json")
            if output.exists() or output.with_suffix(".json.asc").exists():
                raise contract.AtomicError("native receipt output already exists")
            # Preserve exact plan/intent bindings for independent offline review.
            def preserve_file(source_path: Path, target_path: Path) -> None:
                if target_path.exists() or target_path.is_symlink():
                    raise contract.AtomicError("native evidence output already exists")
                with source_path.open("rb") as source_stream, target_path.open("xb") as target_stream:
                    shutil.copyfileobj(source_stream, target_stream)
                    target_stream.flush()
                    os.fsync(target_stream.fileno())
                if contract.readonly._sha(source_path) != contract.readonly._sha(target_path):
                    raise contract.AtomicError("native evidence copy hash differs")
            preserve_file(plan_path, output.with_suffix(".plan.json"))
            preserve_file(after_dump, output.with_suffix(".after.dump"))
            for item in intents.iterdir():
                if not item.is_file() or item.is_symlink() or not re.fullmatch(r"atomic-precommit-[0-9a-f]{64}\.json", item.name):
                    raise contract.AtomicError("native precommit artifact identity differs")
                target = inputs.receipt_directory / (stamp + "-" + item.name)
                preserve_file(item, target)
            with output.open("xb") as stream:
                stream.write(contract.canonical(receipt))
                stream.flush()
                os.fsync(stream.fileno())
            return receipt, output
        except BaseException as error:
            self.failure_receipt(error)
            raise
        finally:
            # Cleanup never broadens to another agent's namespace or volumes.
            self.cleanup_deadline = time.monotonic() + 10
            try:
                self.remove_workers()
                for container in list(self.clones):
                    self.remove_clone(container)
                contract.CATALOG._cleanup_evidence_stage(inputs.staging_directory)
            except BaseException as error:
                self.phase = "BOUNDED_SCOPE_ONLY_CLEANUP"
                self.failure_receipt(error)
                raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "recovery-receipt", "legacy-inspection-receipt", "legacy-inspection-signature", "expectation", "preflight-receipt", "preflight-signature"):
        parser.add_argument("--" + name + "-path", required=True)
    parser.add_argument("--clone-receipt-path", required=True)
    parser.add_argument("--clone-signature-path", required=True)
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--native-clone-only", action="store_true", help="Requires separate approved code/resource review; never writes primary")
    args = parser.parse_args(argv)
    try:
        if args.native_clone_only:
            receipt, output = NativeCloneController(args).run()
            print(json.dumps({"result": receipt["result"], "receipt_path": str(output), "receipt_sha256": receipt["receipt_sha256"], "primary_mutations": 0, "primary_quarantine_authorized": False}, sort_keys=True))
        else:
            plan = prepare_plan(args)
            print(plan.serialized.decode("utf-8"))
    except Exception as error:
        print(json.dumps({"result": "REJECTED", "error_type": type(error).__name__, "primary_apply_implemented": False}, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
