"""Read-only adjudication of one retained, mount-order-only clone failure.

This is not a retry: the clone, old evidence and recovery latch remain intact.
Only new private evidence and network-none, read-only file hash helpers are made.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import uuid
from datetime import UTC, datetime

if __package__:
    from scripts import runtime_epoch_redis_recovery as recovery
else:
    import runtime_epoch_redis_recovery as recovery

epoch = recovery.epoch
boot = recovery.boot
RUN = "5bfd8f013eb74f08b93ba8381dec8350"
WORK = recovery.ROOT / ("run-" + RUN)
LATCH = recovery.ROOT / "retained-adjudication.active"
WORKER_REVISION = "7aaf2ee27a2a71603558925d2323932fa13a201a"
CLONE_ID = "9ff3b898369b9eb84bb38c5ab8ea88bd426ed31f3d84e2dd658122e59f9253f3"
FAILURE_SHA256 = "869bd34e81b4d1ecc610af39e8b08b83a163b3f13b4e38995f48710a976416d6"
# Explicitly frozen sanitized outputs: no secret/config file discovery.
EVIDENCE = {
    "cli-001.stdout": "eb8aac8aad2aba3d02dfbe5e8f98c25a68f1acd0de9d18128692059fc00b32a3",
    "cli-002.stdout": "544bc11d2eedffbf06656f1b28fa88fbfef8f9f749b09153c079d766dc6e8512",
    "cli-005.stdout": "fef96a0425b8f5ec90f7e447568508c144b82c6aa7c7e9f37bdd200e88545932",
    "cli-022.stdout": "b9ce3d44e873389536fb936caf09f18e777ff5ea91a02aa527a1703671fb140f",
    "cli-032.stdout": "2efa224b5f70af0d64f21622c0e429860381e364f94f797993ff8f190afcdb29",
    "cli-052.stdout": "6483f6cfc2d1ef073a2d895fc39855c478918c5c60a9cf81695c574a270e7d23",
    "cli-062.stdout": "97d708aa17c50555b479aeebe65455a09ef2f20955d0a47cb7338dda354ad398",
    "cli-079.stdout": "06b70228a7b5845494285f9e030b8c9a3d0e18dc12073da47f0cc44a8ab85874",
    "cli-089.stdout": "083a6450be546b2a20c60e93062ac488f9b1a433c5ec98ccb3ce10bdcd93426a",
    "cli-099.stdout": "2efa224b5f70af0d64f21622c0e429860381e364f94f797993ff8f190afcdb29",
    "cli-109.stdout": "2efa224b5f70af0d64f21622c0e429860381e364f94f797993ff8f190afcdb29",
    "cli-137.stdout": "2efa224b5f70af0d64f21622c0e429860381e364f94f797993ff8f190afcdb29",
    "cli-147.stdout": "b9ce3d44e873389536fb936caf09f18e777ff5ea91a02aa527a1703671fb140f",
    "cli-157.stdout": "b9ce3d44e873389536fb936caf09f18e777ff5ea91a02aa527a1703671fb140f",
    "cli-160.stdout": "0d8ff44e76b391480ad824379d6aa380ef5676377db45d3ffaa4a8fb63a5043d",
    "cli-161.stdout": "91956d0b53aaeded1d02f77336be2514b7561f9509afa90163ef89ff7236dfcb",
    "cli-164.stdout": "fef96a0425b8f5ec90f7e447568508c144b82c6aa7c7e9f37bdd200e88545932",
    "cli-177.stdout": "dd3fc50f9d78b85a2e7be39b6ec047c73c84b60c01179985165bc1d69bd09f78",
    "redis-aof-recovery-failure.json": FAILURE_SHA256,
    "output-boot-redis-clone-aof-clone/boot-redis-clone.json": "9470376ace3b5a7896df08748a5cd9dd61c2e41701a0d3c409d665f491ab84b4",
}


def equal_metadata(before: object, after: object) -> dict:
    normalized = epoch.normalize_container_metadata(before)
    if normalized != epoch.normalize_container_metadata(after):
        recovery.reject("RETAINED_METADATA_DIFFERS_BEYOND_MOUNT_ENUMERATION")
    return normalized


def validate_observations(values: dict) -> dict:
    failure = values["redis-aof-recovery-failure.json"]
    if failure != {
        "owner": recovery.OWNER,
        "reason": "LEGACY_OR_STANDBY_METADATA_CHANGED",
        "source_revision": WORKER_REVISION,
        "state": "FAILED_CLOSED",
        "trading_started": False,
    }:
        recovery.reject("EXACT_RETAINED_MOUNT_ORDER_FAILURE_REQUIRED")
    identities = (
        ("cli-001.stdout", "cli-160.stdout", epoch.fresh.SOURCE_ID),
        ("cli-002.stdout", "cli-161.stdout", epoch.LEGACY_REDIS_ID),
        ("cli-005.stdout", "cli-164.stdout", boot.CONTAINERS["redis"]),
    )
    metadata = {}
    for before, after, identifier in identities:
        value = equal_metadata(values[before], values[after])
        if value.get("id") != identifier:
            recovery.reject("RETAINED_RESOURCE_IDENTITY_CONFLICT")
        metadata[identifier] = value
    clone = epoch.normalize_container_metadata(values["cli-177.stdout"])
    if (
        clone.get("id") != CLONE_ID
        or (clone.get("state") or {}).get("Status") != "exited"
        or (clone.get("state") or {}).get("ExitCode") != 0
        or (clone.get("state") or {}).get("Running") is not False
    ):
        recovery.reject("EXACT_RETAINED_STOPPED_CLONE_REQUIRED")
    worker = recovery.validate_redis_worker_proof(
        values["output-boot-redis-clone-aof-clone/boot-redis-clone.json"], clone=True
    )
    inventory = recovery.validate_aof_inventory(
        values["cli-032.stdout"], worker_proof=worker
    )
    for file in ("cli-099.stdout", "cli-109.stdout", "cli-137.stdout"):
        if (
            recovery.validate_aof_inventory(values[file], worker_proof=worker)
            != inventory
        ):
            recovery.reject("RETAINED_SOURCE_BACKUP_CLONE_AOF_CONFLICT")
    source = values["cli-022.stdout"]
    backup = values["cli-062.stdout"]
    pristine = values["cli-089.stdout"]
    if source != values["cli-147.stdout"] or source != values["cli-157.stdout"]:
        recovery.reject("RETAINED_ORIGINAL_FULL_MANIFEST_CHANGED")
    first = recovery.validate_copy_proof(
        values["cli-052.stdout"], source_manifest=source
    )
    second = recovery.validate_copy_proof(
        values["cli-079.stdout"], source_manifest=backup
    )
    for manifest in (source, backup, pristine):
        if (
            manifest.get("state") != "COPY_VERIFIED"
            or manifest.get("file_count") != 4
            or manifest.get("total_bytes") != first["total_bytes"]
            or manifest.get("content_sha256") != first["snapshot_content_sha256"]
            or manifest.get("content_sha256") != second["snapshot_content_sha256"]
        ):
            recovery.reject("RETAINED_FULL_COPY_CONTENT_CONFLICT")
        recovery.validate_authoritative_persistence(
            manifest.get("persistence"), source.get("persistence")
        )
    return {
        "metadata": metadata,
        "clone_view": clone,
        "clone_worker_proof": worker,
        "aof_source_before": inventory,
        "original_source_manifest": source,
        "backup_manifest": backup,
        "source_to_backup_copy": first,
        "backup_to_clone_copy": second,
        "pristine_clone_manifest_sha256": pristine["manifest_sha256"],
    }


def load_evidence() -> tuple[dict, bytes]:
    lease = epoch.fresh.safe(recovery.LEASE).read_bytes()
    expected = (
        json.dumps(
            {"owner": recovery.OWNER, "run": RUN, "scope": recovery.SCOPE},
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )
    if lease != expected:
        recovery.reject("EXACT_RETAINED_QUALIFICATION_LATCH_REQUIRED")
    values = {}
    for relative, sha256 in EVIDENCE.items():
        path = WORK / relative
        if epoch.fresh.sha(path) != sha256:
            recovery.reject("FROZEN_RETAINED_EVIDENCE_HASH_CONFLICT")
        values[relative] = recovery._json(path, limit=32_768)
    return values, lease


def adjudicate(
    controller: recovery.RedisAofRecoveryController, values: dict, lease: bytes
) -> dict:
    proofs = validate_observations(values)
    preserved, resources, _ = controller.validate_admission()
    checks = {
        epoch.fresh.SOURCE: epoch.fresh.SOURCE_ID,
        "kairos-paper-gate-redis-1": epoch.LEGACY_REDIS_ID,
        controller.names["redis"]: boot.CONTAINERS["redis"],
    }
    for name, identifier in checks.items():
        equal_metadata(
            proofs["metadata"][identifier], controller.inspect_container(name)
        )
    clone = controller.inspect_container(recovery.CLONE_CONTAINER)
    equal_metadata(proofs["clone_view"], clone)
    controller.require_mount_set(
        recovery.CLONE_CONTAINER,
        {
            recovery.CLONE_VOLUME: ("/data", True),
            str(WORK / "candidate-redis-users.acl"): ("/run/config/users.acl", False),
        },
    )
    original_path = WORK / "original-redis-users.acl"
    candidate_path = WORK / "candidate-redis-users.acl"
    original = epoch.fresh.safe(original_path).read_bytes()
    candidate = epoch.fresh.safe(candidate_path).read_bytes()
    if original != epoch.fresh.safe(
        boot.PARENT / "redis-users.acl"
    ).read_bytes() or candidate != recovery.aof.candidate_acl(original, recovery.OWNER):
        recovery.reject("RETAINED_ORIGINAL_AND_CANDIDATE_ACL_CONFLICT")
    snapshots = {
        "cold_redis_acceptance.py": "scripts/cold_redis_acceptance.py",
        "runtime_epoch_redis_aof.py": "scripts/runtime_epoch_redis_aof.py",
        "operator/runtime_epoch_worker.py": "scripts/runtime_epoch_worker.py",
        "operator/controlled_runtime_worker.py": "scripts/controlled_runtime_worker.py",
    }
    for retained, local in snapshots.items():
        if epoch.fresh.sha(WORK / retained) != epoch.fresh.sha(epoch.REPO / local):
            recovery.reject("RETAINED_PROOF_WORKER_DIFFERS_FROM_SIGNED_SOURCE")
    controller.cold_snapshot = WORK / "cold_redis_acceptance.py"
    controller.aof_snapshot = WORK / "runtime_epoch_redis_aof.py"
    for volume in (
        controller.names["redis_volume"],
        recovery.BACKUP_VOLUME,
        recovery.CLONE_VOLUME,
    ):
        identity = json.loads(
            controller.docker(
                [
                    "volume",
                    "inspect",
                    "--format",
                    '{"name":{{json .Name}},"labels":{{json .Labels}}}',
                    volume,
                ]
            )
        )
        labels = identity.get("labels") or {}
        if (
            identity.get("name") != volume
            or labels.get(epoch.EPOCH_LABEL) != recovery.OWNER
            or labels.get("com.kairos.runtime-epoch.scope") != epoch.EPOCH_SCOPE
        ):
            recovery.reject("EXACT_EXISTING_OWNER_LABELLED_REDIS_VOLUMES_REQUIRED")
    source = controller.cold_manifest(controller.names["redis_volume"], "adjud-source")
    backup = controller.cold_manifest(recovery.BACKUP_VOLUME, "adjud-backup")
    if (
        source != proofs["original_source_manifest"]
        or backup != proofs["backup_manifest"]
    ):
        recovery.reject("RETAINED_CURRENT_SOURCE_OR_PRISTINE_BACKUP_CHANGED")
    replayed = controller.cold_manifest(recovery.CLONE_VOLUME, "adjud-clone")
    recovery.validate_authoritative_persistence(
        replayed.get("persistence"), source["persistence"]
    )
    for volume, tag in (
        (controller.names["redis_volume"], "adjud-source"),
        (recovery.BACKUP_VOLUME, "adjud-backup"),
        (recovery.CLONE_VOLUME, "adjud-clone"),
    ):
        if (
            controller.aof_inventory(volume, tag, proofs["clone_worker_proof"])
            != proofs["aof_source_before"]
        ):
            recovery.reject("CURRENT_SOURCE_BACKUP_CLONE_AOF_CHANGED")
    if (
        controller.cold_manifest(controller.names["redis_volume"], "adjud-source-after")
        != source
        or controller.cold_manifest(recovery.BACKUP_VOLUME, "adjud-backup-after")
        != backup
    ):
        recovery.reject("SOURCE_OR_BACKUP_CHANGED_DURING_READONLY_ADJUDICATION")
    after, resources_after, _ = controller.validate_admission()
    if (
        after["active_latch_sha256"] != preserved["active_latch_sha256"]
        or after["resource_metadata"] != preserved["resource_metadata"]
        or recovery.LEASE.read_bytes() != lease
    ):
        recovery.reject("RETAINED_ADJUDICATION_ADMISSION_CHANGED")
    equal_metadata(clone, controller.inspect_container(recovery.CLONE_CONTAINER))
    # Recheck every frozen evidence hash before emitting a new acceptance.
    load_evidence()
    proof_data = {
        key: value
        for key, value in proofs.items()
        if key not in {"metadata", "clone_view"}
    }
    proof_data.update(
        clone_container_id=CLONE_ID,
        clone_stopped=True,
        backup_volume=recovery.BACKUP_VOLUME,
        clone_volume=recovery.CLONE_VOLUME,
        aof_copy_inventory_sha256=epoch.fresh.digest(proofs["aof_source_before"]),
        named_roles_acl_byte_identical=True,
        cold_worker_sha256=epoch.fresh.sha(controller.cold_snapshot),
        aof_inventory_module_sha256=epoch.fresh.sha(controller.aof_snapshot),
    )
    return {
        "schema_version": 1,
        "result": "PASS_REDIS_AOF_CLONE_QUALIFICATION",
        "owner": recovery.OWNER,
        "scope": recovery.SCOPE,
        "source_revision": controller.expected_revision,
        "run_id": RUN,
        "completed_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "working_directory": str(WORK),
        "proofs": proof_data,
        "source_container_id": boot.CONTAINERS["redis"],
        "previous_boot_run": recovery.BOOT_RUN,
        "previous_boot_failure_sha256": recovery.BOOT_FAILURE_SHA256,
        "previous_boot_binding_sha256": recovery.BINDING_SHA256,
        "previous_boot_active_latch_sha256": preserved["active_latch_sha256"],
        "previous_boot_inputs_unchanged": True,
        "original_acl_sha256": recovery._sha_bytes(original),
        "candidate_acl_sha256": recovery._sha_bytes(candidate),
        "backup_volume": recovery.BACKUP_VOLUME,
        "clone_volume": recovery.CLONE_VOLUME,
        "clone_container": recovery.CLONE_CONTAINER,
        "clone_container_id": CLONE_ID,
        "retained_evidence_adjudication": {
            "result": "PASS_MOUNT_ORDER_ONLY_ADJUDICATION",
            "failure_sha256": FAILURE_SHA256,
            "worker_source_revision": WORKER_REVISION,
            "source_revision": controller.expected_revision,
            "clone_metadata_sha256": epoch.fresh.digest(clone),
            "clone_restarted": False,
            "evidence_rewritten": False,
            "frozen_evidence": EVIDENCE,
            "private_readonly_work": str(controller.work),
        },
        "original_source_unchanged": {
            "legacy": resources["legacy"],
            "standby": resources_after["standby"],
            "source_container_unchanged": True,
        },
        "trading_started": False,
        "primary_acl_changed": False,
        "original_redis_stopped_or_restarted": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adjudicate-retained", action="store_true")
    parser.add_argument("--expected-revision")
    args = parser.parse_args(argv)
    if not args.adjudicate_retained:
        print(
            json.dumps(
                {
                    "result": "PLAN_ONLY",
                    "clone_retry": False,
                    "original_mutation": False,
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 0
    work = None
    controller = None
    try:
        if re.fullmatch(r"[0-9a-f]{40}", args.expected_revision or "") is None:
            recovery.reject("EXPECTED_SIGNED_MAIN_REVISION_REQUIRED")
        boot.verify_source(args.expected_revision)
        boot.git("verify-commit", WORKER_REVISION)
        if (
            boot.git("log", "-1", "--format=%G? %GF", WORKER_REVISION)
            != "G " + epoch.fresh.SIGNER
        ):
            recovery.reject("SIGNED_RETAINED_WORKER_REVISION_REQUIRED")
        values, lease = load_evidence()
        validate_observations(values)
        receipt = WORK / "redis-aof-clone-qualification.json"
        if (
            receipt.exists()
            or receipt.is_symlink()
            or LATCH.exists()
            or LATCH.is_symlink()
        ):
            recovery.reject("RETAINED_ADJUDICATION_ALREADY_ATTEMPTED")
        identifier = uuid.uuid4().hex
        work = WORK / ("readonly-adjudication-" + identifier)
        epoch._private_directory(work)
        recovery._create_only(
            LATCH,
            json.dumps(
                {"owner": recovery.OWNER, "run": RUN, "adjudication_run": identifier},
                sort_keys=True,
            ).encode("ascii")
            + b"\n",
        )
        adjudication_latch_bytes = LATCH.read_bytes()
        controller = recovery.RedisAofRecoveryController(
            recovery.OWNER,
            expected_revision=args.expected_revision,
            workdir=work,
            continuation_attempt="adjud-" + identifier[:8],
            deadline=time.monotonic() + 900,
            run_id=identifier,
        )
        result = adjudicate(controller, values, lease)
        if LATCH.read_bytes() != adjudication_latch_bytes:
            recovery.reject("RETAINED_ADJUDICATION_LATCH_CHANGED")
        epoch.fresh.save(receipt, result)
        print(
            json.dumps(
                {
                    "result": result["result"],
                    "receipt": str(receipt),
                    "sha256": epoch.fresh.sha(receipt),
                    "clone_retried": False,
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - private evidence, sanitized public diagnostic.
        if controller:
            controller.fail_closed_cleanup()
        reason = (
            str(exc)
            if isinstance(exc, epoch.Rejected)
            else "RETAINED_ADJUDICATION_FAILED_" + type(exc).__name__.upper()
        )
        if work:
            epoch.fresh.save(
                work / "adjudication-failure.json",
                {"state": "FAILED_CLOSED", "reason": reason, "trading_started": False},
            )
        print(
            json.dumps(
                {
                    "result": "FAILED_CLOSED",
                    "reason": reason,
                    "automatic_retry": False,
                    "trading_started": False,
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
