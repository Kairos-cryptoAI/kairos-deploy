"""Offline tests for the guarded clone-only AOF recovery controller."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from scripts import runtime_epoch_boot as boot
from scripts import runtime_epoch_controller as epoch
from scripts import runtime_epoch_redis_aof as aof
from scripts import runtime_epoch_redis_recovery as recovery


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _worker_proof(*, clone: bool) -> dict:
    return {
        "state": "PASS_BOOT_REDIS_STATE",
        "owner": recovery.OWNER,
        "mode": "boot-redis-clone" if clone else "boot-redis-state",
        "new_epoch_database": "kairos_epoch_" + recovery.OWNER[:12],
        "outbox_rows": 2220,
        "completed_inbox": 2220,
        "stream_entries": 2221,
        "publication_receipts": 2220,
        "publication_message_ids_sha256": "a" * 64,
        "consumer_groups": 1,
        "pending_deliveries": 0,
        "auth_proofs": {
            "anonymous_ping_refused": True,
            "default_auth_refused": True,
            "anonymous_write_refused_on_clone": clone,
        },
        "trading_started": False,
    }


def _aof_inventory() -> dict:
    return {
        "status": "PASS_AOF_INVENTORY",
        "bytes": 100_000,
        "parsed_source_sha256": "b" * 64,
        "publication_message_ids_sha256": "a" * 64,
        "dbs": [0],
        "ledger_fields": 2220,
        "receipt_count": 2220,
        "xadd_count": 2221,
        "subcommand_counts": {
            "select": 1,
            "multi": 2220,
            "exec": 2220,
            "hset": 2220,
            "xadd": 2221,
            "xgroup|create": 1,
            "xgroup|setid": 1329,
            "xclaim": 10,
            "xack": 1329,
        },
        "matched_receipt_count": 2220,
        "actor_format_valid": True,
        "transactions_balanced": True,
    }


class RedisAofRecoveryTests(unittest.TestCase):
    def test_explicit_copy_size_cap_is_allowlisted_not_a_free_integer(self):
        manifest = {"manifest_sha256": "1" * 64, "content_sha256": "2" * 64}
        proof = {
            "state": "COPY_VERIFIED",
            "source_manifest_sha256": manifest["manifest_sha256"],
            "source_after_manifest_sha256": manifest["manifest_sha256"],
            "snapshot_content_sha256": manifest["content_sha256"],
            "file_count": 4,
            "total_bytes": 16 * 1024 * 1024,
        }
        self.assertEqual(
            recovery.validate_copy_proof(
                proof, source_manifest=manifest,
                max_aof_bytes=recovery.MAX_FORENSIC_AOF_BYTES,
            )["total_bytes"],
            16 * 1024 * 1024,
        )
        with self.assertRaises(epoch.Rejected):
            recovery.validate_copy_proof(
                proof, source_manifest=manifest, max_aof_bytes=256 * 1024 * 1024
            )
        for invalid_cap in (True, float(recovery.MAX_AOF_BYTES)):
            with self.subTest(invalid_cap=invalid_cap), self.assertRaises(epoch.Rejected):
                recovery.validate_copy_proof(
                    proof, source_manifest=manifest, max_aof_bytes=invalid_cap
                )
        with self.assertRaises(epoch.Rejected):
            recovery.validate_copy_proof(
                proof, source_manifest=manifest
            )

    def test_inventory_size_profile_is_named_and_default_stays_eight_mib(self):
        inventory = _aof_inventory()
        inventory["bytes"] = 16 * 1024 * 1024
        with self.assertRaises(epoch.Rejected):
            recovery.validate_aof_inventory(inventory)
        self.assertEqual(
            recovery.validate_aof_inventory(
                inventory, profile=recovery.FORENSIC_AOF_PROFILE
            )["bytes"],
            16 * 1024 * 1024,
        )

    def test_malformed_aof_profile_rejects_before_inventory_validation(self):
        for profile in ([], {}, None, True, 1.0):
            with self.subTest(profile=profile), self.assertRaises(epoch.Rejected):
                recovery.validate_aof_inventory({}, profile=profile)

    def test_async_root_cache_refresh_does_not_weaken_aof_or_file_inventory(self):
        persistence = {
            "format": "REDIS_MULTIPART_AOF",
            "aof_manifest_sha256": recovery.OPEN_SEGMENT_MANIFEST_SHA256,
            "aof_file_hashes": recovery.EXACT_SEGMENT_FILES,
            "rdb_present": True,
        }
        before = {
            "state": "COPY_VERIFIED",
            "file_count": 4,
            "total_bytes": 3257093,
            "manifest_sha256": "a" * 64,
            "content_sha256": "b" * 64,
            "cache_stable_metadata_sha256": "e" * 64,
            "persistence": persistence,
        }
        after = {
            **before,
            "total_bytes": 4175397,
            "manifest_sha256": "c" * 64,
            "content_sha256": "d" * 64,
        }
        proof = recovery.validate_readonly_manifest_stability(before, after)
        self.assertIs(proof["root_rdb_cache_refreshed"], True)
        self.assertIs(proof["authoritative_aof_byte_identical"], True)
        self.assertIs(
            recovery.validate_readonly_manifest_stability(before, before)[
                "root_rdb_cache_refreshed"
            ],
            False,
        )
        for mutation in (
            {"file_count": 5},
            {"total_bytes": recovery.MAX_AOF_BYTES + 1},
            {"unknown_file": True},
            {"cache_stable_metadata_sha256": "f" * 64},
            {"persistence": {**persistence, "rdb_present": False}},
            {
                "persistence": {
                    **persistence,
                    "aof_manifest_sha256": recovery.CLOSED_SEGMENT_MANIFEST_SHA256,
                }
            },
        ):
            with self.assertRaises(epoch.Rejected):
                recovery.validate_readonly_manifest_stability(
                    before, {**after, **mutation}
                )

    def test_canonical_proofs_round_trip_without_dropping_admission_identity(self):
        for clone in (False, True):
            proof = recovery.validate_redis_worker_proof(
                _worker_proof(clone=clone), clone=clone
            )
            self.assertEqual(
                recovery.validate_redis_worker_proof(proof, clone=clone), proof
            )
            for mutation in (
                {"owner": "0" * 32},
                {"new_epoch_database": "other"},
                {"mode": "other"},
            ):
                with self.assertRaises(epoch.Rejected):
                    recovery.validate_redis_worker_proof(
                        {**proof, **mutation}, clone=clone
                    )
        inventory = recovery.validate_aof_inventory(_aof_inventory())
        self.assertEqual(recovery.validate_aof_inventory(inventory), inventory)
        with self.assertRaises(epoch.Rejected):
            recovery.validate_aof_inventory({**inventory, "status": "FAIL"})

    def test_default_invocation_is_a_side_effect_free_plan(self):
        with (
            patch.object(boot, "verify_source", side_effect=AssertionError("called")),
            patch.object(recovery, "_create_run", side_effect=AssertionError("called")),
            patch("builtins.print") as output,
        ):
            self.assertEqual(recovery.main([]), 0)
        plan = json.loads(output.call_args.args[0])
        self.assertEqual(plan["result"], "PLAN_ONLY")
        self.assertIs(plan["clone_start"], False)
        self.assertIs(plan["original_redis_start_stop"], False)
        self.assertIs(plan["primary_acl_change"], False)
        self.assertIs(plan["trading_started"], False)

    def test_failed_boot_artifact_paths_are_exact(self):
        active, failure, status, binding = recovery._failure_paths()
        run = boot.ROOT / "runs" / recovery.BOOT_RUN
        self.assertEqual(active, boot.ROOT / "boot.active")
        self.assertEqual(failure, run / "boot-failure.json")
        self.assertEqual(
            status, run / "output-boot-redis-state-beforestart" / "status.json"
        )
        self.assertEqual(binding, boot.ROOT / "binding.json")

    def test_task_guard_reads_ready_last_result_and_running_boot_process_count(self):
        accepted = CompletedProcess(
            [], 0, b'{"state":"Ready","last_result":1,"boot_python_count":0}'
        )
        with patch.object(recovery.subprocess, "run", return_value=accepted) as run:
            self.assertEqual(
                recovery._bounded_task_state(),
                {"state": "Ready", "last_result": 1, "boot_python_count": 0},
            )
        command = run.call_args.args[0][-1]
        self.assertIn("Get-ScheduledTaskInfo", command)
        self.assertIn("LastTaskResult", command)
        self.assertIn("runtime_epoch_boot\\.py", command)
        rejected = CompletedProcess(
            [], 0, b'{"state":"Ready","last_result":1,"boot_python_count":1}'
        )
        with (
            patch.object(recovery.subprocess, "run", return_value=rejected),
            self.assertRaisesRegex(
                epoch.Rejected, "FAILED_BOOT_TASK_MUST_BE_READY_AND_IDLE"
            ),
        ):
            recovery._bounded_task_state()

    def _failure_fixture(self, root: Path, *, acl: bytes, unrelated: bytes):
        active = root / "boot.active"
        failure = root / "boot-failure.json"
        status = root / "status.json"
        binding = root / "binding.json"
        acl_path = root / "redis-users.acl"
        other_path = root / "other-input.bin"
        active.write_text(
            json.dumps(
                {
                    "owner": recovery.OWNER,
                    "run": recovery.BOOT_RUN,
                    "boot_id": "20261011010101000",
                }
            )
        )
        failure_bytes = json.dumps(
            {
                "state": "FAILED_CLOSED",
                "reason": "WORKER_MODE_FAILED_BOOT-REDIS-STATE",
                "owner": recovery.OWNER,
                "trading_started": False,
            }
        ).encode()
        failure.write_bytes(failure_bytes)
        status.write_text(
            json.dumps(
                {
                    "state": "FAILED_CLOSED",
                    "mode": "boot-redis-state",
                    "reason": "BOOT_REDIS_PUBLICATION_RECEIPT_MISSING",
                    "trading_started": False,
                }
            )
        )
        acl_path.write_bytes(acl)
        other_path.write_bytes(unrelated)
        binding_value = {
            "schema_version": 1,
            "owner": recovery.OWNER,
            "scope": boot.SCOPE,
            "repo": epoch.REPO.as_posix(),
            "python_path": boot.PYTHON.as_posix(),
            "containers": boot.CONTAINERS,
            "parent_receipt_sha256": boot.PARENT_RECEIPT_SHA256,
            "revision": "1" * 40,
            "inputs": {
                acl_path.as_posix(): _sha(b"old-acl\n"),
                other_path.as_posix(): _sha(unrelated),
            },
            "source_files": {"scripts/runtime_epoch_boot.py": "c" * 64},
        }
        binding.write_text(json.dumps(binding_value))
        return active, failure, status, binding, acl_path, other_path, failure_bytes

    def test_admission_allows_only_the_receipted_acl_input_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            acl = b"user default off\nuser role on #hash\n"
            candidate_hash = _sha(acl)
            active, failure, status, binding, acl_path, other, failure_bytes = (
                self._failure_fixture(root, acl=acl, unrelated=b"same")
            )
            with (
                patch.object(recovery, "BOOT_FAILURE_SHA256", _sha(failure_bytes)),
                patch.object(recovery, "BINDING_SHA256", _sha(binding.read_bytes())),
                patch.object(boot, "input_paths", return_value=[acl_path, other]),
                patch.object(boot, "PARENT", root),
            ):
                result = recovery.validate_failure_evidence(
                    active_path=active,
                    failure_path=failure,
                    status_path=status,
                    binding_path=binding,
                    task_state={
                        "state": "Ready",
                        "last_result": 1,
                        "boot_python_count": 0,
                    },
                    allowed_acl_sha256=candidate_hash,
                )
                self.assertEqual(result["boot_run"], recovery.BOOT_RUN)
                with self.assertRaisesRegex(
                    epoch.Rejected, "PREVIOUS_BOOT_PRIVATE_INPUT_CHANGED"
                ):
                    other.write_bytes(b"mutated")
                    recovery.validate_failure_evidence(
                        active_path=active,
                        failure_path=failure,
                        status_path=status,
                        binding_path=binding,
                        task_state={
                            "state": "Ready",
                            "last_result": 1,
                            "boot_python_count": 0,
                        },
                        allowed_acl_sha256=candidate_hash,
                    )

    def test_admission_does_not_accept_acl_change_without_exact_candidate_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            acl = b"user default off\nuser role on #hash\n"
            active, failure, status, binding, acl_path, other, failure_bytes = (
                self._failure_fixture(root, acl=acl, unrelated=b"same")
            )
            with (
                patch.object(recovery, "BOOT_FAILURE_SHA256", _sha(failure_bytes)),
                patch.object(recovery, "BINDING_SHA256", _sha(binding.read_bytes())),
                patch.object(boot, "input_paths", return_value=[acl_path, other]),
                patch.object(boot, "PARENT", root),
                self.assertRaisesRegex(
                    epoch.Rejected, "PREVIOUS_BOOT_PRIVATE_INPUT_CHANGED"
                ),
            ):
                recovery.validate_failure_evidence(
                    active_path=active,
                    failure_path=failure,
                    status_path=status,
                    binding_path=binding,
                    task_state={
                        "state": "Ready",
                        "last_result": 1,
                        "boot_python_count": 0,
                    },
                )

    def test_copy_proof_requires_exact_four_file_bounded_manifest_match(self):
        manifest = {"manifest_sha256": "1" * 64, "content_sha256": "2" * 64}
        good = {
            "state": "COPY_VERIFIED",
            "source_manifest_sha256": manifest["manifest_sha256"],
            "source_after_manifest_sha256": manifest["manifest_sha256"],
            "snapshot_content_sha256": manifest["content_sha256"],
            "file_count": 4,
            "total_bytes": 100,
        }
        self.assertEqual(
            recovery.validate_copy_proof(good, source_manifest=manifest)["file_count"],
            4,
        )
        for mutation in (
            {"file_count": 3},
            {"total_bytes": recovery.MAX_AOF_BYTES + 1},
            {"snapshot_content_sha256": "0" * 64},
        ):
            bad = {**good, **mutation}
            with self.assertRaises(epoch.Rejected):
                recovery.validate_copy_proof(bad, source_manifest=manifest)

    def test_authoritative_aof_hashes_survive_root_dump_cache_change_only(self):
        persistence = {
            "format": "REDIS_MULTIPART_AOF",
            "aof_manifest_sha256": "a" * 64,
            "aof_file_hashes": [
                {
                    "relative_path": "appendonlydir/appendonly.aof.1.base.rdb",
                    "sha256": "b" * 64,
                },
                {
                    "relative_path": "appendonlydir/appendonly.aof.1.incr.aof",
                    "sha256": "c" * 64,
                },
            ],
            "rdb_present": True,
        }
        # Different full source manifest is allowed because dump.rdb can be
        # refreshed by a shutdown; authoritative multipart AOF bytes cannot.
        before = {"manifest_sha256": "1" * 64, "persistence": persistence}
        after = {"manifest_sha256": "2" * 64, "persistence": dict(persistence)}
        self.assertNotEqual(before["manifest_sha256"], after["manifest_sha256"])
        self.assertEqual(
            recovery.validate_authoritative_persistence(
                after["persistence"], persistence
            ),
            persistence,
        )
        for key in ("aof_manifest_sha256", "aof_file_hashes"):
            changed = dict(persistence)
            changed[key] = (
                "d" * 64
                if key == "aof_manifest_sha256"
                else [
                    {
                        "relative_path": "appendonlydir/appendonly.aof.1.base.rdb",
                        "sha256": "d" * 64,
                    },
                    persistence["aof_file_hashes"][1],
                ]
            )
            with self.assertRaisesRegex(
                epoch.Rejected, "REDIS_AOF_AUTHORITATIVE_PERSISTENCE_CHANGED"
            ):
                recovery.validate_authoritative_persistence(changed, persistence)

    def test_only_exact_frozen_manifest_shutdown_endoffset_is_admitted(self):
        opened = {
            "format": "REDIS_MULTIPART_AOF",
            "aof_manifest_sha256": recovery.OPEN_SEGMENT_MANIFEST_SHA256,
            "aof_file_hashes": recovery.EXACT_SEGMENT_FILES,
            "rdb_present": True,
        }
        closed = {
            **opened,
            "aof_manifest_sha256": recovery.CLOSED_SEGMENT_MANIFEST_SHA256,
        }
        self.assertEqual(
            recovery.validate_authoritative_persistence(closed, opened), closed
        )
        self.assertEqual(
            recovery.validate_authoritative_persistence(opened, closed), opened
        )
        for mutation in (
            {"aof_manifest_sha256": "0" * 64},
            {"rdb_present": False},
            {
                "aof_file_hashes": [
                    {**recovery.EXACT_SEGMENT_FILES[0], "sha256": "1" * 64},
                    recovery.EXACT_SEGMENT_FILES[1],
                ]
            },
        ):
            with self.assertRaises(epoch.Rejected):
                recovery.validate_authoritative_persistence(
                    {**closed, **mutation}, opened
                )

    def test_aof_inventory_requires_exact_replay_command_shape_and_matches_worker_ledger(
        self,
    ):
        good = _aof_inventory()
        self.assertEqual(
            recovery.validate_aof_inventory(
                good, worker_proof=_worker_proof(clone=True)
            )["ledger_fields"],
            2220,
        )
        for mutation in (
            {"dbs": [0, 1]},
            {"xadd_count": 2220},
            {"subcommand_counts": {**good["subcommand_counts"], "xgroup|setid": 1328}},
            {"publication_message_ids_sha256": "f" * 64},
        ):
            bad = {**good, **mutation}
            with self.assertRaises(epoch.Rejected):
                recovery.validate_aof_inventory(
                    bad, worker_proof=_worker_proof(clone=True)
                )

    def test_redis_worker_auth_and_queue_proof_is_exact_for_clone_and_original(self):
        self.assertTrue(
            recovery.validate_redis_worker_proof(_worker_proof(clone=True), clone=True)[
                "auth_proofs"
            ]["anonymous_write_refused_on_clone"]
        )
        recovery.validate_redis_worker_proof(_worker_proof(clone=False), clone=False)
        bad = _worker_proof(clone=True)
        bad["auth_proofs"]["anonymous_write_refused_on_clone"] = False
        with self.assertRaisesRegex(epoch.Rejected, "BOOT_REDIS_STATE_PROOF_CONFLICT"):
            recovery.validate_redis_worker_proof(bad, clone=True)

    def test_acl_candidate_keeps_every_named_user_byte_unchanged(self):
        original = (
            b"user default off\r\n"
            b"user kairos_epoch_admin on #admin-hash ~* +@all\r\n"
            b"user kairos_epoch_producer on #producer-hash ~* +@all\r\n"
            b"user kairos_epoch_consumer on #consumer-hash ~* +@all\r\n"
        )
        candidate = aof.candidate_acl(original, recovery.OWNER)
        self.assertEqual(candidate.split(b"\n", 1)[1], original.split(b"\n", 1)[1])
        self.assertIn(b"user default reset off resetpass", candidate)

    def test_verify_original_path_is_readonly_and_never_calls_clone_lifecycle(self):
        controller = object.__new__(recovery.RedisAofRecoveryController)
        controller.proofs = {}
        controller.expected_revision = "d" * 40
        controller.names = {
            "redis": "original-redis",
            "target_pg": "original-pg",
            "redis_volume": "original-volume",
        }
        controller.preserved = None
        calls: list[str] = []
        clone_proof = recovery.validate_redis_worker_proof(
            _worker_proof(clone=True), clone=True
        )
        aof_proof = recovery.validate_aof_inventory(
            _aof_inventory(), worker_proof=clone_proof
        )
        persistence = {
            "format": "REDIS_MULTIPART_AOF",
            "aof_manifest_sha256": "e" * 64,
            "aof_file_hashes": [
                {
                    "relative_path": "appendonlydir/appendonly.aof.1.base.rdb",
                    "sha256": "f" * 64,
                },
                {
                    "relative_path": "appendonlydir/appendonly.aof.1.incr.aof",
                    "sha256": "a" * 64,
                },
            ],
            "rdb_present": True,
        }
        manifest = {
            "state": "COPY_VERIFIED",
            "manifest_sha256": "3" * 64,
            "content_sha256": "2" * 64,
            "cache_stable_metadata_sha256": "5" * 64,
            "file_count": 4,
            "total_bytes": 100,
            "persistence": persistence,
        }
        accepted = {
            "proofs": {
                "original_source_manifest": manifest,
                "backup_manifest": manifest,
            },
            "candidate_acl_sha256": "4" * 64,
        }
        resources = {
            "views": {
                "serve": {"state": {"Status": "exited", "ExitCode": 255}},
                "redis": {"state": {"Status": "running"}},
            }
        }
        preserved = {
            "active_latch_sha256": "7" * 64,
            "task_state": {"state": "Ready", "last_result": 1, "boot_python_count": 0},
            "resource_metadata": {"legacy": {"x": 1}, "standby": {"x": 2}},
        }
        controller.load_qualified_receipt = lambda path, sha: (
            calls.append("receipt")
            or controller.proofs.update(
                accepted_clone_proof=clone_proof, accepted_aof_inventory=aof_proof
            )
            or {**accepted, "previous_boot_active_latch_sha256": "7" * 64}
        )
        controller.validate_admission = lambda **kwargs: (
            setattr(controller, "preserved", preserved) or (preserved, resources, {})
        )
        controller._make_snapshots = lambda: calls.append("snapshot")
        controller._source_view_fingerprint = lambda value: {"redis": "unchanged"}
        controller.cold_manifest = lambda volume, tag, **kwargs: (
            calls.append("manifest:" + tag) or manifest
        )
        controller.aof_inventory = lambda volume, tag: (
            calls.append("aof:" + tag) or aof_proof
        )
        controller._worker_config = lambda **kwargs: (
            calls.append("config") or {"redis_host": "original-redis"}
        )
        controller.phase = lambda mode, config, suffix: (
            calls.append("phase:" + mode) or _worker_proof(clone=False)
        )
        controller.validate_resources = lambda **kwargs: (
            calls.append("resources")
            or {**resources, "legacy": {"x": 1}, "standby": {"x": 2}}
        )
        controller.work = Path("C:/private/run")
        controller.original_manifest_before = None
        controller.expected_revision = "d" * 40
        with (
            patch.object(
                recovery, "_bounded_task_state", return_value=preserved["task_state"]
            ),
            patch.object(
                recovery,
                "_failure_paths",
                return_value=(
                    Path("active"),
                    Path("failure"),
                    Path("status"),
                    Path("binding"),
                ),
            ),
            patch.object(epoch.fresh, "sha", return_value="5" * 64),
        ):
            result = controller.run_verify_original(
                receipt_path=Path("receipt"), receipt_sha256="6" * 64
            )
        self.assertEqual(result["result"], "PASS_ORIGINAL_REDIS_READONLY_VERIFICATION")
        self.assertEqual(
            calls,
            [
                "receipt",
                "snapshot",
                "manifest:verify-before",
                "manifest:verify-backup",
                "aof:verify-before",
                "config",
                "phase:boot-redis-state",
                "aof:verify-after",
                "manifest:verify-after",
                "resources",
            ],
        )
        self.assertNotIn("start", calls)
        self.assertNotIn("stop", calls)

    def test_clone_proof_pipeline_uses_only_owned_private_clone_and_candidate_acl(self):
        controller = object.__new__(recovery.RedisAofRecoveryController)
        controller.run_id = "f" * 32
        controller.names = {
            "redis": "original-redis",
            "redis_volume": "original-volume",
            "network": "private-bridge",
        }
        controller.created = []
        controller.proofs = {}
        controller.candidate_acl_path = Path("C:/private/candidate.acl")
        calls = []
        state = {"Status": "created"}
        identity = "a" * 64
        container_view = {
            "id": identity,
            "name": "/" + recovery.CLONE_CONTAINER,
            "labels": {
                epoch.EPOCH_LABEL: recovery.OWNER,
                "com.kairos.runtime-epoch.scope": epoch.EPOCH_SCOPE,
            },
            "network": "private-bridge",
            "ports": [],
            "state": state,
        }
        controller._clone_container_absent = lambda: calls.append("absent")

        def create(name, image, options, *, command, start, user, memory, cpus):
            calls.append(
                ("create", name, image, options, command, start, user, memory, cpus)
            )
            controller.created.append(name)

        controller._create_container = create
        controller.inspect_container = lambda name: container_view
        controller.require_mount_set = lambda name, mounts: calls.append(
            ("mounts", mounts)
        )

        def docker(args, **kwargs):
            calls.append(tuple(args))
            if args[:2] == ["inspect", "--format"]:
                return '{"Name":"no"}'
            if args and args[0] == "start":
                state["Status"] = "running"
                return ""
            raise AssertionError("unexpected Docker command")

        controller.docker = docker
        controller._worker_config = lambda *, redis_host: (
            calls.append(("config", redis_host)) or {"redis_host": redis_host}
        )
        controller.phase = lambda mode, config, suffix: (
            calls.append(("phase", mode, config, suffix)) or _worker_proof(clone=True)
        )
        controller._stop_clone = lambda: calls.append(
            ("stop-owned-clone", controller.proofs.get("clone_container_id"))
        )
        proof = controller._run_clone_proof()
        create_call = next(
            item for item in calls if isinstance(item, tuple) and item[0] == "create"
        )
        self.assertEqual(create_call[1], recovery.CLONE_CONTAINER)
        self.assertEqual(create_call[6], "999:999")
        self.assertFalse(create_call[5])
        self.assertIn(
            f"type=volume,src={recovery.CLONE_VOLUME},dst=/data", create_call[3]
        )
        self.assertIn(
            f"type=bind,src={controller.candidate_acl_path},dst=/run/config/users.acl,readonly",
            create_call[3],
        )
        self.assertEqual(proof["state"], "PASS_BOOT_REDIS_STATE")
        self.assertIn(
            (
                "phase",
                "boot-redis-clone",
                {"redis_host": recovery.CLONE_CONTAINER},
                "aof-clone",
            ),
            calls,
        )
        self.assertIn(("stop-owned-clone", identity), calls)
        self.assertEqual(controller.names["redis"], "original-redis")
        self.assertEqual(controller.names["redis_volume"], "original-volume")

    def test_original_verification_create_only_latch_blocks_concurrent_retry(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "recovery"
            root.mkdir()
            lease = root / "recovery.active"
            latch = {"owner": recovery.OWNER, "run": "a" * 32, "scope": recovery.SCOPE}
            lease.write_bytes(json.dumps(latch, sort_keys=True).encode("ascii") + b"\n")
            accepted = {"run_id": "a" * 32}
            with (
                patch.object(recovery, "ROOT", root),
                patch.object(recovery, "LEASE", lease),
                patch.object(
                    recovery, "VERIFY_LEASE", root / "original-verification.active"
                ),
                # DACL qualification is covered by native Windows tests; this
                # lock test must remain filesystem-only on Linux CI as well.
                patch.object(
                    epoch,
                    "_private_directory",
                    side_effect=lambda path: path.mkdir(parents=True, exist_ok=False),
                ),
            ):
                run_id, _, _, verify_latch = recovery._create_run(
                    verify=True, accepted=accepted, receipt_sha256="b" * 64
                )
                self.assertIsNotNone(verify_latch)
                self.assertEqual(recovery.VERIFY_LEASE.read_bytes(), verify_latch)
                with self.assertRaisesRegex(
                    epoch.Rejected, "ORIGINAL_VERIFICATION_LATCH_ALREADY_EXISTS"
                ):
                    recovery._create_run(
                        verify=True, accepted=accepted, receipt_sha256="b" * 64
                    )
                self.assertEqual(recovery.VERIFY_LEASE.read_bytes(), verify_latch)
                self.assertNotEqual(run_id, accepted["run_id"])


if __name__ == "__main__":
    unittest.main()
