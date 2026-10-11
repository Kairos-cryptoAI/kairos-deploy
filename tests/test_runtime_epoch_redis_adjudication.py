"""Offline negative proofs for the one retained read-only adjudication."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from scripts import runtime_epoch_redis_adjudication as adjudication
from scripts import runtime_epoch_redis_recovery as recovery


def observations() -> dict:
    source = {
        "state": "COPY_VERIFIED",
        "file_count": 4,
        "total_bytes": 100,
        "manifest_sha256": "a" * 64,
        "content_sha256": "b" * 64,
        "persistence": {
            "format": "REDIS_MULTIPART_AOF",
            "aof_manifest_sha256": "c" * 64,
            "aof_file_hashes": [
                {"relative_path": "base", "sha256": "d" * 64},
                {"relative_path": "incr", "sha256": "e" * 64},
            ],
            "rdb_present": True,
        },
    }
    backup = {**source, "manifest_sha256": "f" * 64}
    clone = {**source, "manifest_sha256": "1" * 64}

    def copied(manifest):
        return {
            "state": "COPY_VERIFIED",
            "source_manifest_sha256": manifest["manifest_sha256"],
            "source_after_manifest_sha256": manifest["manifest_sha256"],
            "snapshot_content_sha256": "b" * 64,
            "file_count": 4,
            "total_bytes": 100,
        }

    inventory = {
        "status": "PASS_AOF_INVENTORY",
        "bytes": 100,
        "parsed_source_sha256": "e" * 64,
        "publication_message_ids_sha256": "9" * 64,
        "dbs": [0],
        "ledger_fields": 2220,
        "receipt_count": 2220,
        "xadd_count": 2221,
        "subcommand_counts": {
            "select": 1,
            "hset": 2220,
            "xadd": 2221,
            "xgroup|create": 1,
            "xgroup|setid": 1329,
            "multi": 3549,
            "exec": 3549,
        },
        "transactions_balanced": True,
        "actor_format_valid": True,
        "matched_receipt_count": 2220,
    }
    worker = {
        "state": "PASS_BOOT_REDIS_STATE",
        "owner": recovery.OWNER,
        "mode": "boot-redis-clone",
        "new_epoch_database": "kairos_epoch_" + recovery.OWNER[:12],
        "outbox_rows": 2220,
        "completed_inbox": 2220,
        "stream_entries": 2221,
        "publication_receipts": 2220,
        "publication_message_ids_sha256": "9" * 64,
        "consumer_groups": 1,
        "pending_deliveries": 0,
        "auth_proofs": {
            "anonymous_ping_refused": True,
            "default_auth_refused": True,
            "anonymous_write_refused_on_clone": True,
        },
        "trading_started": False,
    }
    result = {
        "redis-aof-recovery-failure.json": {
            "owner": recovery.OWNER,
            "reason": "LEGACY_OR_STANDBY_METADATA_CHANGED",
            "source_revision": adjudication.WORKER_REVISION,
            "state": "FAILED_CLOSED",
            "trading_started": False,
        },
        "cli-177.stdout": {
            "id": adjudication.CLONE_ID,
            "mounts": [],
            "state": {"Status": "exited", "ExitCode": 0, "Running": False},
        },
        "output-boot-redis-clone-aof-clone/boot-redis-clone.json": worker,
        "cli-022.stdout": source,
        "cli-062.stdout": backup,
        "cli-089.stdout": clone,
        "cli-147.stdout": copy.deepcopy(source),
        "cli-157.stdout": copy.deepcopy(source),
        "cli-052.stdout": copied(source),
        "cli-079.stdout": copied(backup),
    }
    for before, after, identifier in (
        ("cli-001.stdout", "cli-160.stdout", recovery.epoch.fresh.SOURCE_ID),
        ("cli-002.stdout", "cli-161.stdout", recovery.epoch.LEGACY_REDIS_ID),
        ("cli-005.stdout", "cli-164.stdout", recovery.boot.CONTAINERS["redis"]),
    ):
        mounts = [{"Destination": "/a", "RW": False}, {"Destination": "/b", "RW": True}]
        result[before] = {
            "id": identifier,
            "mounts": mounts,
            "state": {"Status": "exited"},
        }
        result[after] = {**result[before], "mounts": list(reversed(mounts))}
    for file in (
        "cli-032.stdout",
        "cli-099.stdout",
        "cli-109.stdout",
        "cli-137.stdout",
    ):
        result[file] = copy.deepcopy(inventory)
    return result


class RedisRetainedAdjudicationTests(unittest.TestCase):
    def test_default_plan_has_no_git_native_or_evidence_side_effect(self):
        with (
            patch.object(
                adjudication.boot, "verify_source", side_effect=AssertionError("git")
            ),
            patch.object(
                adjudication, "load_evidence", side_effect=AssertionError("evidence")
            ),
            patch("builtins.print") as output,
        ):
            self.assertEqual(adjudication.main([]), 0)
        plan = json.loads(output.call_args.args[0])
        self.assertEqual(plan["result"], "PLAN_ONLY")
        self.assertIs(plan["clone_retry"], False)
        self.assertIs(plan["original_mutation"], False)

    def test_exact_mount_enumeration_only_and_full_proofs_pass(self):
        result = adjudication.validate_observations(observations())
        self.assertEqual(result["clone_worker_proof"]["publication_receipts"], 2220)
        self.assertEqual(result["aof_source_before"]["status"], "PASS_AOF_INVENTORY")

    def test_actual_mount_permissions_health_or_resource_identity_change_rejected(self):
        for field in ("mount", "health", "id"):
            with self.subTest(field=field):
                value = observations()
                after = value["cli-160.stdout"]
                if field == "mount":
                    after["mounts"] = [
                        {**after["mounts"][0], "RW": False},
                        after["mounts"][1],
                    ]
                elif field == "health":
                    after["state"] = {"Status": "running"}
                else:
                    after["id"] = "0" * 64
                with self.assertRaises(recovery.epoch.Rejected):
                    adjudication.validate_observations(value)

    def test_clone_incomplete_stream_pending_or_auth_failure_rejected(self):
        for field, replacement in (
            ("pending_deliveries", 1),
            ("stream_entries", 2220),
            ("owner", "0" * 32),
            ("auth_proofs", {}),
        ):
            value = observations()
            value["output-boot-redis-clone-aof-clone/boot-redis-clone.json"][field] = (
                replacement
            )
            with self.assertRaises(recovery.epoch.Rejected):
                adjudication.validate_observations(value)

    def test_backup_content_aof_or_original_after_manifest_conflict_rejected(self):
        for file, field, replacement in (
            ("cli-062.stdout", "content_sha256", "0" * 64),
            ("cli-109.stdout", "parsed_source_sha256", "0" * 64),
            ("cli-147.stdout", "total_bytes", 101),
        ):
            value = observations()
            value[file][field] = replacement
            with self.assertRaises(recovery.epoch.Rejected):
                adjudication.validate_observations(value)

    def test_wrong_overall_failure_or_running_clone_is_never_relabelled_as_pass(self):
        for file, field, replacement in (
            ("redis-aof-recovery-failure.json", "reason", "OTHER_FAILURE"),
            ("cli-177.stdout", "id", "0" * 64),
            ("cli-177.stdout", "state", {"Status": "running", "Running": True}),
        ):
            value = observations()
            value[file][field] = replacement
            with self.assertRaises(recovery.epoch.Rejected):
                adjudication.validate_observations(value)


if __name__ == "__main__":
    unittest.main()
