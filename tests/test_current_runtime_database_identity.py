"""Synthetic CURRENT identity binding; no database, task or runtime access."""
import copy
import unittest

from test_runtime_epoch_boot_worker import boot_seed

from scripts import runtime_epoch_controller as controller
from scripts import runtime_epoch_current_boot as boot
from scripts import runtime_epoch_worker as worker

OWNER = "0123456789abcdef0123456789abcdef"
IDENTITY = {"count": 1, "sha256": "d" * 64}


def current_seed():
    value = boot_seed()
    value.update({"schema_profile": "current-controlled-v1", "schema_migration_count": 19,
                  "schema_public_table_count": 33, "matched_public_tables": 33,
                  "database_identity": dict(IDENTITY)})
    value["tables"]["news_processing"] = {"count": 0, "sha256": "a" * 64}
    value["tables"]["schema_migrations"]["count"] = 19
    value["tables"]["paper_canary_database_identity"] = dict(IDENTITY)
    value["original_prefix"] = {
        "rows": worker.ORIGINAL_PREFIX_ROWS,
        "audit_table_sha256": worker.CURRENT_ORIGINAL_PREFIX_TABLE_SHA256,
        "last_open_time_ms": worker.ORIGINAL_PREFIX_LAST_OPEN_MS,
        "digest_scope": worker.CURRENT_ORIGINAL_PREFIX_DIGEST_SCOPE,
    }
    return value


def restore_proof():
    return {"owner": OWNER, "mode": "verify-restore", "new_epoch_database": "kairos_epoch_" + OWNER[:12],
            "state": "PASS_ISOLATED_EPOCH_RESTORE", "schema_profile": "current-controlled-v1",
            "schema_migration_count": 19, "schema_public_table_count": 33,
            "matched_public_tables": 33, "tables": copy.deepcopy(current_seed()["tables"])}


class CurrentDatabaseIdentityTests(unittest.TestCase):
    def test_historical_identity_stays_fixed(self):
        worker.validate_boot_database_identity({"paper_canary_database_identity": worker.BOOT_DATABASE_IDENTITY})
        with self.assertRaises(worker.EpochError):
            worker.validate_boot_database_identity({"paper_canary_database_identity": IDENTITY})

    def test_current_requires_explicit_matching_per_epoch_identity(self):
        token = worker.schema_profile_context("current-controlled-v1")
        try:
            worker.validate_boot_database_identity({"paper_canary_database_identity": IDENTITY}, IDENTITY)
            for expected in (None, {"count": 1, "sha256": "b" * 64}, {"count": True, "sha256": "d" * 64}):
                with self.subTest(expected=expected), self.assertRaises(worker.EpochError):
                    worker.validate_boot_database_identity({"paper_canary_database_identity": IDENTITY}, expected)
            worker.validate_boot_seed(current_seed(), OWNER, "kairos_epoch_" + OWNER[:12])
            bad = current_seed()
            bad["database_identity"] = {"count": 1, "sha256": "f" * 64}
            with self.assertRaises(worker.EpochError):
                worker.validate_boot_seed(bad, OWNER, "kairos_epoch_" + OWNER[:12])
        finally:
            worker.reset_schema_profile_context(token)

    def test_controller_requires_current_identity_before_private_config_creation(self):
        value = {"owner": OWNER, "database": "kairos_epoch_" + OWNER[:12],
                 "pg_host": "kairos-epoch-" + OWNER[:12] + "-pg", "redis_host": "kairos-epoch-" + OWNER[:12] + "-redis",
                 "admin_password": "a" * 64, "database_identity": dict(IDENTITY)}
        controller.validate_worker_config(value, mode="boot-state", schema_profile="current-controlled-v1")
        token = worker.schema_profile_context("current-controlled-v1")
        try:
            worker.validate_config(value, "boot-state")
            with self.assertRaises(worker.EpochError):
                worker.validate_config({**value, "unreviewed_field": True}, "boot-state")
        finally:
            worker.reset_schema_profile_context(token)
        bad = dict(value)
        del bad["database_identity"]
        with self.assertRaises(controller.Rejected):
            controller.validate_worker_config(bad, mode="boot-state", schema_profile="current-controlled-v1")
        with self.assertRaises(controller.Rejected):
            controller.validate_worker_config(value, mode="boot-state")

    def test_signed_restore_proof_must_bind_owner_database_mode_and_current_schema(self):
        proof = restore_proof()
        self.assertEqual(boot.database_identity_from_restore_proof({"verify-restore": proof}, OWNER), IDENTITY)
        for field, changed in (("owner", "a" * 32), ("mode", "boot-state"),
                               ("new_epoch_database", "other"), ("schema_migration_count", 18),
                               ("state", "FAILED_CLOSED"), ("matched_public_tables", 32)):
            bad = {**proof, field: changed}
            with self.subTest(field=field), self.assertRaises(boot.CurrentBootRejected):
                boot.database_identity_from_restore_proof({"verify-restore": bad}, OWNER)
        bad = copy.deepcopy(proof)
        del bad["tables"]["news_processing"]
        with self.assertRaises(boot.CurrentBootRejected):
            boot.database_identity_from_restore_proof({"verify-restore": bad}, OWNER)
        with self.assertRaises(boot.CurrentBootRejected):
            boot.database_identity_from_restore_proof({}, OWNER)

    def test_boot_seed_projection_keeps_values_and_rejects_self_consistent_foreign_identity(self):
        seed = current_seed()
        receipt = {**seed, "owner": OWNER, "mode": "boot-state", "new_epoch_database": "kairos_epoch_" + OWNER[:12]}
        self.assertEqual(boot.boot_seed_from_receipt(receipt, OWNER, IDENTITY), seed)
        with self.assertRaises(boot.CurrentBootRejected):
            boot.boot_seed_from_receipt(receipt, OWNER, {"count": 1, "sha256": "f" * 64})
        with self.assertRaises(boot.CurrentBootRejected):
            boot.boot_seed_from_receipt({**receipt, "owner": "b" * 32}, OWNER, IDENTITY)
        with self.assertRaises(boot.CurrentBootRejected):
            boot.boot_seed_from_receipt({**receipt, "unknown_field": True}, OWNER, IDENTITY)


if __name__ == "__main__":
    unittest.main()
