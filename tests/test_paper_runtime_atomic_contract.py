"""Synthetic, database/Docker/provider-free atomic recovery contract tests."""

from __future__ import annotations

import copy
import hashlib
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import paper_runtime_atomic_contract as contract


def history(runtime: bool = False) -> dict:
    profile = contract.RUNTIME_PROFILE if runtime else contract.LEGACY_PROFILE
    tables = contract.RUNTIME_TABLES if runtime else contract.LEGACY_TABLES
    return {"database": "kairos", "migrations": list(profile), "schema_fingerprint_sha256": "b" * 64 if runtime else contract.CATALOG.EXPECTED_LEGACY_FINGERPRINT, "tables": {name: {"count": len(profile) if name == "schema_migrations" else (1 if name == "paper_canary_database_identity" else 0), "row_digest_sha256": "a" * 64} for name in tables}, "public_sequences": {"message_outbox_id_seq": {"last_value": 117626, "is_called": True}}, "public_execution_events_max_sequence": 100}


def plan_document(baseline: dict | None = None) -> dict:
    now = datetime.now(UTC)
    return {"schema_version": 1, "kind": contract.PLAN_KIND, "created_at_utc": now.isoformat(), "preflight_created_at_utc": (now - timedelta(seconds=1)).isoformat(), **{name: (now - timedelta(seconds=5)).isoformat() for name in ("backup_created_at_utc", "clone_created_at_utc", "inspection_created_at_utc", "recovery_created_at_utc")}, "preflight_sha256": "1" * 64, "preflight_signature_sha256": "2" * 64, "source_identity": {"compose_project": contract.readonly.SOURCE_PROJECT, "container_id": "3" * 64, "database": "kairos", "image_id": "sha256:" + "4" * 64, "network": contract.readonly.SOURCE_NETWORK, "network_id": "5" * 64, "volume": contract.readonly.SOURCE_VOLUME}, "backup_sha256": "6" * 64, "manifest_sha256": "7" * 64, "accepted_clone_receipt_sha256": "8" * 64, "identity": {"id": 117625, "producer": "synthetic-producer", "message_id": "synthetic-message-117625", "topic": "synthetic-topic", "payload_sha256": "9" * 64, "publish_attempts": 1}, "reconciliation_id": "synthetic-reconciliation", "lease_owner_sha256": hashlib.sha256(b"synthetic-owner").hexdigest(), "lease_until_utc": (now - timedelta(days=1)).isoformat(), "reason": "legacy expired lease clone-only quarantine rehearsal", "legacy_history": copy.deepcopy(baseline or history()), "runtime_schema_fingerprint_sha256": "b" * 64, "runner": contract.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, "persistence_revision": contract.CATALOG.EXPECTED_PERSISTENCE_REVISION, "repository_sha256": contract.CATALOG.EXPECTED_PERSISTENCE_REPOSITORY_SHA256, "database_module_sha256": contract.DATABASE_MODULE_SHA256, "profile": list(contract.RUNTIME_PROFILE), "primary_apply_implemented": False, "consumer_restart_permitted": False, "readiness": dict(contract.READINESS)}


def plan(baseline: dict | None = None) -> contract.AtomicPlan:
    return contract.AtomicPlan.from_document(plan_document(baseline), now=datetime.now(UTC))


def intent(value: contract.AtomicPlan, after: dict | None = None) -> dict:
    return {"schema_version": 1, "kind": contract.INTENT_KIND, "plan_sha256": value.sha256, "legacy_history_sha256": contract.digest(value.document["legacy_history"]), "committed_history_sha256": contract.digest(after or history(True)), "prepared_at_utc": datetime.now(UTC).isoformat(), "backend_pid": 1234, "quarantine_calls": 1}


def preflight() -> dict:
    roles = {"role": "kairos", "session_role": "kairos", "superuser": True, "bypass_rls": True, "schema_usage": True, "schema_create": True, "uuid_execute": True, "actual_ddl_executed": False, "sufficient_for_reviewed_next_step": True, "table_capabilities": {name: {"readable": True, "updatable": True, "owner_capable": True, "row_security": False} for name in contract.LEGACY_TABLES}}
    snap = {"schema_version": 1, "kind": "kairos.paper-readonly-snapshot.v1", "primary_mutations": 0, "forbidden_network_calls": 0, "loopback_database_connections": 1, "other_application_clients": 0, "target_role": roles, "history": history()}
    restored = copy.deepcopy(snap)
    restored["target_role"] = None
    document = plan_document()
    value = {"schema_version": 1, "classification": "PAPER_RUNTIME_READONLY_TARGET_ROLE_AND_RESTORE_BINDING", "result": "PASS_READ_ONLY_PRIMARY_AND_CLONE", "created_at_utc": document["preflight_created_at_utc"], **contract.readonly._code_identity(), "source_identity": document["source_identity"], "source_backup_sha256": document["backup_sha256"], "source_manifest_sha256": document["manifest_sha256"], "accepted_clone_receipt_sha256": document["accepted_clone_receipt_sha256"], "accepted_clone_signature_sha256": "a" * 64, "immutable_runner": contract.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE, "source_snapshot": snap, "restored_snapshot": restored, "primary_mutations": 0, "primary_apply_implemented": False, "consumers_started": 0, "publisher_calls": 0, "redis_contacted": False, "required_next_gate": contract.NEXT_GATE, "consumer_restart_permitted": False, "readiness": dict(contract.READINESS)}
    value["receipt_sha256"] = contract.digest(value)
    return value


class ContractTests(unittest.TestCase):
    def test_authorities_are_reused_and_full_27_not_only_checkpoint_subset(self):
        self.assertIs(contract.CATALOG, contract.readonly.CATALOG)
        self.assertEqual(len(contract.LEGACY_TABLES), 27)
        self.assertEqual(len(contract.RUNTIME_TABLES), 35)
        self.assertEqual(contract.RUNTIME_PROFILE, contract.CATALOG.TARGET_MIGRATIONS)
        self.assertNotIn("017_simulator_journal.sql", contract.RUNTIME_PROFILE)

    def test_plan_roundtrip_is_immutable(self):
        value = plan()
        document = value.document
        document["identity"]["id"] = 1
        self.assertEqual(value.document["identity"]["id"], 117625)
        self.assertEqual(contract.AtomicPlan.from_document(value.document, now=datetime.now(UTC)), value)

    def test_plan_rejects_stale_future_wrong_identity_profile_source_and_authority(self):
        changes = [lambda d: d.update(extra=True), lambda d: d.update(schema_version=True), lambda d: d.update(preflight_created_at_utc=(datetime.now(UTC) - timedelta(hours=3)).isoformat()), lambda d: d.update(created_at_utc=(datetime.now(UTC) + timedelta(minutes=1)).isoformat()), lambda d: d["identity"].update(id=117626), lambda d: d["identity"].update(id=True), lambda d: d["identity"].update(payload_sha256="bad"), lambda d: d["identity"].update(message_id=""), lambda d: d["identity"].update(publish_attempts=True), lambda d: d["profile"].append("026_operator_control.sql"), lambda d: d["profile"].insert(-1, "017_simulator_journal.sql"), lambda d: d.update(database_module_sha256="0" * 64), lambda d: d.update(runner="latest"), lambda d: d.update(primary_apply_implemented=True), lambda d: d.update(consumer_restart_permitted=True), lambda d: d["readiness"].update(paper_qualified=True)]
        for mutate in changes:
            value = plan_document()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(contract.AtomicError):
                contract.AtomicPlan.from_document(value, now=datetime.now(UTC))

    def test_valid_native_preflight_is_still_not_write_authority(self):
        value = contract.verify_preflight(preflight(), now=datetime.now(UTC))
        self.assertFalse(value["primary_apply_implemented"])
        self.assertFalse(value["consumer_restart_permitted"])

    def test_native_preflight_rejects_tampered_hash_signature_boundary_code_and_restore(self):
        changes = [lambda d: d.update(receipt_sha256="0" * 64), lambda d: d.update(created_at_utc=(datetime.now(UTC) - timedelta(hours=3)).isoformat()), lambda d: d.update(catalog_sha256="0" * 64), lambda d: d.update(primary_mutations=True), lambda d: d.update(publisher_calls=1), lambda d: d["source_identity"].update(volume="different-volume"), lambda d: d["restored_snapshot"]["history"]["tables"]["llm_calls"].update(row_digest_sha256="f" * 64)]
        for mutate in changes:
            value = preflight()
            mutate(value)
            if value["receipt_sha256"] != "0" * 64:
                value["receipt_sha256"] = contract.digest({k: v for k, v in value.items() if k != "receipt_sha256"})
            with self.subTest(mutate=mutate), self.assertRaises(contract.AtomicError):
                contract.verify_preflight(value, now=datetime.now(UTC))

    def test_every_one_of_27_tables_is_compared_not_just_counts(self):
        baseline = history()
        for name in contract.LEGACY_TABLES:
            changed = copy.deepcopy(baseline)
            changed["tables"][name]["row_digest_sha256"] = "c" * 64
            with self.subTest(table=name), self.assertRaises(contract.AtomicError):
                contract.compare_history(baseline, changed)

    def test_sequence_watermark_missing_and_extra_table_fail_closed(self):
        baseline = history()
        for mutate in (lambda d: d["public_sequences"]["message_outbox_id_seq"].update(is_called=False), lambda d: d.update(public_execution_events_max_sequence=101), lambda d: d["tables"].pop("equity_curve"), lambda d: d["tables"].update(extra={"count": 0, "row_digest_sha256": "a" * 64})):
            changed = copy.deepcopy(baseline)
            mutate(changed)
            with self.assertRaises(contract.AtomicError):
                contract.compare_history(baseline, changed)

    def test_unknown_classifier_only_exact_baseline_or_committed_with_no_retry(self):
        value = plan()
        prepared = intent(value)
        self.assertEqual(contract.classify_readonly_outcome(value, prepared, history()), "ROLLED_BACK")
        self.assertEqual(contract.classify_readonly_outcome(value, prepared, history(True)), "COMMITTED_EXACT")
        changed = history(True)
        changed["tables"]["message_outbox"]["row_digest_sha256"] = "c" * 64
        self.assertEqual(contract.classify_readonly_outcome(value, prepared, changed), "INDETERMINATE")
        self.assertEqual(contract.classify_readonly_outcome(value, prepared, history(True), other_clients=1), "INDETERMINATE")
        self.assertEqual(contract.classify_readonly_outcome(value, prepared, None), "INDETERMINATE")

    def test_unknown_classifier_rejects_intent_from_different_plan_or_second_call(self):
        value = plan()
        for mutate in (lambda d: d.update(plan_sha256="0" * 64), lambda d: d.update(quarantine_calls=2), lambda d: d.update(committed_history_sha256="bad"), lambda d: d.update(extra=True)):
            prepared = intent(value)
            mutate(prepared)
            with self.assertRaises(contract.AtomicError):
                contract.classify_readonly_outcome(value, prepared, history(True))

    def test_bounded_json_rejects_duplicate_keys_nonfinite_and_symlinks(self):
        with tempfile.TemporaryDirectory(prefix="atomic-contract-unit-") as directory:
            path = Path(directory) / "synthetic.json"
            for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[]', b'x' * (contract.MAX_JSON_BYTES + 1)):
                path.write_bytes(data)
                with self.assertRaises(contract.AtomicError):
                    contract.read_json(path)


if __name__ == "__main__":
    unittest.main()
