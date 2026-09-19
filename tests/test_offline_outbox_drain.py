from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOL_ROOT = ROOT / "tests" / "offline_outbox_drain"


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


policy = load_module("kairos_offline_outbox_drain_policy_test", TOOL_ROOT / "policy.py")
runner = load_module("kairos_offline_outbox_drain_runner_test", TOOL_ROOT / "runner.py")


def plan_value() -> dict[str, object]:
    return {
        "schema_version": 1,
        "database_name": "kairos",
        "producer": "kairos-quant-scouts",
        "topic": "kairos.market.closed_bar.v1",
        "drain_id": "recovery-drain-20260920-01",
        "maximum_rows": 2,
        "maximum_duration_seconds": 30,
    }


def compose_fixture() -> dict[str, object]:
    build = {
        "context": "tests/offline_outbox_drain",
        "dockerfile": "Dockerfile",
        "pull": True,
        "args": {
            "PERSISTENCE_REPOSITORY": "https://github.com/Kairos-cryptoAI/kairos-persistence",
            "PERSISTENCE_REVISION": policy.PERSISTENCE_REVISION,
        },
    }
    base = {
        "image": "kairos-offline-outbox-drain:20260920-r1",
        "build": build,
        "entrypoint": ["python", "/app/offline_outbox_drain.py"],
        "command": [
            "--mode",
            "inspect",
            "--plan",
            "/run/secrets/offline_outbox_drain_plan",
            "--database-url-file",
            "/run/secrets/offline_outbox_drain_database_url",
        ],
        "read_only": True,
        "mem_limit": "384m",
        "cpus": 0.5,
        "pids_limit": 64,
        "tmpfs": ["/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64m"],
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "restart": "no",
    }
    inspector = {
        **copy.deepcopy(base),
        "profiles": [policy.INSPECT_PROFILE],
        "networks": ["offline-data"],
        "secrets": [
            {"source": "offline_outbox_drain_plan"},
            {"source": "offline_outbox_drain_database_url"},
        ],
    }
    drainer = {
        **copy.deepcopy(base),
        "profiles": [policy.APPLY_PROFILE],
        "networks": ["offline-data", "offline-bus"],
        "secrets": [
            {"source": "offline_outbox_drain_plan"},
            {"source": "offline_outbox_drain_receipt"},
            {"source": "offline_outbox_drain_receipt_signature"},
            {"source": "offline_outbox_drain_database_url"},
            {"source": "offline_outbox_drain_redis_url"},
        ],
    }
    secret_names = {
        "offline_outbox_drain_plan",
        "offline_outbox_drain_receipt",
        "offline_outbox_drain_receipt_signature",
        "offline_outbox_drain_database_url",
        "offline_outbox_drain_redis_url",
    }
    return {
        "name": policy.PROJECT,
        "services": {"outbox-drain-inspector": inspector, "outbox-drainer": drainer},
        "networks": {
            "offline-data": {"external": True, "name": "test-data"},
            "offline-bus": {"external": True, "name": "test-bus"},
        },
        "secrets": {name: {"file": f"/safe/{name}"} for name in secret_names},
    }


class OfflineOutboxDrainPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads((ROOT / "outbox-drain.sources.lock.json").read_text(encoding="utf-8"))
        self.packaged_lock = json.loads((TOOL_ROOT / "source-lock.json").read_text(encoding="utf-8"))
        self.compose = compose_fixture()

    def test_sealed_lock_signer_dockerfile_and_profile_are_accepted(self) -> None:
        self.assertEqual(self.lock, self.packaged_lock)
        self.assertEqual(policy.validate_source_lock(self.lock), [])
        self.assertEqual(policy.validate_trusted_signer(TOOL_ROOT / "trusted-signer.asc", self.lock), [])
        self.assertEqual(policy.validate_dockerfile((TOOL_ROOT / "Dockerfile").read_text(encoding="utf-8")), [])
        self.assertEqual(policy.validate_dockerignore((TOOL_ROOT / ".dockerignore").read_text(encoding="utf-8")), [])
        self.assertEqual(policy.validate_compose(self.compose), [])

    def test_normal_up_cannot_start_a_drain_service(self) -> None:
        self.assertEqual(policy.normal_up_services(self.compose), set())
        self.assertEqual(
            policy.validate_normal_up_compose(
                {"name": policy.PROJECT, "services": {}, "x-outbox-drain-runtime": {"read_only": True}}
            ),
            [],
        )
        self.assertTrue(
            any(
                "must contain no offline outbox drain services" in error
                for error in policy.validate_normal_up_compose(
                    {"name": policy.PROJECT, "services": {"outbox-drainer": {}}}
                )
            )
        )

    def test_profile_rejects_egress_restart_and_scope_escape_hatches(self) -> None:
        broken = copy.deepcopy(self.compose)
        service = broken["services"]["outbox-drainer"]
        service["ports"] = ["443:443"]
        service["restart"] = "unless-stopped"
        service["environment"] = {"KAIROS_OPENAI_API_KEY": "forbidden"}
        service["networks"] = ["offline-data", "offline-bus", "egress"]
        errors = policy.validate_compose(broken)
        self.assertTrue(any("unsafe service option ports" in error for error in errors))
        self.assertTrue(any("automatic restart" in error for error in errors))
        self.assertTrue(any("runtime environment" in error for error in errors))
        self.assertTrue(any("network scope changed" in error for error in errors))

    def test_lock_rejects_mutable_pin_or_unbounded_scope(self) -> None:
        broken = copy.deepcopy(self.lock)
        broken["dependencies"]["kairos-persistence"]["revision"] = "main"
        broken["profile"]["maximum_rows"] = 101
        errors = policy.validate_source_lock(broken)
        self.assertTrue(any("exact source pins" in error for error in errors))
        self.assertTrue(any("exact and bounded" in error for error in errors))


class OfflineOutboxDrainRunnerTests(unittest.TestCase):
    def plan(self):
        return runner.DrainPlan.from_json(plan_value())

    def row(self, row_id: int = 11) -> dict[str, object]:
        payload = {"message_id": f"bar-{row_id}", "symbol": "BTCUSDT", "open_time_ms": row_id * 60_000}
        encoded = runner.canonical_json(payload)
        return {
            "id": row_id,
            "producer": "kairos-quant-scouts",
            "message_id": payload["message_id"],
            "topic": "kairos.market.closed_bar.v1",
            "payload": encoded,
            "payload_sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
            "publish_attempts": 0,
            "published_at": None,
            "dead_lettered_at": None,
            "lease_clear": True,
            "available": True,
            "reconciliation_state": "NONE",
        }

    def receipt(self, *, inspected_at: datetime = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)):
        rows = [self.row(11), self.row(12)]
        return runner.build_inspection_receipt(
            self.plan(),
            database_name="kairos",
            migrations=policy.REQUIRED_MIGRATIONS,
            rows=rows,
            audit_rows={
                str(row["message_id"]): [{"topic": row["topic"], "payload": row["payload"]}]
                for row in rows
            },
            global_counts={"leased": 0, "ambiguous": 0, "dead_lettered": 0, "producer_pending": 2},
            inspected_at=inspected_at,
        )

    def test_plan_is_explicit_allow_listed_and_bounded(self) -> None:
        parser = runner.parser()
        args = parser.parse_args(["--plan", "plan.json", "--database-url-file", "database_url"])
        self.assertEqual(args.mode, "inspect")
        for key, value in (("producer", "other"), ("topic", "other"), ("maximum_rows", 101)):
            malformed = plan_value()
            malformed[key] = value
            with self.assertRaises(runner.DrainInputError):
                runner.DrainPlan.from_json(malformed)

    def test_inspection_receipt_is_exact_redacted_and_freshly_bound(self) -> None:
        receipt = self.receipt()
        rendered = runner.canonical_json(receipt)
        self.assertEqual(receipt["inspection"]["result"], "ELIGIBLE")
        self.assertNotIn('"payload"', rendered)
        self.assertNotIn("postgres://", rendered)
        self.assertNotIn("redis://", rendered)
        identities = runner.validate_apply_receipt(
            receipt,
            self.plan(),
            expected_file_sha256=hashlib.sha256((rendered + "\n").encode("utf-8")).hexdigest(),
            actual_file_sha256=hashlib.sha256((rendered + "\n").encode("utf-8")).hexdigest(),
            now=datetime(2026, 9, 19, 12, 1, tzinfo=UTC),
        )
        self.assertEqual([identity.id for identity in identities], [11, 12])

    def test_schema_or_lease_drift_rejects_before_any_apply(self) -> None:
        row = self.row()
        receipt = runner.build_inspection_receipt(
            self.plan(),
            database_name="kairos",
            migrations=policy.REQUIRED_MIGRATIONS[:-1],
            rows=[row],
            audit_rows={str(row["message_id"]): [{"topic": row["topic"], "payload": row["payload"]}]},
            global_counts={"leased": 1, "ambiguous": 0, "dead_lettered": 0, "producer_pending": 1},
        )
        self.assertEqual(receipt["inspection"]["result"], "REJECTED")
        self.assertFalse(receipt["inspection"]["checks"]["schema_matches"])
        self.assertFalse(receipt["inspection"]["checks"]["no_global_leases"])

    def test_edited_or_stale_receipt_is_rejected_before_apply(self) -> None:
        receipt = self.receipt()
        rendered = runner.canonical_json(receipt)
        edited = copy.deepcopy(receipt)
        edited["inspection"]["identities"][0]["id"] = 999
        with self.assertRaises(runner.DrainInputError):
            runner.validate_apply_receipt(
                edited,
                self.plan(),
                expected_file_sha256=hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                actual_file_sha256=hashlib.sha256(runner.canonical_json(edited).encode("utf-8")).hexdigest(),
                now=datetime(2026, 9, 19, 12, 1, tzinfo=UTC),
            )
        with self.assertRaises(runner.DrainInputError):
            runner.validate_apply_receipt(
                receipt,
                self.plan(),
                expected_file_sha256=hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                actual_file_sha256=hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                now=datetime(2026, 9, 19, 12, 6, tzinfo=UTC),
            )

    def test_acceptance_receipt_is_redacted_and_never_claims_downstream_processing(self) -> None:
        identities = runner.receipt_identities(self.receipt())
        result = runner._acceptance_payload(
            self.plan(),
            receipt_sha256="a" * 64,
            signed_identities=identities,
            acknowledged=identities[:1],
            state="PUBLISH_OUTCOME_UNKNOWN",
        )
        rendered = runner.canonical_json(result)
        self.assertEqual(result["state"], "PUBLISH_OUTCOME_UNKNOWN")
        self.assertNotIn('"payload"', rendered)
        self.assertNotIn("processed", rendered.casefold())

    def test_signature_verification_uses_only_the_pinned_public_signer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "inspection.json"
            signature = Path(directory) / "inspection.json.asc"
            receipt.write_text("{}\n", encoding="utf-8")
            signature.write_text("safe-test-signature\n", encoding="utf-8")
            completed = [
                runner.subprocess.CompletedProcess(args=["gpg"], returncode=0, stdout="", stderr=""),
                runner.subprocess.CompletedProcess(
                    args=["gpgv"],
                    returncode=0,
                    stdout="[GNUPG:] VALIDSIG 40AF365C6682B73D056A6A274DBFF6B65BE9F827 2026-09-19 0 4 0 22 8 00 40AF365C6682B73D056A6A274DBFF6B65BE9F827\n",
                    stderr="",
                ),
            ]
            with mock.patch.object(runner.subprocess, "run", side_effect=completed) as execute:
                runner.verify_receipt_signature(receipt, signature)
            import_call, verify_call = execute.call_args_list
            self.assertIn("--no-default-keyring", import_call.args[0])
            self.assertIn("--keyring", verify_call.args[0])
            self.assertIn(str(signature), verify_call.args[0])
            self.assertIn(str(receipt), verify_call.args[0])


class OfflineOutboxDrainWrapperTests(unittest.TestCase):
    def test_wrapper_is_profile_run_only_and_never_authorizes_a_dynamic_queue(self) -> None:
        wrapper = (ROOT / "scripts" / "Invoke-OfflineOutboxDrain.ps1").read_text(encoding="utf-8")
        self.assertIn('[string]$Mode = "Inspect"', wrapper)
        self.assertIn("Assert-ExactPlan", wrapper)
        self.assertIn("-ArmApply", wrapper)
        self.assertIn("Test-DetachedReceiptSignature", wrapper)
        self.assertIn("Get-FileHash -Algorithm SHA256", wrapper)
        self.assertIn("run --rm --no-deps", wrapper)
        self.assertNotIn("claim_outbox", wrapper)
        self.assertNotIn("docker compose up", wrapper.casefold())

    def test_runner_never_uses_a_dispatcher_or_retry_loop(self) -> None:
        source = (TOOL_ROOT / "runner.py").read_text(encoding="utf-8")
        self.assertIn("OfflineOutboxPrefixDrainer", source)
        self.assertIn("default_transaction_read_only", source)
        self.assertNotIn("DurableMessageBus", source)
        self.assertNotIn("_dispatch_outbox", source)
        self.assertNotIn("claim_outbox", source)
        self.assertNotIn("while True", source)
        self.assertNotIn("for attempt", source.casefold())


if __name__ == "__main__":
    unittest.main()
