"""Database/Docker-free boundary tests for the isolated runtime delivery probe."""

from __future__ import annotations

import ast
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "controlled_runtime_delivery_probe.py"


def _load_probe():
    specification = importlib.util.spec_from_file_location(
        "controlled_runtime_delivery_probe_unit", SCRIPT_PATH
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


probe = _load_probe()


class ProbeBoundaryTests(unittest.TestCase):
    def test_duplicate_delivery_does_not_create_an_extra_audit_row(self) -> None:
        counts = {
            "outbox_rows": 2,
            "inbox_rows": 2,
            "audit_rows": 2,
            "execution_orders": 0,
        }
        probe.require_fixture_counts(counts)
        for change in (
            {"audit_rows": 3},
            {"execution_orders": 1},
            {"outbox_rows": 1},
            {"execution_orders": False},
        ):
            with self.subTest(change=change), self.assertRaises(probe.ProbeError):
                probe.require_fixture_counts({**counts, **change})

    def test_each_durable_bus_uses_the_explicit_short_fixture_settings(self) -> None:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "DurableMessageBus"
        ]
        self.assertEqual(len(calls), 3)
        for call in calls:
            settings = [
                keyword.value for keyword in call.keywords if keyword.arg == "settings"
            ]
            self.assertEqual(len(settings), 1)
            self.assertIsInstance(settings[0], ast.Name)
            self.assertEqual(settings[0].id, "runtime_settings")

    def test_fixture_wire_payload_has_required_durable_metadata(self) -> None:
        from datetime import datetime

        for phase, suffix in (
            ("committed-delivery", "success"),
            ("publish-db-ack-loss", "ack-loss"),
        ):
            with self.subTest(phase=phase):
                value = probe.fixture_payload("012345abcdef", "a" * 32, phase)
                self.assertEqual(
                    value["message_id"], "probe-" + "a" * 32 + "-" + suffix
                )
                self.assertEqual(value["source"], "probe-producer-012345abcdef")
                self.assertEqual(value["schema_version"], "1.0")
                self.assertEqual(
                    datetime.fromisoformat(value["produced_at"].replace("Z", "+00:00"))
                    .utcoffset()
                    .total_seconds(),
                    0,
                )
                self.assertIs(value["synthetic_fixture"], True)
        with self.assertRaises(probe.ProbeError):
            probe.fixture_payload("012345abcdef", "a" * 32, "unreviewed-phase")

    def test_operator_privileges_are_sql_tokens_not_comma_joined_characters(
        self,
    ) -> None:
        statements = probe.operator_control_grant_sql(
            "kairos_probe_runtime_012345abcdef"
        )
        self.assertEqual(
            statements,
            (
                (
                    "GRANT SELECT ON TABLE operator_controls,operator_control_commands,"
                    "operator_control_admissions,operator_control_dispatch_claims "
                    'TO "kairos_probe_runtime_012345abcdef"'
                ),
                (
                    "GRANT INSERT ON TABLE operator_control_admissions,"
                    'operator_control_dispatch_claims TO "kairos_probe_runtime_012345abcdef"'
                ),
            ),
        )
        with self.assertRaises(probe.ProbeError):
            probe.operator_control_grant_sql("kairos")

    def test_jsonb_text_and_decoded_object_have_the_same_canonical_payload(
        self,
    ) -> None:
        import json

        value = {"message_id": "synthetic-only", "fixture": True}
        expected = '{"fixture":true,"message_id":"synthetic-only"}'
        self.assertEqual(probe.canonical_database_payload(value), expected)
        self.assertEqual(probe.canonical_database_payload(json.dumps(value)), expected)
        for invalid in ("invalid JSON", '"JSON string"', "[]", [], None):
            with self.subTest(value=invalid), self.assertRaises(probe.ProbeError):
                probe.canonical_database_payload(invalid)

    def test_failure_diagnostic_never_contains_exception_strings(self) -> None:
        diagnostic = probe.failure_diagnostic(
            TypeError("secret credential or backend SQL"), {"stage": "BUS_START"}
        )
        self.assertEqual(diagnostic, {"error_type": "TypeError", "stage": "BUS_START"})
        self.assertNotIn("secret", str(diagnostic))

    def test_unknown_exception_type_and_untrusted_stage_are_not_emitted(self) -> None:
        unknown = type("SensitiveSecretException", (Exception,), {})
        self.assertEqual(
            probe.failure_diagnostic(unknown("private"), {"stage": "private SQL"}),
            {"error_type": "OTHER", "stage": "ADMISSION"},
        )
        with self.assertRaises(probe.ProbeError):
            probe._stage({}, "private SQL")

    def test_only_explicit_owner_scoped_probe_database_is_accepted(self) -> None:
        name, owner = probe.require_database_name("kairos_runtime_probe_012345abcdef")
        self.assertEqual(name, "kairos_runtime_probe_012345abcdef")
        self.assertEqual(owner, "012345abcdef")
        for value in (
            "kairos",
            "postgres",
            "kairos_sim",
            "kairos_sim_012345abcdef",
            "kairos_runtime_probe_012345abcde",
            "kairos_runtime_probe_012345abcdef0",
            "kairos_runtime_probe_012345ABCDEF",
            "kairos_runtime_probe_012345abcdef; DROP DATABASE kairos",
            "kairos_runtime_probe_012345abcdef/other",
        ):
            with self.subTest(value=value), self.assertRaises(probe.ProbeError):
                probe.require_database_name(value)

    def test_urls_are_derived_for_the_two_fixed_local_roles(self) -> None:
        database = "kairos_runtime_probe_012345abcdef"
        self.assertEqual(
            probe.database_url(database),
            f"postgresql://kairos@127.0.0.1:5432/{database}",
        )
        self.assertEqual(
            probe.database_url(database, "kairos_probe_runtime_012345abcdef"),
            f"postgresql://kairos_probe_runtime_012345abcdef@127.0.0.1:5432/{database}",
        )
        with self.assertRaises(probe.ProbeError):
            probe.database_url(database, "other")

    def test_identifier_quoting_accepts_only_generated_simple_identifiers(self) -> None:
        self.assertEqual(
            probe._identifier("kairos_runtime_probe_012345abcdef"),
            '"kairos_runtime_probe_012345abcdef"',
        )
        for value in ('kairos";DROP DATABASE kairos--', "kairos.sim", "kairos runtime"):
            with self.subTest(value=value), self.assertRaises(probe.ProbeError):
                probe._identifier(value)

    def test_evidence_directory_and_output_are_non_overwriting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="controlled-runtime-probe-") as temp:
            directory = Path(temp)
            self.assertEqual(
                probe.require_evidence_directory(directory), directory.resolve()
            )
            output = probe._evidence_file(directory, "012345abcdef")
            probe._write_evidence(output, {"status": "PASS"})
            self.assertTrue(output.is_file())
            with self.assertRaises(probe.ProbeError):
                probe._evidence_file(directory, "012345abcdef")
        with (
            tempfile.TemporaryDirectory(prefix="controlled-runtime-not-dir-") as temp,
            self.assertRaises(probe.ProbeError),
        ):
            probe.require_evidence_directory(Path(temp) / "missing")

    def test_runtime_grants_are_minimal_for_operator_control_api(self) -> None:
        self.assertEqual(
            probe.OPERATOR_CONTROL_MINIMUM_GRANTS,
            (
                (
                    "SELECT",
                    (
                        "operator_controls",
                        "operator_control_commands",
                        "operator_control_admissions",
                        "operator_control_dispatch_claims",
                    ),
                ),
                (
                    "INSERT",
                    ("operator_control_admissions", "operator_control_dispatch_claims"),
                ),
            ),
        )
        self.assertNotIn(
            "operator_controls", probe.OPERATOR_CONTROL_MINIMUM_GRANTS[1][1]
        )
        self.assertNotIn(
            "operator_control_commands", probe.OPERATOR_CONTROL_MINIMUM_GRANTS[1][1]
        )

    def test_probe_has_no_strategy_execution_or_provider_import_boundary(self) -> None:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        kairos_imports = {name for name in imports if name.startswith("kairos_")}
        self.assertEqual(
            kairos_imports,
            {
                "kairos_core.bus.redis_streams",
                "kairos_persistence",
                "kairos_persistence.database_target",
                "kairos_persistence.operator_control",
                "kairos_persistence.redis_acceptance_evidence",
                "kairos_persistence.repository",
            },
        )
        forbidden = (
            "strategy",
            "risk",
            "execution",
            "llm",
            "router",
            "httpx",
            "openai",
        )
        self.assertFalse(any(token in name for token in forbidden for name in imports))

    def test_cli_exposes_only_database_and_evidence_directory_targets(self) -> None:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        arguments = [
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ]
        self.assertEqual(set(arguments), {"--database", "--directory"})
        self.assertEqual(len(arguments), 2)
        self.assertIn("127.0.0.1:5432", SCRIPT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(probe.REDIS_URL, "redis://127.0.0.1:6379/0")


class EvidenceResolutionProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_group_wait_retries_only_redis_missing_stream_response(self) -> None:
        try:
            from redis.exceptions import ResponseError
        except ImportError:
            raise unittest.SkipTest(
                "redis client is unavailable in this test environment"
            ) from None

        class MissingStream:
            async def xinfo_groups(self, _topic):
                raise ResponseError("no such key")

        class OtherError:
            async def xinfo_groups(self, _topic):
                raise ResponseError("NOPERM command not allowed")

        self.assertFalse(
            await probe._topic_has_group(MissingStream(), "synthetic-topic")
        )
        with self.assertRaisesRegex(ResponseError, "NOPERM"):
            await probe._topic_has_group(OtherError(), "synthetic-topic")

    async def test_exact_synthetic_row_evidence_resolves_idempotently_and_rejects_conflict(
        self,
    ) -> None:
        import hashlib
        import json

        try:
            from kairos_persistence.repository import AuditRepository
            from kairos_persistence.repository import (
                OfflineOutboxTransportResolutionState as State,
            )
        except ImportError:
            raise unittest.SkipTest(
                "current kairos-persistence Redis acceptance resolver is unavailable in this environment"
            ) from None

        payload = {
            "message_id": "probe-012345abcdef-ambiguous",
            "probe_namespace": "012345abcdef",
            "probe_phase": "publish-db-ack-loss",
            "synthetic_fixture": True,
        }
        payload_sha = hashlib.sha256(
            json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        ).hexdigest()
        row = {
            "id": 7,
            "producer": "probe-producer-012345abcdef",
            "message_id": payload["message_id"],
            "topic": "kairos.runtime.probe.012345abcdef.0123456789abcdef.ambiguous",
            "payload": json.dumps(payload),
            "payload_sha256": payload_sha,
            "publish_attempts": 1,
            "reconciliation_id": "reconcile-probe-only",
            "reconciliation_state": "PUBLISH_OUTCOME_UNKNOWN",
        }

        class Pool:
            async def fetchrow(self, _sql, *_args):
                return row

            async def fetchval(self, _sql, *_args):
                return "PUBLISH_OUTCOME_UNKNOWN"

        class Redis:
            async def info(self, section):
                assert section == "server"
                return {"run_id": "a" * 40}

            async def xrange(self, topic, *, min, max):
                assert topic == row["topic"] and min == "-" and max == "+"
                return [("1791624000000-0", {"data": json.dumps(payload)})]

        outcomes = iter(
            SimpleNamespace(state=state)
            for state in (
                State.RESOLVED,
                State.ALREADY_RESOLVED,
                State.REJECTED,
            )
        )

        async def resolve(_self, _identity, *, reconciliation_id, evidence):
            assert reconciliation_id == row["reconciliation_id"]
            return next(outcomes)

        with patch.object(
            AuditRepository, "resolve_unknown_outbox_from_redis_evidence", resolve
        ):
            receipt = await probe._resolve_redis_acceptance(
                SimpleNamespace(pool=Pool()),
                SimpleNamespace(_redis=Redis()),
                row["topic"],
                row["producer"],
                row["message_id"],
                "probe-0123456789abcdef",
            )

        self.assertEqual(receipt["unique_match_count"], 1)
        self.assertEqual(receipt["resolved_state"], "RESOLVED")
        self.assertEqual(receipt["repeat_state"], "ALREADY_RESOLVED")
        self.assertEqual(receipt["conflicting_evidence_state"], "REJECTED")
        self.assertEqual(receipt["evidence"]["stream_ids"], ["1791624000000-0"])
        self.assertNotIn("payload", receipt["evidence"])

    async def test_outbox_wait_ignores_preterminal_row_until_requested_state(
        self,
    ) -> None:
        states = iter(("PUBLISHING", "ACKNOWLEDGED"))

        class Pool:
            calls = 0

            async def fetchrow(self, _sql, *_args):
                self.calls += 1
                return {
                    "id": 1,
                    "publish_attempts": 1,
                    "published_at": None if self.calls == 1 else "committed",
                    "reconciliation_state": next(states),
                }

        row = await probe._wait_outbox(
            SimpleNamespace(pool=Pool()),
            "synthetic-producer",
            "synthetic-message",
            expected_states=frozenset({"ACKNOWLEDGED"}),
        )
        self.assertEqual(row["reconciliation_state"], "ACKNOWLEDGED")


if __name__ == "__main__":
    unittest.main()
