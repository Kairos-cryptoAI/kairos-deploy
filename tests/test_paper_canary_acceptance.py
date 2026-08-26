from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "paper_canary_acceptance.py"
SPEC = importlib.util.spec_from_file_location("paper_canary_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _trade(symbol: str, exit_reason: str) -> dict[str, object]:
    event_types = [
        "DECISION_RECEIVED",
        "ENTRY_FILLED",
        "EXIT_FILLED",
        "EXIT_TRIGGERED",
        "STOP_CREATED",
        "STOP_RECONCILED",
        "TARGET_CREATED",
        "TARGET_RECONCILED",
    ]
    return {
        "symbol": symbol,
        "venue_symbol": MODULE.EXPECTED_VENUE_SYMBOLS[symbol],
        "trading_mode": "PAPER",
        "profile": "DEV",
        "exchange": "evedex",
        "strategy_id": "technical-canary",
        "strategy_revision": "1",
        "state": "FLAT",
        "filled_quantity": 0.001,
        "marketable_ioc_limit": True,
        "next_bar_market": True,
        "decision_binding_valid": True,
        "event_types": sorted(event_types),
        "exit_reasons": [exit_reason],
        "public_event_count": len(event_types),
        "expected_public_event_count": len(event_types),
        "public_sequence_contiguous": True,
        "public_scope_valid": True,
        "protected_sequence_valid": True,
        "internal_failure_count": 0,
        "cancel_order_effects": 0,
        "real_fill_event_count": 1,
    }


def passing_evidence() -> dict[str, object]:
    trades = [
        _trade("BTCUSDT", "STOP"),
        _trade("ETHUSDT", "TARGET"),
        _trade("SOLUSDT", "TIMEOUT"),
        _trade("BNBUSDT", "TARGET"),
        _trade("XRPUSDT", "STOP"),
    ]
    trades[2]["cancel_order_effects"] = 1
    return {
        "schema_version": 1,
        "scope": {
            "environment": "paper:EVEDEX:DEV:PAPER",
            "trading_mode": "PAPER",
            "profile": "DEV",
            "exchange": "evedex",
            "account_id": "kairos-paper-dev-01",
        },
        "recovery": {
            "present": True,
            "entries_blocked": False,
            "recovery_epoch": 2,
            "completed": True,
            "protected_trade_crossed_epoch": True,
        },
        "integrity": {
            "prepared_effects": 0,
            "failed_effects": 0,
            "duplicate_client_order_ids": 0,
            "foreign_scope_trades": 0,
            "foreign_scope_effects": 0,
            "cancel_order_effects": 1,
            "real_fill_events": 5,
            "public_failure_events": 0,
        },
        "trades": trades,
    }


class EvaluatorTests(unittest.TestCase):
    def test_complete_five_symbol_suite_passes_and_is_secret_free(self) -> None:
        evidence = passing_evidence()
        report = MODULE.evaluate_evidence(evidence)
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["accepted"])
        rendered = MODULE.canonical_report_bytes(report).decode()
        self.assertNotIn("kairos-paper-dev-01", rendered)
        self.assertNotIn("trade-secret-identity", rendered)
        self.assertNotIn("order-secret-identity", rendered)
        self.assertNotIn("private", rendered.casefold())

    def test_evaluator_and_serialization_are_deterministic(self) -> None:
        evidence = passing_evidence()
        first = MODULE.canonical_report_bytes(MODULE.evaluate_evidence(evidence))
        second = MODULE.canonical_report_bytes(
            MODULE.evaluate_evidence(copy.deepcopy(evidence))
        )
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first), MODULE.evaluate_evidence(evidence))

    def test_empty_evidence_remains_pending(self) -> None:
        evidence = passing_evidence()
        evidence["trades"] = []
        evidence["integrity"]["real_fill_events"] = 0
        evidence["integrity"]["cancel_order_effects"] = 0
        report = MODULE.evaluate_evidence(evidence)
        self.assertEqual(report["status"], "PENDING")
        self.assertIn("PROTECTED_FLAT_ROUND_TRIPS_MISSING", report["pending_reasons"])
        self.assertIn("REAL_EVEDEX_DEV_FILL_NOT_OBSERVED", report["pending_reasons"])

    def test_every_required_symbol_needs_its_own_protected_round_trip(self) -> None:
        evidence = passing_evidence()
        evidence["trades"].pop()
        evidence["integrity"]["real_fill_events"] = 4
        report = MODULE.evaluate_evidence(evidence)
        self.assertEqual(report["status"], "PENDING")
        self.assertEqual(report["coverage"]["missing_symbols"], ["XRPUSDT"])

    def test_stop_target_timeout_market_limit_cancel_and_restart_are_independent_gates(
        self,
    ) -> None:
        cases = (
            ("recovery", "recovery_epoch", 1, "RESTART_RECOVERY_NOT_YET_PROVEN"),
            (
                "recovery",
                "protected_trade_crossed_epoch",
                False,
                "RESTART_RECOVERY_NOT_YET_PROVEN",
            ),
            (
                "integrity",
                "cancel_order_effects",
                0,
                "ENTRY_CANCEL_COVERAGE_INCOMPLETE",
            ),
        )
        for section, field, value, reason in cases:
            with self.subTest(reason=reason):
                evidence = passing_evidence()
                evidence[section][field] = value
                if field == "cancel_order_effects":
                    evidence["trades"][2]["cancel_order_effects"] = 0
                report = MODULE.evaluate_evidence(evidence)
                self.assertEqual(report["status"], "PENDING")
                self.assertIn(reason, report["pending_reasons"])

        for mutation in ("exit", "mechanism"):
            with self.subTest(mutation=mutation):
                evidence = passing_evidence()
                if mutation == "exit":
                    evidence["trades"][2]["exit_reasons"] = ["TARGET"]
                else:
                    evidence["trades"][0]["marketable_ioc_limit"] = False
                report = MODULE.evaluate_evidence(evidence)
                self.assertEqual(report["status"], "PENDING")
                expected = (
                    "STOP_TARGET_TIMEOUT_COVERAGE_INCOMPLETE"
                    if mutation == "exit"
                    else "MARKETABLE_IOC_LIMIT_COVERAGE_INCOMPLETE"
                )
                self.assertIn(expected, report["pending_reasons"])

    def test_unprotected_fill_fails_even_if_other_symbol_coverage_exists(self) -> None:
        evidence = passing_evidence()
        evidence["trades"][0]["event_types"].remove("STOP_RECONCILED")
        evidence["trades"][0]["public_event_count"] -= 1
        evidence["trades"][0]["expected_public_event_count"] -= 1
        report = MODULE.evaluate_evidence(evidence)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(
            "FILLED_TRADE_LACKS_PROTECTED_FLAT_ROUND_TRIP", report["failure_reasons"]
        )

    def test_duplicate_ids_and_unresolved_effects_fail_closed(self) -> None:
        for field in (
            "duplicate_client_order_ids",
            "prepared_effects",
            "failed_effects",
        ):
            with self.subTest(field=field):
                evidence = passing_evidence()
                evidence["integrity"][field] = 1
                report = MODULE.evaluate_evidence(evidence)
                self.assertEqual(report["status"], "FAIL")
                expected = (
                    "DUPLICATE_CLIENT_ORDER_IDS"
                    if field == "duplicate_client_order_ids"
                    else "UNRESOLVED_PREPARED_OR_FAILED_EFFECTS"
                )
                self.assertIn(expected, report["failure_reasons"])

    def test_nonterminal_failed_emergency_and_foreign_scope_facts_fail(self) -> None:
        variants = []
        nonterminal = passing_evidence()
        nonterminal["trades"][0]["state"] = "ACTIVE"
        variants.append(nonterminal)
        failed = passing_evidence()
        failed["trades"][0]["internal_failure_count"] = 1
        variants.append(failed)
        emergency = passing_evidence()
        emergency["trades"][0]["event_types"].append("EMERGENCY_CLOSE")
        emergency["trades"][0]["event_types"].sort()
        emergency["trades"][0]["public_event_count"] += 1
        emergency["trades"][0]["expected_public_event_count"] += 1
        emergency["integrity"]["public_failure_events"] = 1
        variants.append(emergency)
        foreign = passing_evidence()
        foreign["integrity"]["foreign_scope_trades"] = 1
        variants.append(foreign)
        for evidence in variants:
            with self.subTest(evidence=evidence):
                self.assertEqual(MODULE.evaluate_evidence(evidence)["status"], "FAIL")

    def test_atomic_public_fact_count_and_scope_are_required(self) -> None:
        for field, value in (
            ("public_event_count", 99),
            ("public_sequence_contiguous", False),
            ("public_scope_valid", False),
        ):
            with self.subTest(field=field):
                evidence = passing_evidence()
                evidence["trades"][0][field] = value
                report = MODULE.evaluate_evidence(evidence)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn(
                    "PUBLIC_LIFECYCLE_FACTS_ARE_NOT_ATOMIC_AND_CONTIGUOUS",
                    report["failure_reasons"],
                )

    def test_protection_must_precede_the_flat_exit(self) -> None:
        evidence = passing_evidence()
        evidence["trades"][0]["protected_sequence_valid"] = False
        report = MODULE.evaluate_evidence(evidence)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(
            "FILLED_TRADE_LACKS_PROTECTED_FLAT_ROUND_TRIP", report["failure_reasons"]
        )

    def test_decision_binding_and_exact_exit_attribution_fail_closed(self) -> None:
        invalid_binding = passing_evidence()
        invalid_binding["trades"][0]["decision_binding_valid"] = False
        report = MODULE.evaluate_evidence(invalid_binding)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(
            "TRADE_LINEAGE_OUTSIDE_TECHNICAL_CANARY_V1", report["failure_reasons"]
        )

        ambiguous_exit = passing_evidence()
        ambiguous_exit["trades"][0]["exit_reasons"] = ["STOP", "TARGET"]
        report = MODULE.evaluate_evidence(ambiguous_exit)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(
            "FILLED_TRADE_LACKS_PROTECTED_FLAT_ROUND_TRIP", report["failure_reasons"]
        )

        noncanonical_exit = passing_evidence()
        noncanonical_exit["trades"][0]["exit_reasons"] = ["EMERGENCY", "STOP"]
        report = MODULE.evaluate_evidence(noncanonical_exit)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(
            "FILLED_TRADE_LACKS_PROTECTED_FLAT_ROUND_TRIP", report["failure_reasons"]
        )

    def test_scope_and_strategy_revision_are_exact(self) -> None:
        evidence = passing_evidence()
        evidence["scope"]["profile"] = "PROD"
        evidence["scope"]["account_id"] = "shared-account"
        evidence["trades"][0]["strategy_revision"] = "2"
        report = MODULE.evaluate_evidence(evidence)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn(
            "SCOPE_IS_NOT_DEDICATED_EVEDEX_DEV_PAPER", report["failure_reasons"]
        )
        self.assertIn(
            "TRADE_LINEAGE_OUTSIDE_TECHNICAL_CANARY_V1", report["failure_reasons"]
        )

    def test_malformed_or_nonfinite_evidence_returns_sanitized_failure(self) -> None:
        evidence = passing_evidence()
        evidence["trades"][0]["filled_quantity"] = float("nan")
        report = MODULE.evaluate_evidence(evidence)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_reasons"], ["EVIDENCE_SCHEMA_INVALID"])
        self.assertNotIn(
            "nan", MODULE.canonical_report_bytes(report).decode().casefold()
        )


class CollectorTests(unittest.TestCase):
    def test_collector_uses_direct_compose_exec_psql_and_read_only_transaction(
        self,
    ) -> None:
        evidence = passing_evidence()
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(evidence) + "\n", stderr=""
        )
        with patch.object(MODULE.subprocess, "run", return_value=completed) as run:
            result = MODULE.collect_evidence(
                compose_file=Path("docker-compose.paper.yml"),
                env_file=Path(".env.paper"),
                account_id="kairos-paper-dev-01",
                kairos_environment="paper",
                database_user="kairos",
                database_name="kairos",
                timeout_seconds=30,
                project_name="kairos-paper-gate",
            )
        self.assertEqual(result, evidence)
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["docker", "compose", "-p", "kairos-paper-gate"])
        self.assertIn("exec", command)
        self.assertIn("-T", command)
        self.assertEqual(
            command[command.index("-T") + 1 : command.index("-T") + 3],
            ["timescaledb", "psql"],
        )
        sql = run.call_args.kwargs["input"]
        self.assertIn("REPEATABLE READ READ ONLY", sql)
        self.assertIn("e.order_role = 'ENTRY'", sql)
        self.assertIn("protected_trade_crossed_epoch", sql)
        self.assertIn("risk-trade-decision.v1", sql)
        self.assertIn("IS TRUE", sql)
        self.assertNotIn("INSERT ", sql.upper())
        self.assertNotIn("UPDATE ", sql.upper())
        self.assertNotIn("DELETE ", sql.upper())

    def test_collector_rejects_non_dedicated_account_before_subprocess(self) -> None:
        with (
            patch.object(MODULE.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "dedicated"),
        ):
            MODULE.collect_evidence(
                compose_file=Path("docker-compose.paper.yml"),
                env_file=Path(".env.paper"),
                account_id="production-account",
                kairos_environment="paper",
                database_user="kairos",
                database_name="kairos",
                timeout_seconds=30,
            )
        run.assert_not_called()

    def test_collector_rejects_project_outside_paper_namespace(self) -> None:
        with (
            patch.object(MODULE.subprocess, "run") as run,
            self.assertRaisesRegex(ValueError, "Compose project"),
        ):
            MODULE.collect_evidence(
                compose_file=Path("docker-compose.paper.yml"),
                env_file=Path(".env.paper"),
                account_id="kairos-paper-dev-01",
                kairos_environment="paper",
                database_user="kairos",
                database_name="kairos",
                timeout_seconds=30,
                project_name="production",
            )
        run.assert_not_called()

    def test_database_errors_are_not_copied_into_failure_report(self) -> None:
        report = MODULE.collection_failure_report()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            MODULE.write_report(path, report)
            rendered = path.read_text(encoding="utf-8")
        self.assertEqual(json.loads(rendered)["status"], "FAIL")
        self.assertNotIn("stderr", rendered.casefold())
        self.assertFalse(json.loads(rendered)["contains_credentials"])


if __name__ == "__main__":
    unittest.main()
