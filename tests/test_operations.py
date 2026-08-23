from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.soak_reconnect import fetch_metrics, health_errors, parse_metrics, run_soak


class MetricsTests(unittest.TestCase):
    @staticmethod
    def clean_metrics() -> dict[str, float]:
        return {
            "kairos_persistence_up": 1,
            "kairos_redis_up": 1,
            "kairos_outbox_pending": 0,
            "kairos_outbox_dead_lettered_total": 0,
            "kairos_inbox_failed": 0,
            "kairos_inbox_processing_oldest_age_seconds": -1,
            "kairos_inbox_processing_expired": 0,
            "kairos_execution_effects_prepared": 0,
            "kairos_execution_effects_failed": 0,
            "kairos_outbox_oldest_age_seconds": 0,
        }

    @classmethod
    def clean_paper_metrics(cls) -> dict[str, float]:
        return {
            **cls.clean_metrics(),
            "kairos_closed_bar_gaps_24h": 0,
            "kairos_closed_bar_symbols_24h": 5,
            "kairos_closed_bar_minimum_coverage_ratio_24h": 1,
            "kairos_closed_bar_latest_age_seconds": 30,
            "kairos_venue_measurements_24h": 100,
            "kairos_venue_availability_ratio_24h": 0.995,
            "kairos_venue_poll_expected_24h": 14_400,
            "kairos_venue_poll_attempted_24h": 14_350,
            "kairos_venue_poll_succeeded_24h": 14_328,
            "kairos_venue_poll_failed_24h": 22,
            "kairos_venue_blocked_24h": 1,
            "kairos_venue_p95_abs_basis_bps": 3,
            "kairos_venue_p95_spread_bps": 4,
            "kairos_venue_p95_slippage_bps": 5,
            "kairos_venue_max_book_age_ms": 1_000,
            "kairos_venue_max_timestamp_skew_ms": 500,
            "kairos_venue_p95_latency_ms": 200,
            "kairos_venue_latest_age_seconds": 10,
            "kairos_paper_active_trades": 0,
            "kairos_paper_unprotected_trades": 0,
            "kairos_paper_recovery_blocked": 0,
            "kairos_execution_p95_shortfall_bps": 2,
            "kairos_paper_account_latest_age_seconds": 5,
            "kairos_api_spend_month_usd": 0,
            "kairos_execution_runtime_health_age_seconds": 5,
            "kairos_evedex_auth_age_seconds": 30,
            "kairos_evedex_auth_expires_in_seconds": 300,
            "kairos_evedex_local_mutation_reserve": 29,
            "kairos_evedex_local_mutation_capacity": 30,
            "kairos_evedex_local_mutation_compensation_reserve": 4,
            "kairos_evedex_local_mutation_window_seconds": 60,
            "kairos_evedex_venue_rate_limit_observable": 0,
            "kairos_evedex_venue_rate_limit_reserve": -1,
        }

    def test_parses_prometheus_and_requires_clean_durable_state(self) -> None:
        metrics = parse_metrics(
            """
# HELP ignored ignored
kairos_persistence_up 1
kairos_redis_up 1
kairos_outbox_pending 0
kairos_outbox_dead_lettered_total 0
kairos_inbox_failed 0
kairos_inbox_processing_oldest_age_seconds -1
kairos_inbox_processing_expired 0
kairos_execution_effects_prepared 0
kairos_execution_effects_failed 0
kairos_outbox_oldest_age_seconds 0
"""
        )
        self.assertEqual(health_errors(metrics), [])
        metrics["kairos_inbox_failed"] = 1
        self.assertEqual(health_errors(metrics), ["nonzero:kairos_inbox_failed"])

        metrics = self.clean_metrics()
        metrics["kairos_execution_effects_prepared"] = 1
        metrics["kairos_outbox_pending"] = 1
        metrics["kairos_outbox_oldest_age_seconds"] = 61
        errors = health_errors(metrics)
        self.assertIn("nonzero:kairos_execution_effects_prepared", errors)
        self.assertIn("outbox_backlog_stale", errors)

    def test_missing_metric_fails_closed(self) -> None:
        metrics = self.clean_metrics()
        del metrics["kairos_execution_effects_failed"]
        self.assertIn("missing:kairos_execution_effects_failed", health_errors(metrics))

    def test_paper_gate_enforces_integrity_tca_recovery_and_budget(self) -> None:
        metrics = self.clean_paper_metrics()
        self.assertEqual(health_errors(metrics, paper=True), [])
        metrics["kairos_closed_bar_gaps_24h"] = 1
        metrics["kairos_venue_p95_spread_bps"] = 25.1
        metrics["kairos_paper_recovery_blocked"] = 1
        metrics["kairos_api_spend_month_usd"] = 15.01
        metrics["kairos_venue_availability_ratio_24h"] = 0.98
        metrics["kairos_venue_max_book_age_ms"] = 5_001
        metrics["kairos_evedex_local_mutation_reserve"] = 3
        metrics["kairos_venue_poll_expected_24h"] = 0
        errors = health_errors(metrics, paper=True)
        self.assertIn("nonzero:kairos_closed_bar_gaps_24h", errors)
        self.assertIn("threshold:kairos_venue_p95_spread_bps", errors)
        self.assertIn("paper_recovery_blocked", errors)
        self.assertIn("api_qualification_budget_exceeded", errors)
        self.assertIn("venue_availability_below_0.99", errors)
        self.assertIn("threshold:kairos_venue_max_book_age_ms", errors)
        self.assertIn("evedex_compensation_reserve_exhausted", errors)
        self.assertIn("venue_poll_schedule_incomplete", errors)

        metrics = self.clean_paper_metrics()
        metrics["kairos_paper_account_latest_age_seconds"] = -1
        self.assertIn(
            "paper_account_snapshot_stale", health_errors(metrics, paper=True)
        )

    def test_metrics_url_rejects_non_http_scheme(self) -> None:
        with self.assertRaisesRegex(ValueError, "http or https"):
            fetch_metrics("file:///run/secrets/redis_url")

    @patch("scripts.soak_reconnect.time.sleep")
    @patch("scripts.soak_reconnect.time.monotonic", side_effect=[0, 0, 1, 2, 3, 4, 5])
    @patch("scripts.soak_reconnect.subprocess.run")
    @patch("scripts.soak_reconnect.fetch_metrics")
    def test_restart_is_explicit_and_recovery_is_observed(
        self, fetch, run, _clock, _sleep
    ) -> None:
        fetch.side_effect = [self.clean_metrics(), self.clean_metrics()]
        summary = run_soak(
            metrics_url="http://metrics",
            duration_s=3,
            interval_s=1,
            restart_at_s=1,
            restart_command=["docker", "compose", "restart", "redis"],
        )
        self.assertTrue(summary.restart_executed)
        self.assertTrue(summary.recovered_after_restart)
        self.assertEqual(summary.measured_availability, 1.0)
        run.assert_called_once_with(
            ["docker", "compose", "restart", "redis"], check=True
        )

    @patch("scripts.soak_reconnect.time.sleep")
    @patch(
        "scripts.soak_reconnect.time.monotonic",
        side_effect=[0, 0, 0, 1, 1, 1, 2, 2],
    )
    @patch("scripts.soak_reconnect.fetch_metrics")
    def test_transient_durable_failure_remains_terminal(
        self, fetch, _clock, _sleep
    ) -> None:
        failed = self.clean_metrics()
        failed["kairos_execution_effects_failed"] = 1
        fetch.side_effect = [failed, self.clean_metrics()]
        summary = run_soak(
            metrics_url="http://metrics",
            duration_s=2,
            interval_s=1,
            restart_at_s=None,
            restart_command=None,
        )
        self.assertIn(
            "nonzero:kairos_execution_effects_failed", summary.terminal_errors
        )

    @patch("scripts.soak_reconnect.time.sleep")
    @patch(
        "scripts.soak_reconnect.time.monotonic",
        side_effect=[0, 0, 0, 1, 1, 1, 2, 2],
    )
    @patch("scripts.soak_reconnect.fetch_metrics")
    def test_paper_rolling_window_can_mature_during_one_observation(
        self, fetch, _clock, _sleep
    ) -> None:
        warming = self.clean_paper_metrics()
        warming["kairos_closed_bar_symbols_24h"] = 1
        warming["kairos_closed_bar_minimum_coverage_ratio_24h"] = 0.01
        warming["kairos_venue_measurements_24h"] = 1
        warming["kairos_venue_availability_ratio_24h"] = 0.01
        fetch.side_effect = [warming, self.clean_paper_metrics()]

        summary = run_soak(
            metrics_url="http://metrics",
            duration_s=2,
            interval_s=1,
            restart_at_s=None,
            restart_command=None,
            paper=True,
        )

        self.assertEqual(summary.measured_availability, 1.0)
        self.assertEqual(summary.terminal_errors, ())

    @patch("scripts.soak_reconnect.time.sleep")
    @patch(
        "scripts.soak_reconnect.time.monotonic",
        side_effect=[0, 0, 0, 1, 1, 1, 2, 2],
    )
    @patch("scripts.soak_reconnect.fetch_metrics")
    def test_soak_cannot_pass_below_required_availability(
        self, fetch, _clock, _sleep
    ) -> None:
        fetch.side_effect = [OSError("down"), self.clean_metrics()]
        summary = run_soak(
            metrics_url="http://metrics",
            duration_s=2,
            interval_s=1,
            restart_at_s=None,
            restart_command=None,
            minimum_availability=0.99,
        )
        self.assertEqual(summary.measured_availability, 0.5)
        self.assertIn("availability_below_0.9900", summary.terminal_errors)


class PowerShellScriptTests(unittest.TestCase):
    def test_backup_and_recovery_are_scoped_and_do_not_overwrite_primary_database(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        backup = (root / "scripts" / "Backup-Kairos.ps1").read_text(encoding="utf-8")
        recovery = (root / "scripts" / "Test-Recovery.ps1").read_text(encoding="utf-8")
        self.assertIn("com.docker.compose.project", backup)
        self.assertIn("{{json .Config.Labels}}", backup)
        self.assertIn("{{json .Config.Labels}}", recovery)
        self.assertNotIn("{{ index .Config.Labels", backup)
        self.assertNotIn("{{ index .Config.Labels", recovery)
        self.assertIn("pg_dump", backup)
        self.assertIn("Get-FileHash", backup)
        self.assertIn("kairos_restore_drill_", recovery)
        self.assertIn("timescaledb_pre_restore()", recovery)
        self.assertIn("timescaledb_post_restore()", recovery)
        self.assertIn("pg_restore --exit-on-error", recovery)
        self.assertIn("docker exec --user=root", recovery)
        self.assertIn("dropdb --if-exists --force", recovery)
        self.assertIn("public_execution_events", recovery)
        self.assertIn("paper_canary_arms", recovery)
        self.assertIn("execution_mutation_reservations", recovery)
        self.assertIn("[int]$migrationCount -lt 11", recovery)
        self.assertNotIn("--dbname=$manifest.database", recovery)
        self.assertIn("$manifest.compose_project -ne $ComposeProject", recovery)
        self.assertIn("$manifest.database -ne $Database", recovery)
        self.assertIn('$name = "$ComposeProject-$stamp.dump"', backup)
        self.assertIn("checkpoints = $checkpointsAfter", backup)
        self.assertIn("Database changed during backup checkpoint", backup)
        self.assertIn("Refusing to qualify an empty backup", backup)
        self.assertIn("Restored row count differs", recovery)
        self.assertIn("public_execution_events_max_sequence", recovery)
        for table in (
            "event_audit",
            "execution_orders",
            "position_snapshots",
            "source_cursors",
            "source_usage_reservations",
            "execution_recovery_state",
            "execution_runtime_health",
            "execution_mutation_budget_scopes",
            "execution_mutation_reservations",
        ):
            with self.subTest(table=table):
                self.assertIn(f'"{table}"', backup)
                self.assertIn(f'"{table}"', recovery)


if __name__ == "__main__":
    unittest.main()
