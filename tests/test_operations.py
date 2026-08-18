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
            "kairos_execution_effects_prepared": 0,
            "kairos_execution_effects_failed": 0,
            "kairos_outbox_oldest_age_seconds": 0,
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
kairos_execution_effects_prepared 0
kairos_execution_effects_failed 0
kairos_outbox_oldest_age_seconds 0
"""
        )
        self.assertEqual(health_errors(metrics), [])
        metrics["kairos_inbox_failed"] = 1
        self.assertEqual(health_errors(metrics), ["nonzero:kairos_inbox_failed"])

    def test_missing_metric_fails_closed(self) -> None:
        metrics = self.clean_metrics()
        del metrics["kairos_execution_effects_failed"]
        self.assertIn("missing:kairos_execution_effects_failed", health_errors(metrics))

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
        run.assert_called_once_with(
            ["docker", "compose", "restart", "redis"], check=True
        )

    @patch("scripts.soak_reconnect.time.sleep")
    @patch("scripts.soak_reconnect.time.monotonic", side_effect=[0, 0, 1, 2, 3])
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


class PowerShellScriptTests(unittest.TestCase):
    def test_backup_and_recovery_are_scoped_and_do_not_overwrite_primary_database(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        backup = (root / "scripts" / "Backup-Kairos.ps1").read_text(encoding="utf-8")
        recovery = (root / "scripts" / "Test-Recovery.ps1").read_text(encoding="utf-8")
        self.assertIn("com.docker.compose.project", backup)
        self.assertIn("pg_dump", backup)
        self.assertIn("Get-FileHash", backup)
        self.assertIn("kairos_restore_drill_", recovery)
        self.assertIn("pg_restore --exit-on-error", recovery)
        self.assertIn("dropdb --if-exists --force", recovery)
        self.assertNotIn("--dbname=$manifest.database", recovery)


if __name__ == "__main__":
    unittest.main()
