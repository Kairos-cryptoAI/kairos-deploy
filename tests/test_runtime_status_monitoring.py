"""Offline contracts for the opt-in runtime epoch status monitoring overlay."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _alert_block(rules: str, alert_name: str) -> str:
    match = re.search(
        rf"^      - alert: {re.escape(alert_name)}\n(?P<body>.*?)(?=^      - alert: |\Z)",
        rules,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing alert rule: {alert_name}")
    return match.group("body")


class RuntimeStatusMonitoringTests(unittest.TestCase):
    def test_overlay_is_opt_in_and_mounts_only_the_explicit_status_file_read_only(
        self,
    ) -> None:
        overlay = _text("docker-compose.runtime-status-monitoring.yml")
        self.assertEqual(
            re.findall(r"^  ([\w-]+):$", overlay, flags=re.MULTILINE),
            ["ops-exporter", "prometheus"],
        )
        self.assertIn(
            "KAIROS_RUNTIME_EPOCH_STATUS_PATH: /run/kairos-runtime/status.json",
            overlay,
        )
        self.assertIn(
            "KAIROS_RUNTIME_EPOCH_STATUS_OWNER: ${KAIROS_RUNTIME_EPOCH_STATUS_OWNER:?set the exact 32-hex runtime epoch owner}",
            overlay,
        )
        self.assertIn(
            "source: ${KAIROS_RUNTIME_EPOCH_STATUS_HOST_PATH:?set the exact host status.json path}",
            overlay,
        )
        self.assertIn("target: /run/kairos-runtime/status.json", overlay)
        self.assertIn("read_only: true", overlay)
        self.assertIn("create_host_path: false", overlay)
        self.assertNotIn("depends_on:", overlay)
        self.assertNotIn("command:", overlay)
        self.assertNotIn("secrets:", overlay)

    def test_runtime_prometheus_config_preserves_existing_scrape_and_adds_only_opt_in_rules(
        self,
    ) -> None:
        config = _text("monitoring/prometheus.runtime-status.yml")
        self.assertIn("job_name: kairos-durable-runtime", config)
        self.assertIn("- ops-exporter:9108", config)
        self.assertIn("- /etc/prometheus/alerts.yml", config)
        self.assertIn("- /etc/prometheus/runtime-epoch-alerts.yml", config)
        self.assertEqual(len(re.findall(r"^  - job_name:", config, re.MULTILINE)), 1)

    def test_rules_cover_freshness_failure_missingness_and_broken_observation(
        self,
    ) -> None:
        rules = _text("monitoring/runtime-epoch-alerts.yml")
        alert_names = re.findall(r"^      - alert: (\S+)$", rules, flags=re.MULTILINE)
        self.assertEqual(
            set(alert_names),
            {
                "KairosRuntimeEpochServeStatusUnavailable",
                "KairosRuntimeEpochServeStatusMissing",
                "KairosRuntimeEpochServeStatusInvalid",
                "KairosRuntimeEpochServeFailedClosed",
                "KairosRuntimeEpochServeStale",
            },
        )
        for name, metric in (
            ("KairosRuntimeEpochServeStatusMissing", "status_missing"),
            ("KairosRuntimeEpochServeStatusInvalid", "status_invalid"),
            ("KairosRuntimeEpochServeStatusInvalid", "status_unknown_owner"),
            ("KairosRuntimeEpochServeFailedClosed", "status_failed_closed"),
            ("KairosRuntimeEpochServeStale", "heartbeat_stale"),
        ):
            self.assertIn(
                f"kairos_runtime_epoch_serve_{metric}", _alert_block(rules, name)
            )
        self.assertIn(
            "absent(kairos_runtime_epoch_serve_status_age_seconds",
            _alert_block(rules, "KairosRuntimeEpochServeStatusUnavailable"),
        )
        self.assertEqual(rules.count("severity: critical"), len(alert_names))
        self.assertNotIn("reason", rules.lower())
        self.assertNotIn("error", rules.lower())

    def test_synthetic_rule_fixture_covers_every_alert_without_private_inputs(
        self,
    ) -> None:
        rules = _text("monitoring/runtime-epoch-alerts.yml")
        fixture = _text("monitoring/tests/runtime-epoch-alerts.test.yml")
        ruled = set(re.findall(r"^      - alert: (\S+)$", rules, flags=re.MULTILINE))
        tested = set(
            re.findall(r"^        alertname: (\S+)$", fixture, flags=re.MULTILINE)
        )
        self.assertEqual(tested, ruled)
        self.assertIn("- ../runtime-epoch-alerts.yml", fixture)
        self.assertIn("fresh running epoch remains healthy", fixture)
        self.assertIn("missing configured file alerts and recovers", fixture)
        self.assertIn("missing metrics signal broken observation path", fixture)
        self.assertNotIn("password", fixture.lower())

    def test_ci_runs_opt_in_config_and_synthetic_rule_fixture_with_pinned_offline_promtool(
        self,
    ) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("Validate opt-in runtime-status Prometheus config", workflow)
        self.assertIn(
            "check config /etc/prometheus/prometheus.runtime-status.yml", workflow
        )
        self.assertIn("/etc/prometheus/runtime-epoch-alerts.yml", workflow)
        step = workflow.split(
            "      - name: Test temporal base, PAPER, and runtime epoch alert rules without runtime access\n",
            1,
        )[1].split("      - name:", 1)[0]
        self.assertIn("--network none", step)
        self.assertIn("--read-only", step)
        self.assertIn("runtime-epoch-alerts.test.yml", step)
        self.assertIn(
            "test rules /work/tests/base-alerts.test.yml /work/tests/paper-alerts.test.yml /work/tests/runtime-epoch-alerts.test.yml",
            step,
        )
        self.assertNotIn("--env", step)
        self.assertNotIn("docker compose", step)


if __name__ == "__main__":
    unittest.main()
