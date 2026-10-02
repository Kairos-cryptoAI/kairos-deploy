"""Static wiring checks; promtool performs the actual temporal rule evaluation."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROMETHEUS_IMAGE = (
    "prom/prometheus:v3.13.2@sha256:"
    "508729e0e2d18e11fd742a5a5ca70e557b940a93948c3c95fd0123a6fd538b69"
)


class TemporalAlertFixtureTests(unittest.TestCase):
    def test_availability_absence_uses_the_fixed_scrape_identity_and_same_labels(self) -> None:
        config = (ROOT / "monitoring" / "prometheus.yml").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"job_name:\s*(\S+)", config), ["kairos-durable-runtime"])
        self.assertIn("- ops-exporter:9108", config)
        metric_names = ("up", "kairos_persistence_up", "kairos_redis_up")
        for name in ("alerts.base.yml", "alerts.yml"):
            rules = (ROOT / "monitoring" / name).read_text(encoding="utf-8")
            availability = re.findall(r"      - alert: ([^\n]+)\n        expr: ([^\n]+)\n        for: ([^\n]+)", rules)[:3]
            self.assertEqual(len(availability), 3)
            for (_, expression, deadline), metric in zip(availability, metric_names, strict=True):
                selector = f'{metric}{{job="kairos-durable-runtime", instance="ops-exporter:9108"}}'
                self.assertEqual(expression, f"{selector} != 1 or absent({selector})")
                self.assertEqual(deadline, "30s")

    def test_base_rules_are_identical_to_the_common_paper_prefix(self) -> None:
        base = (ROOT / "monitoring" / "alerts.base.yml").read_text(encoding="utf-8")
        paper = (ROOT / "monitoring" / "alerts.yml").read_text(encoding="utf-8")
        self.assertTrue(paper.startswith(base))

    def test_both_fixtures_cover_every_rule_and_absence_recovery_boundaries(self) -> None:
        for fixture, rule_file in (("base-alerts.test.yml", "alerts.base.yml"), ("paper-alerts.test.yml", "alerts.yml")):
            fixture_text = (ROOT / "monitoring" / "tests" / fixture).read_text(encoding="utf-8")
            rule_text = (ROOT / "monitoring" / rule_file).read_text(encoding="utf-8")
            self.assertIn(f'"../{rule_file}"', fixture_text)
            self.assertIn('evaluation_interval: "15s"', fixture_text)
            self.assertIn('name: "healthy explicit boundaries never fire"', fixture_text)
            self.assertIn('name: "missing fixed target is unavailable not healthy"', fixture_text)
            self.assertIn('name: "stale samples start a fresh deadline and recover"', fixture_text)
            self.assertIn('name: "one failed scrape cannot satisfy the 30s deadline"', fixture_text)
            self.assertIn('name: "another instance cannot mask missing authoritative exporter"', fixture_text)
            self.assertIn('values: "1 1 stale _ _ _ 1x4"', fixture_text)
            for alertname in re.findall(r"      - alert: ([^\n]+)", rule_text):
                with self.subTest(fixture=fixture, alertname=alertname):
                    self.assertIn(f'alertname: "{alertname}"', fixture_text)

    def test_ci_runs_temporal_fixtures_with_pinned_provider_free_promtool(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        step = workflow.split("      - name: Test temporal base and PAPER alert rules without runtime access\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn(PROMETHEUS_IMAGE, step)
        for setting in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges:true", "--memory 256m", "--cpus 1", "--pids-limit 64"):
            self.assertIn(setting, step)
        self.assertEqual(step.count("--mount"), 4)
        self.assertEqual(step.count(",readonly"), 4)
        self.assertIn("test rules /work/tests/base-alerts.test.yml /work/tests/paper-alerts.test.yml", step)
        self.assertNotIn("docker compose", step)
        self.assertNotIn("--env", step)
        self.assertNotIn("--publish", step)
        self.assertNotIn("--volume", step)


if __name__ == "__main__":
    unittest.main()
