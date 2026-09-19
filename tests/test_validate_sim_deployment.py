from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.validate_sim_deployment import load_json, policy, verify_remote_sources

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "sim.sources.lock.json"
FIXTURE_PATH = ROOT / "tests" / "sim_gate" / "compose.fixture.json"
DOCKERFILE_PATH = ROOT / "tests" / "sim_gate" / "Dockerfile"


class SimulatorManifestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = load_json(LOCK_PATH)
        self.compose = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    def test_current_sealed_manifest_and_fixture_are_accepted(self) -> None:
        self.assertEqual(policy.validate_source_lock(self.lock), [])
        self.assertEqual(
            policy.validate_dockerfile(
                DOCKERFILE_PATH.read_text(encoding="utf-8"), self.lock
            ),
            [],
        )
        self.assertEqual(policy.validate_compose(self.compose, self.lock), [])

    def test_execution_marker_and_dockerfile_match_manifest(self) -> None:
        revision = self.lock["dependencies"]["kairos-execution-engine"]["revision"]
        marker = (
            (ROOT / "tests" / "sim_gate" / "execution-revision.txt")
            .read_text(encoding="ascii")
            .strip()
        )
        dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.assertEqual(marker, revision)
        self.assertIn(f"git fetch --depth=1 origin {revision}", dockerfile)

    def test_rejects_shared_resources_and_non_sim_runtime(self) -> None:
        broken = copy.deepcopy(self.compose)
        broken["services"]["sim-gate"]["ports"] = ["443:443"]
        broken["services"]["sim-gate"]["environment"]["KAIROS_TRADING_MODE"] = "PAPER"
        broken["networks"]["isolated"]["external"] = True
        broken["volumes"] = {"paper-data": {"external": True}}
        errors = policy.validate_compose(broken, self.lock)
        self.assertTrue(any("unsafe" in error for error in errors))
        self.assertTrue(any("credential" in error for error in errors))
        self.assertTrue(any("external" in error for error in errors))
        self.assertTrue(any("volumes" in error for error in errors))

    def test_rejects_unpinned_or_ready_manifest(self) -> None:
        broken = copy.deepcopy(self.lock)
        broken["dependencies"]["kairos-core"]["revision"] = "main"
        broken["readiness"]["paper_qualified"] = True
        errors = policy.validate_source_lock(broken)
        self.assertTrue(any("immutable" in error for error in errors))
        self.assertTrue(any("fail-closed" in error for error in errors))

    def test_remote_verifier_is_not_used_by_hermetic_tests(self) -> None:
        self.assertTrue(callable(verify_remote_sources))


if __name__ == "__main__":
    unittest.main()
