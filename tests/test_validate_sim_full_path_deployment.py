from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.validate_sim_full_path_deployment import (
    load_json,
    policy,
    verify_current_release_projection,
    verify_remote_sources,
)

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "sim-full-path.sources.lock.json"
PACKAGED_LOCK_PATH = ROOT / "tests" / "sim_full_path_gate" / "source-lock.json"
FIXTURE_PATH = ROOT / "tests" / "sim_full_path_gate" / "compose.fixture.json"
DOCKERFILE_PATH = ROOT / "tests" / "sim_full_path_gate" / "Dockerfile"
DOCKERIGNORE_PATH = ROOT / "tests" / "sim_full_path_gate" / ".dockerignore"


class FullPathSimulatorManifestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = load_json(LOCK_PATH)
        self.packaged_lock = load_json(PACKAGED_LOCK_PATH)
        self.compose = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    def test_sealed_manifest_projection_packaged_copy_and_fixture_are_accepted(self) -> None:
        self.assertEqual(policy.validate_source_lock(self.lock), [])
        self.assertEqual(verify_current_release_projection(self.lock), [])
        self.assertEqual(self.packaged_lock, self.lock)
        self.assertEqual(policy.validate_dockerfile(DOCKERFILE_PATH.read_text(encoding="utf-8")), [])
        self.assertEqual(policy.validate_dockerignore(DOCKERIGNORE_PATH.read_text(encoding="utf-8")), [])
        self.assertEqual(policy.validate_compose(self.compose), [])

    def test_rejects_durable_resources_authority_and_mutable_sources(self) -> None:
        compose = copy.deepcopy(self.compose)
        compose["services"]["gate"]["env_file"] = [".env"]
        compose["services"]["gate"]["environment"]["KAIROS_EVEDEX_API_KEY"] = "x"
        compose["networks"]["isolated"]["external"] = True
        compose["secrets"] = {"anything": {"file": "secrets/value"}}
        errors = policy.validate_compose(compose)
        self.assertTrue(any("unsafe" in error for error in errors))
        self.assertTrue(any("credential" in error for error in errors))
        self.assertTrue(any("internal" in error for error in errors))
        self.assertTrue(any("durable" in error for error in errors))

        lock = copy.deepcopy(self.lock)
        lock["dependencies"]["kairos-core"]["revision"] = "main"
        lock["readiness"]["live_ready"] = True
        lock_errors = policy.validate_source_lock(lock)
        self.assertTrue(any("immutable" in error for error in lock_errors))
        self.assertTrue(any("fail-closed" in error for error in lock_errors))

    def test_projection_and_remote_verifier_are_explicit(self) -> None:
        wrong = copy.deepcopy(self.lock)
        wrong["dependencies"]["kairos-core"]["revision"] = "0" * 40
        self.assertTrue(verify_current_release_projection(wrong))
        self.assertTrue(callable(verify_remote_sources))


if __name__ == "__main__":
    unittest.main()
