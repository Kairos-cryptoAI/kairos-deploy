from __future__ import annotations

import copy
import unittest
from pathlib import Path

from scripts.validate_current_release_projection import (
    load_json,
    validate_current_release_projection,
)


ROOT = Path(__file__).resolve().parents[1]


class CurrentReleaseProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = load_json(ROOT / "current-release-gate.sources.lock.json")
        self.runtime = load_json(ROOT / "sources.lock.json")
        self.paper = load_json(ROOT / "paper.sources.lock.json")

    def test_runtime_and_paper_locks_match_current_shared_components(self) -> None:
        self.assertEqual(
            validate_current_release_projection(self.current, self.runtime, self.paper), []
        )

    def test_rejects_runtime_dependency_or_service_drift(self) -> None:
        runtime = copy.deepcopy(self.runtime)
        runtime["dependencies"]["kairos-persistence"] = "a" * 40
        runtime["services"]["execution-engine"]["revision"] = "b" * 40

        errors = validate_current_release_projection(self.current, runtime, self.paper)

        self.assertIn(
            "runtime dependency kairos-persistence differs from the current release lock", errors
        )
        self.assertIn(
            "runtime service execution-engine differs from current component kairos-execution-engine",
            errors,
        )

    def test_rejects_paper_dependency_or_service_drift(self) -> None:
        paper = copy.deepcopy(self.paper)
        paper["dependencies"]["kairos-core"] = "a" * 40
        paper["services"]["canary-controller"]["revision"] = "b" * 40

        errors = validate_current_release_projection(self.current, self.runtime, paper)

        self.assertIn("PAPER dependency kairos-core differs from the current release lock", errors)
        self.assertIn(
            "PAPER service canary-controller differs from current component kairos-risk-manager",
            errors,
        )


if __name__ == "__main__":
    unittest.main()
