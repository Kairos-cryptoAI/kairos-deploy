from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_current_release_projection import (
    load_json,
    main,
    validate_current_release_projection,
)

ROOT = Path(__file__).resolve().parents[1]


class CurrentReleaseProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = load_json(ROOT / "current-release-gate.sources.lock.json")
        self.runtime = load_json(ROOT / "sources.lock.json")
        self.paper = load_json(ROOT / "paper.sources.lock.json")
        self.composition = load_json(ROOT / "tests/text_macro_router_gate/source-lock.json")

    def test_runtime_and_paper_locks_match_current_shared_components(self) -> None:
        self.assertEqual(
            validate_current_release_projection(self.current, self.runtime, self.paper, self.composition), []
        )

    def test_rejects_runtime_dependency_or_service_drift(self) -> None:
        runtime = copy.deepcopy(self.runtime)
        runtime["dependencies"]["kairos-persistence"] = "a" * 40
        runtime["services"]["execution-engine"]["revision"] = "b" * 40

        errors = validate_current_release_projection(self.current, runtime, self.paper, self.composition)

        self.assertIn("runtime dependency kairos-persistence differs from the current release lock", errors)
        self.assertIn(
            "runtime service execution-engine differs from current component kairos-execution-engine",
            errors,
        )

    def test_rejects_paper_dependency_or_service_drift(self) -> None:
        paper = copy.deepcopy(self.paper)
        paper["dependencies"]["kairos-core"] = "a" * 40
        paper["services"]["canary-controller"]["revision"] = "b" * 40

        errors = validate_current_release_projection(self.current, self.runtime, paper, self.composition)

        self.assertIn("PAPER dependency kairos-core differs from the current release lock", errors)
        self.assertIn(
            "PAPER service canary-controller differs from current component kairos-risk-manager",
            errors,
        )

    def test_rejects_text_and_macro_runtime_drift(self) -> None:
        for service, component in (
            ("text-scouts", "kairos-text-scouts"),
            ("macro-strategist", "kairos-macro-strategist"),
        ):
            with self.subTest(service=service):
                runtime = copy.deepcopy(self.runtime)
                runtime["services"][service]["revision"] = "a" * 40
                errors = validate_current_release_projection(
                    self.current, runtime, self.paper, self.composition
                )
                self.assertIn(f"runtime service {service} differs from current component {component}", errors)

    def test_rejects_missing_text_macro_or_canonical_repository(self) -> None:
        for service in ("text-scouts", "macro-strategist"):
            for change in ("missing", "origin"):
                with self.subTest(service=service, change=change):
                    runtime = copy.deepcopy(self.runtime)
                    if change == "missing":
                        del runtime["services"][service]
                    else:
                        runtime["services"][service]["repository"] = "https://example.invalid/foreign"
                    errors = validate_current_release_projection(
                        self.current, runtime, self.paper, self.composition
                    )
                    self.assertIn(f"runtime service {service} has a noncanonical source", errors)

    def test_shared_composition_cannot_override_current_gate(self) -> None:
        for name in set(self.current["dependencies"]) & set(self.composition["dependencies"]):
            with self.subTest(name=name):
                composition = copy.deepcopy(self.composition)
                composition["dependencies"][name]["revision"] = "a" * 40
                errors = validate_current_release_projection(
                    self.current, self.runtime, self.paper, composition
                )
                self.assertIn(f"composition dependency {name} differs from the current release lock", errors)

    def test_text_macro_composition_drift_cannot_be_substituted(self) -> None:
        for component, service in (
            ("kairos-text-scouts", "text-scouts"),
            ("kairos-macro-strategist", "macro-strategist"),
        ):
            with self.subTest(component=component):
                composition = copy.deepcopy(self.composition)
                composition["dependencies"][component]["revision"] = "a" * 40
                errors = validate_current_release_projection(
                    self.current, self.runtime, self.paper, composition
                )
                self.assertIn(f"runtime service {service} differs from current component {component}", errors)

    def test_exact_fixture_sets_are_not_expanded_or_shrunk(self) -> None:
        for label in ("current", "composition"):
            for change in ("missing", "extra"):
                with self.subTest(label=label, change=change):
                    current, composition = copy.deepcopy(self.current), copy.deepcopy(self.composition)
                    lock = current if label == "current" else composition
                    if change == "missing":
                        del lock["dependencies"]["kairos-core"]
                    else:
                        lock["dependencies"]["kairos-foreign"] = {"revision": "a" * 40}
                    errors = validate_current_release_projection(
                        current, self.runtime, self.paper, composition
                    )
                    self.assertIn(f"{label} dependency set differs from its exact fixture scope", errors)

    def test_readiness_requires_literal_false_not_absent_falsy_or_truthy(self) -> None:
        for label in ("current", "composition"):
            for field in ("paper_qualified", "alpha_ready", "live_ready"):
                for value in (None, 0, 1, True, "false", [], {}):
                    with self.subTest(label=label, field=field, value=value):
                        current, composition = copy.deepcopy(self.current), copy.deepcopy(self.composition)
                        lock = current if label == "current" else composition
                        if value is None:
                            del lock["readiness"][field]
                        else:
                            lock["readiness"][field] = value
                        errors = validate_current_release_projection(
                            current, self.runtime, self.paper, composition
                        )
                        self.assertIn(f"{label} source lock must remain fail-closed", errors)

    def test_invalid_source_or_identity_fails_closed(self) -> None:
        for change in ("sha", "origin", "purpose", "classification", "schema", "dependencies", "readiness"):
            with self.subTest(change=change):
                composition = copy.deepcopy(self.composition)
                if change == "sha":
                    composition["dependencies"]["kairos-text-scouts"]["revision"] = "HEAD"
                elif change == "origin":
                    composition["dependencies"]["kairos-text-scouts"]["repository"] = (
                        "https://example.invalid/foreign"
                    )
                elif change == "schema":
                    composition["schema_version"] = True
                elif change in ("purpose", "classification"):
                    composition[change] = "HISTORICAL"
                else:
                    composition[change] = None
                self.assertTrue(
                    validate_current_release_projection(self.current, self.runtime, self.paper, composition)
                )

    def test_cli_requires_real_composition_lock_and_preserves_failure_exit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="kairos-projection-") as directory:
            paths = {}
            for name, value in (("current", self.current), ("runtime", self.runtime), ("paper", self.paper)):
                path = Path(directory) / f"{name}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                paths[name] = str(path)
            args = [
                "--current-release-lock",
                paths["current"],
                "--runtime-lock",
                paths["runtime"],
                "--paper-lock",
                paths["paper"],
                "--composition-lock",
                str(Path(directory) / "missing.json"),
            ]
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 2)
            composition = copy.deepcopy(self.composition)
            composition["dependencies"]["kairos-router"]["revision"] = "a" * 40
            path = Path(directory) / "composition.json"
            path.write_text(json.dumps(composition), encoding="utf-8")
            args[-1] = str(path)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)


if __name__ == "__main__":
    unittest.main()
