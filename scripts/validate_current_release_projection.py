"""Verify runtime and PAPER locks are exact projections of the current source set.

The regular deployment validators prove that each profile is internally pinned.
That is not enough: a profile can be internally coherent while silently using an
older revision of a component included in the current release gate.  This
validator compares the shared components of both current engineering gates. It
does not confuse the eight-component REJECT_ALL fixture with the separate
Text/Macro composition. The meta verifier additionally binds all runtime
services (including Quant) and both gate sets to its complete release manifest.
This validator deliberately does not require
profiles to launch every release component; PAPER, for example, intentionally
excludes LLM and alpha services.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

_RUNTIME_SERVICE_COMPONENTS = {
    "text-scouts": "kairos-text-scouts",
    "macro-strategist": "kairos-macro-strategist",
    "strategy-engine": "kairos-strategy-engine",
    "router": "kairos-router",
    "aggregator": "kairos-aggregator",
    "risk-manager": "kairos-risk-manager",
    "execution-engine": "kairos-execution-engine",
    "ops-exporter": "kairos-persistence",
}
_CURRENT_GATE_COMPONENTS = frozenset(
    {
        "kairos-core",
        "kairos-persistence",
        "kairos-llm",
        "kairos-strategy-engine",
        "kairos-router",
        "kairos-aggregator",
        "kairos-risk-manager",
        "kairos-execution-engine",
    }
)
_COMPOSITION_COMPONENTS = (_CURRENT_GATE_COMPONENTS - {"kairos-execution-engine"}) | {
    "kairos-text-scouts",
    "kairos-macro-strategist",
}
_PAPER_SERVICE_COMPONENTS = {
    "strategy-engine": "kairos-strategy-engine",
    "risk-manager": "kairos-risk-manager",
    "canary-controller": "kairos-risk-manager",
    "execution-engine": "kairos-execution-engine",
    "ops-exporter": "kairos-persistence",
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return value


def _mapping(value: Any, *, label: str, errors: list[str]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    errors.append(f"{label} must be an object")
    return {}


def _source_revisions(
    lock: dict[str, Any],
    *,
    label: str,
    purpose: str,
    classification: str,
    names: frozenset[str],
    errors: list[str],
) -> dict[str, str]:
    if (
        type(lock.get("schema_version")) is not int
        or lock["schema_version"] != 1
        or lock.get("purpose") != purpose
        or lock.get("classification") != classification
    ):
        errors.append(f"{label} source lock has an unexpected identity")
    readiness = lock.get("readiness")
    if (
        not isinstance(readiness, dict)
        or any(readiness.get(name) is not False for name in ("paper_qualified", "alpha_ready", "live_ready"))
        or readiness.get("strategy_policy") != "REJECT_ALL"
    ):
        errors.append(f"{label} source lock must remain fail-closed")
    dependencies = _mapping(lock.get("dependencies"), label=f"{label} dependencies", errors=errors)
    if set(dependencies) != names:
        errors.append(f"{label} dependency set differs from its exact fixture scope")
    revisions: dict[str, str] = {}
    for name in sorted(names):
        source = dependencies.get(name)
        if (
            not isinstance(source, dict)
            or source.get("repository") != f"https://github.com/Kairos-cryptoAI/{name}"
            or not isinstance(source.get("revision"), str)
            or re.fullmatch(r"[a-f0-9]{40}", source["revision"]) is None
        ):
            errors.append(f"{label} dependency {name} lacks an exact canonical source")
            continue
        revisions[name] = source["revision"]
    return revisions


def _check_dependencies(
    *,
    profile_name: str,
    dependencies: dict[str, Any],
    expected: dict[str, str],
    names: tuple[str, ...],
    errors: list[str],
) -> None:
    for name in names:
        actual = dependencies.get(name)
        if name not in expected or actual != expected[name]:
            errors.append(f"{profile_name} dependency {name} differs from the current release lock")


def _check_services(
    *,
    profile_name: str,
    services: dict[str, Any],
    component_map: dict[str, str],
    expected: dict[str, str],
    errors: list[str],
) -> None:
    for service_name, component_name in component_map.items():
        source = services.get(service_name)
        actual = source.get("revision") if isinstance(source, dict) else None
        if component_name not in expected or actual != expected[component_name]:
            errors.append(
                f"{profile_name} service {service_name} differs from current component {component_name}"
            )
        if (
            not isinstance(source, dict)
            or source.get("repository") != f"https://github.com/Kairos-cryptoAI/{component_name}"
        ):
            errors.append(f"{profile_name} service {service_name} has a noncanonical source")


def validate_current_release_projection(
    current_lock: dict[str, Any],
    runtime_lock: dict[str, Any],
    paper_lock: dict[str, Any],
    composition_lock: dict[str, Any],
) -> list[str]:
    """Return profile/source drift errors without granting runtime authority."""
    errors: list[str] = []
    current = _source_revisions(
        current_lock,
        label="current",
        purpose="current-release-reject-all-integration-gate",
        classification="ENGINEERING_ONLY",
        names=_CURRENT_GATE_COMPONENTS,
        errors=errors,
    )
    composition = _source_revisions(
        composition_lock,
        label="composition",
        purpose="real-producer-router-review-macro-risk-composed-contracts",
        classification="OFFLINE_ENGINEERING_FIXTURE",
        names=_COMPOSITION_COMPONENTS,
        errors=errors,
    )
    for name in sorted(_CURRENT_GATE_COMPONENTS & _COMPOSITION_COMPONENTS):
        if name not in current or composition.get(name) != current[name]:
            errors.append(f"composition dependency {name} differs from the current release lock")
    # Only the two components absent from the old eight-component gate are added.
    # Shared entries never override that gate's source identity.
    for name in sorted(_COMPOSITION_COMPONENTS - _CURRENT_GATE_COMPONENTS):
        if name in composition:
            current[name] = composition[name]
    runtime_dependencies = _mapping(
        runtime_lock.get("dependencies"), label="runtime dependencies", errors=errors
    )
    runtime_services = _mapping(runtime_lock.get("services"), label="runtime services", errors=errors)
    paper_dependencies = _mapping(paper_lock.get("dependencies"), label="PAPER dependencies", errors=errors)
    paper_services = _mapping(paper_lock.get("services"), label="PAPER services", errors=errors)

    _check_dependencies(
        profile_name="runtime",
        dependencies=runtime_dependencies,
        expected=current,
        names=("kairos-core", "kairos-llm", "kairos-persistence"),
        errors=errors,
    )
    _check_services(
        profile_name="runtime",
        services=runtime_services,
        component_map=_RUNTIME_SERVICE_COMPONENTS,
        expected=current,
        errors=errors,
    )
    _check_dependencies(
        profile_name="PAPER",
        dependencies=paper_dependencies,
        expected=current,
        names=("kairos-core", "kairos-persistence"),
        errors=errors,
    )
    _check_services(
        profile_name="PAPER",
        services=paper_services,
        component_map=_PAPER_SERVICE_COMPONENTS,
        expected=current,
        errors=errors,
    )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--current-release-lock", type=Path, default=Path("current-release-gate.sources.lock.json")
    )
    parser.add_argument("--runtime-lock", type=Path, default=Path("sources.lock.json"))
    parser.add_argument("--paper-lock", type=Path, default=Path("paper.sources.lock.json"))
    parser.add_argument(
        "--composition-lock", type=Path, default=Path("tests/text_macro_router_gate/source-lock.json")
    )
    args = parser.parse_args(argv)
    try:
        errors = validate_current_release_projection(
            load_json(args.current_release_lock),
            load_json(args.runtime_lock),
            load_json(args.paper_lock),
            load_json(args.composition_lock),
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Current release projection validation could not start: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Runtime and PAPER locks match the current REJECT_ALL and Text/Macro composition sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
