"""Verify runtime and PAPER locks are exact projections of the current source set.

The regular deployment validators prove that each profile is internally pinned.
That is not enough: a profile can be internally coherent while silently using an
older revision of a component included in the current release gate.  This
validator compares only shared components.  It deliberately does not require
profiles to launch every release component; PAPER, for example, intentionally
excludes LLM and alpha services.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

_RUNTIME_SERVICE_COMPONENTS = {
    "strategy-engine": "kairos-strategy-engine",
    "router": "kairos-router",
    "aggregator": "kairos-aggregator",
    "risk-manager": "kairos-risk-manager",
    "execution-engine": "kairos-execution-engine",
    "ops-exporter": "kairos-persistence",
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


def _current_revisions(lock: dict[str, Any], errors: list[str]) -> dict[str, str]:
    dependencies = _mapping(lock.get("dependencies"), label="current dependencies", errors=errors)
    revisions: dict[str, str] = {}
    for name, source in dependencies.items():
        if not isinstance(source, dict) or not isinstance(source.get("revision"), str):
            errors.append(f"current dependency {name} lacks a revision")
            continue
        revisions[str(name)] = source["revision"]
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
        if actual != expected.get(name):
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
        if actual != expected.get(component_name):
            errors.append(
                f"{profile_name} service {service_name} differs from current component {component_name}"
            )


def validate_current_release_projection(
    current_lock: dict[str, Any], runtime_lock: dict[str, Any], paper_lock: dict[str, Any]
) -> list[str]:
    """Return profile/source drift errors without granting runtime authority."""
    errors: list[str] = []
    current = _current_revisions(current_lock, errors)
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
    args = parser.parse_args(argv)
    try:
        errors = validate_current_release_projection(
            load_json(args.current_release_lock),
            load_json(args.runtime_lock),
            load_json(args.paper_lock),
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Current release projection validation could not start: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Runtime and PAPER source locks match their current-release projection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
