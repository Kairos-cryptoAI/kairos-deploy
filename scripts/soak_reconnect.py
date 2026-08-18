"""Observe durable-runtime health and optionally exercise an explicit Redis restart."""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404
import time
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

REQUIRED_METRICS = (
    "kairos_persistence_up",
    "kairos_redis_up",
    "kairos_outbox_pending",
    "kairos_outbox_dead_lettered_total",
    "kairos_inbox_failed",
    "kairos_execution_effects_prepared",
    "kairos_execution_effects_failed",
    "kairos_outbox_oldest_age_seconds",
)

ZERO_REQUIRED = (
    "kairos_outbox_dead_lettered_total",
    "kairos_inbox_failed",
    "kairos_execution_effects_failed",
)


def parse_metrics(payload: str) -> dict[str, float]:
    result: dict[str, float] = {}
    for raw in payload.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2 and "{" not in parts[0]:
            try:
                result[parts[0]] = float(parts[1])
            except ValueError:
                continue
    return result


def fetch_metrics(url: str) -> dict[str, float]:
    if urlsplit(url).scheme not in {"http", "https"}:
        raise ValueError("metrics URL must use http or https")
    request = urllib.request.Request(url, headers={"User-Agent": "kairos-soak/1.0"})
    with urllib.request.urlopen(request, timeout=5) as response:  # nosec B310
        return parse_metrics(response.read().decode("utf-8"))


def health_errors(metrics: dict[str, float]) -> list[str]:
    errors: list[str] = []
    for name in REQUIRED_METRICS:
        if name not in metrics:
            errors.append(f"missing:{name}")
    if metrics.get("kairos_persistence_up") != 1.0:
        errors.append("persistence_unavailable")
    if metrics.get("kairos_redis_up") != 1.0:
        errors.append("redis_unavailable")
    for name in ZERO_REQUIRED:
        if name in metrics and metrics[name] != 0.0:
            errors.append(f"nonzero:{name}")
    return errors


@dataclass(frozen=True)
class SoakSummary:
    samples: int
    healthy_samples: int
    transport_errors: int
    restart_executed: bool
    recovered_after_restart: bool
    terminal_errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "live_orders_allowed": False,
            "samples": self.samples,
            "healthy_samples": self.healthy_samples,
            "transport_errors": self.transport_errors,
            "restart_executed": self.restart_executed,
            "recovered_after_restart": self.recovered_after_restart,
            "terminal_errors": list(self.terminal_errors),
        }


def _write_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def run_soak(
    *,
    metrics_url: str,
    duration_s: float,
    interval_s: float,
    restart_at_s: float | None,
    restart_command: Sequence[str] | None,
) -> SoakSummary:
    started = time.monotonic()
    samples = healthy = transport_errors = 0
    restarted = recovered = False
    durable_failures: set[str] = set()
    last_errors: list[str] = ["no_samples"]
    while time.monotonic() - started < duration_s or samples == 0:
        elapsed = time.monotonic() - started
        if restart_at_s is not None and not restarted and elapsed >= restart_at_s:
            if not restart_command:
                raise ValueError("restart command is required when restart_at_s is set")
            subprocess.run(list(restart_command), check=True)  # nosec B603
            restarted = True
        try:
            metrics = fetch_metrics(metrics_url)
            samples += 1
            last_errors = health_errors(metrics)
            durable_failures.update(
                error
                for error in last_errors
                if error not in {"redis_unavailable", "metrics_unavailable"}
            )
            if not last_errors:
                healthy += 1
                if restarted:
                    recovered = True
        except (OSError, TimeoutError):
            transport_errors += 1
            last_errors = ["metrics_unavailable"]
        if time.monotonic() - started < duration_s:
            time.sleep(interval_s)
    return SoakSummary(
        samples=samples,
        healthy_samples=healthy,
        transport_errors=transport_errors,
        restart_executed=restarted,
        recovered_after_restart=(recovered if restarted else True),
        terminal_errors=tuple(sorted(durable_failures | set(last_errors))),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics-url", default="http://127.0.0.1:9108/metrics")
    parser.add_argument("--duration-s", type=float, default=1800)
    parser.add_argument("--interval-s", type=float, default=5)
    parser.add_argument("--restart-at-s", type=float)
    parser.add_argument("--restart-redis", action="store_true")
    parser.add_argument("--compose-project", default="kairos")
    parser.add_argument("--compose-file", type=Path, default=Path("docker-compose.yml"))
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.duration_s <= 0 or args.interval_s <= 0:
        parser.error("durations must be positive")
    if args.restart_at_s is not None and not args.restart_redis:
        parser.error("--restart-at-s requires --restart-redis")
    command = None
    if args.restart_redis:
        if args.restart_at_s is None:
            parser.error("--restart-redis requires --restart-at-s")
        command = [
            "docker",
            "compose",
            "-p",
            args.compose_project,
            "--env-file",
            str(args.env_file.resolve()),
            "-f",
            str(args.compose_file.resolve()),
            "restart",
            "redis",
        ]
    summary = run_soak(
        metrics_url=args.metrics_url,
        duration_s=args.duration_s,
        interval_s=args.interval_s,
        restart_at_s=args.restart_at_s,
        restart_command=command,
    )
    _write_atomic(args.report, summary.to_dict())
    print(json.dumps(summary.to_dict(), sort_keys=True))
    return 0 if not summary.terminal_errors and summary.recovered_after_restart else 1


if __name__ == "__main__":
    raise SystemExit(main())
