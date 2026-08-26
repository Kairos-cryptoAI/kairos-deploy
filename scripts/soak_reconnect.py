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
    "kairos_inbox_processing_oldest_age_seconds",
    "kairos_inbox_processing_expired",
    "kairos_execution_effects_prepared",
    "kairos_execution_effects_failed",
    "kairos_outbox_oldest_age_seconds",
)

ZERO_REQUIRED = (
    "kairos_outbox_dead_lettered_total",
    "kairos_inbox_failed",
    "kairos_inbox_processing_expired",
    "kairos_execution_effects_prepared",
    "kairos_execution_effects_failed",
)

MAX_OUTBOX_AGE_SECONDS = 60.0

PAPER_REQUIRED_METRICS = (
    "kairos_closed_bar_gaps_24h",
    "kairos_closed_bar_symbols_24h",
    "kairos_closed_bar_minimum_coverage_ratio_24h",
    "kairos_closed_bar_latest_age_seconds",
    "kairos_venue_measurements_24h",
    "kairos_venue_availability_ratio_24h",
    "kairos_venue_poll_expected_24h",
    "kairos_venue_poll_attempted_24h",
    "kairos_venue_poll_succeeded_24h",
    "kairos_venue_poll_failed_24h",
    "kairos_venue_blocked_24h",
    "kairos_venue_p95_abs_basis_bps",
    "kairos_venue_p95_spread_bps",
    "kairos_venue_p95_slippage_bps",
    "kairos_venue_max_book_age_ms",
    "kairos_venue_max_timestamp_skew_ms",
    "kairos_venue_p95_latency_ms",
    "kairos_venue_latest_age_seconds",
    "kairos_paper_active_trades",
    "kairos_paper_unprotected_trades",
    "kairos_paper_recovery_blocked",
    "kairos_execution_p95_shortfall_bps",
    "kairos_paper_account_latest_age_seconds",
    "kairos_api_spend_month_usd",
    "kairos_execution_runtime_health_age_seconds",
    "kairos_evedex_auth_age_seconds",
    "kairos_evedex_auth_expires_in_seconds",
    "kairos_evedex_local_mutation_reserve",
    "kairos_evedex_local_mutation_capacity",
    "kairos_evedex_local_mutation_compensation_reserve",
    "kairos_evedex_local_mutation_window_seconds",
    "kairos_evedex_venue_rate_limit_observable",
    "kairos_evedex_venue_rate_limit_reserve",
)

PAPER_ZERO_REQUIRED = (
    "kairos_closed_bar_gaps_24h",
    "kairos_paper_unprotected_trades",
)

# These predicates describe a rolling 24-hour evidence window.  A new PAPER
# database is expected to report them while that window fills; only the final
# sample may qualify the gate.  Counting warm-up as service downtime would make
# a documented 24-hour observation require an undocumented second 24 hours.
PAPER_WINDOW_READINESS_ERRORS = {
    "venue_measurements_missing",
    "closed_bar_symbol_coverage_incomplete",
    "closed_bar_coverage_below_0.999",
    "venue_availability_below_0.99",
    "venue_poll_schedule_incomplete",
}

# These facts are not ordinary transient health states.  Once observed during a
# qualification session they remain part of that session's failed evidence even
# if a later reconciliation or rolling window makes the current gauge look clean.
IRREVERSIBLE_QUALIFICATION_ERRORS = {
    "nonzero:kairos_outbox_dead_lettered_total",
    "nonzero:kairos_inbox_failed",
    "nonzero:kairos_execution_effects_failed",
    "nonzero:kairos_closed_bar_gaps_24h",
    "nonzero:kairos_paper_unprotected_trades",
    "venue_poll_fact_counts_inconsistent",
    "api_qualification_budget_exceeded",
    "evedex_mutation_budget_unsafe",
}


def _is_window_readiness_error(error: str) -> bool:
    return error in PAPER_WINDOW_READINESS_ERRORS or error.startswith("threshold:")


def _sample_availability_errors(errors: list[str], *, paper: bool) -> list[str]:
    if not paper:
        return errors
    return [error for error in errors if not _is_window_readiness_error(error)]


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


def fetch_metrics_command(command: Sequence[str]) -> dict[str, float]:
    if not command:
        raise ValueError("metrics command must not be empty")
    completed = subprocess.run(  # nosec B603
        list(command),
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return parse_metrics(completed.stdout)


def health_errors(metrics: dict[str, float], *, paper: bool = False) -> list[str]:
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
    if metrics.get("kairos_outbox_oldest_age_seconds", 0.0) > MAX_OUTBOX_AGE_SECONDS:
        errors.append("outbox_backlog_stale")
    if not paper:
        return errors
    for name in PAPER_REQUIRED_METRICS:
        if name not in metrics:
            errors.append(f"missing:{name}")
    for name in PAPER_ZERO_REQUIRED:
        if name in metrics and metrics[name] != 0.0:
            errors.append(f"nonzero:{name}")
    if metrics.get("kairos_venue_measurements_24h", 0.0) < 1:
        errors.append("venue_measurements_missing")
    if metrics.get("kairos_closed_bar_symbols_24h", 0.0) != 5:
        errors.append("closed_bar_symbol_coverage_incomplete")
    if metrics.get("kairos_closed_bar_minimum_coverage_ratio_24h", 0.0) < 0.999:
        errors.append("closed_bar_coverage_below_0.999")
    if metrics.get("kairos_closed_bar_latest_age_seconds", 0.0) > 90:
        errors.append("closed_bar_stream_stale")
    if metrics.get("kairos_venue_availability_ratio_24h", 0.0) < 0.99:
        errors.append("venue_availability_below_0.99")
    if metrics.get("kairos_venue_poll_expected_24h", 0.0) != 14_400:
        errors.append("venue_poll_schedule_incomplete")
    attempted = metrics.get("kairos_venue_poll_attempted_24h", 0.0)
    succeeded = metrics.get("kairos_venue_poll_succeeded_24h", 0.0)
    failed = metrics.get("kairos_venue_poll_failed_24h", 0.0)
    if succeeded + failed > attempted:
        errors.append("venue_poll_fact_counts_inconsistent")
    if metrics.get("kairos_venue_latest_age_seconds", 0.0) > 60:
        errors.append("venue_measurement_stale")
    for name in (
        "kairos_venue_p95_abs_basis_bps",
        "kairos_venue_p95_spread_bps",
        "kairos_venue_p95_slippage_bps",
        "kairos_execution_p95_shortfall_bps",
    ):
        if metrics.get(name, 0.0) > 25:
            errors.append(f"threshold:{name}")
    for name, maximum in (
        ("kairos_venue_max_book_age_ms", 5_000),
        ("kairos_venue_max_timestamp_skew_ms", 2_000),
        ("kairos_venue_p95_latency_ms", 5_000),
    ):
        if metrics.get(name, 0.0) > maximum:
            errors.append(f"threshold:{name}")
    if metrics.get("kairos_paper_recovery_blocked", 0.0) != 0:
        errors.append("paper_recovery_blocked")
    if not 0 <= metrics.get("kairos_paper_account_latest_age_seconds", -1.0) <= 60:
        errors.append("paper_account_snapshot_stale")
    if metrics.get("kairos_api_spend_month_usd", 0.0) > 15:
        errors.append("api_qualification_budget_exceeded")
    if not 0 <= metrics.get("kairos_execution_runtime_health_age_seconds", -1.0) <= 60:
        errors.append("execution_runtime_health_missing_or_stale")
    if metrics.get("kairos_evedex_auth_age_seconds", -1.0) < 0:
        errors.append("evedex_auth_age_unknown")
    if metrics.get("kairos_evedex_auth_expires_in_seconds", -1.0) < 60:
        errors.append("evedex_auth_expired_or_near_expiry")
    capacity = metrics.get("kairos_evedex_local_mutation_capacity", -1.0)
    reserve = metrics.get("kairos_evedex_local_mutation_reserve", -1.0)
    compensation = metrics.get(
        "kairos_evedex_local_mutation_compensation_reserve", -1.0
    )
    window = metrics.get("kairos_evedex_local_mutation_window_seconds", -1.0)
    if capacity != 30 or compensation < 4 or window < 60:
        errors.append("evedex_mutation_budget_unsafe")
    if reserve < compensation:
        errors.append("evedex_compensation_reserve_exhausted")
    venue_observable = metrics.get("kairos_evedex_venue_rate_limit_observable", -1.0)
    venue_reserve = metrics.get("kairos_evedex_venue_rate_limit_reserve", -1.0)
    if venue_observable not in {0.0, 1.0}:
        errors.append("evedex_venue_rate_limit_observability_unknown")
    if venue_observable == 1.0 and venue_reserve < 1:
        errors.append("evedex_venue_rate_limit_exhausted")
    return errors


@dataclass(frozen=True)
class SoakSummary:
    samples: int
    healthy_samples: int
    transport_errors: int
    restart_executed: bool
    recovered_after_restart: bool
    minimum_availability: float
    measured_availability: float
    paper_gate: bool
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
            "minimum_availability": self.minimum_availability,
            "measured_availability": self.measured_availability,
            "paper_gate": self.paper_gate,
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
    metrics_url: str | None,
    metrics_command: Sequence[str] | None = None,
    duration_s: float,
    interval_s: float,
    restart_at_s: float | None,
    restart_command: Sequence[str] | None,
    paper: bool = False,
    minimum_availability: float = 0.99,
) -> SoakSummary:
    if not 0 < minimum_availability <= 1:
        raise ValueError("minimum_availability must be in (0, 1]")
    if (metrics_url is None) == (metrics_command is None):
        raise ValueError("exactly one metrics transport must be configured")
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
            metrics = (
                fetch_metrics(metrics_url)
                if metrics_url is not None
                else fetch_metrics_command(metrics_command or ())
            )
            samples += 1
            last_errors = health_errors(metrics, paper=paper)
            durable_failures.update(
                error
                for error in last_errors
                if error in IRREVERSIBLE_QUALIFICATION_ERRORS
            )
            if not _sample_availability_errors(last_errors, paper=paper):
                healthy += 1
                if restarted:
                    recovered = True
        except (OSError, subprocess.SubprocessError, TimeoutError):
            transport_errors += 1
            last_errors = ["metrics_unavailable"]
        if time.monotonic() - started < duration_s:
            time.sleep(interval_s)
    total_attempts = samples + transport_errors
    measured_availability = healthy / total_attempts if total_attempts else 0.0
    if measured_availability < minimum_availability:
        durable_failures.add(f"availability_below_{minimum_availability:.4f}")
    return SoakSummary(
        samples=samples,
        healthy_samples=healthy,
        transport_errors=transport_errors,
        restart_executed=restarted,
        recovered_after_restart=(recovered if restarted else True),
        minimum_availability=minimum_availability,
        measured_availability=measured_availability,
        paper_gate=paper,
        terminal_errors=tuple(sorted(durable_failures | set(last_errors))),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    metrics_source = parser.add_mutually_exclusive_group()
    metrics_source.add_argument("--metrics-url")
    metrics_source.add_argument("--metrics-via-compose", action="store_true")
    parser.add_argument("--duration-s", type=float, default=1800)
    parser.add_argument("--interval-s", type=float, default=5)
    parser.add_argument("--restart-at-s", type=float)
    parser.add_argument("--restart-redis", action="store_true")
    parser.add_argument("--paper", action="store_true")
    parser.add_argument("--minimum-availability", type=float, default=0.99)
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
    metrics_command = None
    metrics_url = args.metrics_url
    if args.metrics_via_compose:
        metrics_command = [
            "docker",
            "compose",
            "-p",
            args.compose_project,
            "--env-file",
            str(args.env_file.resolve()),
            "-f",
            str(args.compose_file.resolve()),
            "exec",
            "-T",
            "ops-exporter",
            "python",
            "-c",
            (
                "import urllib.request; "
                "print(urllib.request.urlopen("
                "'http://127.0.0.1:9108/metrics', timeout=5"
                ").read().decode(), end='')"
            ),
        ]
    elif metrics_url is None:
        metrics_url = "http://127.0.0.1:9108/metrics"
    summary = run_soak(
        metrics_url=metrics_url,
        metrics_command=metrics_command,
        duration_s=args.duration_s,
        interval_s=args.interval_s,
        restart_at_s=args.restart_at_s,
        restart_command=command,
        paper=args.paper,
        minimum_availability=args.minimum_availability,
    )
    _write_atomic(args.report, summary.to_dict())
    print(json.dumps(summary.to_dict(), sort_keys=True))
    return 0 if not summary.terminal_errors and summary.recovered_after_restart else 1


if __name__ == "__main__":
    raise SystemExit(main())
