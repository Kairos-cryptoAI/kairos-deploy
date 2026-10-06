"""Installed adaptive candidate -> existing refusal path; never a trading pass."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from kairos_aggregator.candidate_review import CandidateReviewBrain
from kairos_core.enums import ReviewDecision, TradingMode
from kairos_execution.config import ExecSettings
from kairos_execution.paper_engine import PaperExecutionEngine
from kairos_risk.config import RiskSettings
from kairos_risk.paper import PaperRiskPipeline
from kairos_router.aggregation import TextAggregate
from kairos_router.candidate import CandidateRouterPolicy
from kairos_strategy.adaptive import evaluate_adaptive_closed_bars
from kairos_strategy.candles import Candle
from kairos_strategy.provenance import canonical_sha256
from kairos_strategy.runtime import candle_to_closed_bar
from kairos_strategy.timeframes import aggregate

import policy
from test_reject_all_path import _FailClosedGateway, _NoVenueAccess, _synthetic_sidecar_node, _venue


def _adaptive_bars():
    rows = []
    for minute in range(55 * 60):
        opened, closed = 100.0 + 0.01 * minute, 100.0 + 0.01 * (minute + 1)
        rows.append(
            Candle(
                symbol="BTCUSDT",
                timeframe="1m",
                open_time_ms=minute * 60_000,
                close_time_ms=(minute + 1) * 60_000 - 1,
                open=opened,
                close=closed,
                high=closed + 0.4,
                low=opened - 0.4,
                volume=1.0,
            )
        )
    prefix15 = [row for row in aggregate(rows, "15m") if row.close_time_ms <= rows[-11].close_time_ms]
    mean = sum(row.close for row in prefix15[-20:]) / 20
    tail = prefix15[-15:]
    atr = (
        sum(
            max(row.high - row.low, abs(row.high - prior.close), abs(row.low - prior.close))
            for prior, row in zip(tail, tail[1:], strict=False)
        )
        / 14
    )
    first_close = rows[-11].close
    rows = rows[:-10]
    for opened, high, low, closed in (
        (first_close, first_close, mean - 0.4 * atr, mean + 0.05 * atr),
        (mean + 0.05 * atr, mean + 0.75 * atr, mean - 0.1 * atr, mean + 0.65 * atr),
    ):
        for step in range(5):
            minute = len(rows)
            left, right = opened + (closed - opened) * step / 5, opened + (closed - opened) * (step + 1) / 5
            rows.append(
                Candle(
                    symbol="BTCUSDT",
                    timeframe="1m",
                    open_time_ms=minute * 60_000,
                    close_time_ms=(minute + 1) * 60_000 - 1,
                    open=left,
                    close=right,
                    high=max(left, right, high if step == 2 else right),
                    low=min(left, right, low if step == 2 else right),
                    volume=1.0,
                )
            )
    return tuple(candle_to_closed_bar(row) for row in rows)


@pytest.mark.asyncio
async def test_installed_adaptive_candidate_remains_refused_and_has_zero_external_effects(tmp_path: Path):
    policy.validate_environment()
    policy.validate_installed_sources(policy.LOCK)
    bars = _adaptive_bars()
    result = evaluate_adaptive_closed_bars(
        bars, observed_at_ms=bars[-1].close_time_ms + 1, source_set_sha256=canonical_sha256(policy.LOCK)
    )
    assert result.intent is not None and result.regime_observation is not None
    assert result.evaluation.evaluation_complete and not result.evaluation.trading_authority
    route = CandidateRouterPolicy(source="adaptive-engineering-gate").build(result.intent, TextAggregate())
    gateway = _FailClosedGateway()
    clock = result.intent.entry_eligible_ts_ms
    review = await CandidateReviewBrain(
        gateway, source="adaptive-engineering-gate", clock_ms=lambda: clock
    ).review_legacy_engineering(route, ())
    assert review.decision is ReviewDecision.DEFER and len(gateway.workloads) == 1
    decision = PaperRiskPipeline(
        RiskSettings(
            _env_file=None,
            trading_mode=TradingMode.PAPER,
            environment="paper-dev",
            bus_backend="redis",
            redis_url="redis://current-release-gate.invalid:6379/0",
        )
    ).evaluate(
        review,
        _venue(clock, result.intent.reference_price),
        account=None,
        allocation=None,
        decided_at_ms=clock,
    )
    assert not decision.approved and "strategy_not_paper_approved" in decision.rejection_reasons
    assert (decision.quantity, decision.notional_usd, decision.worst_case_loss_usd) == (0.0, 0.0, 0.0)
    assert decision.intent.canonical_intent_bytes() == result.intent.canonical_intent_bytes()
    api_path, signing_path = tmp_path / "synthetic-api-key", tmp_path / "synthetic-signing-key"
    engine = PaperExecutionEngine(
        _NoVenueAccess(),
        SimpleNamespace(pool=object()),
        object(),
        ExecSettings(
            _env_file=None,
            trading_mode=TradingMode.PAPER,
            environment="paper-dev",
            bus_backend="redis",
            redis_url="redis://current-release-gate.invalid:6379/0",
            account_id="kairos-paper-dev-01",
            evedex_dev_api_key_file=api_path,
            evedex_dev_private_key_file=signing_path,
            evedex_dev_expected_account_id="synthetic-remote-account",
            evedex_sidecar_node=_synthetic_sidecar_node(),
        ),
    )
    outcome = await engine.handle(decision)
    assert outcome.events == () and not api_path.exists() and not signing_path.exists()
