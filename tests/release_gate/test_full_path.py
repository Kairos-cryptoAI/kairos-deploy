"""Deterministic closed-bar-to-refusal gate for the current frozen strategy.

This complements the Docker Risk/Redis/PostgreSQL/Execution test.  It invokes
the published Strategy, Router, Aggregator, Risk and Execution boundaries in
one causal order, but deliberately uses a synthetic failed LLM call and a
rejected decision.  Consequently it cannot call a provider, create an order,
or access EVEDEX credentials while still proving that an unapproved strategy
cannot cross the execution boundary.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from kairos_aggregator.candidate_review import CandidateReviewBrain
from kairos_core.contracts import VenueQualityV1
from kairos_core.enums import EvedexProfile, ReviewDecision, Side, TradingMode
from kairos_execution.config import ExecSettings
from kairos_execution.paper_engine import PaperExecutionEngine
from kairos_risk.config import RiskSettings
from kairos_risk.paper import PaperRiskPipeline
from kairos_router.aggregation import TextAggregate
from kairos_router.candidate import CandidateRouterPolicy
from kairos_strategy.candles import Candle
from kairos_strategy.runtime import (
    candle_to_closed_bar,
    canonical_intent_batch_bytes,
    generate_runtime_strategy_intents,
)
from kairos_strategy.sleeves.regime_aligned_right_tail import RegimeAlignedRightTailConfig


class _FailClosedGateway:
    """A local transport failure, never a provider client or API call."""

    def __init__(self) -> None:
        self.workloads: list[object] = []

    async def complete(self, *, workload, **_kwargs):
        self.workloads.append(workload)
        raise RuntimeError("synthetic provider outage")


class _NoVenueAccess:
    """Any venue touch in the rejected path is a test failure."""

    name = "never-called"

    def __getattr__(self, name: str):  # pragma: no cover - asserted by the test path
        raise AssertionError(f"rejected decision accessed venue method {name}")


def _closed_bars() -> tuple:
    """25 complete UTC hours that deterministically emit one frozen intent."""

    price = 100.0
    rows: list[Candle] = []
    hourly_return = 0.01
    minute_return = (1 + hourly_return) ** (1 / 60) - 1
    for minute in range(25 * 60):
        opened = price
        closed = opened * (1 + minute_return)
        spread = opened * 0.0005
        rows.append(
            Candle(
                symbol="BTCUSDT",
                timeframe="1m",
                open_time_ms=minute * 60_000,
                close_time_ms=(minute + 1) * 60_000 - 1,
                open=opened,
                high=max(opened, closed) + spread,
                low=min(opened, closed) - spread,
                close=closed,
                volume=100.0,
                quote_volume=100.0 * closed,
                taker_buy_volume=55.0,
                taker_buy_quote_volume=55.0 * closed,
            )
        )
        price = closed
    return tuple(candle_to_closed_bar(row) for row in rows)


def _venue(now_ms: int, reference_price: float) -> VenueQualityV1:
    return VenueQualityV1(
        source="synthetic-full-path-gate",
        profile=EvedexProfile.DEV,
        symbol="BTCUSD:DEV",
        observed_at_ms=now_ms,
        expires_at_ms=now_ms + 5_000,
        reference_timestamp_ms=now_ms,
        book_timestamp_ms=now_ms,
        reference_mid_price=reference_price,
        best_bid=reference_price * 0.9999,
        best_ask=reference_price * 1.0001,
        venue_mid_price=reference_price,
        basis_bps=0.0,
        spread_bps=2.0,
        assessed_notional_usd=100.0,
        depth_usd=1_000.0,
        buy_slippage_bps=1.0,
        sell_slippage_bps=1.0,
        taker_fee_bps=5.0,
        reference_age_ms=0,
        book_age_ms=0,
        latency_ms=1,
        timestamp_skew_ms=0,
        entry_allowed=True,
    )


@pytest.mark.asyncio
async def test_frozen_strategy_full_path_is_deterministic_and_cannot_reach_venue(tmp_path):
    bars = _closed_bars()
    config = RegimeAlignedRightTailConfig(regime_sma_bars=3)
    first = generate_runtime_strategy_intents("regime_aligned_right_tail_v1", bars, config)
    second = generate_runtime_strategy_intents("regime_aligned_right_tail_v1", bars, config)
    assert len(first) == len(second) == 1
    assert canonical_intent_batch_bytes(first) == canonical_intent_batch_bytes(second)
    intent = first[0]

    route = CandidateRouterPolicy(source="release-gate-router").build(intent, TextAggregate())
    gateway = _FailClosedGateway()
    reviewed_at_ms = intent.entry_eligible_ts_ms
    review = await CandidateReviewBrain(
        gateway,
        source="release-gate-aggregator",
        clock_ms=lambda: reviewed_at_ms,
    ).review(route, ())
    assert gateway.workloads, "the only LLM path must be observed through the fail-closed adapter"
    assert review.decision is ReviewDecision.DEFER
    assert review.reason_codes == ("LLM_FAILURE",)
    assert review.intent.model_dump(mode="json") == intent.model_dump(mode="json")
    assert review.route.intent.model_dump(mode="json") == intent.model_dump(mode="json")

    decision = PaperRiskPipeline(
        RiskSettings(
            _env_file=None,
            trading_mode=TradingMode.PAPER,
            environment="paper-dev",
            bus_backend="redis",
            redis_url="redis://synthetic-release-gate.invalid:6379/0",
        )
    ).evaluate(
        review,
        _venue(intent.decision_ts_ms, intent.reference_price),
        account=None,
        allocation=None,
        decided_at_ms=reviewed_at_ms,
    )
    assert not decision.approved
    assert "review_defer" in decision.rejection_reasons
    assert "strategy_not_paper_approved" in decision.rejection_reasons
    assert (decision.quantity, decision.notional_usd, decision.worst_case_loss_usd) == (0.0, 0.0, 0.0)
    assert decision.intent.model_dump(mode="json") == intent.model_dump(mode="json")

    api_path = tmp_path / "synthetic-api-key"
    signing_path = tmp_path / "synthetic-signing-key"
    settings = ExecSettings(
        _env_file=None,
        trading_mode=TradingMode.PAPER,
        environment="paper-dev",
        bus_backend="redis",
        redis_url="redis://synthetic-release-gate.invalid:6379/0",
        account_id="kairos-paper-dev-01",
        evedex_dev_api_key_file=api_path,
        evedex_dev_private_key_file=signing_path,
        evedex_dev_expected_account_id="synthetic-remote-account",
    )
    engine = PaperExecutionEngine(
        _NoVenueAccess(),
        SimpleNamespace(pool=object()),
        object(),
        settings,
    )
    result = await engine.handle(decision)
    assert result.events == ()
    assert not api_path.exists() and not signing_path.exists()
