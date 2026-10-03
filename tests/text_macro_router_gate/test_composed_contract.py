"""Real producer -> Router -> review -> mandatory risk constraints, synthetic only.

Only remote model responses are fixed test doubles. Producer transformations,
event-time selection, routing, review guards and risk policy are actual packages.
No production adaptive evaluator is invented or selected by this fixture.
"""

from __future__ import annotations

import asyncio
import json
import socket
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from kairos_aggregator.candidate_review import (
    CandidateReviewBrain,
    CandidateReviewOutput,
)
from kairos_core import canonical_sha256
from kairos_core.bus import BusEnvelope, InMemoryBus
from kairos_core.contracts import (
    AccountSnapshotV2,
    CandidateReviewV1,
    CandidateRouteV1,
    ExitPlanV1,
    StrategicAllocation,
    StrategyIntentV1,
    StrategyProvenanceV1,
    VenueQualityV1,
)
from kairos_core.enums import (
    CandidateReviewTier,
    EvedexProfile,
    ImpactDirection,
    MarketRegime,
    ReasoningEffort,
    ReviewDecision,
    Side,
    StrategicTrigger,
    SystemMode,
    TradingMode,
)
from kairos_core.topics import Topics
from kairos_llm.models import LLMWorkload
from kairos_macro.context import build_macro_context
from kairos_macro.strategist import AllocationOutput, MacroStrategist
from kairos_macro.triggers import ShockDetector
from kairos_risk.config import RiskSettings
from kairos_risk.paper import PaperReservations, PaperRiskPipeline
from kairos_router.config import RouterSettings
from kairos_router.service import RouterService
from kairos_text.freshness import EventFreshnessFilter
from kairos_text.models import NewsItem
from kairos_text.schemas import ExtractedSentiment, SentimentBatch
from kairos_text.sentiment import SentimentExtractor
from pydantic import ValidationError

T0 = 1_800_000_000_000  # Exact minute boundary, synthetic clock, not market evidence.
DECISION = T0 + 59_999
REVIEW_TIME = T0 + 60_100
RISK_TIME = T0 + 60_400
NOW = datetime.fromtimestamp(DECISION / 1_000, UTC)
STRATEGY = "trend_breakout_v1"  # Existing sleeve remains explicitly PAPER-denied.


class SchemaGateway:
    """Explicit zero-cost provider boundary double, never a real provider client."""

    def __init__(self, output, *, fail=False):
        self.output, self.fail, self.calls = output, fail, []

    async def complete(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("SYNTHETIC_MODEL_UNAVAILABLE")
        parsed = kwargs["schema"].model_validate(self.output)
        content = parsed.model_dump_json()
        return SimpleNamespace(
            parsed=parsed,
            provider="offline-fixture",
            model="synthetic-schema-response",
            resolved_model="synthetic-schema-response",
            request_id="fixture-request",
            budget_reservation_id="fixture-zero-cost-reservation",
            content=content,
            effort=(
                ReasoningEffort.HIGH
                if kwargs["workload"] is LLMWorkload.AGGREGATOR_CONFLICT
                else ReasoningEffort.MEDIUM
            ),
            latency_s=0.0,
            cost_usd=0.0,
        )


def intent(side=Side.LONG):
    stop, target = (95.0, 105.0) if side is Side.LONG else (105.0, 95.0)
    return StrategyIntentV1(
        source="strategy-engine",
        strategy_id=STRATEGY,
        strategy_revision="fixture-only-v1",
        symbol="BTCUSDT",
        side=side,
        decision_ts_ms=DECISION,
        entry_eligible_ts_ms=T0 + 60_000,
        entry_expires_ts_ms=T0 + 120_000,
        reference_price=100.0,
        signal_strength=0.8,
        gross_reward_bps=500.0,
        exit_plan=ExitPlanV1(stop_price=stop, target_price=target, max_holding_ms=180_000),
        provenance=StrategyProvenanceV1(
            strategy_code_sha256="a" * 64,
            config_sha256="b" * 64,
            input_window_sha256="c" * 64,
            features_sha256="d" * 64,
            input_bar_sha256s=("e" * 64,),
        ),
    )


def news(*, age_s=1, title="Bitcoin adoption rally", count=1):
    return [
        NewsItem(
            title=title,
            source="fixture.invalid",
            source_kind="rss",
            url=f"https://fixture.invalid/news/{index}",
            published_at=NOW - timedelta(seconds=age_s),
            timestamp_is_estimated=False,
        )
        for index in range(count)
    ]


async def text_signals(*, score=0.8, age_s=1, count=1, fail=False, title="Bitcoin adoption rally"):
    items = EventFreshnessFilter(600, 5, clock=lambda: NOW).select(
        news(age_s=age_s, count=count, title=title)
    )
    gateway = SchemaGateway(
        SentimentBatch(
            signals=[
                ExtractedSentiment(
                    topic="BTCUSDT",
                    sentiment=score,
                    impact=ImpactDirection.BULLISH if score > 0 else ImpactDirection.BEARISH,
                    confidence=0.99,
                    summary="Synthetic evidence; never a trading instruction",
                    item_ids=list(range(1, count + 1)),
                )
            ]
        ),
        fail=fail,
    )
    signals = await SentimentExtractor(gateway).extract(items)
    if items:
        assert gateway.calls[0]["workload"] is LLMWorkload.TEXT_SCOUTS
        assert gateway.calls[0]["schema"] is SentimentBatch
        assert (
            json.loads(gateway.calls[0]["user"])["items"][0]["published_at"]
            == items[0].published_at.isoformat()
        )
    else:
        assert gateway.calls == []
    return signals, gateway


async def route_candidate(candidate, signals, *, mode=SystemMode.NORMAL, trading=TradingMode.DRY_RUN):
    bus = InMemoryBus()
    router = RouterService(
        RouterSettings(_env_file=None, bus_backend="memory", trading_mode=trading),
        bus=bus,
        clock=lambda: NOW,
    )
    router.system_mode = mode
    for signal in signals:
        router._process_sentiment(BusEnvelope("news", Topics.SENTIMENT_SIGNAL, signal.to_payload()))
    stream = bus.subscribe(Topics.STRATEGY_ROUTE)
    pending = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)  # Register actual in-memory subscriber before production publish.
    try:
        await router._process_intent(BusEnvelope("intent", Topics.STRATEGY_INTENT, candidate.to_payload()))
        await asyncio.sleep(0)
        if not pending.done():
            return None, router
        route = CandidateRouteV1.model_validate(pending.result().payload)
        assert route.intent.to_payload() == candidate.to_payload()
        return route, router
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        await stream.aclose()


async def review_candidate(route, signals, decision="ALLOW", *, priority=100, fail=False, at=REVIEW_TIME):
    gateway = SchemaGateway(
        CandidateReviewOutput(decision=decision, priority=priority, reason_codes=("SYNTHETIC_FIXTURE",)),
        fail=fail,
    )
    review = await CandidateReviewBrain(gateway, clock_ms=lambda: at).review(route, signals)
    assert review.intent.to_payload() == route.intent.to_payload()
    assert isinstance(review, CandidateReviewV1)
    if gateway.calls:
        context = json.loads(gateway.calls[0]["user"])
        assert context["authority"] == "review_only"
        assert context["immutable_intent"] == json.loads(json.dumps(route.intent.identity_payload()))
        assert {item["message_id"] for item in context["evidence"]} == set(route.evidence_ids)
    return review, gateway


async def macro_allocation(regime=MarketRegime.BULL, *, pct_1h=2.0, fail=False, strategy=STRATEGY):
    shock = ShockDetector().check_price(pct_1h)
    trigger = StrategicTrigger.SHOCK_EVENT if shock else StrategicTrigger.SCHEDULE
    context = build_macro_context(
        portfolio={"equity_usd": 10_000, "synthetic": True},
        performance={"status": "NOT_PERFORMANCE_EVIDENCE"},
        regime_hint=regime.value,
        regime_evidence={"method": "synthetic-fixture", "as_of_ts_ms": DECISION},
        market_factors={"symbol": "BTCUSDT", "pct_change_1h": pct_1h},
        macro_factors={"status": "synthetic-only"},
        onchain_factors={"status": "unavailable"},
        trigger={} if shock is None else {"kind": shock.kind, "severity": shock.severity},
    )
    gateway = SchemaGateway(
        {
            "regime": regime,
            "stable_reserve_pct": 0.2,
            "strategy_weights": [{"strategy_name": strategy, "weight": 0.8}],
            "max_gross_leverage": 20.0,
            "rationale": "Synthetic-only allocation; not trading authority",
        },
        fail=fail,
    )
    allocation = await MacroStrategist(gateway, allowed_strategy_ids=(STRATEGY,)).allocate(
        context,
        trigger=trigger,
        message_id="fixture-macro",
        correlation_id="fixture-sample",
    )
    assert gateway.calls[0]["workload"] is LLMWorkload.MACRO_STRATEGIST
    assert gateway.calls[0]["schema"] is AllocationOutput
    assert json.loads(gateway.calls[0]["user"])["trigger"] == (
        {} if shock is None else {"kind": shock.kind, "severity": shock.severity}
    )
    # Fixture reception timestamp is explicit; no historical service-clock claim.
    allocation = StrategicAllocation.model_validate(
        {**allocation.to_payload(), "produced_at": NOW.isoformat()}
    )
    return allocation, gateway


def risk_decision(review, allocation, *, open_risk=0.0):
    settings = RiskSettings(_env_file=None)
    assert settings.paper_strategy_allowlist == []
    assert settings.paper_per_trade_risk_fraction == 0.0025
    assert settings.paper_max_total_open_risk_fraction == 0.01
    venue = VenueQualityV1(
        source="quant-scouts",
        profile=EvedexProfile.DEV,
        symbol="BTCUSD:DEV",
        observed_at_ms=T0 + 60_300,
        expires_at_ms=T0 + 65_300,
        reference_timestamp_ms=T0 + 60_200,
        book_timestamp_ms=T0 + 60_200,
        reference_mid_price=100.0,
        best_bid=99.99,
        best_ask=100.01,
        venue_mid_price=100.0,
        basis_bps=0.0,
        spread_bps=(100.01 - 99.99) / 100.0 * 10_000,
        assessed_notional_usd=1_000.0,
        depth_usd=5_000.0,
        buy_slippage_bps=1.0,
        sell_slippage_bps=1.0,
        taker_fee_bps=5.0,
        reference_age_ms=100,
        book_age_ms=100,
        latency_ms=20,
        timestamp_skew_ms=0,
        entry_allowed=True,
    )
    account = AccountSnapshotV2(
        source="execution-engine",
        trading_mode=TradingMode.PAPER,
        evedex_profile=EvedexProfile.DEV,
        account_id=settings.paper_account_id,
        equity_usd=10_000.0,
        available_balance_usd=9_000.0,
        margin_used_usd=0.0,
        durable_day_start_equity_usd=10_000.0,
        durable_peak_equity_usd=10_000.0,
        total_open_risk_usd=0.0,
        captured_at_ms=T0 + 60_200,
        reconciliation_seq=1,
        reconciled=True,
        reconciliation_detail="synthetic fixture only",
    )
    result = PaperRiskPipeline(settings).evaluate(
        review,
        venue,
        account=account,
        allocation=allocation,
        decided_at_ms=RISK_TIME,
        reservations=PaperReservations(open_risk_usd=open_risk),
    )
    assert not result.approved
    assert "strategy_not_paper_approved" in result.rejection_reasons
    assert result.quantity == result.notional_usd == result.worst_case_loss_usd == 0.0
    assert 0 <= result.loss_budget_usd <= account.equity_usd * 0.0025
    assert result.leverage == 1.0  # Macro 20x never overrides immutable PAPER cap.
    assert result.intent.to_payload() == review.intent.to_payload()
    return result


@pytest.mark.parametrize(
    "regime,side,score,pct_1h,expected_macro_rejection",
    [
        (MarketRegime.BULL, Side.LONG, 0.8, 2.0, None),
        (MarketRegime.CHOP, Side.LONG, 0.3, 0.0, "macro_regime_chop"),
        (MarketRegime.BEAR, Side.SHORT, -0.8, -15.0, None),
        (MarketRegime.BEAR, Side.LONG, -0.8, -15.0, "macro_regime_forbids_long"),
        (MarketRegime.BULL, Side.SHORT, -0.8, 2.0, "macro_regime_forbids_short"),
    ],
)
async def test_bull_range_crash_and_macro_conflicts(regime, side, score, pct_1h, expected_macro_rejection):
    candidate = intent(side)
    before = canonical_sha256(candidate)
    signals, _ = await text_signals(score=score)
    route, _ = await route_candidate(candidate, signals)
    assert route is not None
    review, _ = await review_candidate(route, signals)
    allocation, _ = await macro_allocation(regime, pct_1h=pct_1h)
    decision = risk_decision(review, allocation)
    if expected_macro_rejection:
        assert expected_macro_rejection in decision.rejection_reasons
    else:
        assert not any(reason.startswith("macro_regime_") for reason in decision.rejection_reasons)
    assert canonical_sha256(candidate) == before


@pytest.mark.parametrize("decision", ["ALLOW", "VETO", "DEFER"])
async def test_review_outputs_have_no_execution_authority(decision):
    signals, _ = await text_signals()
    route, _ = await route_candidate(intent(), signals)
    review, gateway = await review_candidate(route, signals, decision)
    assert review.decision.value == decision
    assert gateway.calls[0]["workload"] is LLMWorkload.AGGREGATOR_NORMAL
    allocation, _ = await macro_allocation()
    result = risk_decision(review, allocation)
    if decision != "ALLOW":
        assert f"review_{decision.lower()}" in result.rejection_reasons


async def test_fresh_opposing_news_escalates_review_and_strong_allow_is_guarded():
    # Three independent URLs raise producer confidence to .85; score -.85 is material.
    signals, _ = await text_signals(score=-1.0, count=3)
    route, _ = await route_candidate(intent(), signals)
    assert route.review_tier is CandidateReviewTier.CONFLICT
    assert route.requested_reasoning_effort is ReasoningEffort.HIGH
    review, gateway = await review_candidate(route, signals, "ALLOW")
    assert gateway.calls[0]["workload"] is LLMWorkload.AGGREGATOR_CONFLICT
    assert review.decision is ReviewDecision.DEFER
    assert "CONFLICT_ALLOW_GUARD" in review.reason_codes


@pytest.mark.parametrize("age_s", [601, -6])
async def test_stale_or_future_news_never_escalates_candidate(age_s):
    signals, gateway = await text_signals(score=-1.0, age_s=age_s)
    assert signals == [] and gateway.calls == []
    route, _ = await route_candidate(intent(), signals)
    assert route.review_tier is CandidateReviewTier.NORMAL
    assert route.evidence_ids == ()
    assert route.conflict_rationale is None


@pytest.mark.parametrize("age_s", [601, -1, -6])
async def test_router_ingestion_itself_rejects_noncausal_producer_evidence(age_s):
    # Bypass only upstream freshness selection to exercise the actual consumer
    # boundary against a late/future valid producer artifact.
    gateway = SchemaGateway(
        SentimentBatch(
            signals=[
                ExtractedSentiment(
                    topic="BTCUSDT",
                    sentiment=-1.0,
                    impact=ImpactDirection.BEARISH,
                    confidence=0.99,
                    summary="Synthetic late/future news",
                    item_ids=[1],
                )
            ]
        )
    )
    signals = await SentimentExtractor(gateway).extract(news(age_s=age_s))
    assert len(signals) == 1
    route, _ = await route_candidate(intent(), signals)
    assert route.review_tier is CandidateReviewTier.NORMAL
    assert route.evidence_ids == ()


async def test_actual_router_rejects_existing_sleeve_in_paper():
    signals, _ = await text_signals()
    route, router = await route_candidate(intent(), signals, trading=TradingMode.PAPER)
    assert router.settings.paper_strategy_allowlist == []
    assert route is None


async def test_conflict_safe_mode_suppresses_opposite_news_route():
    signals, _ = await text_signals(score=-1.0)
    route, _ = await route_candidate(intent(), signals, mode=SystemMode.CONFLICT_SAFE)
    assert route is None


@pytest.mark.parametrize("decision", ["VETO", "DEFER"])
async def test_conflict_review_preserves_refusal(decision):
    signals, _ = await text_signals(score=-0.8)
    route, _ = await route_candidate(intent(), signals)
    review, _ = await review_candidate(route, signals, decision)
    assert route.review_tier is CandidateReviewTier.CONFLICT
    assert review.decision.value == decision


async def test_replay_news_and_candidate_deliver_only_one_identical_route():
    signals, _ = await text_signals()
    repeated, _ = await text_signals()
    assert [signal.to_payload() for signal in repeated] == [signal.to_payload() for signal in signals]
    candidate = intent()
    route, router = await route_candidate(candidate, signals + repeated)
    text = router._text_aggregate_at("BTCUSDT", as_of=NOW)
    assert text.sentiment_ids == route.evidence_ids == (signals[0].message_id,)
    count = router.bus._counter
    await router._process_intent(BusEnvelope("replay", Topics.STRATEGY_INTENT, candidate.to_payload()))
    assert router.bus._counter == count


@pytest.mark.parametrize("failure_kind", ["model", "deadline"])
async def test_review_failure_or_deadline_defers_without_altering_candidate(
    failure_kind,
):
    signals, _ = await text_signals()
    route, _ = await route_candidate(intent(), signals)
    review, gateway = await review_candidate(
        route,
        signals,
        fail=failure_kind == "model",
        at=route.review_deadline_ms + 1 if failure_kind == "deadline" else REVIEW_TIME,
    )
    assert review.decision is ReviewDecision.DEFER
    assert review.reviewer == "DETERMINISTIC"
    assert review.reason_codes == ("LLM_FAILURE" if failure_kind == "model" else "REVIEW_DEADLINE_EXCEEDED",)
    assert len(gateway.calls) == (1 if failure_kind == "model" else 0)


@pytest.mark.parametrize("failure_kind", ["model", "unconfigured_strategy"])
async def test_macro_failure_becomes_defensive_separate_constraint(failure_kind):
    signals, _ = await text_signals()
    route, _ = await route_candidate(intent(), signals)
    review, _ = await review_candidate(route, signals)
    allocation, _ = await macro_allocation(
        fail=failure_kind == "model",
        strategy="invented" if failure_kind == "unconfigured_strategy" else STRATEGY,
    )
    assert allocation.strategy_weights == {} and allocation.stable_reserve_pct == 1.0
    assert allocation.max_gross_leverage == 1.0
    result = risk_decision(review, allocation)
    assert "strategy_has_no_macro_allocation" in result.rejection_reasons
    assert "macro_regime_chop" in result.rejection_reasons


async def test_stale_macro_remains_denied_even_when_review_allows():
    signals, _ = await text_signals()
    route, _ = await route_candidate(intent(), signals)
    review, _ = await review_candidate(route, signals)
    allocation, _ = await macro_allocation()
    stale = StrategicAllocation.model_validate(
        {
            **allocation.to_payload(),
            "produced_at": (NOW - timedelta(hours=27)).isoformat(),
        }
    )
    result = risk_decision(review, stale)
    assert "strategic_allocation_stale" in result.rejection_reasons


async def test_news_fallback_abstains_from_unjustified_high_confidence():
    signals, _ = await text_signals(fail=True)
    assert len(signals) == 1 and signals[0].source.endswith(":local")
    assert signals[0].confidence <= 0.25
    route, _ = await route_candidate(intent(), signals)
    assert route.review_tier is CandidateReviewTier.NORMAL
    assert route.evidence_ids == ()  # local two-term confidence .20 < Router .25


async def test_priority_macro_leverage_and_reserved_risk_cannot_raise_caps():
    signals, _ = await text_signals()
    route, _ = await route_candidate(intent(), signals)
    allocation, _ = await macro_allocation()
    low, _ = await review_candidate(route, signals, priority=0)
    high, _ = await review_candidate(route, signals, priority=100)
    for reserved in (0.0, 90.0, 100.0):
        low_result = risk_decision(low, allocation, open_risk=reserved)
        high_result = risk_decision(high, allocation, open_risk=reserved)
        assert (
            low_result.loss_budget_usd == high_result.loss_budget_usd == min(25.0, max(0.0, 100.0 - reserved))
        )
        if reserved == 100.0:
            assert "portfolio_open_risk_limit_exhausted" in high_result.rejection_reasons
    for cap in (
        {"paper_per_trade_risk_fraction": 0.0025001},
        {"paper_max_total_open_risk_fraction": 0.010001},
    ):
        with pytest.raises(ValidationError):
            RiskSettings(_env_file=None, **cap)


def test_review_schema_cannot_add_trading_parameters():
    for parameter in (
        "side",
        "quantity",
        "leverage",
        "stop_price",
        "target_price",
        "live_ready",
    ):
        with pytest.raises(ValidationError):
            CandidateReviewOutput.model_validate(
                {
                    "decision": "ALLOW",
                    "priority": 100,
                    "reason_codes": ["FIXTURE"],
                    parameter: 1,
                }
            )


def test_external_transport_and_provider_factory_are_actually_denied():
    from kairos_llm.gateway import LLMGateway

    with pytest.raises(AssertionError, match="forbidden"):
        socket.getaddrinfo("fixture.invalid", 443)
    with socket.socket() as transport, pytest.raises(AssertionError, match="forbidden"):
        transport.connect(("127.0.0.1", 1))  # No general loopback/DB exception.
    with pytest.raises(AssertionError, match="forbidden"):
        LLMGateway()
