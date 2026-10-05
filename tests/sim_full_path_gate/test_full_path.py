"""One sealed, deterministic bar-to-simulator lifecycle proof.

The review response is a local zero-cost test double. It exercises the real
review boundary without constructing a provider client or contacting a service.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from kairos_aggregator.candidate_review import CandidateReviewBrain
from kairos_core import RESEARCH_ARMS, Topics, canonical_sha256
from kairos_core.bus.base import BusEnvelope, MessageBus, Publishable
from kairos_core.contracts import (
    AdaptiveCandidateProtocolV1,
    EvidenceReferenceV1,
    LLMProposalAdaptiveCandidateArmV1,
    LLMProposalCompletionReceiptV1,
    LLMProposalModelProvenanceV1,
    LLMTradeProposalV1,
    RecordedBookLevelV1,
    RecordedTopNBookFrameV2,
    ResearchDecisionSampleV1,
    ResearchObservationScheduleV1,
    ResearchObservationWindowV1,
    SimulationAdmissionV2,
    SimulationAssumptionsV1,
    SimulationSessionV1,
    SimulationStrategyRefV1,
    StrategyOnlyAdaptiveCandidateArmV1,
    StrategyReviewAdaptiveCandidateArmV1,
)
from kairos_core.enums import LLMProposalAction, ReasoningEffort, ReviewDecision, Side
from kairos_core.research_pairing import (
    ScheduledResearchSampleV1,
    StrategyEvaluationEvidenceV1,
    build_research_decision_sample,
)
from kairos_execution.simulation import SimulationExecutionController
from kairos_llm.budget import BudgetedLLMGateway
from kairos_llm.models import LLMWorkload, ModelRouter
from kairos_llm.pricing import PriceTable
from kairos_llm.proposals import LLMProposalOutputV1
from kairos_llm.research import (
    RESEARCH_INPUT_FEATURE_SHA256,
    ResearchEvidenceError,
    ResearchPromptArtifactV1,
    ResearchProposalCoordinator,
)
from kairos_llm.schemas import LLMResult, TokenUsage
from kairos_persistence import (
    Database,
    MessageIdentityConflict,
    MigrationProfile,
    PersistenceSettings,
    ResearchAdaptiveCandidateProtocolRepository,
    ResearchDecisionSampleRepository,
    ResearchEvidenceRepository,
    ResearchObservationScheduleRepository,
    ResearchSourceReceiptV1,
    ResearchStrategyEvaluationReceiptV1,
    SimulationRepository,
    SimulatorProposalRepository,
    consume_simulator_proposals,
)
from kairos_persistence.database_target import connect_verified_database, require_database_target_url
from kairos_risk import SimulationRiskPolicy
from kairos_router.aggregation import TextAggregate
from kairos_router.candidate import CandidateRouterPolicy
from kairos_strategy.candles import Candle
from kairos_strategy.provenance import installed_source_tree_sha256
from kairos_strategy.registry import get_strategy
from kairos_strategy.runtime import (
    candle_to_closed_bar,
    canonical_intent_batch_bytes,
    generate_runtime_strategy_intents,
)
from kairos_strategy.sleeves.regime_aligned_right_tail import RegimeAlignedRightTailConfig

import policy

_SYMBOLS = ("BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT")
_DATABASE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")


class _LocalReviewGateway:
    """A fixed local response object, not an LLM client or transport."""

    def __init__(self, decision: ReviewDecision) -> None:
        self.decision = decision
        self.calls: list[dict[str, object]] = []

    async def complete(self, **kwargs):
        self.calls.append(kwargs)
        parsed = {
            "decision": self.decision.value,
            "priority": 7 if self.decision is ReviewDecision.ALLOW else 0,
            "reason_codes": (
                "SIMULATOR_GATE_ALLOW" if self.decision is ReviewDecision.ALLOW else "SIMULATOR_GATE_VETO",
            ),
        }
        content = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        return SimpleNamespace(
            content=content,
            parsed=parsed,
            model="local-deterministic-review-double",
            resolved_model="local-deterministic-review-double",
            effort=ReasoningEffort.MEDIUM,
            cost_usd=0.0,
            latency_s=0.0,
            provider="simulator-gate-local",
            request_id=f"local-review-{self.decision.value.lower()}",
            budget_reservation_id=f"simulator-gate-no-budget-{self.decision.value.lower()}",
        )


class _LocalResearchBudget:
    """Synthetic accounting only; never the runtime or paid-provider budget."""

    def __init__(self) -> None:
        self.reservations: list[dict[str, object]] = []
        self.commits: list[dict[str, object]] = []

    async def reserve(self, **kwargs) -> None:
        self.reservations.append(kwargs)

    async def commit(self, **kwargs) -> None:
        self.commits.append(kwargs)


class _LocalResearchGateway:
    """Fixed proposal double; checks committed START before any local response."""

    def __init__(
        self, journal: ResearchEvidenceRepository, action: LLMProposalAction, *, forbid_calls: bool = False
    ) -> None:
        self.journal, self.action = journal, action
        self.forbid_calls = forbid_calls
        self.settings = SimpleNamespace(max_retries=0, max_output_tokens=2_048)
        self.router = ModelRouter()
        self.calls: list[dict[str, object]] = []

    async def complete(self, **kwargs) -> LLMResult:
        assert not self.forbid_calls, "restart must replay durable receipts without another local response"
        payload = json.loads(kwargs["user"].split("\n", 1)[1])
        roster = await self.journal.pending_observations(campaign_id=payload["campaign_id"])
        assert any(
            row["sample_id"] == payload["sample_id"]
            and row["arm_id"] == "llm-proposal-research"
            and row["state"] == "STARTED_UNRESOLVED"
            for row in roster
        )
        for item in payload["sources"]:
            stored = await self.journal.load_source(item["receipt_sha256"])
            assert stored.content == item["content"]
            assert stored.content_sha256 == item["evidence"]["content_sha256"]
        self.calls.append(kwargs)
        route = self.router.resolve(workload=kwargs["workload"])
        content = json.dumps(
            {
                "contract_version": "kairos-llm-proposal-output.v1",
                "action": self.action.value,
                "rationale": "Fixed synthetic conflict fixture; advisory only, not an order.",
                "evidence_ids": [item["evidence_id"] for item in payload["sources"]],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        # Nonzero synthetic usage exercises the real budget validation. This
        # price-table calculation is not a provider bill or paid reservation.
        usage = TokenUsage(input_tokens=150, output_tokens=30)
        return LLMResult(
            content=content,
            parsed=LLMProposalOutputV1.model_validate_json(content),
            model=route.choice.model,
            resolved_model=route.choice.model,
            effort=route.effort.value,
            usage=usage,
            cost_usd=PriceTable().cost(route.choice.model, usage),
            latency_s=0.0,
            workload=kwargs["workload"].value,
            provider=route.choice.provider.value,
            request_id=f"local-research-{payload['sample_id']}",
        )


class _ProposalGateBus(MessageBus):
    """One-message transport double for the real SIM proposal consumer."""

    def __init__(self) -> None:
        self._messages: asyncio.Queue[BusEnvelope] = asyncio.Queue()
        self.subscribed = asyncio.Event()
        self.acknowledged = asyncio.Event()
        self.subscription: tuple[str, str | None, str | None] | None = None
        self.acks: list[tuple[str, str, str | None]] = []

    async def publish(self, topic: str, message: Publishable) -> str:
        message_id = f"sim-proposal-{self._messages.qsize() + 1}"
        await self._messages.put(BusEnvelope(id=message_id, topic=topic, payload=self._to_payload(message)))
        return message_id

    async def subscribe(
        self,
        topic: str,
        *,
        group: str | None = None,
        consumer: str | None = None,
    ):
        self.subscription = (topic, group, consumer)
        self.subscribed.set()
        while True:
            yield await self._messages.get()

    async def ack(self, topic: str, envelope: BusEnvelope, *, group: str | None = None) -> None:
        self.acks.append((topic, envelope.id, group))
        self.acknowledged.set()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _adaptive_protocol_fixture() -> tuple[ResearchObservationScheduleV1, AdaptiveCandidateProtocolV1]:
    """Build a fully deterministic three-arm roster with no provider calls."""

    market_as_of_ts_ms = 1_760_000_000_000
    schedule = ResearchObservationScheduleV1(
        campaign_id="sim-full-path-adaptive-protocol-v1",
        strategy_id="regime-aligned-right-tail-v1",
        strategy_revision="synthetic-fixed-config-v1",
        source_set_sha256=_hash("synthetic-closed-bars-source-set-v1"),
        evaluator_sha256=_hash("deterministic-sim-evaluator-v1"),
        windows=(
            ResearchObservationWindowV1(
                sample_id="fixed-sample-0001",
                symbol="BTCUSDT",
                timeframe="1m",
                market_as_of_ts_ms=market_as_of_ts_ms,
                market_snapshot_sha256=_hash("synthetic-closed-btc-1m-bar-v1"),
                paired_at_ts_ms=market_as_of_ts_ms + 1_000,
                sample_deadline_ts_ms=market_as_of_ts_ms + 10_000,
            ),
        ),
    )
    protocol = AdaptiveCandidateProtocolV1(
        campaign_id=schedule.campaign_id,
        schedule_digest=schedule.schedule_digest,
        arms=(
            StrategyOnlyAdaptiveCandidateArmV1(
                candidate_id="strategy-baseline",
                candidate_revision="synthetic-fixed-config-v1",
                artifact_sha256=_hash("strategy-baseline-artifact-v1"),
                input_feature_sha256=_hash("shared-input-features-v1"),
                decision_mapping_sha256=_hash("strategy-intent-mapping-v1"),
                hypothetical_exit_sha256=_hash("shared-hypothetical-exits-v1"),
                cost_model_sha256=_hash("shared-simulated-cost-model-v1"),
            ),
            StrategyReviewAdaptiveCandidateArmV1(
                candidate_id="strategy-review-candidate",
                candidate_revision="synthetic-fixed-config-v1",
                artifact_sha256=_hash("strategy-review-artifact-v1"),
                input_feature_sha256=_hash("shared-input-features-v1"),
                decision_mapping_sha256=_hash("allow-veto-defer-mapping-v1"),
                hypothetical_exit_sha256=_hash("shared-hypothetical-exits-v1"),
                cost_model_sha256=_hash("shared-simulated-cost-model-v1"),
                provider="openai",
                model="local-test-identity-only",
                prompt_sha256=_hash("local-review-prompt-v1"),
                schema_sha256=_hash("local-review-schema-v1"),
            ),
            LLMProposalAdaptiveCandidateArmV1(
                candidate_id="llm-proposal-candidate",
                candidate_revision="synthetic-fixed-config-v1",
                artifact_sha256=_hash("llm-proposal-artifact-v1"),
                input_feature_sha256=_hash("shared-input-features-v1"),
                decision_mapping_sha256=_hash("research-proposal-mapping-v1"),
                hypothetical_exit_sha256=_hash("shared-hypothetical-exits-v1"),
                cost_model_sha256=_hash("shared-simulated-cost-model-v1"),
                provider="deepseek",
                model="local-test-identity-only",
                prompt_sha256=_hash("local-proposal-prompt-v1"),
                schema_sha256=_hash("local-proposal-schema-v1"),
            ),
        ),
    )
    return schedule, protocol


def _adaptive_protocol_sample(
    schedule: ResearchObservationScheduleV1,
    protocol: AdaptiveCandidateProtocolV1,
    arm_id: str,
) -> ResearchDecisionSampleV1:
    """Create a matched, no-LLM-call observation linked to its frozen arm."""

    window = schedule.windows[0]
    assert window.market_snapshot_sha256 is not None
    assert schedule.schedule_digest is not None
    return ResearchDecisionSampleV1(
        campaign_id=schedule.campaign_id,
        arm_id=arm_id,
        arm_protocol_digest=protocol.arm_digest(arm_id),  # type: ignore[arg-type]
        sample_id=window.sample_id,
        symbol=window.symbol,
        timeframe=window.timeframe,
        market_as_of_ts_ms=window.market_as_of_ts_ms,
        market_snapshot_sha256=window.market_snapshot_sha256,
        paired_at_ts_ms=window.paired_at_ts_ms,
        sample_deadline_ts_ms=window.sample_deadline_ts_ms,
        strategy_id=schedule.strategy_id,
        strategy_revision=schedule.strategy_revision,
        strategy_outcome="NO_INTENT",
        strategy_evaluation_sha256=_hash("shared-no-intent-evaluation-v1"),
        strategy_evidence_as_of_ts_ms=window.market_as_of_ts_ms,
        strategy_market_snapshot_sha256=window.market_snapshot_sha256,
        llm_outcome="NOT_CALLED",
    )


def _tick(value: float, *, rounding: str) -> float:
    """Construct a valid sealed book level under the frozen $0.01 tick."""

    tick = Decimal("0.01")
    return float((Decimal(str(value)) / tick).to_integral_value(rounding=rounding) * tick)


def _strategy_bars(*, hourly_return: float = 0.01):
    """The frozen sleeve receives exactly 25 complete synthetic UTC hours."""

    price = 100.0
    candles: list[Candle] = []
    minute_return = (1 + hourly_return) ** (1 / 60) - 1
    for minute in range(25 * 60):
        opened = price
        closed = opened * (1 + minute_return)
        spread = opened * 0.0005
        candles.append(
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
    return tuple(candle_to_closed_bar(candle) for candle in candles)


def _auxiliary_bar(symbol: str):
    return candle_to_closed_bar(
        Candle(
            symbol=symbol,
            timeframe="1m",
            open_time_ms=0,
            close_time_ms=59_999,
            open=100.0,
            high=101.0,
            low=99.0,
            close=100.0,
            volume=10.0,
            quote_volume=1_000.0,
            taker_buy_volume=5.0,
            taker_buy_quote_volume=500.0,
        )
    )


def _exit_bar(intent, *, exit_kind: str = "STOP_EXIT_IOC", open_time_ms: int | None = None):
    if intent.side is not Side.LONG:
        raise AssertionError("sealed full-path fixture must emit the expected frozen LONG intent")
    opened_at = intent.entry_eligible_ts_ms if open_time_ms is None else open_time_ms
    if exit_kind == "STOP_EXIT_IOC":
        high, low, close = (
            intent.exit_plan.target_price * 1.01,
            intent.exit_plan.stop_price * 0.99,
            intent.reference_price,
        )
    elif exit_kind == "TARGET_EXIT_IOC":
        high, low, close = (
            intent.exit_plan.target_price * 1.01,
            intent.reference_price,
            intent.reference_price,
        )
    elif exit_kind == "TIMEOUT_EXIT_IOC":
        high = low = close = intent.reference_price
    else:
        raise ValueError("unsupported synthetic exit fixture")
    return candle_to_closed_bar(
        Candle(
            symbol=intent.symbol,
            timeframe="1m",
            open_time_ms=opened_at,
            close_time_ms=opened_at + 59_999,
            open=intent.reference_price,
            high=high,
            low=low,
            close=close,
            volume=100.0,
            quote_volume=100.0 * intent.reference_price,
            taker_buy_volume=55.0,
            taker_buy_quote_volume=55.0 * intent.reference_price,
        )
    )


def _independent_research_proposal(
    *,
    sample_id: str,
    symbol: str,
    market_as_of_ts_ms: int,
    market_snapshot_sha256: str,
    evidence_bar_sha256: str,
    action: LLMProposalAction,
) -> LLMTradeProposalV1:
    """A local zero-cost hypothesis; it never receives a strategy intent."""

    return LLMTradeProposalV1(
        campaign_id="sim-full-path-proposal-boundary-v1",
        arm_id="llm-generated-candidate",
        sample_id=sample_id,
        symbol=symbol,
        timeframe="1m",
        market_as_of_ts_ms=market_as_of_ts_ms,
        expires_at_ts_ms=market_as_of_ts_ms + 60_000,
        market_snapshot_sha256=market_snapshot_sha256,
        action=action,
        rationale="Synthetic test proposal; advisory only.",
        evidence=(
            EvidenceReferenceV1(
                kind="closed_bar",
                reference=f"{symbol}:1m:{market_as_of_ts_ms}",
                content_sha256=evidence_bar_sha256,
                observed_at_ms=market_as_of_ts_ms,
            ),
        ),
        model_provenance=LLMProposalModelProvenanceV1(
            provider="simulator-gate-local",
            requested_model="local-proposal-double",
            resolved_model="local-proposal-double-v1",
            request_id=f"sim-proposal-{sample_id}",
            prompt_sha256=_hash("local proposal prompt"),
            response_sha256=_hash("local proposal response"),
            budget_reservation_id=f"simulator-gate-no-budget-{sample_id}",
            latency_ms=0,
            cost_usd=0.0,
        ),
    )


def _research_proposal(intent, *, sample_id: str) -> LLMTradeProposalV1:
    decision_bar_sha256 = intent.provenance.input_bar_sha256s[-1]
    return _independent_research_proposal(
        sample_id=sample_id,
        symbol=intent.symbol,
        market_as_of_ts_ms=intent.decision_ts_ms,
        market_snapshot_sha256=decision_bar_sha256,
        evidence_bar_sha256=decision_bar_sha256,
        action=LLMProposalAction.LONG_BIAS,
    )


def _research_schedule(proposal: LLMTradeProposalV1) -> ScheduledResearchSampleV1:
    definition = get_strategy("regime_aligned_right_tail_v1")
    return ScheduledResearchSampleV1(
        campaign_id=proposal.campaign_id,
        arm_id=proposal.arm_id,
        sample_id=proposal.sample_id,
        symbol=proposal.symbol,
        timeframe=proposal.timeframe,
        market_as_of_ts_ms=proposal.market_as_of_ts_ms,
        market_snapshot_sha256=proposal.market_snapshot_sha256,
        strategy_id=definition.strategy_id,
        strategy_revision=definition.revision,
        paired_at_ts_ms=proposal.market_as_of_ts_ms + 1,
        sample_deadline_ts_ms=proposal.market_as_of_ts_ms + 60_000,
    )


def _synthetic_strategy_evaluation(
    schedule: ScheduledResearchSampleV1,
    *,
    bars,
    config: RegimeAlignedRightTailConfig,
    intents,
) -> StrategyEvaluationEvidenceV1:
    """Hash the actual deterministic run; this local fixture is not alpha evidence."""

    decision_bars = tuple(bar for bar in bars if bar.close_time_ms <= schedule.market_as_of_ts_ms)
    assert decision_bars and decision_bars[-1].close_time_ms == schedule.market_as_of_ts_ms
    assert decision_bars[-1].bar_sha256 == schedule.market_snapshot_sha256
    assert all(intent.decision_ts_ms == schedule.market_as_of_ts_ms for intent in intents)
    assert len(intents) <= 1
    evaluation_sha256 = canonical_sha256(
        {
            "contract_version": "sim-full-path-local-evaluation.v1",
            "campaign_id": schedule.campaign_id,
            "arm_id": schedule.arm_id,
            "sample_id": schedule.sample_id,
            "strategy_id": schedule.strategy_id,
            "strategy_revision": schedule.strategy_revision,
            "config_sha256": config.fingerprint,
            "input_bar_sha256s": [bar.bar_sha256 for bar in decision_bars],
            "intent_batch_sha256": hashlib.sha256(canonical_intent_batch_bytes(intents)).hexdigest(),
        }
    )
    return StrategyEvaluationEvidenceV1(
        campaign_id=schedule.campaign_id,
        arm_id=schedule.arm_id,
        sample_id=schedule.sample_id,
        strategy_id=schedule.strategy_id,
        strategy_revision=schedule.strategy_revision,
        symbol=schedule.symbol,
        timeframe=schedule.timeframe,
        evidence_as_of_ts_ms=schedule.market_as_of_ts_ms,
        market_snapshot_sha256=schedule.market_snapshot_sha256,
        evaluation_sha256=evaluation_sha256,
        intent_id=intents[0].intent_id if intents else None,
    )


def _paired_research_sample(
    proposal: LLMTradeProposalV1,
    *,
    bars,
    config: RegimeAlignedRightTailConfig,
    intents,
) -> ResearchDecisionSampleV1:
    schedule = _research_schedule(proposal)
    evaluation = _synthetic_strategy_evaluation(schedule, bars=bars, config=config, intents=intents)
    completion = LLMProposalCompletionReceiptV1(
        campaign_id=schedule.campaign_id,
        arm_id=schedule.arm_id,
        sample_id=schedule.sample_id,
        symbol=schedule.symbol,
        timeframe=schedule.timeframe,
        market_as_of_ts_ms=schedule.market_as_of_ts_ms,
        market_snapshot_sha256=schedule.market_snapshot_sha256,
        sample_deadline_ts_ms=schedule.sample_deadline_ts_ms,
        attempt_id=proposal.model_provenance.budget_reservation_id,
        proposal_id=proposal.proposal_id,
        model_provenance=proposal.model_provenance,
        attempt_started_at_ts_ms=schedule.market_as_of_ts_ms,
        response_observed_at_ts_ms=schedule.paired_at_ts_ms,
    )
    return build_research_decision_sample(
        schedule,
        strategy_evaluation=evaluation,
        strategy_intent=intents[0] if intents else None,
        llm_proposal=proposal,
        llm_completion=completion,
        llm_was_called=True,
    )


def _source_qualified_fixture(bars, session: SimulationSessionV1):
    """Bind a synthetic roster to actual installed code and immutable tape bytes.

    This is a local engineering fixture, not a registered scientific campaign.
    The evaluator is run separately from the persisted sources below.
    """

    definition = get_strategy("regime_aligned_right_tail_v1")
    config = RegimeAlignedRightTailConfig(regime_sma_bars=3)
    code_sha256 = installed_source_tree_sha256(definition.source_files)
    evaluator_sha256 = canonical_sha256(
        {
            "contract_version": "sim-full-path-source-evaluator.v1",
            "strategy_code_sha256": code_sha256,
            "config_sha256": config.fingerprint,
            "market_cutoff_ts_ms": bars[-1].close_time_ms,
            "input_bar_sha256s": [bar.bar_sha256 for bar in bars],
        }
    )
    prompt = ResearchPromptArtifactV1(
        system="Use only the independently saved synthetic market evidence. Return strict JSON.",
        user_prefix="Data:",
        workload=LLMWorkload.AGGREGATOR_NORMAL,
        reasoning_effort="medium",
        provider_effort="medium",
        max_output_tokens=2_048,
    )
    schedule = ResearchObservationScheduleV1(
        campaign_id=f"{session.tape_id}-source-research",
        strategy_id=definition.strategy_id,
        strategy_revision=definition.revision,
        source_set_sha256=session.tape_sha256,
        evaluator_sha256=evaluator_sha256,
        windows=(
            ResearchObservationWindowV1(
                sample_id="saved-bar-sample-1",
                symbol=bars[-1].symbol,
                timeframe=bars[-1].timeframe,
                market_as_of_ts_ms=bars[-1].close_time_ms,
                market_snapshot_sha256=bars[-1].bar_sha256,
                paired_at_ts_ms=bars[-1].close_time_ms + 500,
                sample_deadline_ts_ms=bars[-1].close_time_ms + 10_000,
            ),
        ),
    )
    common = {
        "candidate_revision": definition.revision,
        "artifact_sha256": code_sha256,
        "input_feature_sha256": RESEARCH_INPUT_FEATURE_SHA256,
        "decision_mapping_sha256": canonical_sha256({"outcomes": [item.value for item in LLMProposalAction]}),
        "hypothetical_exit_sha256": canonical_sha256(
            {
                "stop_atr": config.stop_atr_multiple,
                "reward_to_risk": config.target_reward_to_risk,
                "max_hold_hours": config.max_hold_hours,
            }
        ),
        "cost_model_sha256": session.assumptions.assumptions_sha256,
    }
    route = ModelRouter().resolve(workload=prompt.workload)
    llm = {
        "provider": route.choice.provider.value,
        "model": route.choice.model,
        "prompt_sha256": prompt.prompt_sha256,
        "schema_sha256": canonical_sha256(LLMProposalOutputV1.model_json_schema()),
    }
    protocol = AdaptiveCandidateProtocolV1(
        campaign_id=schedule.campaign_id,
        schedule_digest=schedule.schedule_digest,
        arms=(
            StrategyOnlyAdaptiveCandidateArmV1(candidate_id="saved-strategy", **common),
            StrategyReviewAdaptiveCandidateArmV1(candidate_id="not-called-review", **common, **llm),
            LLMProposalAdaptiveCandidateArmV1(candidate_id="local-proposal-double", **common, **llm),
        ),
    )
    window = schedule.windows[0]
    source = ResearchSourceReceiptV1(
        campaign_id=schedule.campaign_id,
        sample_id=window.sample_id,
        schedule_digest=schedule.schedule_digest,
        candidate_protocol_digest=protocol.protocol_digest,
        source_kind="MARKET_SNAPSHOT",
        source_name="sealed-synthetic-bars",
        reference=f"{window.symbol}:1m:{window.market_as_of_ts_ms}",
        source_as_of_ts_ms=window.market_as_of_ts_ms,
        observed_at_ts_ms=window.market_as_of_ts_ms,
        content=bars[-1].identity_payload(),
    )
    assert source.content_sha256 == bars[-1].bar_sha256
    return schedule, protocol, prompt, source, config


def _uncalled_verified_sample(schedule, protocol, evaluation, arm_id: str):
    """Explicitly retain uncalled arms, never infer review decisions from bias."""

    window = schedule.windows[0]
    sample = build_research_decision_sample(
        ScheduledResearchSampleV1(
            campaign_id=schedule.campaign_id,
            arm_id=arm_id,
            sample_id=window.sample_id,
            symbol=window.symbol,
            timeframe=window.timeframe,
            market_as_of_ts_ms=window.market_as_of_ts_ms,
            market_snapshot_sha256=window.market_snapshot_sha256,
            strategy_id=schedule.strategy_id,
            strategy_revision=schedule.strategy_revision,
            paired_at_ts_ms=window.paired_at_ts_ms,
            sample_deadline_ts_ms=window.sample_deadline_ts_ms,
        ),
        strategy_evaluation=evaluation.as_evidence(arm_id),
        strategy_intent=evaluation.intent,
        llm_was_called=False,
    )
    return ResearchDecisionSampleV1.model_validate(
        {**sample.to_payload(), "sample_record_id": None, "arm_protocol_digest": protocol.arm_digest(arm_id)}
    )


def _frame(
    *,
    tape_id: str,
    sequence: int,
    symbol: str,
    persisted_at_ms: int,
    previous_frame_sha256: str | None,
    bid: float,
    ask: float,
) -> RecordedTopNBookFrameV2:
    raw_payload = json.dumps(
        {
            "asks": [[str(ask), "10"]],
            "bids": [[str(bid), "10"]],
            "lastUpdateId": sequence,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return RecordedTopNBookFrameV2(
        source="sim-full-path-gate",
        tape_id=tape_id,
        stream_epoch="sealed-fixture-epoch-1",
        symbol=symbol,
        tape_sequence=sequence,
        exchange_update_id=sequence,
        exchange_at_ms=persisted_at_ms - 10,
        received_at_ms=persisted_at_ms - 5,
        persisted_at_ms=persisted_at_ms,
        raw_payload=raw_payload,
        raw_payload_sha256=_hash(raw_payload),
        previous_frame_sha256=previous_frame_sha256,
        continuity="ADMITTED",
        source_reason="SNAPSHOT_RECEIVED",
        bids=(RecordedBookLevelV1(price=bid, quantity=10.0),),
        asks=(RecordedBookLevelV1(price=ask, quantity=10.0),),
    )


def _settings() -> tuple[PersistenceSettings, str]:
    url = os.environ["KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL"]
    database_name = urlsplit(url).path.removeprefix("/")
    if database_name != policy.DATABASE or not _DATABASE_NAME.fullmatch(database_name):
        raise RuntimeError("full-path simulator requires its exact disposable database")
    require_database_target_url(url, database_name, local_only=True)
    return PersistenceSettings(database_url=url), database_name


async def _seed_sealed_session(
    repository: SimulationRepository,
    *,
    tape_id: str,
    exit_kind: str = "STOP_EXIT_IOC",
    include_exit_book: bool = True,
):
    bars = _strategy_bars()
    config = RegimeAlignedRightTailConfig(regime_sma_bars=3)
    first = generate_runtime_strategy_intents("regime_aligned_right_tail_v1", bars, config)
    replay = generate_runtime_strategy_intents("regime_aligned_right_tail_v1", bars, config)
    assert len(first) == len(replay) == 1
    assert canonical_intent_batch_bytes(first) == canonical_intent_batch_bytes(replay)
    intent = first[0]
    exit_open = intent.entry_eligible_ts_ms
    if exit_kind == "TIMEOUT_EXIT_IOC":
        exit_open += intent.exit_plan.max_holding_ms
    exit_bar = _exit_bar(intent, exit_kind=exit_kind, open_time_ms=exit_open)

    for bar in bars:
        assert await repository.record_closed_bar(tape_id, bar)
    # Retain the unchanged 72-hour plan. Replay every intervening flat minute
    # so the sealed tape remains contiguous; no elapsed-time waiting occurs.
    for opened_at in range(intent.entry_eligible_ts_ms, exit_bar.open_time_ms, 60_000):
        assert await repository.record_closed_bar(
            tape_id, _exit_bar(intent, exit_kind="TIMEOUT_EXIT_IOC", open_time_ms=opened_at)
        )
    assert await repository.record_closed_bar(tape_id, exit_bar)
    for symbol in _SYMBOLS[1:]:
        assert await repository.record_closed_bar(tape_id, _auxiliary_bar(symbol))

    previous: str | None = None
    frames: dict[str, RecordedTopNBookFrameV2] = {}
    for sequence, symbol in enumerate(_SYMBOLS, start=1):
        multiplier = 1.0001 if symbol == intent.symbol else 1.001
        frame = _frame(
            tape_id=tape_id,
            sequence=sequence,
            symbol=symbol,
            persisted_at_ms=intent.entry_eligible_ts_ms + sequence - 1,
            previous_frame_sha256=previous,
            bid=_tick(intent.reference_price * (2 - multiplier), rounding=ROUND_FLOOR),
            ask=_tick(intent.reference_price * multiplier, rounding=ROUND_CEILING),
        )
        assert await repository.record_book_frame(frame)
        frames[symbol] = frame
        previous = frame.frame_sha256
    exit_price = {
        "STOP_EXIT_IOC": intent.exit_plan.stop_price * 1.01,
        "TARGET_EXIT_IOC": intent.exit_plan.target_price * 1.001,
        "TIMEOUT_EXIT_IOC": intent.reference_price,
    }[exit_kind]
    if include_exit_book:
        exit_bid = _tick(exit_price, rounding=ROUND_FLOOR)
        exit_frame = _frame(
            tape_id=tape_id,
            sequence=len(_SYMBOLS) + 1,
            symbol=intent.symbol,
            persisted_at_ms=exit_bar.close_time_ms + 10,
            previous_frame_sha256=previous,
            bid=exit_bid,
            ask=_tick(exit_bid * 1.0002, rounding=ROUND_CEILING),
        )
        assert await repository.record_book_frame(exit_frame)
    seal = await repository.seal_tape(tape_id, sealed_at_ms=exit_bar.close_time_ms + 100)
    assert seal.execution_environment == "SIMULATED"
    assert not seal.paper_qualification_eligible and not seal.trial15_eligible and not seal.alpha_claim
    assert await repository.verify_tape(tape_id)

    session = SimulationSessionV1(
        source="sim-full-path-gate",
        tape_id=tape_id,
        tape_sha256=seal.tape_sha256,
        assumptions=SimulationAssumptionsV1(
            latency_ms=25,
            maximum_book_age_ms=5_000,
            maximum_frame_latency_ms=1_000,
            depth_participation_fraction=1.0,
            adverse_slippage_bps=0.0,
            taker_fee_bps=5.0,
            price_tick=0.01,
            quantity_step=0.001,
        ),
        strategy_allowlist=(
            SimulationStrategyRefV1(
                strategy_id=intent.strategy_id,
                strategy_revision=intent.strategy_revision,
            ),
        ),
        started_at_ms=intent.decision_ts_ms,
        ends_at_ms=exit_bar.close_time_ms + 120_000,
    )
    assert await repository.create_session(session)
    return intent, session, frames[intent.symbol], exit_bar


async def _seed_wait_session(repository: SimulationRepository, *, tape_id: str):
    """Seal flat synthetic bars for a pure-generator no-intent check.

    This 25-hour fixture does not meet the production service's larger
    scheduling/warmup requirement and is not evidence of runtime uptime.
    """

    bars = _strategy_bars(hourly_return=0.0)
    config = RegimeAlignedRightTailConfig(regime_sma_bars=3)
    assert generate_runtime_strategy_intents("regime_aligned_right_tail_v1", bars, config) == ()
    for bar in bars:
        assert await repository.record_closed_bar(tape_id, bar)
    for symbol in _SYMBOLS[1:]:
        assert await repository.record_closed_bar(tape_id, _auxiliary_bar(symbol))

    market_as_of_ts_ms = bars[-1].close_time_ms
    previous: str | None = None
    for sequence, symbol in enumerate(_SYMBOLS, start=1):
        frame = _frame(
            tape_id=tape_id,
            sequence=sequence,
            symbol=symbol,
            persisted_at_ms=market_as_of_ts_ms + sequence,
            previous_frame_sha256=previous,
            bid=99.99,
            ask=100.01,
        )
        assert await repository.record_book_frame(frame)
        previous = frame.frame_sha256
    seal = await repository.seal_tape(tape_id, sealed_at_ms=market_as_of_ts_ms + 100)
    assert seal.execution_environment == "SIMULATED"
    assert not seal.paper_qualification_eligible and not seal.trial15_eligible and not seal.alpha_claim
    assert await repository.verify_tape(tape_id)

    definition = get_strategy("regime_aligned_right_tail_v1")
    session = SimulationSessionV1(
        source="sim-full-path-gate",
        tape_id=tape_id,
        tape_sha256=seal.tape_sha256,
        assumptions=SimulationAssumptionsV1(
            latency_ms=25,
            maximum_book_age_ms=5_000,
            maximum_frame_latency_ms=1_000,
            depth_participation_fraction=1.0,
            adverse_slippage_bps=0.0,
            taker_fee_bps=5.0,
            price_tick=0.01,
            quantity_step=0.001,
        ),
        strategy_allowlist=(
            SimulationStrategyRefV1(
                strategy_id=definition.strategy_id,
                strategy_revision=definition.revision,
            ),
        ),
        started_at_ms=market_as_of_ts_ms,
        ends_at_ms=market_as_of_ts_ms + 120_000,
    )
    assert await repository.create_session(session)
    return bars, config, session


async def _load_research_bars(repository: SimulationRepository, tape_id: str, market_as_of_ms: int):
    """Bounded keyset replay; never feed a future exit bar into the evaluator."""
    assert await repository.verify_tape(tape_id)
    cursor: int | None = None
    replayed_bars = []
    page_size = 257
    while True:
        page = await repository.load_closed_bar_page(
            tape_id,
            "BTCUSDT",
            after_open_time_ms=cursor,
            limit=page_size,
        )
        if not page:
            break
        replayed_bars.extend(bar for bar in page if bar.close_time_ms <= market_as_of_ms)
        cursor = page[-1].open_time_ms
        if len(page) < page_size or page[-1].close_time_ms >= market_as_of_ms:
            break
    return tuple(replayed_bars)


async def _assert_strategy_replays_from_sealed_tape(
    repository: SimulationRepository, tape_id: str, intent
) -> None:
    """Prove strategy replay uses the bounded, immutable database bar reader."""

    expected_bars = _strategy_bars()
    replayed_bars = await _load_research_bars(repository, tape_id, intent.decision_ts_ms)

    assert replayed_bars == expected_bars
    replayed_intents = generate_runtime_strategy_intents(
        "regime_aligned_right_tail_v1",
        replayed_bars,
        RegimeAlignedRightTailConfig(regime_sma_bars=3),
    )
    assert canonical_intent_batch_bytes(replayed_intents) == canonical_intent_batch_bytes((intent,))


async def _review(intent, decision: ReviewDecision):
    route = CandidateRouterPolicy(source="sim-full-path-gate-router").build(intent, TextAggregate())
    gateway = _LocalReviewGateway(decision)
    review = await CandidateReviewBrain(
        gateway,
        source="sim-full-path-gate-aggregator",
        clock_ms=lambda: intent.decision_ts_ms + 1,
    ).review_legacy_engineering(route, ())
    assert len(gateway.calls) == 1
    assert review.decision is decision
    assert review.intent.model_dump(mode="json") == intent.model_dump(mode="json")
    assert review.route.intent.model_dump(mode="json") == intent.model_dump(mode="json")
    assert review.model_provenance is not None
    assert review.model_provenance.provider == "simulator-gate-local"
    assert review.model_provenance.cost_usd == 0.0
    return review


def test_independent_research_pair_keeps_wait_and_opposite_signal_non_executable() -> None:
    config = RegimeAlignedRightTailConfig(regime_sma_bars=3)
    flat_bars = _strategy_bars(hourly_return=0.0)
    flat_intents = generate_runtime_strategy_intents("regime_aligned_right_tail_v1", flat_bars, config)
    assert flat_intents == ()
    assert canonical_intent_batch_bytes(flat_intents) == canonical_intent_batch_bytes(
        generate_runtime_strategy_intents("regime_aligned_right_tail_v1", flat_bars, config)
    )
    final_bar = flat_bars[-1]
    assert final_bar.bar_sha256 is not None
    wait_proposal = _independent_research_proposal(
        sample_id="wait-arm-sample-1",
        symbol=final_bar.symbol,
        market_as_of_ts_ms=final_bar.close_time_ms,
        market_snapshot_sha256=final_bar.bar_sha256,
        evidence_bar_sha256=final_bar.bar_sha256,
        action=LLMProposalAction.LONG_BIAS,
    )
    wait_sample = _paired_research_sample(wait_proposal, bars=flat_bars, config=config, intents=flat_intents)
    assert wait_sample.strategy_outcome == "NO_INTENT"
    assert wait_sample.strategy_intent_id is None
    assert wait_sample.strategy_evaluation_sha256 is not None
    assert wait_sample.llm_outcome == "LONG_BIAS"
    assert wait_sample.llm_proposal_id == wait_proposal.proposal_id
    assert wait_sample.llm_completion_receipt_id is not None

    trend_bars = _strategy_bars()
    trend_intents = generate_runtime_strategy_intents("regime_aligned_right_tail_v1", trend_bars, config)
    assert len(trend_intents) == 1 and trend_intents[0].side is Side.LONG
    intent = trend_intents[0]
    decision_bar_sha256 = intent.provenance.input_bar_sha256s[-1]
    opposite_proposal = _independent_research_proposal(
        sample_id="opposite-arm-sample-1",
        symbol=intent.symbol,
        market_as_of_ts_ms=intent.decision_ts_ms,
        market_snapshot_sha256=decision_bar_sha256,
        evidence_bar_sha256=decision_bar_sha256,
        action=LLMProposalAction.SHORT_BIAS,
    )
    opposite_sample = _paired_research_sample(
        opposite_proposal, bars=trend_bars, config=config, intents=trend_intents
    )
    assert opposite_sample.strategy_outcome == "LONG"
    assert opposite_sample.strategy_intent_id == intent.intent_id
    assert opposite_sample.llm_outcome == "SHORT_BIAS"
    assert opposite_sample.llm_proposal_id == opposite_proposal.proposal_id
    for sample in (wait_sample, opposite_sample):
        assert sample.authority == "SIM_RESEARCH_ONLY"
        assert not {"order", "quantity", "price", "venue", "risk_decision"}.intersection(
            sample.identity_payload()
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sealed_full_path_is_deterministic_and_stop_wins_after_restart() -> None:
    policy.validate_environment()
    policy.validate_database_url(os.environ["KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL"])
    policy.validate_installed_sources()
    settings, database_name = _settings()
    database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
    await connect_verified_database(database, database_name, local_only=True)
    try:
        await database.migrate()
        repository = SimulationRepository(database.pool)
        proposal_repository = SimulatorProposalRepository(database)
        intent, session, entry_frame, exit_bar = await _seed_sealed_session(
            repository, tape_id="full-path-allow-tape"
        )
        await _assert_strategy_replays_from_sealed_tape(repository, session.tape_id, intent)
        proposal = _research_proposal(intent, sample_id="allow-arm-sample-1")
        proposal_bus = _ProposalGateBus()
        proposal_consumer = asyncio.create_task(
            consume_simulator_proposals(
                proposal_repository,
                proposal_bus,
                consumer="sim-full-path-gate",
            )
        )
        try:
            await asyncio.wait_for(proposal_bus.subscribed.wait(), timeout=1)
            proposal_message_id = await proposal_bus.publish(Topics.LLM_TRADE_PROPOSAL, proposal)
            await asyncio.wait_for(proposal_bus.acknowledged.wait(), timeout=1)
        finally:
            proposal_consumer.cancel()
            with pytest.raises(asyncio.CancelledError):
                await proposal_consumer
        assert proposal_bus.subscription == (
            Topics.LLM_TRADE_PROPOSAL,
            "simulator-llm-proposal-ledger-v1",
            "sim-full-path-gate",
        )
        assert proposal_bus.acks == [
            (Topics.LLM_TRADE_PROPOSAL, proposal_message_id, "simulator-llm-proposal-ledger-v1")
        ]
        assert not await proposal_repository.record(proposal)
        assert await proposal_repository.load_page(
            campaign_id=proposal.campaign_id,
            arm_id=proposal.arm_id,
            limit=10,
        ) == (proposal,)

        decision_bar_sha256 = intent.provenance.input_bar_sha256s[-1]
        opposite_proposal = _independent_research_proposal(
            sample_id="opposite-arm-sample-1",
            symbol=intent.symbol,
            market_as_of_ts_ms=intent.decision_ts_ms,
            market_snapshot_sha256=decision_bar_sha256,
            evidence_bar_sha256=decision_bar_sha256,
            action=LLMProposalAction.SHORT_BIAS,
        )
        opposite_sample = _paired_research_sample(
            opposite_proposal,
            bars=_strategy_bars(),
            config=RegimeAlignedRightTailConfig(regime_sma_bars=3),
            intents=(intent,),
        )
        assert opposite_sample.strategy_outcome == "LONG"
        assert opposite_sample.llm_outcome == "SHORT_BIAS"
        assert await proposal_repository.record(opposite_proposal)
        sample_repository = ResearchDecisionSampleRepository(database)
        assert await sample_repository.record(opposite_sample)
        assert not await sample_repository.record(opposite_sample)
        assert await sample_repository.load_page(
            campaign_id=opposite_sample.campaign_id,
            arm_id=opposite_sample.arm_id,
            limit=10,
        ) == (opposite_sample,)
        assert (
            await database.pool.fetchval(
                "SELECT count(*) FROM sim_risk_decisions WHERE session_id=$1", session.session_id
            )
            == 0
        )
        assert (
            await database.pool.fetchval(
                "SELECT count(*) FROM sim_admissions WHERE session_id=$1", session.session_id
            )
            == 0
        )
        assert (
            await database.pool.fetchval(
                "SELECT count(*) FROM sim_commands WHERE session_id=$1", session.session_id
            )
            == 0
        )
        stored_evidence = await database.pool.fetchrow(
            """SELECT frame_contract_version, source_reason, raw_payload_text, raw_payload_sha256
               FROM sim_book_frames WHERE tape_id=$1 AND tape_sequence=1""",
            session.tape_id,
        )
        assert stored_evidence is not None
        assert dict(stored_evidence) == {
            "frame_contract_version": "sim-book-frame.v2",
            "source_reason": "SNAPSHOT_RECEIVED",
            "raw_payload_text": entry_frame.raw_payload,
            "raw_payload_sha256": entry_frame.raw_payload_sha256,
        }
        review = await _review(intent, ReviewDecision.ALLOW)
        decided_at_ms = intent.entry_eligible_ts_ms + 10
        decision = SimulationRiskPolicy(source="sim-full-path-gate-risk").evaluate(
            session=session,
            review=review,
            selected_book_frame=entry_frame,
            decided_at_ms=decided_at_ms,
            requested_quantity=0.01,
        )
        assert decision.approved
        assert decision.execution_environment == "SIMULATED"
        assert not decision.paper_qualification_eligible
        assert not decision.trial15_eligible
        assert not decision.alpha_claim
        assert await repository.record_risk_decision(decision)
        admission = SimulationAdmissionV2(
            source="sim-full-path-gate",
            decision=decision,
            admitted_at_ms=decided_at_ms,
        )
        controller = SimulationExecutionController(repository, source="sim-full-path-gate-controller")
        trade = await controller.start_trade(admission, created_at_ms=decided_at_ms)
        # Admission happens ten milliseconds after eligibility. The first
        # call proves the command remains durable-but-pending before the
        # frozen 25 ms latency has elapsed; the second uses exact arrival.
        pending = await controller.submit_entry(trade, as_of_ms=intent.entry_eligible_ts_ms + 25)
        assert pending.receipt is None and pending.lifecycle_state == "PENDING" and not pending.replayed
        entry = await controller.submit_entry(trade, as_of_ms=intent.entry_eligible_ts_ms + 35)
        assert entry.receipt is not None and entry.receipt.status == "FILLED"
        assert entry.lifecycle_state == "ACTIVE" and not entry.replayed

        await database.close()
        database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
        await connect_verified_database(database, database_name, local_only=True)
        repository = SimulationRepository(database.pool)
        restarted = SimulationExecutionController(repository, source="sim-full-path-gate-controller")
        replayed_entry = await restarted.submit_entry(trade, as_of_ms=intent.entry_eligible_ts_ms + 35)
        assert replayed_entry.replayed
        assert replayed_entry.command.command_id == entry.command.command_id
        assert replayed_entry.receipt == entry.receipt

        exit_outcome = await restarted.process_closed_bar(
            trade,
            exit_bar,
            as_of_ms=exit_bar.close_time_ms + 30,
        )
        assert exit_outcome is not None and exit_outcome.receipt is not None
        assert exit_outcome.command.command_kind == "STOP_EXIT_IOC"
        assert exit_outcome.receipt.status == "FILLED"
        assert exit_outcome.lifecycle_state == "FLAT"
        assert await repository.verify_trade_chain(trade.trade_id)
        journal = await repository.load_trade_journal(trade.trade_id)
        assert journal is not None and journal.state == "FLAT" and len(journal.events) == 3
        assert await repository.list_prepared_commands(session.session_id) == ()
        assert await repository.list_terminal_trades_without_result(session.session_id) == ()
        assert (
            await database.pool.fetchval(
                "SELECT count(*) FROM sim_commands WHERE trade_id=$1", trade.trade_id
            )
            == 2
        )
        assert (
            await database.pool.fetchval("SELECT count(*) FROM sim_results WHERE trade_id=$1", trade.trade_id)
            == 1
        )
    finally:
        await database.close()


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "action", "expected_strategy"),
    [("wait", LLMProposalAction.LONG_BIAS, "NO_INTENT"), ("opposite", LLMProposalAction.SHORT_BIAS, "LONG")],
)
async def test_source_qualified_conflict_replays_independent_receipts_without_another_call(
    scenario, action, expected_strategy
) -> None:
    """Compose actual Strategy replay with the real journal, never an economic seal."""

    policy.validate_environment()
    policy.validate_database_url(os.environ["KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL"])
    policy.validate_installed_sources()
    settings, database_name = _settings()
    database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
    await connect_verified_database(database, database_name, local_only=True)
    try:
        await database.migrate()
        simulation = SimulationRepository(database.pool)
        if scenario == "wait":
            _, _, session = await _seed_wait_session(simulation, tape_id="source-qualified-wait-tape")
            market_clock = session.started_at_ms
        else:
            intent, session, _, _ = await _seed_sealed_session(
                simulation, tape_id="source-qualified-opposite-tape"
            )
            market_clock = intent.decision_ts_ms
        bars = await _load_research_bars(simulation, session.tape_id, market_clock)
        assert len(bars) == 1_500 and bars[-1].close_time_ms == market_clock
        schedule, protocol, prompt, source, config = _source_qualified_fixture(bars, session)
        journal = ResearchEvidenceRepository(database)
        execution_tables = (
            "sim_risk_decisions",
            "sim_admissions",
            "sim_trades",
            "sim_commands",
            "sim_results",
        )
        counts_before = {
            table: await database.pool.fetchval(f"SELECT count(*) FROM {table}") for table in execution_tables
        }
        assert await ResearchObservationScheduleRepository(database).register(schedule)
        assert await ResearchAdaptiveCandidateProtocolRepository(database).register(protocol)
        assert await journal.enroll_campaign(schedule.campaign_id)
        assert await journal.record_source(source)
        assert not await journal.record_source(source)
        assert await journal.load_source(source.receipt_sha256) == source

        # Evaluate only DB-replayed, causal bars after the roster/source is
        # committed. No supplied outcome can replace this actual generator run.
        evaluated = generate_runtime_strategy_intents("regime_aligned_right_tail_v1", bars, config)
        assert len(evaluated) <= 1
        assert canonical_intent_batch_bytes(evaluated) == canonical_intent_batch_bytes(
            generate_runtime_strategy_intents("regime_aligned_right_tail_v1", bars, config)
        )
        evaluation = ResearchStrategyEvaluationReceiptV1(
            campaign_id=schedule.campaign_id,
            sample_id=source.sample_id,
            schedule_digest=schedule.schedule_digest,
            candidate_protocol_digest=protocol.protocol_digest,
            strategy_id=schedule.strategy_id,
            strategy_revision=schedule.strategy_revision,
            symbol=bars[-1].symbol,
            timeframe=bars[-1].timeframe,
            evidence_as_of_ts_ms=market_clock,
            evaluated_at_ts_ms=market_clock + 10,
            market_snapshot_sha256=source.content_sha256,
            evaluator_sha256=schedule.evaluator_sha256,
            source_receipt_sha256s=(source.receipt_sha256,),
            intent=evaluated[0] if evaluated else None,
        )
        assert await journal.record_evaluation(evaluation)
        assert not await journal.record_evaluation(evaluation)
        assert await journal.load_evaluation(evaluation.receipt_sha256) == evaluation
        wrong_evaluator = ResearchStrategyEvaluationReceiptV1.model_validate(
            {**evaluation.model_dump(mode="json"), "receipt_sha256": None, "evaluator_sha256": "0" * 64}
        )
        with pytest.raises(MessageIdentityConflict, match="evaluator"):
            await journal.record_evaluation(wrong_evaluator)

        late_source = ResearchSourceReceiptV1(
            campaign_id=schedule.campaign_id,
            sample_id=source.sample_id,
            schedule_digest=schedule.schedule_digest,
            candidate_protocol_digest=protocol.protocol_digest,
            source_kind="NEWS",
            source_name="local-late-fixture",
            reference="late-synthetic-news",
            source_as_of_ts_ms=market_clock - 1,
            observed_at_ts_ms=market_clock + 1,
            content={"headline": "Synthetic late observation, never admitted as causal input."},
        )
        assert await journal.record_source(late_source)
        budget = _LocalResearchBudget()
        underlying = _LocalResearchGateway(journal, action)
        clocks = iter((market_clock + 100, market_clock + 200))
        coordinator = ResearchProposalCoordinator(
            BudgetedLLMGateway(underlying, budget), journal, clock=lambda: next(clocks)
        )
        request = {
            "schedule": schedule,
            "protocol": protocol,
            "sample_id": source.sample_id,
            "prompt": prompt,
            "source_receipt_sha256s": (source.receipt_sha256,),
            "workload": prompt.workload,
        }
        with pytest.raises(ResearchEvidenceError, match="causal cutoff"):
            await coordinator.observe(
                **{**request, "source_receipt_sha256s": (source.receipt_sha256, late_source.receipt_sha256)}
            )
        with pytest.raises(MessageIdentityConflict):
            await coordinator.observe(**{**request, "source_receipt_sha256s": ("0" * 64,)})
        assert budget.reservations == underlying.calls == []
        observation = await coordinator.observe(**request)
        assert observation.terminal is not None and observation.terminal.terminal_status == "COMPLETED"
        assert len(underlying.calls) == len(budget.reservations) == len(budget.commits) == 1
        assert observation.start.attempt_id == budget.reservations[0]["reservation_id"]
        assert observation.start.attempt_id == budget.commits[0]["reservation_id"]
        sample = await coordinator.replay_sample(
            **request, evaluation_receipt_sha256=evaluation.receipt_sha256
        )
        assert sample.strategy_outcome == expected_strategy and sample.llm_outcome == action.value
        assert sample.arm_protocol_digest == protocol.arm_digest("llm-proposal-research")
        assert sample.strategy_evaluation_sha256 == evaluation.receipt_sha256
        assert sample.llm_completion_receipt_id == observation.terminal.completion.completion_receipt_id
        assert sample.authority == "SIM_RESEARCH_ONLY"

        await database.close()
        database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
        await connect_verified_database(database, database_name, local_only=True)
        journal = ResearchEvidenceRepository(database)
        restart_budget = _LocalResearchBudget()
        restart_gateway = _LocalResearchGateway(journal, action, forbid_calls=True)
        restarted = ResearchProposalCoordinator(BudgetedLLMGateway(restart_gateway, restart_budget), journal)
        assert await restarted.observe(**request) == observation
        assert (
            await restarted.replay_sample(**request, evaluation_receipt_sha256=evaluation.receipt_sha256)
            == sample
        )
        assert not await journal.record_verified_sample(sample)
        assert restart_budget.reservations == restart_budget.commits == restart_gateway.calls == []
        for arm_id in RESEARCH_ARMS[:2]:
            uncalled = _uncalled_verified_sample(schedule, protocol, evaluation, arm_id)
            assert uncalled.llm_outcome == "NOT_CALLED"
            assert await journal.record_verified_sample(uncalled)
        qualified = await journal.seal_verified_coverage(campaign_id=schedule.campaign_id)
        assert await journal.seal_verified_coverage(campaign_id=schedule.campaign_id) == qualified
        assert qualified.qualification == "INDEPENDENT_SOURCE_REPLAY_ONLY"
        assert not qualified.economic_qualification and not qualified.paper_qualification
        assert not qualified.live_orders_allowed
        assert qualified.coverage.expected_result_count == 3
        assert qualified.source_ids_sha256 == canonical_sha256(
            {"receipt_ids": sorted((source.receipt_sha256, late_source.receipt_sha256))}
        )
        assert qualified.evaluation_ids_sha256 == canonical_sha256(
            {"receipt_ids": [evaluation.receipt_sha256]}
        )
        assert qualified.attempt_start_ids_sha256 == canonical_sha256(
            {"receipt_ids": [observation.start.receipt_sha256]}
        )
        assert qualified.attempt_terminal_ids_sha256 == canonical_sha256(
            {"receipt_ids": [observation.terminal.receipt_sha256]}
        )
        counts_after = {
            table: await database.pool.fetchval(f"SELECT count(*) FROM {table}") for table in execution_tables
        }
        assert counts_after == counts_before
    finally:
        await database.close()


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exit_kind", "include_exit_book"),
    [("TARGET_EXIT_IOC", True), ("TIMEOUT_EXIT_IOC", True), ("TARGET_EXIT_IOC", False)],
)
async def test_durable_target_timeout_and_missing_fresh_book_survive_restart_without_duplicate_fill(
    exit_kind, include_exit_book
) -> None:
    policy.validate_environment()
    policy.validate_database_url(os.environ["KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL"])
    policy.validate_installed_sources()
    settings, database_name = _settings()
    database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
    await connect_verified_database(database, database_name, local_only=True)
    try:
        await database.migrate()
        repository = SimulationRepository(database.pool)
        intent, session, entry_frame, exit_bar = await _seed_sealed_session(
            repository,
            tape_id=f"full-path-{exit_kind.lower()}-{int(include_exit_book)}-tape",
            exit_kind=exit_kind,
            include_exit_book=include_exit_book,
        )
        await _assert_strategy_replays_from_sealed_tape(repository, session.tape_id, intent)
        review = await _review(intent, ReviewDecision.ALLOW)
        decided_at_ms = intent.entry_eligible_ts_ms + 10
        decision = SimulationRiskPolicy(source="sim-full-path-exit-risk").evaluate(
            session=session,
            review=review,
            selected_book_frame=entry_frame,
            decided_at_ms=decided_at_ms,
            requested_quantity=0.01,
        )
        assert decision.approved and not decision.alpha_claim
        assert await repository.record_risk_decision(decision)
        admission = SimulationAdmissionV2(
            source="sim-full-path-exits", decision=decision, admitted_at_ms=decided_at_ms
        )
        controller = SimulationExecutionController(repository, source="sim-full-path-exits")
        trade = await controller.start_trade(admission, created_at_ms=decided_at_ms)
        entry = await controller.submit_entry(trade, as_of_ms=intent.entry_eligible_ts_ms + 35)
        assert entry.receipt is not None and entry.receipt.status == "FILLED"
        # Persist the exit before logical arrival, then restart with PREPARED
        # evidence rather than fabricating a successful terminal receipt.
        pending = await controller.process_closed_bar(trade, exit_bar, as_of_ms=exit_bar.close_time_ms + 1)
        assert pending is not None and pending.receipt is None and pending.lifecycle_state == "ACTIVE"
        assert pending.command.command_kind == exit_kind
        await database.close()
        database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
        await connect_verified_database(database, database_name, local_only=True)
        repository = SimulationRepository(database.pool)
        restarted = SimulationExecutionController(repository, source="sim-full-path-exits")
        outcomes = await restarted.recover_prepared(session.session_id, as_of_ms=exit_bar.close_time_ms + 30)
        assert len(outcomes) == 1 and outcomes[0].command == pending.command
        outcome = outcomes[0]
        assert outcome.receipt is not None
        if include_exit_book:
            assert outcome.receipt.status == "FILLED" and outcome.lifecycle_state == "FLAT"
            assert outcome.receipt.filled_quantity == pytest.approx(entry.receipt.filled_quantity)
        else:
            assert outcome.receipt.status == "BLOCKED" and outcome.lifecycle_state == "UNRESOLVED"
            assert "STALE_BOOK" in outcome.receipt.reason_codes
            assert outcome.receipt.filled_quantity == 0 and outcome.receipt.average_price is None
            assert outcome.receipt.model_frame_sha256 is None
        assert (
            await restarted.process_closed_bar(trade, exit_bar, as_of_ms=exit_bar.close_time_ms + 100) is None
        )
        assert (
            await restarted.recover_prepared(session.session_id, as_of_ms=exit_bar.close_time_ms + 100) == ()
        )
        receipt = await repository.load_command_receipt(pending.command.command_id)
        assert receipt == outcome.receipt
        journal = await repository.load_trade_journal(trade.trade_id)
        assert journal is not None and len(journal.events) == 3 and journal.state == outcome.lifecycle_state
        assert await repository.verify_trade_chain(trade.trade_id)
        assert await repository.list_prepared_commands(session.session_id) == ()
        assert await repository.list_terminal_trades_without_result(session.session_id) == ()
        assert (
            await database.pool.fetchval(
                "SELECT count(*) FROM sim_commands WHERE trade_id=$1", trade.trade_id
            )
            == 2
        )
        assert (
            await database.pool.fetchval("SELECT count(*) FROM sim_results WHERE trade_id=$1", trade.trade_id)
            == 1
        )
    finally:
        await database.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_strategy_wait_and_independent_llm_proposal_are_only_sim_research_evidence() -> None:
    policy.validate_environment()
    policy.validate_database_url(os.environ["KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL"])
    policy.validate_installed_sources()
    settings, database_name = _settings()
    database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
    await connect_verified_database(database, database_name, local_only=True)
    try:
        await database.migrate()
        repository = SimulationRepository(database.pool)
        bars, config, session = await _seed_wait_session(repository, tape_id="full-path-wait-tape")
        assert await repository.verify_tape(session.tape_id)

        replayed_bars = []
        cursor: int | None = None
        while True:
            page = await repository.load_closed_bar_page(
                session.tape_id,
                "BTCUSDT",
                after_open_time_ms=cursor,
                limit=257,
            )
            if not page:
                break
            replayed_bars.extend(page)
            cursor = page[-1].open_time_ms
            if len(page) < 257:
                break
        assert tuple(replayed_bars) == bars
        intents = generate_runtime_strategy_intents("regime_aligned_right_tail_v1", replayed_bars, config)
        assert intents == ()
        assert canonical_intent_batch_bytes(intents) == canonical_intent_batch_bytes(
            generate_runtime_strategy_intents("regime_aligned_right_tail_v1", replayed_bars, config)
        )

        final_bar = replayed_bars[-1]
        assert final_bar.bar_sha256 is not None
        proposal = _independent_research_proposal(
            sample_id="wait-arm-sample-1",
            symbol=final_bar.symbol,
            market_as_of_ts_ms=final_bar.close_time_ms,
            market_snapshot_sha256=final_bar.bar_sha256,
            evidence_bar_sha256=final_bar.bar_sha256,
            action=LLMProposalAction.LONG_BIAS,
        )
        sample = _paired_research_sample(proposal, bars=replayed_bars, config=config, intents=intents)
        assert sample.strategy_outcome == "NO_INTENT" and sample.strategy_intent_id is None
        assert sample.llm_outcome == "LONG_BIAS" and sample.llm_proposal_id == proposal.proposal_id
        assert sample.authority == "SIM_RESEARCH_ONLY"

        proposal_repository = SimulatorProposalRepository(database)
        sample_repository = ResearchDecisionSampleRepository(database)
        assert await proposal_repository.record(proposal)
        assert await sample_repository.record(sample)
        assert not await proposal_repository.record(proposal)
        assert not await sample_repository.record(sample)
        assert proposal in await proposal_repository.load_page(
            campaign_id=proposal.campaign_id,
            arm_id=proposal.arm_id,
            limit=10,
        )
        assert sample in await sample_repository.load_page(
            campaign_id=sample.campaign_id,
            arm_id=sample.arm_id,
            limit=10,
        )
        for table in ("sim_risk_decisions", "sim_admissions", "sim_trades", "sim_commands"):
            assert (
                await database.pool.fetchval(
                    f"SELECT count(*) FROM {table} WHERE session_id=$1", session.session_id
                )
                == 0
            )
    finally:
        await database.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_veto_persists_rejected_sim_evidence_without_admission_or_command() -> None:
    policy.validate_environment()
    settings, database_name = _settings()
    database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
    await connect_verified_database(database, database_name, local_only=True)
    try:
        await database.migrate()
        repository = SimulationRepository(database.pool)
        intent, session, entry_frame, _ = await _seed_sealed_session(
            repository, tape_id="full-path-veto-tape"
        )
        await _assert_strategy_replays_from_sealed_tape(repository, session.tape_id, intent)
        review = await _review(intent, ReviewDecision.VETO)
        decision = SimulationRiskPolicy(source="sim-full-path-gate-risk").evaluate(
            session=session,
            review=review,
            selected_book_frame=entry_frame,
            decided_at_ms=intent.entry_eligible_ts_ms + 10,
            requested_quantity=0.01,
        )
        assert not decision.approved
        assert decision.quantity == 0.0 and decision.price_cap is None
        assert "REVIEW_VETO" in decision.rejection_reasons
        assert await repository.record_risk_decision(decision)
        assert (
            await database.pool.fetchval(
                "SELECT count(*) FROM sim_admissions WHERE session_id=$1", session.session_id
            )
            == 0
        )
        assert (
            await database.pool.fetchval(
                "SELECT count(*) FROM sim_trades WHERE session_id=$1", session.session_id
            )
            == 0
        )
        assert (
            await database.pool.fetchval(
                "SELECT count(*) FROM sim_commands WHERE session_id=$1", session.session_id
            )
            == 0
        )
    finally:
        await database.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_adaptive_candidate_protocol_is_sealed_as_non_authoritative_sim_evidence() -> None:
    """Persist the exact preregistered three-arm matrix without affecting readiness or execution."""

    policy.validate_environment()
    policy.validate_database_url(os.environ["KAIROS_SIM_FULL_PATH_GATE_DATABASE_URL"])
    policy.validate_installed_sources()
    source_lock = json.loads(Path(__file__).with_name("source-lock.json").read_text(encoding="utf-8"))
    assert source_lock["classification"] == "SIMULATED"
    assert source_lock["readiness"] == {
        "paper_qualified": False,
        "alpha_ready": False,
        "live_ready": False,
        "strategy_policy": "REJECT_ALL",
    }

    settings, database_name = _settings()
    database = Database(settings, migration_profile=MigrationProfile.SIMULATOR)
    await connect_verified_database(database, database_name, local_only=True)
    try:
        await database.migrate()
        schedule_repository = ResearchObservationScheduleRepository(database)
        protocol_repository = ResearchAdaptiveCandidateProtocolRepository(database)
        sample_repository = ResearchDecisionSampleRepository(database)
        schedule, protocol = _adaptive_protocol_fixture()

        # Capture execution-side counts so this proof asserts that registering
        # research evidence has no trade, order, result, or risk side effect.
        execution_tables = (
            "sim_risk_decisions",
            "sim_admissions",
            "sim_trades",
            "sim_commands",
            "sim_results",
        )
        execution_counts_before = {
            table: await database.pool.fetchval(f"SELECT count(*) FROM {table}") for table in execution_tables
        }

        assert schedule.authority == "SIM_RESEARCH_ONLY"
        assert protocol.authority == "SIM_RESEARCH_ONLY"
        assert await schedule_repository.register(schedule)
        assert not await schedule_repository.register(schedule)
        assert await protocol_repository.register(protocol)
        assert not await protocol_repository.register(protocol)

        stored_arm_digests: dict[str, str] = {}
        research_samples: list[ResearchDecisionSampleV1] = []
        for arm_id in RESEARCH_ARMS:
            expected_digest = protocol.arm_digest(arm_id)
            assert (
                await protocol_repository.resolve_arm_digest(
                    campaign_id=schedule.campaign_id,
                    arm_id=arm_id,
                )
                == expected_digest
            )
            sample = _adaptive_protocol_sample(schedule, protocol, arm_id)
            research_samples.append(sample)
            assert sample.authority == "SIM_RESEARCH_ONLY"
            assert sample.llm_outcome == "NOT_CALLED"
            assert sample.arm_protocol_digest == expected_digest
            assert await sample_repository.record(sample)
            assert not await sample_repository.record(sample)
            stored = await sample_repository.load_page(
                campaign_id=schedule.campaign_id,
                arm_id=arm_id,
                limit=1,
            )
            assert stored == (sample,)
            stored_arm_digests[arm_id] = sample.arm_protocol_digest

        seal = await schedule_repository.seal_coverage(campaign_id=schedule.campaign_id)
        assert seal.authority == "SIM_RESEARCH_ONLY"
        assert seal.campaign_id == schedule.campaign_id
        assert seal.schedule_digest == schedule.schedule_digest
        assert seal.candidate_protocol_digest == protocol.protocol_digest
        assert seal.expected_result_count == len(schedule.windows) * len(RESEARCH_ARMS)
        assert stored_arm_digests == {arm_id: protocol.arm_digest(arm_id) for arm_id in RESEARCH_ARMS}

        stored_seal = await database.pool.fetchrow(
            """SELECT schedule_digest, candidate_protocol_digest, expected_result_count,
                      authority, payload
               FROM sim_research_coverage_seals WHERE campaign_id=$1""",
            schedule.campaign_id,
        )
        assert stored_seal is not None
        assert stored_seal["schedule_digest"] == schedule.schedule_digest
        assert stored_seal["candidate_protocol_digest"] == protocol.protocol_digest
        assert stored_seal["expected_result_count"] == 3
        assert stored_seal["authority"] == "SIM_RESEARCH_ONLY"

        forbidden_identity_fields = {
            "admission",
            "order",
            "pnl",
            "performance",
            "price",
            "quantity",
            "risk_decision",
            "trade",
            "venue",
        }
        research_payloads = (
            schedule.identity_payload(),
            protocol.identity_payload(),
            *(sample.identity_payload() for sample in research_samples),
            seal.identity_payload(),
        )
        for payload in research_payloads:
            assert not forbidden_identity_fields.intersection(payload)

        execution_counts_after = {
            table: await database.pool.fetchval(f"SELECT count(*) FROM {table}") for table in execution_tables
        }
        assert execution_counts_after == execution_counts_before
    finally:
        await database.close()
