"""Real bounded PG/Redis composition; all upstream/provider I/O is fixture-only.

This target exercises actual producer processing and event handlers, not a new
trading strategy or continuous daemon. It proves only committed-delivery replay:
provider ambiguity before an uncommitted handler remains a separate limitation.
No provider, venue, primary database, operator ARM or execution service is used.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import quote, urlsplit, urlunsplit

import pytest
from kairos_aggregator.candidate_service import CandidateReviewService
from kairos_aggregator.config import AggregatorSettings
from kairos_core import canonical_sha256
from kairos_core.bus import BusEnvelope
from kairos_core.bus.redis_streams import RedisStreamsBus
from kairos_core.contracts import (
    AccountSnapshotV2,
    CandidateReviewV1,
    CandidateRouteV1,
    DecisionContextV1,
    EvidenceReferenceV1,
    LLMProposalModelProvenanceV1,
    LLMTradeProposalV1,
    MarketSnapshot,
    RiskTradeDecisionV1,
    VenueQualityV1,
)
from kairos_core.contracts.base import datetime_from_unix_ms
from kairos_core.enums import LLMProposalAction, ReasoningEffort, Side, StrategicTrigger
from kairos_core.topics import Topics
from kairos_llm import LLMWorkload
from kairos_macro.config import MacroSettings
from kairos_macro.service import MacroService
from kairos_persistence import Database, DurableMessageBus, MigrationProfile, PersistenceSettings
from kairos_persistence.database_target import connect_verified_database
from kairos_persistence.operator_control import OperatorControlRepository
from kairos_risk.config import RiskSettings
from kairos_risk.service import RiskService
from kairos_router.config import RouterSettings
from kairos_router.service import RouterService
from kairos_strategy.candles import Candle
from kairos_strategy.runtime import (
    candle_to_closed_bar,
    canonical_intent_batch_bytes,
    generate_runtime_strategy_intents,
)
from kairos_strategy.sleeves import RangeMeanReversionConfig
from kairos_text.config import TextSettings
from kairos_text.models import NewsItem
from kairos_text.service import TextScoutsService

from native_policy import CLASSIFICATION, DATABASE_ENV, REDIS_ENV, require_targets

pytestmark = [pytest.mark.asyncio, pytest.mark.native_composition]


class CommittedAckLoss(RuntimeError):
    """Fixture fault after real PostgreSQL inbox/output commit."""


class AckLossRedis(RedisStreamsBus):
    def __init__(self, url, topic):
        super().__init__(url)
        self.topic, self.fired = topic, False
        self.lost_entry_id = None

    async def ack(self, topic, envelope, *, group=None):
        if topic == self.topic and not self.fired:
            self.fired = True
            self.lost_entry_id = envelope.id
            raise CommittedAckLoss("FIXTURE_COMMITTED_ACK_LOSS")
        await super().ack(topic, envelope, group=group)


class FixtureImmediateReclaimRedis(RedisStreamsBus):
    """Accelerated fixture clock for the actual XAUTOCLAIM implementation only."""

    def subscribe(self, topic, *, group=None, consumer=None):
        return super().subscribe(
            topic, group=group, consumer=consumer, block_ms=20, reclaim_idle_ms=0, reclaim_every_s=0.01
        )


class FixtureNewsSource:
    name, enabled = "fixture-no-network-feed", True

    def __init__(self, items):
        self.items = items

    async def fetch(self):
        return list(self.items)


class FixtureOnlyGateway:
    """Injected provider result, zero spend, not a provider-budget qualification."""

    def __init__(self, case):
        self.case, self.calls = case, []

    async def complete(self, *, system, user, workload, schema):
        self.calls.append(workload)
        if workload is LLMWorkload.TEXT_SCOUTS:
            items = json.loads(user)["items"]
            sign = -1.0 if self.case == "conflict" else 1.0
            payload = {
                "signals": [
                    {
                        "topic": "BTCUSDT",
                        "sentiment": sign * 0.95,
                        "impact": "bearish" if sign < 0 else "bullish",
                        "confidence": 0.95,
                        "summary": "Fixture-only official Bitcoin news; not market evidence.",
                        "item_ids": [item["id"] for item in items],
                    }
                ]
            }
        elif workload is LLMWorkload.MACRO_STRATEGIST:
            if self.case == "macro-failure":
                raise RuntimeError("FIXTURE_MODEL_FAILURE")
            payload = {
                "regime": "BEAR" if self.case == "bear" else "BULL",
                "stable_reserve_pct": 0.2,
                "strategy_weights": [{"strategy_name": "range_mean_reversion_v1", "weight": 0.8}],
                "max_gross_leverage": 20.0,
                "rationale": "Fixture-only allocation, not alpha.",
            }
        else:
            assert workload in {LLMWorkload.AGGREGATOR_NORMAL, LLMWorkload.AGGREGATOR_CONFLICT}
            payload = {
                "decision": {"veto": "VETO", "defer": "DEFER"}.get(self.case, "ALLOW"),
                "priority": 100,
                "reason_codes": ["FIXTURE_ONLY_REVIEW"],
            }
        return SimpleNamespace(
            parsed=schema.model_validate(payload),
            content=json.dumps(payload, sort_keys=True),
            provider="engineering-fixture",
            model="fixture-schema-result",
            resolved_model="fixture-schema-result",
            request_id=f"fixture-{self.case}-{workload.value}",
            budget_reservation_id=f"fixture-zero-cost-{self.case}-{len(self.calls)}",
            latency_s=0.0,
            cost_usd=0.0,
            effort=ReasoningEffort.HIGH
            if workload is LLMWorkload.AGGREGATOR_CONFLICT
            else ReasoningEffort.MEDIUM,
        )

    async def close(self):
        pass


def history_fixture(anchor_ms, *, quiet=False):
    """Same 200 trailing parity bars plus 60 neutral complete-frame warmup bars."""
    closes = [100.0 + (index % 2) * 0.2 for index in range(40)]
    closes[-2:] = [96.0, 98.0]
    trailing = []
    for index in range(200):
        close = 100.0 if quiet else closes[index // 5]
        trailing.append(
            Candle(
                symbol="BTCUSDT",
                timeframe="1m",
                open_time_ms=anchor_ms - (200 - index) * 60_000,
                close_time_ms=anchor_ms - (199 - index) * 60_000 - 1,
                open=close,
                high=close + 0.2,
                low=close - 0.2,
                close=close,
                volume=10.0,
                quote_volume=10.0 * close,
                taker_buy_volume=5.0,
                taker_buy_quote_volume=5.0 * close,
            )
        )
    earlier = [
        Candle(
            symbol="BTCUSDT",
            timeframe="1m",
            open_time_ms=anchor_ms - (260 - index) * 60_000,
            close_time_ms=anchor_ms - (259 - index) * 60_000 - 1,
            open=bar.open,
            high=bar.high,
            low=bar.low,
            close=bar.close,
            volume=bar.volume,
            quote_volume=bar.quote_volume,
            taker_buy_volume=bar.taker_buy_volume,
            taker_buy_quote_volume=bar.taker_buy_quote_volume,
        )
        for index, bar in enumerate(trailing[:60])
    ]
    return tuple(candle_to_closed_bar(bar) for bar in earlier + trailing)


def candidate_fixture(anchor_ms, *, quiet=False):
    bars = history_fixture(anchor_ms, quiet=quiet)
    config = RangeMeanReversionConfig(
        vwap_lookback_bars=3,
        atr_period=2,
        regime_lookback_hours=2,
        maximum_regime_efficiency=1,
        maximum_abs_hourly_slope=1,
        band_atr_multiple=0.5,
        stop_atr_multiple=1,
        max_hold_bars=6,
    )
    intents = generate_runtime_strategy_intents("range_mean_reversion_v1", bars, config)
    replay = generate_runtime_strategy_intents("range_mean_reversion_v1", bars, config)
    assert canonical_intent_batch_bytes(intents) == canonical_intent_batch_bytes(replay)
    latest = tuple(intent for intent in intents if intent.decision_ts_ms == bars[-1].close_time_ms)
    assert len(latest) == (0 if quiet else 1)
    return latest, bars


def account_fixture(now):
    return AccountSnapshotV2(
        source="engineering-only-account",
        trading_mode="PAPER",
        evedex_profile="DEV",
        account_id="kairos-paper-dev-01",
        equity_usd=10_000.0,
        available_balance_usd=9_000.0,
        margin_used_usd=0.0,
        durable_day_start_equity_usd=10_000.0,
        durable_peak_equity_usd=10_000.0,
        total_open_risk_usd=0.0,
        captured_at_ms=now,
        reconciliation_seq=now,
        reconciled=True,
        reconciliation_detail="FIXTURE_ONLY_NOT_VENUE",
    )


def market_fixture(now, price):
    return MarketSnapshot(
        source="engineering-only-market",
        produced_at=datetime_from_unix_ms(now),
        symbol="BTCUSDT",
        mid_price=price,
        volume_usd=1_000.0,
        quant_bias=Side.LONG,
        order_book={
            "best_bid": price * 0.9999,
            "best_ask": price * 1.0001,
            "spread_bps": 2.0,
            "imbalance": 0.1,
            "depth_usd": 5_000.0,
        },
        derivatives={"funding_rate": 0.0, "open_interest": 1_000.0},
        indicators={"rsi_14": 50.0, "macd": 0.0, "macd_signal": 0.0, "macd_hist": 0.0},
    )


def venue_fixture(now, price):
    bid, ask = price * 0.9999, price * 1.0001
    return VenueQualityV1(
        source="engineering-only-venue-NOT_EXCHANGE",
        profile="DEV",
        symbol="BTCUSD:DEV",
        observed_at_ms=now,
        expires_at_ms=now + 5_000,
        reference_timestamp_ms=now,
        book_timestamp_ms=now,
        reference_mid_price=price,
        best_bid=bid,
        best_ask=ask,
        venue_mid_price=price,
        basis_bps=0.0,
        spread_bps=(ask - bid) / price * 10_000,
        assessed_notional_usd=1_000.0,
        depth_usd=5_000.0,
        buy_slippage_bps=1.0,
        sell_slippage_bps=1.0,
        taker_fee_bps=5.0,
        reference_age_ms=0,
        book_age_ms=0,
        latency_ms=0,
        timestamp_skew_ms=0,
        entry_allowed=True,
    )


async def wait_until(predicate, tasks=(), timeout=4.0):
    async with asyncio.timeout(timeout):
        while not await predicate():
            for task in tasks:
                if task.done():
                    await task
                    raise AssertionError("CONSUMER_RETURNED_EARLY")
            await asyncio.sleep(0.01)


async def consume_target(bus, topic, group, target, handler):
    async for envelope in bus.subscribe(topic, group=group, consumer="fixed-composition-target"):
        if envelope.payload["message_id"] == target:
            result = handler(envelope)
            if result is not None:
                await result
        await bus.ack(topic, envelope, group=group)


async def consume_targets(bus, topic, group, targets, handler):
    selected = set(targets)
    async for envelope in bus.subscribe(topic, group=group, consumer="fixed-context-target"):
        if envelope.payload["message_id"] in selected:
            await handler(envelope)
        await bus.ack(topic, envelope, group=group)


async def completed_targets(pool, bus, group, message_ids):
    return await pool.fetchval(
        "SELECT count(*) FROM message_inbox WHERE consumer=$1 AND message_id=ANY($2::text[]) "
        "AND status='COMPLETED'",
        f"{bus.service_name}:{group}",
        list(message_ids),
    ) == len(message_ids)


async def completed(pool, bus, group, message_id):
    return (
        await pool.fetchval(
            "SELECT status='COMPLETED' FROM message_inbox WHERE consumer=$1 AND message_id=$2",
            f"{bus.service_name}:{group}",
            message_id,
        )
        is True
    )


async def audited(pool, topic, message_id=None):
    rows = await pool.fetch(
        "SELECT payload FROM event_audit WHERE topic=$1 AND ($2::text IS NULL OR message_id=$2) "
        "ORDER BY produced_at,message_id",
        topic,
        message_id,
    )
    return [json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"] for row in rows]


async def stop(tasks):
    for task in tasks:
        task.cancel()
    outcomes = await asyncio.gather(*tasks, return_exceptions=True)
    for outcome in outcomes:
        if isinstance(outcome, BaseException) and not isinstance(outcome, asyncio.CancelledError):
            raise outcome


async def delivered_and_acked(transport, topic, group, transport_id):
    """Independent real Redis proof: group passed this exact ID and it left PEL."""
    groups = await transport._redis.xinfo_groups(topic)
    selected = next((item for item in groups if item["name"] == group), None)
    if selected is None:
        return False
    position = tuple(int(part) for part in selected["last-delivered-id"].split("-"))
    expected = tuple(int(part) for part in transport_id.split("-"))
    return position >= expected and not await transport._redis.xpending_range(
        topic, group, transport_id, transport_id, 1
    )


async def runtime_url_fixture(owner, database_url):
    """Isolated database owner provisions only synthetic runtime privileges."""
    name = urlsplit(database_url).path.removeprefix("/")
    runtime = "composition_runtime_" + name.rsplit("_", 1)[-1][:16]
    if await owner.pool.fetchval(
        "SELECT 1 FROM pg_roles WHERE rolname=ANY($1::text[])", [runtime, "kairos_operator"]
    ):
        raise AssertionError("FRESH_FIXTURE_ROLES_REQUIRED")
    password = secrets.token_hex(24)
    await owner.pool.execute("CREATE ROLE kairos_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
    await owner.pool.execute(
        f"CREATE ROLE {runtime} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE "
        f"NOREPLICATION PASSWORD '{password}'"
    )
    await owner.pool.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    await owner.pool.execute(f"GRANT USAGE ON SCHEMA public TO {runtime}")
    await owner.pool.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {runtime}")
    await owner.pool.execute(
        f"GRANT INSERT,UPDATE,DELETE ON event_audit,message_inbox,message_outbox TO {runtime}"
    )
    await owner.pool.execute(f"GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO {runtime}")
    await owner.pool.execute(
        f"GRANT INSERT ON operator_control_admissions,operator_control_dispatch_claims TO {runtime}"
    )
    parsed = urlsplit(database_url)
    return urlunsplit(parsed._replace(netloc=f"{runtime}:{quote(password)}@127.0.0.1:5432"))


async def test_real_producers_router_review_risk_durable_replay_on_disposable_pg_redis(request):
    request.node.user_properties.extend(
        [
            ("classification", CLASSIFICATION),
            ("provider_io", "FIXTURE_ONLY_ZERO_COST"),
            ("news_io", "FIXTURE_ONLY"),
            ("live_authority", "false"),
            ("provider_precommit_no_resend_qualified", "false"),
        ]
    )
    # No skip path: explicit option+fixed synthetic targets are mandatory.
    assert request.config.getoption("--native-composition")
    database_url, redis_url = os.environ.get(DATABASE_ENV), os.environ.get(REDIS_ENV)
    name = require_targets(database_url, redis_url)
    owner = Database(
        PersistenceSettings(
            _env_file=None, database_url=database_url, pool_min_size=1, pool_max_size=2, command_timeout_s=5.0
        ),
        migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
    )
    resources, tasks, case_tasks = [], [], []
    raw_redis = RedisStreamsBus(redis_url)
    resources.append(raw_redis)
    try:
        async with asyncio.timeout(60.0):
            await connect_verified_database(owner, name, local_only=True)
            await owner.verify_schema()
            assert int(await owner.pool.fetchval("SHOW max_connections")) == 32
            request.node.user_properties.append(("fixture_max_connections", "32"))
            assert await owner.pool.fetchval("SELECT count(*) FROM event_audit") == 0
            assert await raw_redis._redis.dbsize() == 0
            runtime_url = await runtime_url_fixture(owner, database_url)

            def bus(service, *, ack_loss=False, fixture_reclaim=False):
                settings = PersistenceSettings(
                    _env_file=None,
                    database_url=runtime_url,
                    pool_min_size=1,
                    pool_max_size=2,
                    command_timeout_s=5.0,
                    outbox_poll_s=0.02,
                )
                database = Database(settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME)
                transport = (
                    AckLossRedis(redis_url, Topics.STRATEGY_ROUTE)
                    if ack_loss
                    else FixtureImmediateReclaimRedis(redis_url)
                    if fixture_reclaim
                    else RedisStreamsBus(redis_url)
                )
                result = DurableMessageBus(
                    transport,
                    service_name=service,
                    settings=settings,
                    database=database,
                    verify_schema_only=True,
                    required_migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
                )
                resources.append(result)
                return result

            publisher = bus("composition-fixture-publisher")
            await publisher.start()
            await OperatorControlRepository(publisher.database.pool).verify_runtime_access()
            request.node._composition_phase = "clock"
            now = await owner.pool.fetchval(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
            )
            if now % 300_000 >= 285_000:
                # Fixture preparation only, before any input/event/attempt; no retry.
                target = now // 300_000 * 300_000 + 300_001
                async with asyncio.timeout(16):
                    while now < target:
                        await asyncio.sleep(0.05)
                        now = await owner.pool.fetchval(
                            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
                        )
            anchor = now // 300_000 * 300_000
            intents, bars = candidate_fixture(anchor)
            intent = intents[0]
            initial_intent_bytes = canonical_intent_batch_bytes(intents)
            # Exact generator provenance, not a synthetic hash or a claimed full warmup window.
            required_tail = intent.provenance.input_bar_sha256s[-60:]
            by_hash = {bar.bar_sha256: bar for bar in bars}
            context_bars = tuple(by_hash[digest] for digest in required_tail)
            context_market = market_fixture(intent.decision_ts_ms, intent.reference_price)
            for bar in context_bars:
                await publisher.publish(Topics.CLOSED_BAR, bar)
            await publisher.publish(Topics.MARKET_SNAPSHOT, context_market)

            for case in ("allow", "veto", "defer", "conflict", "stale", "bear", "macro-failure"):
                case_tasks = []
                case_resource_start = len(resources)
                request.node._composition_phase = "producer"
                gateway = FixtureOnlyGateway(case)

                def logical_clock():
                    return datetime_from_unix_ms(intent.decision_ts_ms + 200)

                text_bus, macro_bus = bus(f"composition-text-{case}"), bus(f"composition-macro-{case}")
                router_bus = bus(f"composition-router-{case}")
                review_bus = bus(f"composition-review-{case}", ack_loss=case == "allow")
                risk_bus = bus(f"composition-risk-{case}")
                news_at = intent.decision_ts_ms - (1_900_000 if case == "stale" else 1_000)
                news = [
                    NewsItem(
                        title="Bitcoin official ETF market update",
                        body="Fixture only.",
                        source=f"fixture-official-{index}",
                        source_kind="rss",
                        timestamp_is_estimated=False,
                        url=f"https://fixture.invalid/{case}/{index}",
                        published_at=datetime_from_unix_ms(news_at),
                    )
                    for index in range(3)
                ]
                text = TextScoutsService(
                    TextSettings(
                        _env_file=None,
                        service_name=f"composition-text-{case}",
                        bus_backend="redis",
                        enable_x=False,
                        enable_reddit=False,
                        enable_gdelt=False,
                        enable_rss=False,
                        relevance_threshold=0,
                    ),
                    bus=text_bus,
                    gateway=gateway,
                    sources=[FixtureNewsSource(news)],
                    clock=logical_clock,
                )
                assert await text.poll_once() == (0 if case == "stale" else 1)
                signals = await audited(owner.pool, Topics.SENTIMENT_SIGNAL)
                selected = next(
                    (item for item in signals if item["source"] == text.settings.service_name), None
                )
                router = RouterService(
                    RouterSettings(
                        _env_file=None, service_name=f"composition-router-{case}", bus_backend="redis"
                    ),
                    bus=router_bus,
                    clock=logical_clock,
                )
                review = CandidateReviewService(
                    AggregatorSettings(
                        _env_file=None, service_name=f"composition-review-{case}", bus_backend="redis"
                    ),
                    bus=review_bus,
                    gateway=gateway,
                    clock_ms=lambda: intent.decision_ts_ms + 300,
                )
                request.node._composition_phase = "review-context"
                for topic, messages, handler, label in (
                    (Topics.CLOSED_BAR, context_bars, review._handle_closed_bar, "bars"),
                    (Topics.MARKET_SNAPSHOT, (context_market,), review._handle_market, "market"),
                ):
                    identities = tuple(message.message_id for message in messages)
                    context_group = f"review-context-{label}-{case}"
                    context_task = asyncio.create_task(
                        consume_targets(review_bus, topic, context_group, identities, handler)
                    )
                    case_tasks.append(context_task)
                    await wait_until(
                        lambda review_bus=review_bus, context_group=context_group, identities=identities: (
                            completed_targets(owner.pool, review_bus, context_group, identities)
                        ),
                        [context_task],
                    )
                if selected is not None:
                    request.node._composition_phase = "news"
                    for receiver, handler, label in (
                        (router_bus, router._process_sentiment, "router-news"),
                        (review_bus, review._handle_sentiment, "review-news"),
                    ):
                        group = f"{label}-{case}"
                        task = asyncio.create_task(
                            consume_target(
                                receiver, Topics.SENTIMENT_SIGNAL, group, selected["message_id"], handler
                            )
                        )
                        case_tasks.append(task)
                        await wait_until(
                            lambda receiver=receiver, group=group, selected=selected: completed(
                                owner.pool, receiver, group, selected["message_id"]
                            ),
                            [task],
                        )

                request.node._composition_phase = "macro"
                event_now = await owner.pool.fetchval(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint"
                )
                account, market = (
                    account_fixture(event_now),
                    market_fixture(event_now, intent.reference_price),
                )
                await publisher.publish(Topics.ACCOUNT_SNAPSHOT_V2, account)
                await publisher.publish(Topics.MARKET_SNAPSHOT, market)
                macro = MacroService(
                    MacroSettings(
                        _env_file=None,
                        service_name=f"composition-macro-{case}",
                        bus_backend="redis",
                        allowed_strategy_ids=(intent.strategy_id,),
                        account_history_account_id=account.account_id,
                        account_history_version="v2",
                    ),
                    bus=macro_bus,
                    gateway=gateway,
                )
                await macro.restore_history()
                allocation = await macro.run_once(StrategicTrigger.SCHEDULE, trigger_id=f"fixture-{case}")
                assert allocation.produced_at <= datetime.now(UTC)  # do not rewrite producer envelope
                assert macro.history_status["state"] == "restored"
                assert LLMWorkload.MACRO_STRATEGIST in gateway.calls

                risk = RiskService(
                    RiskSettings(
                        _env_file=None,
                        trading_mode="PAPER",
                        environment="composition-disposable-fixture",
                        bus_backend="redis",
                        service_name=f"composition-risk-{case}",
                    ),
                    bus=risk_bus,
                )
                request.node._composition_phase = "risk-inputs"
                await risk._recover_paper_state()
                venue = venue_fixture(event_now, intent.reference_price)
                await publisher.publish(Topics.VENUE_QUALITY, venue)
                for topic, payload, handler, label in (
                    (Topics.ACCOUNT_SNAPSHOT_V2, account, risk._handle_paper_account, "account"),
                    (Topics.VENUE_QUALITY, venue, risk._handle_paper_venue, "venue"),
                    (Topics.STRATEGIC_ALLOCATION, allocation, risk._handle_allocation, "allocation"),
                ):
                    group = f"risk-{label}-{case}"
                    task = asyncio.create_task(
                        consume_target(risk_bus, topic, group, payload.message_id, handler)
                    )
                    case_tasks.append(task)
                    await wait_until(
                        lambda risk_bus=risk_bus, group=group, payload=payload: completed(
                            owner.pool, risk_bus, group, payload.message_id
                        ),
                        [task],
                    )
                assert risk.paper.recovery_complete
                assert risk.strategic_allocation.to_payload() == allocation.to_payload()
                assert risk.settings.paper_strategy_allowlist == []
                assert risk.settings.paper_per_trade_risk_fraction == 0.0025
                assert risk.settings.paper_max_total_open_risk_fraction == 0.01

                request.node._composition_phase = "route"
                route_group = f"router-intent-{case}"
                task = asyncio.create_task(
                    consume_target(
                        router_bus,
                        Topics.STRATEGY_INTENT,
                        route_group,
                        intent.message_id,
                        router._process_intent,
                    )
                )
                case_tasks.append(task)
                await publisher.publish(Topics.STRATEGY_INTENT, intent)
                await wait_until(
                    lambda router_bus=router_bus, route_group=route_group: completed(
                        owner.pool, router_bus, route_group, intent.message_id
                    ),
                    [task],
                )
                routes = await audited(owner.pool, Topics.STRATEGY_ROUTE)
                route = CandidateRouteV1.model_validate(
                    next(item for item in routes if item["source"] == router.settings.service_name)
                )
                assert canonical_intent_batch_bytes((route.intent,)) == initial_intent_bytes
                assert route.review_tier.value == ("CONFLICT" if case == "conflict" else "NORMAL")
                request.node._composition_phase = "review"
                group = f"review-route-{case}"
                review_task = asyncio.create_task(
                    consume_target(
                        review_bus, Topics.STRATEGY_ROUTE, group, route.message_id, review._handle_route
                    )
                )
                case_tasks.append(review_task)
                if case == "allow":
                    with pytest.raises(CommittedAckLoss):
                        await asyncio.wait_for(review_task, 4)
                    case_tasks.remove(review_task)  # expected observed exception already consumed
                    assert await completed(owner.pool, review_bus, group, route.message_id)
                    assert review_bus.transport.fired
                    lost_entry_id = review_bus.transport.lost_entry_id
                    assert await raw_redis._redis.xpending_range(
                        Topics.STRATEGY_ROUTE, group, lost_entry_id, lost_entry_id, 1
                    )
                else:
                    await wait_until(
                        lambda review_bus=review_bus, group=group, route=route: completed(
                            owner.pool, review_bus, group, route.message_id
                        ),
                        [review_task],
                    )
                payloads = await audited(owner.pool, Topics.CANDIDATE_REVIEW)
                reviewed = CandidateReviewV1.model_validate(
                    next(item for item in payloads if item["route"]["route_id"] == route.route_id)
                )
                contexts = await audited(owner.pool, Topics.DECISION_CONTEXT)
                context = DecisionContextV1.model_validate(
                    next(item for item in contexts if item["route_id"] == route.route_id)
                )
                context.validate_for_route(route)
                assert not context.missing_required_sources()
                assert context.closed_bar_scope == "DECLARED_INPUT_TAIL"
                # Real Macro output is later than this fixture's strategy event.
                # It constrains Risk separately; it is not backdated into review.
                assert (
                    next(source for source in context.sources if source.kind == "macro").availability
                    == "UNAVAILABLE"
                )
                assert any(
                    item.kind == "decision_context" and item.reference == context.context_id
                    for item in reviewed.evidence
                )
                assert reviewed.intent.to_payload() == intent.to_payload()
                expected = {"veto": "VETO", "defer": "DEFER", "conflict": "DEFER"}.get(case, "ALLOW")
                assert reviewed.decision.value == expected
                if case == "conflict":
                    assert "CONFLICT_ALLOW_GUARD" in reviewed.reason_codes
                    assert LLMWorkload.AGGREGATOR_CONFLICT in gateway.calls
                if case == "stale":
                    assert LLMWorkload.TEXT_SCOUTS not in gateway.calls
                    assert route.evidence_ids == ()

                request.node._composition_phase = "risk"
                group_risk = f"risk-review-{case}"
                task = asyncio.create_task(
                    consume_target(
                        risk_bus,
                        Topics.CANDIDATE_REVIEW,
                        group_risk,
                        reviewed.message_id,
                        risk._handle_paper_review,
                    )
                )
                case_tasks.append(task)
                await wait_until(
                    lambda risk_bus=risk_bus, group_risk=group_risk, reviewed=reviewed: completed(
                        owner.pool, risk_bus, group_risk, reviewed.message_id
                    ),
                    [task],
                )
                rows = await audited(owner.pool, Topics.RISK_TRADE_DECISION)
                decision = RiskTradeDecisionV1.model_validate(
                    next(item for item in rows if item["review"]["review_id"] == reviewed.review_id)
                )
                assert not decision.approved
                assert "strategy_not_paper_approved" in decision.rejection_reasons
                assert "operator_control_unavailable" in decision.rejection_reasons
                assert decision.quantity == decision.notional_usd == decision.worst_case_loss_usd == 0
                if expected != "ALLOW":
                    assert f"review_{expected.lower()}" in decision.rejection_reasons
                if case == "bear":
                    assert "macro_regime_forbids_long" in decision.rejection_reasons
                if case == "macro-failure":
                    assert "macro_regime_chop" in decision.rejection_reasons
                    assert allocation.strategy_weights == {}

                calls_before = list(gateway.calls)
                await stop(case_tasks)
                case_tasks.clear()
                if case == "allow":
                    request.node._composition_phase = "replay"
                    # Fresh component/bus/database objects: no test-supplied durable cache.
                    restarted_review_bus = bus("composition-review-allow", fixture_reclaim=True)
                    restarted = CandidateReviewService(
                        AggregatorSettings(
                            _env_file=None, service_name="composition-review-allow", bus_backend="redis"
                        ),
                        bus=restarted_review_bus,
                        gateway=gateway,
                        clock_ms=lambda: intent.decision_ts_ms + 300,
                    )
                    replay = asyncio.create_task(
                        consume_target(
                            restarted_review_bus,
                            Topics.STRATEGY_ROUTE,
                            group,
                            route.message_id,
                            restarted._handle_route,
                        )
                    )
                    tasks.append(replay)
                    route_transport_id = await raw_redis.publish(Topics.STRATEGY_ROUTE, route)

                    async def replay_acked(group=group, route_transport_id=route_transport_id):
                        return await delivered_and_acked(
                            raw_redis, Topics.STRATEGY_ROUTE, group, route_transport_id
                        )

                    await wait_until(replay_acked, [replay])

                    # The original committed ACK-loss entry was actually reclaimed
                    # by the fresh transport and durably deduplicated before ACK.
                    async def old_reclaimed_and_acked(group=group, lost_entry_id=lost_entry_id):
                        return not await raw_redis._redis.xpending_range(
                            Topics.STRATEGY_ROUTE, group, lost_entry_id, lost_entry_id, 1
                        )

                    await wait_until(old_reclaimed_and_acked, [replay])
                    assert (await raw_redis._redis.xpending(Topics.STRATEGY_ROUTE, group))["pending"] == 0
                    assert gateway.calls == calls_before
                    assert len(await audited(owner.pool, Topics.CANDIDATE_REVIEW, reviewed.message_id)) == 1
                    assert len(await audited(owner.pool, Topics.DECISION_CONTEXT, context.message_id)) == 1
                    fresh_macro = MacroService(
                        macro.settings, bus=bus("composition-macro-allow"), gateway=gateway
                    )
                    await fresh_macro.restore_history()
                    replayed_allocation = await fresh_macro.run_once(
                        StrategicTrigger.SCHEDULE, trigger_id="fixture-allow"
                    )
                    assert replayed_allocation.to_payload() == allocation.to_payload()
                    assert gateway.calls == calls_before
                    fresh_risk_bus = bus("composition-risk-allow")
                    fresh_risk = RiskService(risk.settings, bus=fresh_risk_bus)
                    await fresh_risk._recover_paper_state()
                    risk_replay = asyncio.create_task(
                        consume_target(
                            fresh_risk_bus,
                            Topics.CANDIDATE_REVIEW,
                            group_risk,
                            reviewed.message_id,
                            fresh_risk._handle_paper_review,
                        )
                    )
                    tasks.append(risk_replay)
                    review_transport_id = await raw_redis.publish(Topics.CANDIDATE_REVIEW, reviewed)

                    async def risk_replay_acked(
                        group_risk=group_risk, review_transport_id=review_transport_id
                    ):
                        return await delivered_and_acked(
                            raw_redis, Topics.CANDIDATE_REVIEW, group_risk, review_transport_id
                        )

                    await wait_until(risk_replay_acked, [risk_replay])
                    assert (
                        len(await audited(owner.pool, Topics.RISK_TRADE_DECISION, decision.message_id)) == 1
                    )
                    assert not fresh_risk.paper.reservations.symbols

                # Each scenario owns its pools and consumers. Retain only the
                # recovered risk boundary needed by the final advisory-refusal
                # check; do not accumulate seven scenarios' PostgreSQL pools.
                await stop(tasks)
                tasks.clear()
                for resource in tuple(resources[case_resource_start:]):
                    if case == "allow" and resource is fresh_risk_bus:
                        continue
                    await resource.close()
                    resources.remove(resource)

            request.node._composition_phase = "quiet"
            quiet, quiet_bars = candidate_fixture(anchor, quiet=True)
            assert quiet == ()
            count_before = len(await audited(owner.pool, Topics.RISK_TRADE_DECISION))
            proposal = LLMTradeProposalV1(
                campaign_id="composition-engineering-fixture",
                arm_id="llm-proposal-research",
                sample_id="quiet-no-intent",
                symbol="BTCUSDT",
                timeframe="1m",
                market_as_of_ts_ms=quiet_bars[-1].close_time_ms,
                expires_at_ts_ms=quiet_bars[-1].close_time_ms + 60_000,
                market_snapshot_sha256=quiet_bars[-1].bar_sha256,
                action=LLMProposalAction.SHORT_BIAS,
                rationale="Engineering-only advisory; no executable intent or order.",
                evidence=(
                    EvidenceReferenceV1(
                        kind="closed_bar",
                        reference="fixture-quiet-anchor",
                        content_sha256=quiet_bars[-1].bar_sha256,
                        observed_at_ms=quiet_bars[-1].close_time_ms,
                    ),
                ),
                model_provenance=LLMProposalModelProvenanceV1(
                    provider="engineering-fixture",
                    requested_model="fixture-proposal",
                    resolved_model="fixture-proposal",
                    request_id="fixture-quiet",
                    prompt_sha256=canonical_sha256({"fixture": "prompt"}),
                    response_sha256=canonical_sha256({"fixture": "response"}),
                    budget_reservation_id="fixture-zero-cost-quiet",
                    latency_ms=0,
                    cost_usd=0,
                ),
            )
            await publisher.publish(Topics.LLM_TRADE_PROPOSAL, proposal)
            # Prove the actual typed risk review boundary refuses the advisory
            # even if a caller deliberately presents it to the wrong handler.
            with pytest.raises(ValueError):
                await fresh_risk._handle_paper_review(
                    BusEnvelope(
                        id="fixture-wrong-topic-advisory",
                        topic=Topics.LLM_TRADE_PROPOSAL,
                        payload=proposal.to_payload(),
                    )
                )
            assert len(await audited(owner.pool, Topics.LLM_TRADE_PROPOSAL, proposal.message_id)) == 1
            assert len(await audited(owner.pool, Topics.RISK_TRADE_DECISION)) == count_before
            assert await owner.pool.fetchval("SELECT count(*) FROM operator_controls") == 0
            assert await owner.pool.fetchval("SELECT count(*) FROM operator_control_admissions") == 0
            assert await owner.pool.fetchval("SELECT count(*) FROM operator_control_dispatch_claims") == 0
            assert await owner.pool.fetchval("SELECT count(*) FROM execution_orders") == 0
            assert not await audited(owner.pool, Topics.VALIDATED_ORDER)
            assert not await audited(owner.pool, Topics.TACTICAL_COMMAND)
            request.node._composition_phase = "drain"

            async def drained():
                return (
                    await owner.pool.fetchval(
                        "SELECT count(*) FROM message_outbox WHERE published_at IS NULL"
                    )
                    == 0
                )

            await wait_until(drained, tasks)
    finally:
        # One aggregate cleanup bound, not N independent five-second extensions.
        # Preserve the earlier diagnostic phase unless cleanup itself is first failure.
        async with asyncio.timeout(15):
            try:
                await stop([*tasks, *case_tasks])
            finally:
                try:
                    outcomes = await asyncio.gather(
                        *(resource.close() for resource in reversed(resources)), return_exceptions=True
                    )
                    if any(isinstance(outcome, BaseException) for outcome in outcomes):
                        raise RuntimeError("FIXTURE_RESOURCE_CLEANUP_FAILED")
                finally:
                    await owner.close()
