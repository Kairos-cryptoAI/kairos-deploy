"""Actual Redis/PG Risk pipeline, strict admission and Execution; fake venue only."""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from kairos_core.bus.redis_streams import RedisStreamsBus
from kairos_core.contracts import RiskTradeDecisionV1, VenueQualityV1
from kairos_core.topics import Topics
from kairos_execution.config import ExecSettings
from kairos_execution.service import ExecutionService
from kairos_persistence import Database, DurableMessageBus, PersistenceSettings, TradeState
from kairos_persistence.canary_arm import PaperCanaryArmRepository
from kairos_persistence.canary_session import CanarySessionRepository, millis
from kairos_risk.config import RiskSettings
from kairos_risk.service import RiskService

# Only fixtures from exact committed Execution641a080 tests enter PYTHONPATH.
# No fixture supplies the risk decision; the real Risk coordinator computes it.
from tests.canary_session_fixtures import fresh_review, seed_receipt
from tests.test_integration_paper_engine import FakePaperAdapter, MutableClock

from policy import (
    DATABASE_URL,
    REDIS_URL,
    connect_verified,
    require_fresh_database,
    validate_environment,
    validate_installed_sources,
)
from witness import (
    InjectedCommittedAckLoss,
    attach_witness,
    close_test_runtime,
    completed_inbox_snapshot,
    delivery_acknowledged,
    wait_until,
)

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


def synthetic_venue(now):
    return VenueQualityV1(
        source="synthetic-release-gate",
        profile="DEV",
        symbol="BTCUSD:DEV",
        observed_at_ms=now,
        expires_at_ms=now + 5000,
        reference_timestamp_ms=now,
        book_timestamp_ms=now,
        reference_mid_price=100,
        best_bid=99.99,
        best_ask=100.01,
        venue_mid_price=100,
        basis_bps=0,
        spread_bps=2,
        assessed_notional_usd=10.001,
        depth_usd=5000,
        buy_slippage_bps=1,
        sell_slippage_bps=1,
        taker_fee_bps=5,
        reference_age_ms=0,
        book_age_ms=0,
        latency_ms=1,
        timestamp_skew_ms=0,
        entry_allowed=True,
    )


async def cancel_task(task):
    if task is None:
        return
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


@pytest.fixture
async def empty_data_services():
    validate_environment()
    validate_installed_sources()
    observer = Database(PersistenceSettings(database_url=DATABASE_URL, pool_max_size=4))
    redis = RedisStreamsBus(REDIS_URL)
    try:
        await require_fresh_database(observer)
        # Both empty-store checks precede the first migration/fixture write.
        assert await redis._redis.dbsize() == 0
        await observer.migrate()
        assert await observer.pool.fetchval("SELECT count(*) FROM schema_migrations") == 16
        yield observer, redis
    finally:
        await redis.close()
        await observer.close()


async def test_review_real_risk_redis_execution_commit_ack_redelivery_restart(tmp_path, empty_data_services):
    observer, redis = empty_data_services
    sessions, scope, plan, session = await seed_receipt(observer)
    scope_file = tmp_path / "independent-scope.json"
    scope_file.write_text(scope.model_dump_json(), encoding="utf-8")
    clock = MutableClock(datetime.now(UTC))
    evidence, received_facts = [], []
    fault = {"fired": False, "event": asyncio.Event()}
    services, tasks = [], []
    expected_failures = {}
    publisher = DurableMessageBus(
        RedisStreamsBus(REDIS_URL),
        service_name="kairos-release-gate",
        settings=PersistenceSettings(database_url=DATABASE_URL, pool_max_size=4),
    )

    class SyntheticVenue(FakePaperAdapter):
        async def close(self):
            pass

        async def fetch_depth(self, **kwargs):
            return {
                "t": millis(datetime.now(UTC)),
                "asks": [{"price": 100.01, "quantity": 1}],
                "bids": [{"price": 99.99, "quantity": 1}],
            }

        async def place_limit(self, **kwargs):
            claim = await observer.pool.fetchrow(
                "SELECT * FROM paper_canary_dispatch_claims WHERE effect_id=$1", kwargs["effect_id"]
            )
            assert claim and claim["session_id"] == session["session_id"]
            clock.value = datetime.now(UTC)
            return await super().place_limit(**kwargs)

    adapter = SyntheticVenue(clock)
    adapter.state["account"]["id"] = scope.remote_account_id

    async def start_risk():
        risk = RiskService(
            RiskSettings(
                _env_file=None,
                trading_mode="PAPER",
                environment=scope.environment,
                redis_url=REDIS_URL,
                paper_account_id=scope.account_id,
                paper_strategy_allowlist=["technical-canary@1"],
            )
        )
        services.append(risk)
        await connect_verified(risk.bus.database)
        await attach_witness(risk, database=observer, evidence=evidence)
        task = asyncio.create_task(risk.run())
        tasks.append(task)

        async def recovered():
            if task.done():
                await task
            return isinstance(risk.paper_canary_repository, PaperCanaryArmRepository)

        await wait_until(recovered, description="real Risk durable recovery and arm repository")
        return risk, task

    async def start_execution(*, with_scope, inject_ack_loss):
        execution = ExecutionService(
            ExecSettings(
                _env_file=None,
                trading_mode="PAPER",
                environment=scope.environment,
                redis_url=REDIS_URL,
                account_id=scope.account_id,
                canary_scope_file=scope_file if with_scope else None,
                evedex_dev_expected_account_id=scope.remote_account_id,
                evedex_dev_api_key_file=tmp_path / "NOT_CREATED_API_KEY",
                evedex_dev_private_key_file=tmp_path / "NOT_CREATED_SIGNING_KEY",
            )
        )
        services.append(execution)
        await connect_verified(execution.bus.database)
        await attach_witness(
            execution, database=observer, evidence=evidence, fault=fault if inject_ack_loss else None
        )
        # The sole venue replacement. No sidecar method or credential read is
        # invoked; all admission, recovery, journal and consumer code stays real.
        execution._paper_adapter = adapter
        await execution._initialize_paper_execution()
        assert execution.paper_engine is not None and not execution.paper_engine.recovery_blocked
        task = asyncio.create_task(execution._consume_paper_decisions())
        tasks.append(task)
        return execution, task

    async def receive_facts():
        async for envelope in publisher.subscribe(
            Topics.TRADE_EXECUTION_EVENT, group="release-gate", consumer="facts"
        ):
            received_facts.append(envelope.payload)
            await publisher.ack(Topics.TRADE_EXECUTION_EVENT, envelope, group="release-gate")

    async def refresh_authoritative_account(execution, risk):
        previous_seq = risk.paper.account.reconciliation_seq if risk.paper.account is not None else 0
        await execution._publish_account_snapshot()

        async def account_ready():
            account = risk.paper.account
            return (
                risk.paper.recovery_complete
                and account is not None
                and account.reconciliation_seq > previous_seq
            )

        await wait_until(account_ready, description="real bus authoritative account bootstrap")

    try:
        await connect_verified(publisher.database)
        await publisher.start()
        facts_task = asyncio.create_task(receive_facts())
        tasks.append(facts_task)
        execution, execution_task = await start_execution(with_scope=True, inject_ack_loss=True)
        expected_failures[execution_task] = InjectedCommittedAckLoss
        risk, risk_task = await start_risk()
        # Warm account reconciliation and its bus path before any 5s venue TTL.
        await refresh_authoritative_account(execution, risk)
        now = millis(await observer.pool.fetchval("SELECT clock_timestamp()"))
        if now % 60000 > 15000:
            # Synthetic test input waits for genuine eligibility; no DB time or
            # production 5s venue/30s candidate gate is weakened.
            await asyncio.sleep((60000 - now % 60000) / 1000 + 0.05)
            # The minute wait can exceed the unchanged 30s account freshness
            # limit. Refresh it fully before starting the venue TTL.
            await refresh_authoritative_account(execution, risk)
        now = millis(await observer.pool.fetchval("SELECT clock_timestamp()"))
        assert now % 60000 <= 15000, "account bootstrap missed the bounded fresh candidate window"
        review, allocation = fresh_review(scope, plan.slots[0], now)
        adapter.state["instruments"][0]["updatedAt"] = datetime.fromtimestamp(now / 1000, UTC).isoformat()
        venue = synthetic_venue(now)
        await publisher.publish(Topics.VENUE_QUALITY, venue)

        async def ready():
            current = risk.paper._venue.get("BTCUSD:DEV")
            return (
                risk.paper.recovery_complete
                and current is not None
                and current.measurement_id == venue.measurement_id
            )

        await wait_until(ready, timeout=3, description="real bus account and venue ingestion")
        # The arm's real transaction stages review/allocation outbox messages.
        # The actual Risk service consumes its own producer's durable outbox.
        await risk.paper_canary_repository.arm(
            account_id=scope.account_id,
            review=review,
            allocation=allocation,
            session_id=session["session_id"],
            slot_id=plan.slots[0].slot_id,
        )
        with pytest.raises(InjectedCommittedAckLoss):
            await asyncio.wait_for(execution_task, timeout=10)
        assert fault["fired"] and adapter.calls[:3] == ["ENTRY", "STOP_LOSS", "TAKE_PROFIT"]
        decisions = await observer.pool.fetch(
            "SELECT payload FROM event_audit WHERE topic=$1", Topics.RISK_TRADE_DECISION
        )
        assert len(decisions) == 1
        payload = (
            json.loads(decisions[0]["payload"])
            if isinstance(decisions[0]["payload"], str)
            else decisions[0]["payload"]
        )
        decision = RiskTradeDecisionV1.model_validate(payload)
        assert decision.source == "kairos-risk-manager" and decision.approved
        assert decision.quantity == 0.1 and decision.leverage == 1
        assert decision.intent == review.intent and decision.exit_plan == review.intent.exit_plan
        assert decision.loss_budget_usd <= 10000 * 0.0025
        assert any(item.get("decision_outbox_committed_before_ack") for item in evidence)
        failed_ack = next(item for item in evidence if item["topic"] == Topics.RISK_TRADE_DECISION)
        assert failed_ack["pg_completed_before_ack"] and not failed_ack["redis_ack_sent"]
        inbox_keys = {
            "risk": ("kairos-risk-manager:risk-paper", review.message_id),
            "execution": ("kairos-execution-engine:execution-paper", decision.message_id),
        }

        async def inbox_snapshots():
            return {
                name: await completed_inbox_snapshot(observer, consumer=consumer, message_id=message_id)
                for name, (consumer, message_id) in inbox_keys.items()
            }

        inbox_before_replay = await inbox_snapshots()

        # Restart real Risk state/consumer and Execution after the committed
        # delivery lost its external ACK. Do not delete inbox rows or effects.
        await cancel_task(risk_task)
        await execution.close()
        pending_id = fault["envelope"].id
        # Age ONLY this synthetic pending delivery in the isolated Redis so the
        # unchanged production180s XAUTOCLAIM rule can be exercised immediately.
        await redis._redis.xclaim(
            Topics.RISK_TRADE_DECISION,
            "execution-paper",
            "synthetic-dead-consumer",
            min_idle_time=0,
            message_ids=[pending_id],
            idle=180001,
        )
        risk2, _ = await start_risk()
        execution2, _ = await start_execution(with_scope=False, inject_ack_loss=False)
        assert execution2.paper_engine._canary_scope is None
        await execution2._publish_account_snapshot()

        async def reclaimed():
            return any(
                item["topic"] == Topics.RISK_TRADE_DECISION
                and item["transport_id"] == pending_id
                and item["reclaimed"]
                and item["redis_ack_sent"]
                for item in evidence
            )

        await wait_until(reclaimed, description="actual Redis XAUTOCLAIM of committed execution delivery")
        assert adapter.calls.count("ENTRY") == 1
        assert await inbox_snapshots() == inbox_before_replay, "reclaim changed completed inbox evidence"
        # Also deliver duplicate bytes with NEW Redis IDs: both durable inboxes
        # must suppress computation/mutation after their caches were restarted.
        review_duplicate_id = await redis.publish(Topics.CANDIDATE_REVIEW, review)
        decision_duplicate_id = await redis.publish(Topics.RISK_TRADE_DECISION, decision)
        assert decision_duplicate_id != pending_id

        async def duplicate_acks():
            return delivery_acknowledged(
                evidence,
                topic=Topics.CANDIDATE_REVIEW,
                transport_id=review_duplicate_id,
                consumer=inbox_keys["risk"][0],
            ) and delivery_acknowledged(
                evidence,
                topic=Topics.RISK_TRADE_DECISION,
                transport_id=decision_duplicate_id,
                consumer=inbox_keys["execution"][0],
            )

        await wait_until(duplicate_acks, description="duplicate deliveries suppressed by durable inbox")
        assert await inbox_snapshots() == inbox_before_replay, (
            "duplicate re-entered completed inbox processing"
        )
        assert (
            await observer.pool.fetchval(
                "SELECT count(*) FROM event_audit WHERE topic=$1", Topics.RISK_TRADE_DECISION
            )
            == 1
        )
        assert adapter.calls.count("ENTRY") == 1
        await sessions.stop(session["session_id"])
        engine = execution2.paper_engine
        trade = await engine.trades.get(decision.trade_id)
        assert trade and trade.state is TradeState.ACTIVE and trade.timeout_at is not None
        # Virtual-clock advance applies only after all entry/redelivery proofs;
        # it exercises the real timeout FSM, never grants entry authority.
        clock.value = trade.timeout_at + timedelta(milliseconds=1)
        engine.clock = clock
        for event in await engine.reconcile_once():
            await execution2.bus.publish(Topics.TRADE_EXECUTION_EVENT, event)
        await execution2._publish_account_snapshot()
        trade = await engine.trades.get(decision.trade_id)
        assert trade and trade.state is TradeState.FLAT

        async def quiescent():
            return (
                any(item["lifecycle_state"] == "FLAT" for item in received_facts)
                and await observer.pool.fetchval(
                    "SELECT count(*) FROM message_outbox WHERE published_at IS NULL"
                )
                == 0
                and await observer.pool.fetchval(
                    "SELECT count(*) FROM message_inbox WHERE status <> 'COMPLETED'"
                )
                == 0
            )

        await wait_until(quiescent, description="final durable inbox/outbox completion")
        assert not await observer.pool.fetchval(
            "SELECT 1 FROM execution_effects WHERE status IN ('PREPARED','FAILED') LIMIT 1"
        )
        assert await observer.pool.fetchval("SELECT count(*) FROM paper_canary_dispatch_claims") == 1
        assert (await CanarySessionRepository(observer.pool).refresh(session["session_id"]))[
            "state"
        ] == "ABORTED"
        assert received_facts and all(item["trade_id"] == decision.trade_id for item in received_facts)
        assert any(
            item["event_type"] == "EXIT_FILLED" and item["lifecycle_state"] == "FLAT"
            for item in received_facts
        )
        for topic, group in (
            (Topics.CANDIDATE_REVIEW, "risk-paper"),
            (Topics.RISK_TRADE_DECISION, "execution-paper"),
            (Topics.TRADE_EXECUTION_EVENT, "release-gate"),
        ):

            async def acknowledged(topic=topic, group=group):
                return (await redis._redis.xpending(topic, group))["pending"] == 0

            await wait_until(acknowledged, description=f"empty Redis PEL for {group}/{topic}")
        for task in tasks:
            if task.done() and not task.cancelled() and task is not execution_task:
                assert task.exception() is None, f"unexpected background task failure: {task.exception()}"
        receipt = {
            "result": "PASS",
            "synthetic_only": True,
            "real_risk_pipeline": True,
            "real_postgres_redis": True,
            "entry_calls": adapter.calls.count("ENTRY"),
            "acks_witnessed": len(evidence),
            "facts_received": len(received_facts),
            "exact_duplicate_ids": [review_duplicate_id, decision_duplicate_id],
            "inbox_replay_unchanged": True,
            "paper_qualified": False,
            "alpha_ready": False,
            "live_ready": False,
        }
    finally:
        await close_test_runtime(tasks, [publisher, *services], expected_failures=expected_failures)
    # Never print a successful receipt before all background/close failures have
    # been observed. Fixture teardown still closes the observer/Redis clients.
    print(json.dumps(receipt, sort_keys=True))
