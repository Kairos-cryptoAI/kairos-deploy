"""Thin real Redis transport observer/fault injector; no business-rule bypass."""

from __future__ import annotations

import asyncio
import json

from kairos_core.bus.redis_streams import RedisStreamsBus
from kairos_core.topics import Topics

from policy import REDIS_URL


class InjectedCommittedAckLoss(RuntimeError):
    pass


def delivery_acknowledged(evidence, *, topic, transport_id, consumer):
    """Only this exact injected delivery counts; old ACK totals cannot satisfy it."""
    return any(
        item["topic"] == topic
        and item["transport_id"] == transport_id
        and item["consumer"] == consumer
        and item["redis_ack_sent"]
        for item in evidence
    )


async def completed_inbox_snapshot(database, *, consumer, message_id):
    """Read the committed claim/result without changing a lease or attempt."""
    row = await database.pool.fetchrow(
        """SELECT status, attempts, result, first_seen_at, updated_at, lease_until,
                  topic, payload_sha256
           FROM message_inbox WHERE consumer=$1 AND message_id=$2""",
        consumer,
        message_id,
    )
    assert row is not None and row["status"] == "COMPLETED", "expected a committed completed inbox"
    assert row["attempts"] == 1, "the synthetic message unexpectedly re-entered processing"
    return dict(row)


async def close_test_runtime(tasks, services, *, expected_failures=None, close_timeout=10.0):
    """Observe even late task failures, close every resource, then fail together."""
    expected_failures = {} if expected_failures is None else expected_failures
    failures = []
    for task in reversed(tasks):
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            allowed = expected_failures.get(task)
            if allowed is None or not isinstance(exc, allowed):
                failures.append(exc)
    for service in reversed(services):
        try:
            await asyncio.wait_for(service.close(), timeout=close_timeout)
        except Exception as exc:
            failures.append(exc)
    if failures:
        raise ExceptionGroup("release gate background/cleanup failures", failures)


class AckWitnessBus(RedisStreamsBus):
    def __init__(self, *, service_name, database, evidence, fault=None):
        super().__init__(REDIS_URL)
        self.service_name = service_name
        self.database = database
        self.evidence = evidence
        self.fault = fault

    async def ack(self, topic, envelope, *, group=None):
        group = group or envelope.meta.get("group", "default")
        message_id = envelope.payload["message_id"]
        consumer = f"{self.service_name}:{group}"
        # A different pool/connection observes COMMITTED rows, not the consumer's
        # still-open transaction. This is the production transport ACK boundary.
        status = await self.database.pool.fetchval(
            "SELECT status FROM message_inbox WHERE consumer=$1 AND message_id=$2", consumer, message_id
        )
        assert status == "COMPLETED", "Redis ACK attempted before durable inbox completion"
        record = dict(
            topic=topic,
            consumer=consumer,
            message_id=message_id,
            transport_id=envelope.id,
            reclaimed=bool(envelope.meta.get("reclaimed")),
            pg_completed_before_ack=True,
            redis_ack_sent=False,
        )
        if topic == Topics.CANDIDATE_REVIEW:
            rows = await self.database.pool.fetch(
                "SELECT payload FROM event_audit WHERE topic=$1 AND payload->'review'->>'review_id'=$2",
                Topics.RISK_TRADE_DECISION,
                envelope.payload["review_id"],
            )
            assert len(rows) == 1, "Risk ACK requires exactly one committed decision"
            decision = (
                json.loads(rows[0]["payload"]) if isinstance(rows[0]["payload"], str) else rows[0]["payload"]
            )
            assert decision["approved"] is True, decision["rejection_reasons"]
            assert (
                await self.database.pool.fetchval(
                    "SELECT count(*) FROM message_outbox WHERE message_id=$1", decision["message_id"]
                )
                == 1
            )
            record["decision_id"] = decision["decision_id"]
            record["decision_outbox_committed_before_ack"] = True
        if topic == Topics.RISK_TRADE_DECISION:
            trade_id = envelope.payload["trade_id"]
            assert (
                await self.database.pool.fetchval(
                    "SELECT count(*) FROM execution_trades WHERE trade_id=$1", trade_id
                )
                == 1
            )
            assert not await self.database.pool.fetchval(
                "SELECT 1 FROM execution_effects WHERE trade_id=$1 "
                "AND status IN ('PREPARED','FAILED') LIMIT 1",
                trade_id,
            )
            facts = await self.database.pool.fetch(
                "SELECT message_id FROM event_audit WHERE topic=$1 AND payload->>'trade_id'=$2",
                Topics.TRADE_EXECUTION_EVENT,
                trade_id,
            )
            assert facts, "Execution ACK requires committed lifecycle facts"
            assert await self.database.pool.fetchval(
                "SELECT count(*) FROM message_outbox WHERE message_id=ANY($1::text[])",
                [row["message_id"] for row in facts],
            ) == len(facts)
            record["lifecycle_facts_committed_before_ack"] = len(facts)
        self.evidence.append(record)
        if topic == Topics.RISK_TRADE_DECISION and self.fault is not None and not self.fault["fired"]:
            self.fault.update(fired=True, envelope=envelope, group=group)
            self.fault["event"].set()
            raise InjectedCommittedAckLoss("synthetic crash after PG commit, before Redis XACK")
        await super().ack(topic, envelope, group=group)
        record["redis_ack_sent"] = True


async def attach_witness(service, *, database, evidence, fault=None):
    # Constructor-created transport has not been started; only this test-owned
    # real Redis subclass replaces it. DurableMessageBus and handlers stay real.
    await service.bus.transport.close()
    service.bus.transport = AckWitnessBus(
        service_name=service.settings.service_name,
        database=database,
        evidence=evidence,
        fault=fault,
    )


async def wait_until(predicate, *, timeout=10.0, description="condition"):
    async def poll():
        while not await predicate():
            await asyncio.sleep(0.02)

    try:
        await asyncio.wait_for(poll(), timeout=timeout)
    except TimeoutError as exc:
        raise AssertionError(f"release gate timed out waiting for {description}") from exc
