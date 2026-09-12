"""Hermetic evidence and teardown checks, using installed packages but no services."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from witness import (
    InjectedCommittedAckLoss,
    close_test_runtime,
    completed_inbox_snapshot,
    delivery_acknowledged,
)


def record(**overrides):
    return {
        "topic": "topic",
        "transport_id": "new-1",
        "consumer": "service:group",
        "redis_ack_sent": True,
    } | overrides


@pytest.mark.parametrize(
    "change",
    [
        {"topic": "other"},
        {"transport_id": "old-1"},
        {"consumer": "other:group"},
        {"redis_ack_sent": False},
    ],
)
def test_exact_ack_rejects_other_or_uncommitted_deliveries(change):
    evidence = [record(transport_id="old-1"), record(transport_id="old-2"), record(**change)]
    assert not delivery_acknowledged(evidence, topic="topic", transport_id="new-1", consumer="service:group")


def test_exact_ack_ignores_previous_ack_totals():
    evidence = [record(transport_id=f"old-{index}") for index in range(10)]
    assert not delivery_acknowledged(evidence, topic="topic", transport_id="new-1", consumer="service:group")
    evidence.append(record())
    assert delivery_acknowledged(evidence, topic="topic", transport_id="new-1", consumer="service:group")


def inbox_row(**overrides):
    now = datetime(2026, 9, 12, tzinfo=UTC)
    return {
        "status": "COMPLETED",
        "attempts": 1,
        "result": '{"transport_id":"original-1"}',
        "first_seen_at": now,
        "updated_at": now,
        "lease_until": now + timedelta(seconds=180),
        "topic": "topic",
        "payload_sha256": "a" * 64,
    } | overrides


def fake_database(row):
    async def fetchrow(query, consumer, message_id):
        assert query.strip().startswith("SELECT ")
        assert "FROM message_inbox WHERE consumer=$1 AND message_id=$2" in query
        assert (consumer, message_id) == ("service:group", "message")
        return row

    return SimpleNamespace(pool=SimpleNamespace(fetchrow=fetchrow))


@pytest.mark.asyncio
async def test_inbox_snapshot_captures_every_replay_mutation_field():
    row = inbox_row()
    snapshot = await completed_inbox_snapshot(
        fake_database(row), consumer="service:group", message_id="message"
    )
    assert snapshot == row and snapshot is not row
    for field in ("result", "first_seen_at", "updated_at", "lease_until", "payload_sha256", "topic"):
        changed = row | {field: "different"}
        assert snapshot != changed


@pytest.mark.parametrize(
    "row", [None, inbox_row(status="PROCESSING"), inbox_row(status="FAILED"), inbox_row(attempts=2)]
)
@pytest.mark.asyncio
async def test_inbox_snapshot_requires_first_completed_processing(row):
    with pytest.raises(AssertionError):
        await completed_inbox_snapshot(fake_database(row), consumer="service:group", message_id="message")


class Resource:
    def __init__(self, failure=None):
        self.closed = False
        self.failure = failure

    async def close(self):
        self.closed = True
        if self.failure is not None:
            raise self.failure


async def raises(exc):
    raise exc


@pytest.mark.asyncio
async def test_cleanup_observes_already_completed_late_task_failure():
    failure = RuntimeError("late task failure after final assertion")
    task = asyncio.create_task(raises(failure))
    await asyncio.sleep(0)
    resource = Resource()
    with pytest.raises(ExceptionGroup) as caught:
        await close_test_runtime([task], [resource])
    assert caught.value.exceptions == (failure,)
    assert resource.closed


@pytest.mark.asyncio
async def test_cleanup_collects_failure_raised_during_task_cancellation():
    started = asyncio.Event()
    failure = RuntimeError("task failed while cancellation unwound")

    async def worker():
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            raise failure

    task = asyncio.create_task(worker())
    await started.wait()
    resource = Resource()
    with pytest.raises(ExceptionGroup) as caught:
        await close_test_runtime([task], [resource])
    assert caught.value.exceptions == (failure,)
    assert resource.closed


@pytest.mark.asyncio
async def test_cleanup_allows_only_designated_ack_fault_task():
    expected = asyncio.create_task(raises(InjectedCommittedAckLoss("expected")))
    unexpected_error = InjectedCommittedAckLoss("wrong task")
    unexpected = asyncio.create_task(raises(unexpected_error))
    await asyncio.sleep(0)
    resource = Resource()
    with pytest.raises(ExceptionGroup) as caught:
        await close_test_runtime(
            [expected, unexpected],
            [resource],
            expected_failures={expected: InjectedCommittedAckLoss},
        )
    assert caught.value.exceptions == (unexpected_error,)
    assert resource.closed


@pytest.mark.asyncio
async def test_cleanup_closes_every_resource_despite_multiple_failures():
    failure_one, failure_two = RuntimeError("first close"), ValueError("second close")
    resources = [Resource(failure_one), Resource(), Resource(failure_two)]
    with pytest.raises(ExceptionGroup) as caught:
        await close_test_runtime([], resources)
    assert caught.value.exceptions == (failure_two, failure_one)
    assert all(resource.closed for resource in resources)


@pytest.mark.asyncio
async def test_cleanup_normal_cancellation_and_designated_fault_pass():
    idle = asyncio.create_task(asyncio.Event().wait())
    fault = asyncio.create_task(raises(InjectedCommittedAckLoss("expected")))
    await asyncio.sleep(0)
    resource = Resource()
    await close_test_runtime([idle, fault], [resource], expected_failures={fault: InjectedCommittedAckLoss})
    assert idle.cancelled() and resource.closed


@pytest.mark.asyncio
async def test_cleanup_hung_close_is_bounded_and_remaining_resources_close():
    class HungResource:
        async def close(self):
            await asyncio.Event().wait()

    resource = Resource()
    with pytest.raises(ExceptionGroup) as caught:
        await close_test_runtime([], [resource, HungResource()], close_timeout=0.01)
    assert len(caught.value.exceptions) == 1 and isinstance(caught.value.exceptions[0], TimeoutError)
    assert resource.closed
