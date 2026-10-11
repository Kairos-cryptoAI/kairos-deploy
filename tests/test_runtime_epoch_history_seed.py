"""Pure contracts for the bounded audit-only runtime epoch history seed."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import runtime_epoch_history_seed as seed


def _bar(symbol: str, open_ms: int) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": seed.SCHEMA_VERSION,
        "message_id": "pending",
        "correlation_id": "pending",
        "causation_id": None,
        "produced_at": datetime.fromtimestamp(
            (open_ms + 59_999) / 1000, UTC
        ).isoformat(),
        "source": seed.SOURCE,
        "contract_version": seed.CONTRACT_VERSION,
        "venue": "BINANCE_UM",
        "symbol": symbol,
        "timeframe": "1m",
        "open_time_ms": open_ms,
        "close_time_ms": open_ms + 59_999,
        "open": 10.0,
        "high": 12.0,
        "low": 9.0,
        "close": 11.0,
        "base_volume": 20.0,
        "quote_volume": 200.0,
        "taker_buy_base_volume": 12.0,
        "taker_buy_quote_volume": 120.0,
        "is_closed": True,
        "bar_sha256": "pending",
    }
    identity = {name: payload[name] for name in seed._BAR_IDENTITY_FIELDS}
    bar_hash = hashlib.sha256(seed.canonical_json(identity)).hexdigest()
    payload["bar_sha256"] = bar_hash
    payload["message_id"] = bar_hash
    payload["correlation_id"] = bar_hash
    return payload


def _row(symbol: str, open_ms: int) -> dict[str, object]:
    payload = _bar(symbol, open_ms)
    encoded = seed.canonical_json(payload)
    return {
        "produced_at": payload["produced_at"],
        "message_id": payload["message_id"],
        "topic": seed.TOPIC,
        "source": seed.SOURCE,
        "schema_version": seed.SCHEMA_VERSION,
        "correlation_id": payload["correlation_id"],
        "causation_id": None,
        "payload": payload,
        "outbox_count": 1,
        "outbox_topic": seed.TOPIC,
        "outbox_producer": seed.SOURCE,
        "outbox_payload": copy.deepcopy(payload),
        "stored_payload_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _rows() -> list[dict[str, object]]:
    return [
        _row(symbol, open_ms)
        for symbol in seed.SYMBOLS
        for open_ms in (60_000, 120_000)
    ]


def _expectation(rows: list[dict[str, object]]) -> seed.SeedExpectation:
    accumulator = seed._Accumulator(
        {symbol: seed.Anchor(1, 0, 0, 0) for symbol in seed.SYMBOLS},
        "0" * 64,
        seed.SeedLimits(),
    )
    for row in rows:
        accumulator.add(row)
    digest = accumulator.digest.hexdigest()
    anchors = {
        symbol: seed.Anchor(
            accumulator.counts[symbol],
            accumulator.first[symbol],
            accumulator.last[symbol][0],
            accumulator.last[symbol][1],
        )
        for symbol in seed.SYMBOLS
    }
    return seed.SeedExpectation(anchors, digest)


class _Transaction:
    def __init__(self, target: _Target) -> None:
        self.target = target
        self.before: list[tuple[object, ...]] = []

    async def __aenter__(self):
        self.before = list(self.target.inserted)
        return self

    async def __aexit__(self, exc_type, _exc, _tb):
        if exc_type is not None:
            self.target.inserted[:] = self.before
        return False


class _Target:
    def __init__(self) -> None:
        self.inserted: list[tuple[object, ...]] = []
        self.outbox_rows = 0
        self.queries: list[str] = []
        self.batch_sizes: list[int] = []

    def transaction(self):
        return _Transaction(self)

    async def fetchrow(self, query: str, *_args):
        self.queries.append(query)
        if query != seed.TARGET_EMPTY_CHECK_SQL:
            raise AssertionError("unexpected target query")
        return {
            "event_audit_rows": len(self.inserted),
            "message_outbox_rows": self.outbox_rows,
        }

    async def executemany(self, query: str, args):
        self.queries.append(query)
        if query != seed.TARGET_INSERT_SQL:
            raise AssertionError("unexpected target mutation")
        self.batch_sizes.append(len(args))
        if len(args) > 1_000:
            raise AssertionError("target insert batch exceeded 1000")
        self.inserted.extend(args)


def _identities() -> tuple[seed.SourceIdentity, seed.TargetIdentity]:
    return (
        seed.SourceIdentity("kairos", "source-epoch-1", True, True),
        seed.TargetIdentity("kairos_epoch_012345abcdef", "new-epoch-2", True, True),
    )


class RuntimeEpochHistorySeedTests(unittest.TestCase):
    def run_seed(self, rows, expected=None, target=None):
        source, target_identity = _identities()
        destination = target or _Target()

        async def stream():
            for row in rows:
                yield row

        result = asyncio.run(
            seed.seed_history(
                stream(),
                destination,
                source=source,
                target_identity=target_identity,
                expected=expected or _expectation(rows),
            )
        )
        return result, destination

    def test_valid_seed_copies_only_event_audit_and_leaves_outbox_empty(self):
        rows = _rows()
        receipt, target = self.run_seed(rows)
        self.assertEqual(receipt.rows, len(rows))
        self.assertEqual(receipt.target_outbox_rows_after, 0)
        self.assertEqual(len(target.inserted), len(rows))
        self.assertEqual(target.outbox_rows, 0)
        self.assertLessEqual(max(target.batch_sizes), 1_000)
        self.assertEqual(
            sum("INSERT INTO" in q.upper() for q in target.queries),
            len(target.batch_sizes),
        )
        self.assertTrue(
            all(
                q == seed.TARGET_INSERT_SQL
                for q in target.queries
                if "INSERT" in q.upper()
            )
        )

    def test_measure_history_produces_ordered_digest_for_second_pass_binding(self):
        rows = _rows()
        expected = _expectation(rows)

        async def stream():
            for row in rows:
                yield row

        measured = asyncio.run(seed.measure_history(stream(), expected.anchors))
        self.assertEqual(measured, expected)

    def test_corrupt_stored_payload_hash_is_rejected(self):
        rows = _rows()
        rows[0]["stored_payload_sha256"] = "f" * 64
        with self.assertRaises(seed.SeedError):
            self.run_seed(rows)

    def test_duplicate_message_id_is_rejected(self):
        rows = _rows()
        rows[1] = copy.deepcopy(rows[0])
        with self.assertRaises(seed.SeedError):
            self.run_seed(rows)

    def test_per_symbol_gap_is_rejected(self):
        rows = _rows()
        rows[1]["payload"] = _bar(seed.SYMBOLS[0], 180_000)
        rows[1]["outbox_payload"] = copy.deepcopy(rows[1]["payload"])
        rows[1]["message_id"] = rows[1]["payload"]["message_id"]
        rows[1]["correlation_id"] = rows[1]["message_id"]
        rows[1]["produced_at"] = rows[1]["payload"]["produced_at"]
        rows[1]["stored_payload_sha256"] = hashlib.sha256(
            seed.canonical_json(rows[1]["payload"])
        ).hexdigest()
        with self.assertRaises(seed.SeedError):
            self.run_seed(rows)

    def test_wrong_topic_symbol_or_schema_is_rejected(self):
        for field, value in (
            ("topic", "kairos.market.snapshot"),
            ("schema_version", "2.0"),
        ):
            with self.subTest(field=field):
                rows = _rows()
                rows[0][field] = value
                with self.assertRaises(seed.SeedError):
                    self.run_seed(rows)
        rows = _rows()
        rows[0]["payload"] = _bar("DOGEUSDT", 60_000)
        with self.assertRaises(seed.SeedError):
            self.run_seed(rows)

    def test_non_bar_rows_are_excluded_at_source_query_boundary(self):
        self.assertIn("WHERE a.topic = $1 AND a.source = $2", seed.SOURCE_EXPORT_SQL)
        self.assertNotIn("INSERT", seed.SOURCE_EXPORT_SQL.upper())
        rows = _rows()
        rows.append({**rows[0], "topic": "kairos.market.snapshot"})
        with self.assertRaises(seed.SeedError):
            self.run_seed(rows)

    def test_same_database_foreign_name_and_protected_shadow_are_rejected(self):
        source, target = _identities()
        for invalid in (
            seed.TargetIdentity("kairos", "different", True, True),
            seed.TargetIdentity("kairos_epoch_nothex000", "new", True, True),
            seed.TargetIdentity(target.database_name, source.epoch_id, True, True),
            seed.TargetIdentity(
                target.database_name, "new", True, True, protected_source_or_shadow=True
            ),
        ):
            with self.subTest(target=invalid), self.assertRaises(seed.SeedError):
                seed.validate_epoch_pair(source, invalid)

    def test_target_mutation_sql_cannot_touch_outbox_or_other_tables(self):
        normalized = " ".join(seed.TARGET_INSERT_SQL.lower().split())
        self.assertIn("insert into public.event_audit", normalized)
        self.assertNotIn("message_outbox", normalized)
        self.assertNotIn("message_inbox", normalized)
        self.assertNotIn("execution_", normalized)
        self.assertNotIn("update ", normalized)
        self.assertNotIn("delete ", normalized)

    def test_invalid_ohlc_and_nonfinal_bar_are_rejected(self):
        for mutation in (
            lambda p: p.update(high=8.0),
            lambda p: p.update(close_time_ms=p["open_time_ms"] + 58_000),
            lambda p: p.update(is_closed=False),
        ):
            rows = _rows()
            payload = copy.deepcopy(rows[0]["payload"])
            mutation(payload)
            rows[0]["payload"] = payload
            with self.assertRaises(seed.SeedError):
                self.run_seed(rows)

    def test_incomplete_seed_rolls_back_all_inserted_audit_rows(self):
        rows = _rows()
        target = _Target()
        expected = _expectation(rows)
        anchors = dict(expected.anchors)
        anchors[seed.SYMBOLS[-1]] = seed.Anchor(3, 60_000, 180_000, 239_999)
        incomplete = seed.SeedExpectation(anchors, expected.ordered_digest_sha256)
        with self.assertRaises(seed.SeedError):
            self.run_seed(rows, expected=incomplete, target=target)
        self.assertEqual(target.inserted, [])
        self.assertEqual(target.outbox_rows, 0)

    def test_target_must_be_empty_before_seed(self):
        target = _Target()
        target.outbox_rows = 1
        with self.assertRaises(seed.SeedError):
            self.run_seed(_rows(), target=target)
        self.assertEqual(target.inserted, [])

    def test_target_batch_size_never_exceeds_one_thousand(self):
        rows = [
            _row(symbol, i * seed.MINUTE_MS)
            for symbol in seed.SYMBOLS
            for i in range(1, 202)
        ]
        expected = _expectation(rows)
        receipt, target = self.run_seed(rows, expected=expected)
        self.assertEqual(receipt.rows, 1_005)
        self.assertEqual(target.batch_sizes, [1_000, 5])


if __name__ == "__main__":
    unittest.main()
