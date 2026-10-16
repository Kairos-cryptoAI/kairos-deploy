"""Focused offline checks for the bounded one-statement anchor lookup."""

from __future__ import annotations

import asyncio
import re
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import runtime_epoch_worker as worker


def _audit_rows(*, bars=2):
    rows = []
    for symbol in worker.SYMBOLS:
        for index in range(bars):
            open_ms = 60_000 * (index + 1)
            rows.append(
                {
                    "topic": worker.TOPIC,
                    "source": worker.SOURCE,
                    "symbol": symbol,
                    "produced_at": 10_000 - open_ms,
                    "message_id": f"{symbol}-{index}",
                    "payload": {
                        "symbol": symbol,
                        "open_time_ms": open_ms,
                        "close_time_ms": open_ms + worker.MINUTE - 1,
                        "produced_at": 10_000 - open_ms,
                    },
                }
            )
    return rows


def _sql_semantics(rows, topic, source, symbols):
    """Small independent reference for the query's grouping/key selection."""
    matching = [
        row
        for row in rows
        if row["topic"] == topic
        and row["source"] == source
        and row["symbol"] in symbols
    ]
    result = []
    for symbol in sorted({row["symbol"] for row in matching}):
        group = [row for row in matching if row["symbol"] == symbol]
        opens = [int(row["payload"]["open_time_ms"]) for row in group]
        latest = max(
            group,
            key=lambda row: (
                int(row["payload"]["open_time_ms"]),
                row["produced_at"],
                row["message_id"],
            ),
        )
        result.append(
            {
                "symbol": symbol,
                "n": len(group),
                "u": len(set(opens)),
                "lo": min(opens),
                "hi": max(opens),
                "payload": latest["payload"],
            }
        )
    return result


class _Connection:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    async def fetch(self, sql, *args):
        self.calls.append((sql, args))
        return _sql_semantics(self.rows, *args)


class _Acquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_):
        return False


class _Pool:
    def __init__(self, rows):
        self.connection = _Connection(rows)

    def acquire(self):
        return _Acquire(self.connection)


class _ClosedBarEvent:
    @classmethod
    def model_validate(cls, payload):
        required = {"symbol", "open_time_ms", "close_time_ms"}
        if not isinstance(payload, dict) or not required <= payload.keys():
            raise ValueError("invalid event")
        if type(payload["open_time_ms"]) is not int:
            raise ValueError("invalid open time")
        return types.SimpleNamespace(**payload)


class AnchorQueryTests(unittest.TestCase):
    def setUp(self):
        self.core = types.ModuleType("kairos_core")
        self.contracts = types.ModuleType("kairos_core.contracts")
        self.contracts.ClosedBarEventV1 = _ClosedBarEvent
        self.core.contracts = self.contracts
        self.modules = mock.patch.dict(
            sys.modules,
            {"kairos_core": self.core, "kairos_core.contracts": self.contracts},
        )
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def lookup(self, rows):
        pool = _Pool(rows)
        values = asyncio.run(worker.anchors(pool))
        return values, pool.connection

    def test_query_is_one_narrow_scan_and_keyed_payload_join(self):
        sql = re.sub(r"\s+", " ", worker.ANCHORS_SQL.lower())
        self.assertIn("with matching as materialized", sql)
        self.assertIn("count(distinct open_ms)", sql)
        self.assertIn(
            "order by symbol, open_ms desc, produced_at desc, message_id desc", sql
        )
        matching = sql.split("), stats as", 1)[0]
        self.assertNotRegex(matching, r"select\s+\*|select\s+payload\s*(,|from)")
        self.assertIn("audit.produced_at = latest.produced_at", sql)
        self.assertIn("audit.message_id = latest.message_id", sql)

        _, connection = self.lookup(_audit_rows())
        self.assertEqual(len(connection.calls), 1)
        self.assertEqual(
            connection.calls[0][1],
            (worker.TOPIC, worker.SOURCE, list(worker.SYMBOLS)),
        )

    def test_valid_chains_choose_largest_open_time_not_latest_produced_time(self):
        rows = _audit_rows()
        values, _ = self.lookup(rows)
        for symbol in worker.SYMBOLS:
            self.assertEqual(values[symbol].open_time_ms, 2 * worker.MINUTE)
            # Fixture deliberately makes produced_at run in the opposite direction.
            self.assertEqual(values[symbol].produced_at, 10_000 - 2 * worker.MINUTE)

    def test_irrelevant_source_does_not_change_chain_or_anchor(self):
        rows = _audit_rows()
        irrelevant = _audit_rows(bars=1)[0].copy()
        irrelevant["source"] = "other-source"
        irrelevant["payload"] = {"symbol": worker.SYMBOLS[0], "open_time_ms": -60_000}
        rows.append(irrelevant)
        values, _ = self.lookup(rows)
        self.assertEqual(values[worker.SYMBOLS[0]].open_time_ms, 2 * worker.MINUTE)

    def test_missing_symbol_is_rejected_before_any_model_parse(self):
        rows = [row for row in _audit_rows() if row["symbol"] != worker.SYMBOLS[-1]]
        with mock.patch.object(
            _ClosedBarEvent,
            "model_validate",
            wraps=_ClosedBarEvent.model_validate,
        ) as parse:
            with self.assertRaisesRegex(
                worker.EpochError, "FIVE_UNIQUE_CONTIGUOUS_CHAINS_REQUIRED"
            ):
                self.lookup(rows)
            parse.assert_not_called()

    def test_duplicate_symbol_summary_is_rejected_before_any_model_parse(self):
        pool = _Pool(_audit_rows())
        original_fetch = pool.connection.fetch

        async def duplicate_summary(sql, *args):
            result = await original_fetch(sql, *args)
            return [*result, result[0]]

        pool.connection.fetch = duplicate_summary
        with mock.patch.object(
            _ClosedBarEvent,
            "model_validate",
            wraps=_ClosedBarEvent.model_validate,
        ) as parse:
            with self.assertRaisesRegex(
                worker.EpochError, "FIVE_UNIQUE_CONTIGUOUS_CHAINS_REQUIRED"
            ):
                asyncio.run(worker.anchors(pool))
            parse.assert_not_called()

    def test_duplicate_open_time_and_gap_are_rejected_before_model_parse(self):
        duplicate = _audit_rows()
        duplicate.append(duplicate[0].copy())
        gap = [
            row
            for row in _audit_rows(bars=3)
            if not (
                row["symbol"] == worker.SYMBOLS[0]
                and row["payload"]["open_time_ms"] == 2 * worker.MINUTE
            )
        ]
        for rows in (duplicate, gap):
            with (
                self.subTest(rows=len(rows)),
                mock.patch.object(
                    _ClosedBarEvent,
                    "model_validate",
                    wraps=_ClosedBarEvent.model_validate,
                ) as parse,
            ):
                with self.assertRaisesRegex(
                    worker.EpochError, "FIVE_UNIQUE_CONTIGUOUS_CHAINS_REQUIRED"
                ):
                    self.lookup(rows)
                parse.assert_not_called()

    def test_malformed_latest_payload_fails_only_after_valid_chain_checks(self):
        rows = _audit_rows()
        latest = next(
            row
            for row in rows
            if row["symbol"] == worker.SYMBOLS[0]
            and row["payload"]["open_time_ms"] == 2 * worker.MINUTE
        )
        latest["payload"] = {
            "symbol": worker.SYMBOLS[0],
            "open_time_ms": 2 * worker.MINUTE,
        }
        with self.assertRaisesRegex(ValueError, "invalid event"):
            self.lookup(rows)


class AnchorBoundsTests(unittest.TestCase):
    @staticmethod
    def anchors(open_ms=60_000):
        return {
            symbol: types.SimpleNamespace(close_time_ms=open_ms + worker.MINUTE - 1)
            for symbol in worker.SYMBOLS
        }

    def test_required_bars_and_bounded_end_respect_global_pending_cap(self):
        values = self.anchors()
        latest = max(event.close_time_ms + 1 for event in values.values())
        target = latest + 10_000 * worker.MINUTE
        end = worker.bounded_runtime_end(values, target)
        self.assertLessEqual(worker.required_bars(values, end), worker.MAX_PENDING)
        self.assertLessEqual(end, target)

    def test_required_bars_rejects_invalid_end_and_symbol_set(self):
        values = self.anchors()
        with self.assertRaisesRegex(
            worker.EpochError, "FIXED_CATCHUP_INTERVAL_REQUIRED"
        ):
            worker.required_bars(values, 120_001)
        with self.assertRaisesRegex(
            worker.EpochError, "FIXED_CATCHUP_INTERVAL_REQUIRED"
        ):
            worker.required_bars({"BTCUSDT": values["BTCUSDT"]}, 120_000)

    def test_bounded_end_rejects_skew_above_pending_cap(self):
        old_anchor = -26 * worker.MINUTE
        values = {
            symbol: types.SimpleNamespace(
                close_time_ms=(0 if index == len(worker.SYMBOLS) - 1 else old_anchor)
                + worker.MINUTE
                - 1
            )
            for index, symbol in enumerate(worker.SYMBOLS)
        }
        target = worker.MINUTE
        with self.assertRaisesRegex(
            worker.EpochError, "RUNTIME_WATERMARK_SKEW_EXCEEDS_PENDING_CAP"
        ):
            worker.bounded_runtime_end(values, target)


if __name__ == "__main__":
    unittest.main()
