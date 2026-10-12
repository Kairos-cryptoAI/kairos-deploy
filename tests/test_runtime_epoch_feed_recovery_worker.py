"""Offline, stdlib-only contract tests for the create-only R6 recovery."""

from __future__ import annotations

import time
import unittest
from types import SimpleNamespace

from scripts import runtime_epoch_feed_recovery as controller
from scripts import runtime_epoch_feed_recovery_worker as feed
from scripts import runtime_epoch_worker as epoch


def sample_state(*, drained: bool) -> dict:
    tables = {
        name: {"count": 0, "sha256": "0" * 64}
        for name in epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES
    }
    tables["event_audit"] = {"count": feed.BASE_AUDIT_ROWS, "sha256": "1" * 64}
    tables["message_outbox"] = {"count": feed.BASE_OUTBOX_ROWS, "sha256": "2" * 64}
    tables["message_inbox"] = {
        "count": feed.BASE_OUTBOX_ROWS if drained else feed.BASE_INBOX_ROWS,
        "sha256": "3" * 64,
    }
    tables["paper_canary_database_identity"] = dict(epoch.BOOT_DATABASE_IDENTITY)
    queue = {
        "outbox_rows": feed.BASE_OUTBOX_ROWS,
        "inbox_rows": tables["message_inbox"]["count"],
        "completed_inbox": tables["message_inbox"]["count"],
        "pending_outbox": 0 if drained else len(feed.TARGETS),
        "unresolved_inbox": 0,
        "trading_rows": 0,
        "missing_inbox_message_ids": [] if drained else sorted(feed.TARGET_IDS),
    }
    receipts = (
        feed.BASE_OUTBOX_ROWS if drained else feed.BASE_OUTBOX_ROWS - len(feed.TARGETS)
    )
    anchor_counts = (67_924, 67_924, 67_924, 67_924, 67_922)
    anchors = {}
    for symbol, count in zip(epoch.SYMBOLS, anchor_counts):
        first = 1_020_000
        last = first + (count - 1) * epoch.MINUTE
        anchors[symbol] = {
            "count": count,
            "first_open_time_ms": first,
            "last_open_time_ms": last,
            "last_close_time_ms": last + epoch.MINUTE - 1,
        }
    return {
        "state": "PASS_R6_STATE",
        "matched_public_tables": len(tables),
        "tables": tables,
        "sequences": {
            "message_outbox_id_seq": {
                "last_value": feed.BASE_OUTBOX_ROWS,
                "is_called": True,
            }
        },
        "anchors": anchors,
        "original_prefix": {
            "rows": epoch.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": epoch.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": epoch.ORIGINAL_PREFIX_LAST_OPEN_MS,
        },
        "queue": queue,
        "preserved_queue_prefixes": {
            "message_outbox": {
                "n": feed.BASE_OUTBOX_ROWS - len(feed.TARGETS),
                "sha": "4" * 64,
            },
            "message_inbox": {"n": feed.BASE_INBOX_ROWS, "sha": "5" * 64},
        },
        "trading_started": False,
        "redis": {
            "stream_entries": receipts + 1,
            "publication_receipts": receipts,
            "publication_receipts_sha256": "6" * 64,
            "publication_message_ids_sha256": "7" * 64,
            "stream_sha256": "8" * 64,
            "stream_last_id": "999-0",
            "consumer_group": "bars",
            "last_delivered_id": "999-0",
            "pending_deliveries": 0,
            "pending_target_message_ids": [],
            "trading_started": False,
        },
        "owner": feed.OWNER,
        "mode": "r6-state",
        "new_epoch_database": "kairos_epoch_" + feed.OWNER[:12],
    }


class FeedRecoveryWorkerTests(unittest.TestCase):
    def test_exact_pending_set_accepts_only_four_pinned_rows(self):
        rows = [
            {
                "id": target["outbox_id"],
                "message_id": target["message_id"],
                "payload_sha256": target["payload_sha256"],
            }
            for target in feed.TARGETS
        ]
        feed.validate_exact_pending_rows(rows)
        with self.assertRaises(epoch.EpochError):
            feed.validate_exact_pending_rows(rows[:-1])
        changed = [dict(row) for row in rows]
        changed[0]["payload_sha256"] = "f" * 64
        with self.assertRaises(epoch.EpochError):
            feed.validate_exact_pending_rows(changed)
        extra = rows + [
            {"id": 5809, "message_id": "a" * 64, "payload_sha256": "b" * 64}
        ]
        with self.assertRaises(epoch.EpochError):
            feed.validate_exact_pending_rows(extra)

    def test_full_expected_prestate_is_four_unpublished_not_four_published(self):
        value = sample_state(drained=False)
        feed.validate_expected_state(value, include_redis=True)
        value["redis"]["publication_receipts"] += len(feed.TARGETS)
        value["redis"]["stream_entries"] += len(feed.TARGETS)
        with self.assertRaises(epoch.EpochError):
            feed.validate_expected_state(value, include_redis=True)

    def test_exact_drain_poststate_preserves_outbox_and_closes_four_inboxes(self):
        value = sample_state(drained=True)
        feed.validate_expected_state(value, include_redis=True)
        value["queue"]["missing_inbox_message_ids"] = [next(iter(feed.TARGET_IDS))]
        with self.assertRaises(epoch.EpochError):
            feed.validate_expected_state(value, include_redis=True)

    def test_drain_transition_preserves_every_unrelated_table_and_history_field(self):
        before = sample_state(drained=False)
        after = sample_state(drained=True)
        feed.validate_drain_transition(before, after)
        changed = sample_state(drained=True)
        changed["tables"]["schema_migrations"]["sha256"] = "f" * 64
        with self.assertRaises(epoch.EpochError):
            feed.validate_drain_transition(before, changed)
        changed = sample_state(drained=True)
        changed["sequences"]["message_outbox_id_seq"]["last_value"] += 1
        with self.assertRaises(epoch.EpochError):
            feed.validate_drain_transition(before, changed)

    def test_live_batch_end_never_exceeds_existing_pending_cap(self):
        seed = {
            "anchors": {
                symbol: {
                    "count": 1,
                    "first_open_time_ms": 0,
                    "last_open_time_ms": 0,
                    "last_close_time_ms": epoch.MINUTE - 1,
                }
                for symbol in epoch.SYMBOLS
            }
        }
        end = feed.bounded_live_batch_end(seed, 10_000 * epoch.MINUTE)
        count = sum(
            max(0, (end - (row["last_close_time_ms"] + 1)) // epoch.MINUTE)
            for row in seed["anchors"].values()
        )
        self.assertGreater(end, epoch.MINUTE)
        self.assertEqual(count, epoch.MAX_PENDING)

    def test_controller_accepts_only_the_exact_prestate_and_drain_shape(self):
        controller.validate_prestate(sample_state(drained=False))
        controller.validate_drained(sample_state(drained=True))
        wrong = sample_state(drained=False)
        wrong["tables"]["event_audit"]["count"] += 1
        with self.assertRaises(epoch.EpochError):
            controller.validate_prestate(wrong)

    def test_graceful_stop_receipt_matches_a_fresh_nontrading_status(self):
        from datetime import UTC, datetime

        status = {
            "state": "RUNNING_NONTRADING",
            "owner": feed.OWNER,
            "cycles": 4,
            "watermarks_ms": {symbol: 1_800_000_000_000 for symbol in epoch.SYMBOLS},
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "completed_inbox": feed.BASE_OUTBOX_ROWS,
            "uncompleted_publications": 0,
            "new_publications": 1,
            "observed_at_utc": datetime.now(UTC).isoformat(),
            "PAPER_QUALIFIED": False,
            "ALPHA_READY": False,
            "LIVE_READY": False,
            "STRATEGY_POLICY": "REJECT_ALL",
        }
        receipt = {
            **status,
            "state": "STOPPED_NONTRADING",
            "mode": "serve",
            "new_epoch_database": "kairos_epoch_" + feed.OWNER[:12],
            "graceful_shutdown": True,
        }
        controller.validate_graceful_stop_receipt(receipt, status)
        receipt["watermarks_ms"] = dict(receipt["watermarks_ms"])
        receipt["watermarks_ms"][epoch.SYMBOLS[0]] += 1
        with self.assertRaises(controller.epoch.Rejected):
            controller.validate_graceful_stop_receipt(receipt, status)

    def test_audit_tail_noop_issues_no_worker_phase(self):
        anchor = 4_000_000_000_000
        prefix = {
            "rows": epoch.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": epoch.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": epoch.ORIGINAL_PREFIX_LAST_OPEN_MS,
        }
        state = {
            "state": "PASS_BOOT_STATE",
            "tables": {
                "event_audit": {"count": feed.BASE_AUDIT_ROWS, "sha256": "a" * 64},
                "message_outbox": {"count": feed.BASE_OUTBOX_ROWS, "sha256": "b" * 64},
                "message_inbox": {"count": feed.BASE_OUTBOX_ROWS, "sha256": "c" * 64},
            },
            "sequences": {
                "outbox": {"last_value": feed.BASE_OUTBOX_ROWS, "is_called": True}
            },
            "original_prefix": prefix,
            "anchors": {
                symbol: {"last_close_time_ms": anchor, "count": 1}
                for symbol in epoch.SYMBOLS
            },
        }
        calls = []
        fake = SimpleNamespace(
            boot_state=lambda _tag: state,
            phase=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
        current, receipts = controller.R6FeedRecoveryController.audit_only_tail(
            fake, state, {}, "noop"
        )
        self.assertEqual(current, state)
        self.assertEqual(receipts, [])
        self.assertEqual(calls, [])

    def test_r6_clean_state_bridges_to_the_generic_boot_snapshot_before_tail(self):
        r6 = sample_state(drained=True)
        safe_close = ((int(time.time() * 1000) // epoch.MINUTE) + 10) * epoch.MINUTE - 1
        for anchor in r6["anchors"].values():
            anchor["last_open_time_ms"] = safe_close - epoch.MINUTE + 1
            anchor["first_open_time_ms"] = (
                anchor["last_open_time_ms"] - (anchor["count"] - 1) * epoch.MINUTE
            )
            anchor["last_close_time_ms"] = safe_close
        boot_state = {
            key: r6[key]
            for key in ("tables", "sequences", "anchors", "original_prefix")
        }
        boot_state["state"] = "PASS_BOOT_STATE"
        boot_state["queue"] = {
            key: r6["queue"][key]
            for key in (
                "outbox_rows",
                "inbox_rows",
                "completed_inbox",
                "pending_outbox",
                "unresolved_inbox",
                "trading_rows",
            )
        }
        bridged = controller.validate_boot_bridge(r6, boot_state)
        self.assertIs(bridged, boot_state)

        calls = []
        fake = SimpleNamespace(
            boot_state=lambda _tag: boot_state,
            phase=lambda *args, **kwargs: calls.append((args, kwargs)),
            names={"target_pg": "pg", "redis": "redis"},
            _history_password="unused-test-value",
        )
        current, receipts = controller.R6FeedRecoveryController.audit_only_tail(
            fake, bridged, {}, "bridge-noop"
        )
        self.assertEqual(current, boot_state)
        self.assertEqual(receipts, [])
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
