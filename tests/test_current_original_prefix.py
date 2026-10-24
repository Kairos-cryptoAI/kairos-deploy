from __future__ import annotations

import unittest

from scripts import runtime_epoch_worker as worker


class CurrentOriginalPrefixTests(unittest.TestCase):
    def setUp(self):
        self.token = worker.schema_profile_context("current-controlled-v1")

    def tearDown(self):
        worker.reset_schema_profile_context(self.token)

    def test_current_projection_excludes_only_import_timestamp(self):
        expected = worker.expected_original_prefix()
        self.assertEqual(
            expected,
            {
                "rows": worker.ORIGINAL_PREFIX_ROWS,
                "audit_table_sha256": worker.CURRENT_ORIGINAL_PREFIX_TABLE_SHA256,
                "last_open_time_ms": worker.ORIGINAL_PREFIX_LAST_OPEN_MS,
                "digest_scope": worker.CURRENT_ORIGINAL_PREFIX_DIGEST_SCOPE,
            },
        )
        sql = worker.original_prefix_digest_sql()
        self.assertIn("(to_jsonb(t) - 'persisted_at')::text", sql)
        self.assertIn("payload->>'open_time_ms'", sql)

    def test_current_boot_seed_and_history_state_bind_explicit_scope(self):
        counts = {
            "BTCUSDT": 34_633,
            "ETHUSDT": 34_633,
            "SOLUSDT": 34_633,
            "BNBUSDT": 34_633,
            "XRPUSDT": 34_632,
        }
        anchors = {}
        for symbol, count in counts.items():
            first = 1_787_754_720_000 if symbol == "XRPUSDT" else 1_787_754_660_000
            last = first + (count - 1) * worker.MINUTE
            anchors[symbol] = {
                "count": count,
                "first_open_time_ms": first,
                "last_open_time_ms": last,
                "last_close_time_ms": last + worker.MINUTE - 1,
            }

        identity = {"count": 1, "sha256": "c" * 64}
        tables = {
            name: {"count": 0, "sha256": "a" * 64}
            for name in worker.schema_profile()["public_tables"]
        }
        tables["schema_migrations"]["count"] = 19
        tables["event_audit"]["count"] = worker.ORIGINAL_PREFIX_ROWS
        tables["event_audit"]["sha256"] = "b" * 64
        tables["paper_canary_database_identity"] = identity
        seed = {
            "state": "PASS_BOOT_STATE",
            "matched_public_tables": 33,
            "tables": tables,
            "sequences": {},
            "anchors": anchors,
            "original_prefix": worker.expected_original_prefix(),
            "queue": {
                "outbox_rows": 0,
                "inbox_rows": 0,
                "completed_inbox": 0,
                "pending_outbox": 0,
                "unresolved_inbox": 0,
                "trading_rows": 0,
            },
            "trading_started": False,
            "schema_profile": "current-controlled-v1",
            "schema_migration_count": 19,
            "schema_public_table_count": 33,
            "database_identity": identity,
        }
        worker.validate_boot_seed(seed, "0123456789abcdef0123456789abcdef", "kairos_epoch_0123456789ab")

        history = {
            "matched_public_tables": 33,
            "original_prefix": worker.expected_original_prefix(),
            "rows": worker.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": "b" * 64,
            "anchors": anchors,
            "outbox_rows": 0,
            "inbox_rows": 0,
            "orders_rows": 0,
            "effects_rows": 0,
            "trading_started": False,
        }
        worker.validate_history_state(history)

        bad_seed = {**seed, "original_prefix": {**seed["original_prefix"], "digest_scope": "wrong"}}
        with self.assertRaises(worker.EpochError):
            worker.validate_boot_seed(bad_seed, "0123456789abcdef0123456789abcdef", "kairos_epoch_0123456789ab")
        bad_history = {**history, "original_prefix": {**history["original_prefix"], "digest_scope": "wrong"}}
        with self.assertRaises(worker.EpochError):
            worker.validate_history_state(bad_history)
        for key, changed in (
            ("rows", worker.ORIGINAL_PREFIX_ROWS - 1),
            ("audit_table_sha256", "f" * 64),
            ("last_open_time_ms", worker.ORIGINAL_PREFIX_LAST_OPEN_MS + worker.MINUTE),
            ("unexpected", True),
        ):
            with self.subTest(field=key), self.assertRaises(worker.EpochError):
                worker.validate_boot_seed(
                    {**seed, "original_prefix": {**seed["original_prefix"], key: changed}},
                    "0123456789abcdef0123456789abcdef", "kairos_epoch_0123456789ab",
                )


class HistoricalOriginalPrefixCompatibilityTests(unittest.TestCase):
    def test_default_profile_retains_original_prefix_bytes_and_sql_projection(self):
        self.assertEqual(
            worker.expected_original_prefix(),
            {
                "rows": worker.ORIGINAL_PREFIX_ROWS,
                "audit_table_sha256": worker.ORIGINAL_PREFIX_TABLE_SHA256,
                "last_open_time_ms": worker.ORIGINAL_PREFIX_LAST_OPEN_MS,
            },
        )
        self.assertEqual(
            worker.original_prefix_digest_sql(),
            """SELECT count(*) n,encode(sha256(convert_to(COALESCE(string_agg(row_sha,'' ORDER BY row_sha),''),'UTF8')),'hex') digest
             FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') row_sha
                     FROM event_audit t WHERE (payload->>'open_time_ms')::bigint <= $1) r""",
        )


if __name__ == "__main__":
    unittest.main()
