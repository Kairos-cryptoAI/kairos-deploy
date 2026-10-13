"""Offline tests for the fixed, isolated R7 read/recovery profile."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from scripts import runtime_epoch_r7_read_profile as r7
from scripts import runtime_epoch_read_recovery_worker as r5


def state_fixture() -> dict:
    epoch = r5.epoch
    tables = {
        name: {"count": 0, "sha256": "0" * 64}
        for name in epoch.CONTROLLED_RUNTIME_PUBLIC_TABLES
    }
    tables["event_audit"]["count"] = 342_379
    tables["message_outbox"]["count"] = 8_045
    tables["message_inbox"]["count"] = 8_035
    tables["paper_canary_database_identity"] = dict(epoch.BOOT_DATABASE_IDENTITY)
    anchors = {}
    counts = (68_476, 68_476, 68_476, 68_476, 68_475)
    for symbol, count in zip(epoch.SYMBOLS, counts, strict=True):
        first = 1_780_000_020_000
        last = first + (count - 1) * epoch.MINUTE
        anchors[symbol] = {
            "count": count,
            "first_open_time_ms": first,
            "last_open_time_ms": last,
            "last_close_time_ms": last + epoch.MINUTE - 1,
        }
    ids = sorted(r7.R7_TARGET_IDS)
    return {
        "owner": r7.R7_OWNER,
        "mode": "r7-state",
        "new_epoch_database": "kairos_epoch_" + r7.R7_OWNER[:12],
        "state": "PASS_R7_STATE",
        "matched_public_tables": len(tables),
        "tables": tables,
        "sequences": {},
        "anchors": anchors,
        "original_prefix": {
            "rows": epoch.ORIGINAL_PREFIX_ROWS,
            "audit_table_sha256": epoch.ORIGINAL_PREFIX_TABLE_SHA256,
            "last_open_time_ms": epoch.ORIGINAL_PREFIX_LAST_OPEN_MS,
        },
        "queue": {
            "outbox_rows": 8_045,
            "inbox_rows": 8_035,
            "completed_inbox": 8_035,
            "pending_outbox": 0,
            "unresolved_inbox": 0,
            "trading_rows": 0,
            "missing_inbox_message_ids": ids,
        },
        "preserved_queue_prefixes": {
            "message_outbox": {"n": 8_035, "sha": "1" * 64},
            "message_inbox": {"n": 8_035, "sha": "2" * 64},
        },
        "trading_started": False,
        "redis": {
            "stream_entries": 8_046,
            "publication_receipts": 8_045,
            "publication_receipts_sha256": "3" * 64,
            "publication_message_ids_sha256": "4" * 64,
            "stream_sha256": "5" * 64,
            "stream_last_id": "6000-0",
            "consumer_group": "bars",
            "last_delivered_id": "5900-0",
            "pending_deliveries": 10,
            "pending_target_message_ids": ids,
            "trading_started": False,
        },
    }


def config(**changes) -> dict:
    value = {
        "owner": r7.R7_OWNER,
        "database": "kairos_epoch_" + r7.R7_OWNER[:12],
        "pg_host": "kairos-epoch-" + r7.R7_OWNER[:12] + "-pg",
        "redis_host": "kairos-epoch-" + r7.R7_OWNER[:12] + "-redis",
        "admin_password": "a" * 64,
        "producer_password": "b" * 64,
        "consumer_password": "c" * 64,
        "redis_producer_password": "d" * 64,
        "redis_consumer_password": "e" * 64,
    }
    value.update(changes)
    return value


class ProfileIsolationTests(unittest.TestCase):
    def test_r7_constants_are_private_and_r5_globals_are_unchanged(self):
        self.assertIsNot(r7._R5_R7_INTERNAL, r5)
        self.assertIs(r7._R5_R7_INTERNAL.epoch, r5.epoch)
        self.assertEqual(
            dict(r7._R5_R7_INTERNAL.EXPECTED_COUNTS), r7.R7_EXPECTED_COUNTS
        )
        self.assertEqual(
            r5.EXPECTED_COUNTS, {"audit": 336429, "outbox": 5336, "inbox": 5331}
        )
        self.assertEqual(len(r5.TARGETS), 5)
        self.assertEqual(len(r7.R7_TARGETS), 10)
        self.assertEqual(r7._R5_R7_INTERNAL.RESTORE_HOST, r7.R7_RESTORE_HOST)
        with self.assertRaises(TypeError):
            r7.R7_TARGETS[0]["outbox_id"] = 1

    def test_fixed_r7_target_metadata(self):
        self.assertEqual(r7.R7_TARGET_OUTBOX_IDS, frozenset(range(8049, 8059)))
        self.assertEqual(len(r7.R7_TARGET_IDS), 10)
        self.assertEqual(
            [(row["symbol"], row["open_time_ms"]) for row in r7.R7_TARGETS[:4]],
            [
                ("XRPUSDT", 1_791_863_100_000),
                ("XRPUSDT", 1_791_863_160_000),
                ("ETHUSDT", 1_791_863_100_000),
                ("ETHUSDT", 1_791_863_160_000),
            ],
        )
        for row in r7.R7_TARGETS:
            self.assertRegex(row["message_id"], r"^[0-9a-f]{64}$")
            self.assertRegex(row["payload_sha256"], r"^[0-9a-f]{64}$")


class StateAdmissionTests(unittest.TestCase):
    def test_full_r7_state_normalizes_to_private_r5_contract_without_mutation(self):
        state = state_fixture()
        normalized = r7.validate_expected_state(state)

        self.assertEqual(state["mode"], "r7-state")
        self.assertEqual(state["state"], "PASS_R7_STATE")
        self.assertEqual(normalized["queue"]["outbox_rows"], 8_045)
        self.assertEqual(
            normalized["queue"]["missing_inbox_message_ids"], sorted(r7.R7_TARGET_IDS)
        )
        self.assertEqual(normalized["redis"]["publication_receipts"], 8_045)

    def test_state_rejects_wrong_counts_unknown_pending_ids_and_trading(self):
        cases = (
            {"queue": {"outbox_rows": 5_336}},
            {"redis": {"pending_target_message_ids": ["not-r7"]}},
            {"trading_started": True},
            {"state": "PASS_R5_STATE"},
            {"mode": "r5-state"},
        )
        for change in cases:
            value = state_fixture()
            value.update(change)
            with self.subTest(change=change), self.assertRaises(r5.epoch.EpochError):
                r7.validate_expected_state(value)

    def test_all_three_modes_require_exact_owned_config_and_restore07(self):
        r7.validate_config("r7-state", config())

        drain_config = config(expected_state=state_fixture())
        r7.validate_config("r7-drain", drain_config)

        common = config()
        restore_config = {
            key: common[key]
            for key in ("owner", "database", "pg_host", "redis_host", "admin_password")
        }
        restore_config.update(
            restore_host=r7.R7_RESTORE_HOST,
            restore_database=r7.R7_RESTORE_DATABASE,
            restore_admin_password="b" * 64,
            expected_seed=state_fixture(),
        )
        r7.validate_config("r7-verify-restore", restore_config)

        for mode, invalid in (
            ("r7-state", {"restore_database": "kairos"}),
            ("r7-drain", {"expected_state": {**state_fixture(), "queue": {}}}),
            (
                "r7-verify-restore",
                {"restore_host": "kairos-epoch-69893dc7b7c6-restore-transport06"},
            ),
            ("r7-verify-restore", {"producer_password": "f" * 64}),
            ("r5-drain", {}),
        ):
            base = {
                "r7-state": config(),
                "r7-drain": drain_config,
                "r7-verify-restore": restore_config,
                "r5-drain": drain_config,
            }[mode]
            with (
                self.subTest(mode=mode, invalid=invalid),
                self.assertRaises(r5.epoch.EpochError),
            ):
                r7.validate_config(mode, {**base, **invalid})

    def test_drain_translation_uses_r7_values_then_normalizes_expected_state(self):
        original = state_fixture()
        internal_mode, internal = r7._normalize_config(
            "r7-drain",
            config(expected_state=original),
        )
        self.assertEqual(internal_mode, "r5-drain")
        self.assertEqual(internal["expected_state"]["state"], "PASS_R5_STATE")
        self.assertEqual(internal["expected_state"]["mode"], "r5-state")
        self.assertEqual(original["state"], "PASS_R7_STATE")


class ResultTranslationTests(unittest.IsolatedAsyncioTestCase):
    async def test_dispatch_translates_only_known_r5_success_state(self):
        with mock.patch.object(
            r7._R5_R7_INTERNAL,
            "dispatch_r5",
            return_value={"state": "PASS_R5_STATE", "trading_started": False},
        ) as dispatch:
            result = await r7.dispatch_r7(
                "r7-state", config(), Path("offline-status.json")
            )

        self.assertEqual(result, {"state": "PASS_R7_STATE", "trading_started": False})
        self.assertEqual(dispatch.await_args.args[0], "r5-state")
        self.assertEqual(dispatch.await_args.args[1], config())

    async def test_unknown_or_failed_internal_state_is_never_promoted(self):
        for internal_state in ("PASS_R5_STATE_PARTIAL", "FAILED"):
            with (
                mock.patch.object(
                    r7._R5_R7_INTERNAL,
                    "dispatch_r5",
                    return_value={"state": internal_state},
                ),
                self.assertRaises(r5.epoch.EpochError),
            ):
                await r7.dispatch_r7("r7-state", config(), Path("offline-status.json"))


if __name__ == "__main__":
    unittest.main()
