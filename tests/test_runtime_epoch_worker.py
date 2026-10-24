"""Offline unit contracts for the isolated non-trading epoch worker."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import runtime_epoch_worker as worker

OWNER = "0123456789abcdef0123456789abcdef"
DB = "kairos_epoch_0123456789ab"


def _catchup_config(**changes):
    end = (int(time.time() * 1000) // worker.MINUTE - 1) * worker.MINUTE
    value = {
        "owner": OWNER,
        "database": DB,
        "pg_host": "kairos-epoch-0123456789ab-pg",
        "redis_host": "kairos-epoch-0123456789ab-redis",
        "end_exclusive_ms": end,
        "maximum_bars": worker.MAX_BARS,
        "history_password": "a" * 64,
    }
    value.update(changes)
    return value


class WorkerConfigTests(unittest.TestCase):
    def test_only_current_full_table_integrity_queries_use_the_explicit_budget(self):
        helper = types.ModuleType("controlled_runtime_worker")
        helper._table_digest = mock.AsyncMock(return_value={"count": 1, "sha256": "a" * 64})
        connection, budget = object(), object()
        with mock.patch.dict(sys.modules, {"controlled_runtime_worker": helper}):
            asyncio.run(worker.epoch_table_digest(connection, "event_audit", budget))
            helper._table_digest.assert_awaited_once_with(connection, "event_audit", budget)
            helper._table_digest.reset_mock()
            token = worker.schema_profile_context("current-controlled-v1")
            try:
                asyncio.run(worker.epoch_table_digest(connection, "event_audit", budget))
            finally:
                worker.reset_schema_profile_context(token)
            helper._table_digest.assert_awaited_once_with(connection, "event_audit", budget, query_timeout=120)

    def test_schema_profiles_are_explicit_immutable_and_historical_by_default(self):
        self.assertEqual(worker.schema_profile()["identity"], "historical-default")
        historical = worker.schema_profile("historical-default")
        current = worker.schema_profile("current-controlled-v1")
        self.assertEqual(len(historical["migrations"]), 18)
        self.assertEqual(len(historical["public_tables"]), 32)
        self.assertEqual(len(current["migrations"]), 19)
        self.assertEqual(len(current["public_tables"]), 33)
        self.assertIn("028_news_processing.sql", current["migrations"])
        self.assertIn("news_processing", current["public_tables"])
        with self.assertRaises(TypeError):
            current["identity"] = "changed"
        with self.assertRaises(TypeError):
            worker.SCHEMA_PROFILES["other"] = current

    def test_profile_context_selects_inventory_without_mutating_historical_constant(self):
        original = worker.CONTROLLED_RUNTIME_PUBLIC_TABLES
        token = worker.schema_profile_context("current-controlled-v1")
        try:
            self.assertEqual(
                worker.schema_profile_report(),
                {
                    "schema_profile": "current-controlled-v1",
                    "schema_migration_count": 19,
                    "schema_public_table_count": 33,
                },
            )
            self.assertIn("news_processing", worker.schema_profile()["public_tables"])
            worker.validate_epoch_table_inventory(
                list(worker.schema_profile()["public_tables"])
            )
            with self.assertRaises(worker.EpochError):
                worker.validate_epoch_table_inventory(list(original))
        finally:
            worker.reset_schema_profile_context(token)
        self.assertIs(worker.CONTROLLED_RUNTIME_PUBLIC_TABLES, original)
        self.assertEqual(worker.schema_profile()["identity"], "historical-default")
        self.assertEqual(worker.schema_profile_report(), {})

    def test_current_boot_seed_requires_exact_current_profile_metadata(self):
        from test_runtime_epoch_boot_worker import boot_seed

        state = boot_seed()
        state["matched_public_tables"] = 33
        state["tables"]["news_processing"] = {"count": 0, "sha256": "a" * 64}
        state["schema_profile"] = "current-controlled-v1"
        state["schema_migration_count"] = 19
        state["schema_public_table_count"] = 33
        token = worker.schema_profile_context("current-controlled-v1")
        try:
            worker.validate_boot_seed(state, OWNER, DB)
            for key, changed in (
                ("schema_profile", "historical-default"),
                ("schema_migration_count", 18),
                ("schema_public_table_count", 32),
            ):
                bad = copy.deepcopy(state)
                bad[key] = changed
                with self.subTest(key=key), self.assertRaises(worker.EpochError):
                    worker.validate_boot_seed(bad, OWNER, DB)
            bad = copy.deepcopy(state)
            del bad["schema_public_table_count"]
            with self.assertRaises(worker.EpochError):
                worker.validate_boot_seed(bad, OWNER, DB)
        finally:
            worker.reset_schema_profile_context(token)

    def test_historical_boot_seed_field_set_remains_exact(self):
        from test_runtime_epoch_boot_worker import boot_seed

        state = boot_seed()
        worker.validate_boot_seed(state, OWNER, DB)
        state["schema_profile"] = "historical-default"
        with self.assertRaises(worker.EpochError):
            worker.validate_boot_seed(state, OWNER, DB)

    def test_current_profile_checks_historical_source_and_current_target_manifests(self):
        class Connection:
            def __init__(self, versions):
                self.versions = versions

            async def fetch(self, _query):
                return [{"version": version} for version in self.versions]

        async def verify():
            token = worker.schema_profile_context("current-controlled-v1")
            try:
                await worker.verify_schema(
                    Connection(worker.HISTORICAL_CONTROLLED_RUNTIME_MIGRATIONS),
                    source=True,
                )
                await worker.verify_schema(
                    Connection(worker.CURRENT_CONTROLLED_RUNTIME_MIGRATIONS)
                )
                with self.assertRaises(worker.EpochError):
                    await worker.verify_schema(
                        Connection(worker.HISTORICAL_CONTROLLED_RUNTIME_MIGRATIONS)
                    )
                with self.assertRaises(worker.EpochError):
                    await worker.verify_schema(
                        Connection(worker.CURRENT_CONTROLLED_RUNTIME_MIGRATIONS),
                        source=True,
                    )
            finally:
                worker.reset_schema_profile_context(token)

        asyncio.run(verify())

    def test_reviewed_restore_clone_names_are_exact_epoch_and_nonce_scoped(self):
        owner = "69893dc7b7c647f49967387e7efca9fb"
        good = "kairos-epoch-69893dc7b7c6-restore-reviewed-0123abcd"
        self.assertTrue(worker.is_reviewed_boot_restore_host(owner, good))
        for invalid_owner, host in (
            (OWNER, good),
            (owner, good + "-extra"),
            (owner, good[:-1]),
            (owner, good.replace("0123abcd", "arbitrary")),
            (owner, None),
            (owner, "kairos-paper-gate-timescaledb-1"),
        ):
            with self.subTest(owner=invalid_owner, host=host):
                self.assertFalse(
                    worker.is_reviewed_boot_restore_host(invalid_owner, host)
                )

    @staticmethod
    def _seed_config(**changes):
        value = {
            "owner": OWNER,
            "database": DB,
            "pg_host": "kairos-epoch-0123456789ab-pg",
            "redis_host": "kairos-epoch-0123456789ab-redis",
            "source_host": "kairos-epoch-0123456789ab-source",
            "source_database": "kairos_recovery_0123456789ab_epoch",
            "source_password": "a" * 64,
            "history_password": "b" * 64,
            "source_dump_sha256": worker.SOURCE_DUMP_SHA256,
            "seed_expectation": {"accepted_dump_sha256": worker.SOURCE_DUMP_SHA256},
        }
        value.update(changes)
        return value

    def test_seed_accepts_exact_pinned_dump_provenance(self):
        worker.validate_config(self._seed_config(), "seed")

    def test_seed_rejects_missing_or_tampered_dump_provenance_before_connect(self):
        valid = self._seed_config()
        invalid_configs = (
            {key: value for key, value in valid.items() if key != "source_dump_sha256"},
            {key: value for key, value in valid.items() if key != "seed_expectation"},
            {**valid, "source_dump_sha256": "0" * 64},
            {
                **valid,
                "seed_expectation": {"accepted_dump_sha256": "0" * 64},
            },
            {
                **valid,
                "seed_expectation": {
                    "accepted_dump_sha256": worker.SOURCE_DUMP_SHA256,
                    "unexpected": True,
                },
            },
        )
        for config in invalid_configs:
            with (
                self.subTest(config=config),
                mock.patch.object(
                    worker, "source_connection", new=mock.AsyncMock()
                ) as connect_source,
                self.assertRaisesRegex(
                    worker.EpochError, "PINNED_SOURCE_DUMP_PROVENANCE_REQUIRED"
                ),
            ):
                asyncio.run(worker.dispatch("seed", config, Path("unused")))
            connect_source.assert_not_awaited()

    def test_catchup_requires_owned_epoch_boundary_and_exact_cap(self):
        worker.validate_config(_catchup_config(), "catchup")
        for changes in (
            {"database": "kairos"},
            {"owner": "f" * 32},
            {"pg_host": "kairos-paper-gate-postgres-1"},
            {"maximum_bars": worker.MAX_BARS - 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(worker.EpochError):
                worker.validate_config(_catchup_config(**changes), "catchup")

    def test_catchup_requires_minute_aligned_finality_safe_deadline(self):
        config = _catchup_config()
        config["end_exclusive_ms"] = (
            int(time.time() * 1000) // worker.MINUTE + 1
        ) * worker.MINUTE
        with self.assertRaisesRegex(
            worker.EpochError, "FIXED_FINALITY_SAFE_DEADLINE_REQUIRED"
        ):
            worker.validate_config(config, "catchup")
        config = _catchup_config()
        config["end_exclusive_ms"] += 1
        with self.assertRaises(worker.EpochError):
            worker.validate_config(config, "catchup")

    def test_runtime_modes_reject_admin_and_old_source_credentials(self):
        common = {
            "owner": OWNER,
            "database": DB,
            "pg_host": "kairos-epoch-0123456789ab-pg",
            "redis_host": "kairos-epoch-0123456789ab-redis",
            "producer_password": "a" * 64,
            "consumer_password": "b" * 64,
            "redis_producer_password": "c" * 64,
            "redis_consumer_password": "d" * 64,
        }
        worker.validate_config(common, "qualify")
        with self.assertRaisesRegex(
            worker.EpochError, "RUNTIME_ADMIN_CREDENTIAL_REJECTED"
        ):
            worker.validate_config({**common, "admin_password": "e" * 64}, "qualify")
        with self.assertRaisesRegex(
            worker.EpochError, "RUNTIME_ADMIN_CREDENTIAL_REJECTED"
        ):
            worker.validate_config({**common, "source_password": "e" * 64}, "serve")

    def test_controller_generated_hex_password_is_accepted(self):
        # The controller's `secrets.token_hex(32)` is exactly 64 lowercase hex.
        config = _catchup_config(history_password="ab" * 32)
        worker.validate_config(config, "catchup")
        with self.assertRaisesRegex(
            worker.EpochError, "NEW_PRIVATE_CREDENTIAL_REQUIRED"
        ):
            worker.validate_config(
                _catchup_config(history_password="Ab_-" + "9x" * 30), "catchup"
            )

    def test_bar_count_math_is_exact_for_all_five_symbols(self):
        events = {
            symbol: types.SimpleNamespace(close_time_ms=999_999)
            for symbol in worker.SYMBOLS
        }
        self.assertEqual(worker.required_bars(events, 1_000_000 + worker.MINUTE), 5)
        with self.assertRaisesRegex(
            worker.EpochError, "FIXED_CATCHUP_INTERVAL_REQUIRED"
        ):
            worker.required_bars({"BTCUSDT": next(iter(events.values()))}, 1_060_000)
        with self.assertRaises(worker.EpochError):
            worker.required_bars(events, 1_000_001)


class EpochTableInventoryTests(unittest.TestCase):
    def test_fresh_controlled_inventory_is_exact_sorted_32(self):
        tables = list(worker.CONTROLLED_RUNTIME_PUBLIC_TABLES)
        self.assertEqual(len(tables), 32)
        self.assertEqual(tables, sorted(set(tables)))
        worker.validate_epoch_table_inventory(tables)

    def test_equal_count_cannot_admit_wrong_table(self):
        tables = list(worker.CONTROLLED_RUNTIME_PUBLIC_TABLES)
        tables[-1] = "unexpected_legacy_table"
        with self.assertRaisesRegex(
            worker.EpochError, "EXACT_EPOCH_TABLE_INVENTORY_REQUIRED"
        ):
            worker.validate_epoch_table_inventory(sorted(tables))

    def test_missing_duplicate_extra_and_legacy_39_are_refused(self):
        tables = list(worker.CONTROLLED_RUNTIME_PUBLIC_TABLES)
        invalid = (
            tables[:-1],
            tables[:-1] + [tables[0]],
            tables + ["unexpected_table"],
            tables + [f"legacy_extra_{number}" for number in range(7)],
            list(reversed(tables)),
        )
        for value in invalid:
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(
                    worker.EpochError, "EXACT_EPOCH_TABLE_INVENTORY_REQUIRED"
                ),
            ):
                worker.validate_epoch_table_inventory(value)


class PartialHistoryStateTests(unittest.TestCase):
    @staticmethod
    def value():
        counts = {s: 35428 if s == "XRPUSDT" else 35429 for s in worker.SYMBOLS}
        counts["BNBUSDT"] = 34633
        anchors = {}
        for symbol, count in counts.items():
            first = 1787754720000 if symbol == "XRPUSDT" else 1787754660000
            last = first + (count - 1) * worker.MINUTE
            anchors[symbol] = {
                "count": count,
                "first_open_time_ms": first,
                "last_open_time_ms": last,
                "last_close_time_ms": last + worker.MINUTE - 1,
            }
        return {
            "rows": 176348,
            "audit_table_sha256": "a68b53a7784613ef7011d589a00d813391c32987d70aea4fcbba10ad672000ef",
            "anchors": anchors,
            "matched_public_tables": 32,
            "original_prefix": {
                "rows": worker.ORIGINAL_PREFIX_ROWS,
                "audit_table_sha256": worker.ORIGINAL_PREFIX_TABLE_SHA256,
                "last_open_time_ms": worker.ORIGINAL_PREFIX_LAST_OPEN_MS,
            },
            "outbox_rows": 0,
            "inbox_rows": 0,
            "orders_rows": 0,
            "effects_rows": 0,
            "trading_started": False,
        }

    def test_valid_partial_state_has_exact_original_prefix_and_contiguous_chains(self):
        worker.validate_history_state(self.value())

    def test_original_prefix_alteration_is_rejected(self):
        for key, value in (
            ("rows", 173165),
            ("audit_table_sha256", "0" * 64),
            ("last_open_time_ms", 0),
        ):
            state = self.value()
            state["original_prefix"][key] = value
            with self.subTest(key=key), self.assertRaises(worker.EpochError):
                worker.validate_history_state(state)

    def test_queue_trading_missing_symbol_gap_or_shifted_first_bar_are_rejected(self):
        states = []
        for key in ("outbox_rows", "inbox_rows", "orders_rows", "effects_rows"):
            state = self.value()
            state[key] = 1
            states.append(state)
        state = self.value()
        del state["anchors"]["BNBUSDT"]
        states.append(state)
        state = self.value()
        state["anchors"]["BTCUSDT"]["count"] -= 1
        states.append(state)
        state = self.value()
        for key in ("first_open_time_ms", "last_open_time_ms", "last_close_time_ms"):
            state["anchors"]["BTCUSDT"][key] += worker.MINUTE
        states.append(state)
        for state in states:
            with self.subTest(state=state), self.assertRaises(worker.EpochError):
                worker.validate_history_state(state)

    def test_explicit_audit_digest_is_enforced_without_changing_legacy_seed_contract(
        self,
    ):
        digest = self.value()["audit_table_sha256"]
        worker.validate_expected_audit_digest({"rows": 173164}, {"sha256": "0" * 64})
        worker.validate_expected_audit_digest(
            {"audit_table_sha256": digest}, {"sha256": digest}
        )
        for expected in ("0" * 64, "not-a-hash"):
            with self.assertRaisesRegex(
                worker.EpochError, "EXPECTED_FULL_AUDIT_DIGEST_CONFLICT"
            ):
                worker.validate_expected_audit_digest(
                    {"audit_table_sha256": expected}, {"sha256": digest}
                )

    def test_history_state_configuration_is_exact_and_has_no_runtime_credentials(self):
        config = {
            k: v
            for k, v in _catchup_config().items()
            if k in {"owner", "database", "pg_host", "redis_host"}
        }
        config["admin_password"] = "a" * 64
        worker.validate_config(config, "history-state")
        for changed in (
            {**config, "consumer_password": "b" * 64},
            {k: v for k, v in config.items() if k != "admin_password"},
        ):
            with self.assertRaisesRegex(
                worker.EpochError, "EXACT_READONLY_HISTORY_STATE_CONFIG_REQUIRED"
            ):
                worker.validate_config(changed, "history-state")

    def test_native_snapshot_uses_one_readonly_repeatable_transaction_and_closes(self):
        state = self.value()

        class Transaction:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class Connection:
            def __init__(self):
                self.closed = False
                self.tx = None

            def transaction(self, **kwargs):
                self.tx = kwargs
                return Transaction()

            async def fetch(self, _query):
                return [{"relname": n} for n in worker.CONTROLLED_RUNTIME_PUBLIC_TABLES]

            async def fetchrow(self, query, *args):
                if "row_sha" in query:
                    return {"n": 173164, "digest": worker.ORIGINAL_PREFIX_TABLE_SHA256}
                anchor = state["anchors"][args[-1]]
                return {
                    "n": anchor["count"],
                    "u": anchor["count"],
                    "lo": anchor["first_open_time_ms"],
                    "hi": anchor["last_open_time_ms"],
                }

            async def fetchval(self, query):
                self_test.assertTrue(query.startswith("SELECT count(*) FROM public."))
                return 0

            async def close(self):
                self.closed = True

        self_test = self
        connection = Connection()
        helper = types.ModuleType("controlled_runtime_worker")
        helper.Budget = lambda: object()
        helper._table_digest = mock.AsyncMock(
            return_value={"count": 176348, "sha256": state["audit_table_sha256"]}
        )
        with (
            mock.patch.dict(sys.modules, {"controlled_runtime_worker": helper}),
            mock.patch.object(
                worker, "connect", new=mock.AsyncMock(return_value=connection)
            ),
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
        ):
            result = asyncio.run(worker.history_state({}))
        self.assertEqual(result["state"], "VERIFIED_AUDIT_ONLY_HISTORY_STATE")
        self.assertEqual(
            connection.tx, {"isolation": "repeatable_read", "readonly": True}
        )
        self.assertTrue(connection.closed)


class FetchTimeoutRetryTests(unittest.TestCase):
    @staticmethod
    def session(outcomes):
        class Content:
            async def iter_chunked(self, _size):
                yield b"[]"

        class Response:
            status = 200
            content_length = 2
            content = Content()

            def __init__(self, outcome):
                self.outcome = outcome

            async def __aenter__(self):
                if isinstance(self.outcome, BaseException):
                    raise self.outcome
                self.status = self.outcome
                return self

            async def __aexit__(self, *_args):
                return False

        class Session:
            def __init__(self):
                self.calls = []

            def get(self, url, **kwargs):
                self.calls.append((url, copy.deepcopy(kwargs)))
                return Response(outcomes[len(self.calls) - 1])

        return Session()

    def test_timeout_get_retry_keeps_identical_parameters_and_never_publishes(self):
        session = self.session([TimeoutError(), 200])
        with mock.patch.object(worker.asyncio, "sleep", new=mock.AsyncMock()) as pause:
            self.assertEqual(
                asyncio.run(
                    worker.fetch_closed_bar_page(session, "BTCUSDT", 60000, 120000)
                ),
                [],
            )
        self.assertEqual(session.calls[0], session.calls[1])
        pause.assert_awaited_once_with(2)

    def test_three_timed_out_reads_fail_closed_with_safe_reason(self):
        session = self.session([TimeoutError()] * 3)
        with (
            mock.patch.object(worker.asyncio, "sleep", new=mock.AsyncMock()) as pause,
            self.assertRaisesRegex(
                worker.EpochError, "OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT"
            ),
        ):
            asyncio.run(worker.fetch_closed_bar_page(session, "BTCUSDT", 60000, 120000))
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(pause.await_args_list, [mock.call(2), mock.call(4)])

    def test_http_rejection_is_not_retried(self):
        session = self.session([429])
        with (
            mock.patch.object(worker.asyncio, "sleep", new=mock.AsyncMock()) as pause,
            self.assertRaisesRegex(
                worker.EpochError, "OFFICIAL_CLOSED_BAR_FETCH_FAILED"
            ),
        ):
            asyncio.run(worker.fetch_closed_bar_page(session, "BTCUSDT", 60000, 120000))
        self.assertEqual(len(session.calls), 1)
        pause.assert_not_awaited()


class HistorySnapshotTests(unittest.TestCase):
    @staticmethod
    def anchors():
        return {
            symbol: {
                "count": 2,
                "first_open_time_ms": 60_000,
                "last_open_time_ms": 120_000,
                "last_close_time_ms": 179_999,
            }
            for symbol in worker.SYMBOLS
        }

    def test_restore_requires_exact_expected_chains_and_global_audit_count(self):
        anchors = self.anchors()
        worker.validate_history_snapshot(10, anchors, {"anchors": anchors})
        with self.assertRaisesRegex(worker.EpochError, "EXTRA_OR_MISSING"):
            worker.validate_history_snapshot(11, anchors, {"anchors": anchors})

    def test_extra_missing_or_changed_symbol_anchor_is_rejected(self):
        anchors = self.anchors()
        changed = self.anchors()
        changed["BTCUSDT"]["last_close_time_ms"] += 1
        for actual in (
            changed,
            {k: v for k, v in anchors.items() if k != "BTCUSDT"},
            {**anchors, "OTHER": anchors["BTCUSDT"]},
        ):
            with self.assertRaises(worker.EpochError):
                worker.validate_history_snapshot(10, actual, {"anchors": anchors})

    def test_invalid_expected_chain_and_missing_expectation_are_rejected(self):
        anchors = self.anchors()
        invalid = self.anchors()
        invalid["BTCUSDT"]["count"] = 3
        for expected in (None, {}, {"anchors": invalid}):
            with self.assertRaises(worker.EpochError):
                worker.validate_history_snapshot(10, anchors, expected)


class HistoryRotationTests(unittest.TestCase):
    @staticmethod
    def config(**changes):
        value = {
            "owner": OWNER,
            "database": DB,
            "pg_host": "kairos-epoch-0123456789ab-pg",
            "redis_host": "kairos-epoch-0123456789ab-redis",
            "admin_password": "a" * 64,
            "history_password": "b" * 64,
        }
        value.update(changes)
        return value

    def test_rotation_rejects_other_hosts_and_extra_credentials_before_connect(self):
        for config in (
            self.config(pg_host="kairos-epoch-0123456789ab-source"),
            self.config(pg_host="kairos-paper-gate-timescaledb-1"),
            self.config(producer_password="c" * 64),
            self.config(history_password="a" * 64),
            {k: v for k, v in self.config().items() if k != "admin_password"},
        ):
            with (
                mock.patch.object(worker, "connect", new=mock.AsyncMock()) as connect,
                self.assertRaises(worker.EpochError),
            ):
                asyncio.run(worker.dispatch("rotate-history", config, Path("unused")))
            connect.assert_not_awaited()

    def test_rotation_changes_only_fixed_role_and_verifies_new_identity(self):
        admin = mock.AsyncMock()
        history = mock.AsyncMock()
        history.fetchrow.return_value = {
            "role": "kairos_epoch_history",
            "database": DB,
        }
        config = self.config()
        with (
            mock.patch.object(
                worker, "connect", new=mock.AsyncMock(side_effect=[admin, history])
            ) as connect,
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()) as verify,
        ):
            result = asyncio.run(
                worker.dispatch("rotate-history", config, Path("unused"))
            )
        connect.assert_has_awaits(
            [mock.call(config, "kairos"), mock.call(config, "kairos_epoch_history")]
        )
        admin.execute.assert_awaited_once_with(
            "ALTER ROLE kairos_epoch_history PASSWORD '" + "b" * 64 + "'"
        )
        history.execute.assert_not_awaited()
        self.assertEqual(verify.await_count, 2)
        admin.close.assert_awaited_once()
        history.close.assert_awaited_once()
        self.assertEqual(result["state"], "HISTORY_CREDENTIAL_ROTATED")
        self.assertFalse(result["queue_mutations"])
        self.assertNotIn(config["history_password"], json.dumps(result))

    def test_rotation_failure_closes_connection_and_does_not_continue(self):
        admin = mock.AsyncMock()
        admin.execute.side_effect = RuntimeError("private driver diagnostic")
        with (
            mock.patch.object(
                worker, "connect", new=mock.AsyncMock(return_value=admin)
            ) as connect,
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
            self.assertRaises(RuntimeError),
        ):
            asyncio.run(
                worker.dispatch("rotate-history", self.config(), Path("unused"))
            )
        connect.assert_awaited_once()
        admin.close.assert_awaited_once()


class _FakeTransaction:
    def __init__(self, connection):
        self.connection = connection
        self.before_audit = 0
        self.before_outbox = 0

    async def __aenter__(self):
        self.before_audit = self.connection.audit_count
        self.before_outbox = len(self.connection.outbox)
        return self

    async def __aexit__(self, exc_type, _exc, _tb):
        if exc_type is not None:
            self.connection.audit_count = self.before_audit
            del self.connection.outbox[self.before_outbox :]
        return False


class _FakeConnection:
    def __init__(self):
        self.audit_count = 0
        self.outbox = []

    def transaction(self):
        return _FakeTransaction(self)

    async def fetch(self, query, *_args):
        if "FROM event_audit" in query:
            return []
        raise AssertionError("unexpected query")


class _PoolAcquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_args):
        return False


class _FakePool:
    def __init__(self, connection=None):
        self.connection = connection or _FakeConnection()
        self.closed = False

    def acquire(self):
        return _PoolAcquire(self.connection)

    async def close(self):
        self.closed = True


class _FakeEvent:
    message_id = "fixture-message-id"

    def to_payload(self):
        return {"message_id": self.message_id, "value": 42}


class WriterTests(unittest.TestCase):
    def _modules(self, *, fail_outbox=False):
        connection = _FakeConnection()
        pool = _FakePool(connection)
        calls = []

        class FakeAuditRepository:
            def __init__(self, _pool):
                pass

            @staticmethod
            def _require_matching_audit_identity(
                rows, *, message_id, topic, canonical_json
            ):
                if rows:
                    raise AssertionError("unexpected pre-existing audit row in fixture")

            async def append_payload(self, topic, payload, *, connection):
                encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                digest = hashlib.sha256(encoded.encode()).hexdigest()
                calls.append(("audit", topic, payload, encoded, digest))
                connection.audit_count += 1
                return True

            async def enqueue_outbox(
                self, connection, message_id, topic, encoded, digest, producer
            ):
                calls.append(("outbox", message_id, topic, encoded, digest, producer))
                if fail_outbox:
                    raise RuntimeError("simulated outbox failure")
                connection.outbox.append(message_id)

        repository_module = types.ModuleType("kairos_persistence.repository")
        repository_module.AuditRepository = FakeAuditRepository
        runtime_module = types.ModuleType("kairos_persistence.runtime")

        def canonical_payload(payload):
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            return encoded, hashlib.sha256(encoded.encode()).hexdigest()

        runtime_module.canonical_payload = canonical_payload
        package_module = types.ModuleType("kairos_persistence")
        package_module.__path__ = []
        return (
            pool,
            calls,
            {
                "kairos_persistence": package_module,
                "kairos_persistence.repository": repository_module,
                "kairos_persistence.runtime": runtime_module,
            },
        )

    def test_audit_only_writer_never_enqueues_outbox(self):
        pool, calls, modules = self._modules()
        with mock.patch.dict(sys.modules, modules):
            writer = worker.EpochWriter(pool)
            asyncio.run(writer.append(_FakeEvent(), publish=False))
        self.assertEqual(pool.connection.audit_count, 1)
        self.assertEqual(pool.connection.outbox, [])
        self.assertEqual([call[0] for call in calls], ["audit"])

    def test_current_publication_writes_audit_and_outbox_in_same_transaction(self):
        pool, calls, modules = self._modules()
        with mock.patch.dict(sys.modules, modules):
            writer = worker.EpochWriter(pool)
            asyncio.run(writer.append(_FakeEvent(), publish=True))
        self.assertEqual(pool.connection.audit_count, 1)
        self.assertEqual(pool.connection.outbox, ["fixture-message-id"])
        self.assertEqual([call[0] for call in calls], ["audit", "outbox"])

    def test_outbox_failure_rolls_back_the_paired_audit_insert(self):
        pool, _calls, modules = self._modules(fail_outbox=True)
        with mock.patch.dict(sys.modules, modules):
            writer = worker.EpochWriter(pool)
            with self.assertRaisesRegex(RuntimeError, "simulated outbox failure"):
                asyncio.run(writer.append(_FakeEvent(), publish=True))
        self.assertEqual(pool.connection.audit_count, 0)
        self.assertEqual(pool.connection.outbox, [])


class _FakeOutboxConnection:
    def __init__(self, rows):
        self.rows = rows
        self.published_updates = []
        self.unlocked = False

    async def fetchval(self, query, *_args):
        if "pg_try_advisory_lock" in query:
            return True
        if "count(*) FROM message_outbox" in query:
            return 0
        raise AssertionError("unexpected fetchval")

    async def fetch(self, query, *args):
        if "FROM message_outbox" not in query:
            raise AssertionError("unexpected query")
        return self.rows[: args[0]]

    async def execute(self, query, *args):
        if "pg_advisory_unlock" in query:
            self.unlocked = True
            return "SELECT 1"
        if "UPDATE message_outbox" in query:
            self.published_updates.append(args[0])
            return "UPDATE 1"
        raise AssertionError("unexpected mutation")


class _FakeRedis:
    def __init__(self):
        self.ledger = {}
        self.stream = {}
        self.sequence = 0
        self.lua_calls = []

    async def eval(
        self, script, numkeys, stream_key, ledger_key, message_id, digest, encoded
    ):
        self.lua_calls.append(
            (script, numkeys, stream_key, ledger_key, message_id, digest, encoded)
        )
        prior = self.ledger.get(message_id)
        if prior is not None:
            if prior[0] != digest:
                raise RuntimeError("EPOCH_IDENTITY_CONFLICT")
            if prior[1] not in self.stream:
                raise RuntimeError("EPOCH_RECEIPT_WITHOUT_STREAM")
            if self.stream[prior[1]] != encoded:
                raise RuntimeError("EPOCH_STREAM_PAYLOAD_CONFLICT")
            # Mirrors the Lua duplicate path; the worker's script is separately
            # asserted below to bind the stream data as well as the digest.
            return prior[1]
        self.sequence += 1
        stream_id = f"{self.sequence}-0"
        self.stream[stream_id] = encoded
        self.ledger[message_id] = (digest, stream_id)
        return stream_id


class PublicationTests(unittest.TestCase):
    @staticmethod
    def _row(payload):
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        return {
            "id": 1,
            "message_id": payload["message_id"],
            "topic": worker.TOPIC,
            "payload": payload,
            "payload_sha256": digest,
            "producer": worker.SOURCE,
            "reconciliation_state": "NONE",
            "dead_lettered_at": None,
        }

    def _run_flush(self, row, redis, connection=None):
        fake_connection = connection or _FakeOutboxConnection([row])
        pool = _FakePool(fake_connection)
        package_module = types.ModuleType("kairos_persistence")
        package_module.__path__ = []
        runtime_module = types.ModuleType("kairos_persistence.runtime")

        def canonical_payload(payload):
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            return encoded, hashlib.sha256(encoded.encode()).hexdigest()

        runtime_module.canonical_payload = canonical_payload
        with mock.patch.dict(
            sys.modules,
            {
                "kairos_persistence": package_module,
                "kairos_persistence.runtime": runtime_module,
            },
        ):
            count = asyncio.run(worker.flush({"owner": OWNER}, pool, redis))
        return count, fake_connection

    def test_lua_binds_identity_conflicts_and_missing_stream_fail_closed(self):
        self.assertIn("p[1]~=ARGV[2]", worker.PUBLICATION_LUA)
        self.assertIn("EPOCH_IDENTITY_CONFLICT", worker.PUBLICATION_LUA)
        self.assertIn("EPOCH_RECEIPT_WITHOUT_STREAM", worker.PUBLICATION_LUA)
        self.assertIn("XRANGE", worker.PUBLICATION_LUA)
        self.assertIn("XADD", worker.PUBLICATION_LUA)
        self.assertIn("HSET", worker.PUBLICATION_LUA)
        self.assertRegex(worker.PUBLICATION_LUA, r"row\[[^]]+\].*ARGV\[3\]")

    def test_same_message_and_payload_returns_same_receipt_without_reappend(self):
        payload = {"message_id": "m1", "symbol": "BTCUSDT"}
        row = self._row(payload)
        redis = _FakeRedis()
        _first, _ = self._run_flush(row, redis)
        second_count, second_connection = self._run_flush(row, redis)
        self.assertEqual(second_count, 1)
        self.assertEqual(len(redis.stream), 1)
        self.assertEqual(len(redis.ledger), 1)
        self.assertEqual(second_connection.published_updates, [1])

    def test_digest_conflict_and_receipt_without_stream_are_not_positive_receipts(self):
        payload = {"message_id": "m1", "symbol": "BTCUSDT"}
        row = self._row(payload)
        redis = _FakeRedis()
        self._run_flush(row, redis)
        conflicting = self._row({**payload, "symbol": "ETHUSDT"})
        conflicting["id"] = 2
        conflicting["message_id"] = "m1"
        # Change the stored content identity while keeping the logical ID.
        changed_payload = {**conflicting["payload"], "message_id": "m1", "extra": True}
        conflicting["payload"] = changed_payload
        conflicting["payload_sha256"] = hashlib.sha256(
            json.dumps(changed_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        conflicting["topic"] = worker.TOPIC
        conflicting["producer"] = worker.SOURCE
        with self.assertRaisesRegex(RuntimeError, "EPOCH_IDENTITY_CONFLICT"):
            self._run_flush(conflicting, redis)
        del redis.stream[redis.ledger["m1"][1]]
        with self.assertRaisesRegex(RuntimeError, "EPOCH_RECEIPT_WITHOUT_STREAM"):
            self._run_flush(row, redis)
        redis.stream[redis.ledger["m1"][1]] = "foreign payload"
        with self.assertRaisesRegex(RuntimeError, "EPOCH_STREAM_PAYLOAD_CONFLICT"):
            self._run_flush(row, redis)


class FailureHandlingTests(unittest.TestCase):
    def _run_confirmation_retry_case(self, case):
        pool = _FakePool(_FakeOutboxConnection([]))
        asyncpg = types.ModuleType("asyncpg")

        async def create_pool(*_args, **_kwargs):
            return pool

        asyncpg.create_pool = create_pool
        aiohttp = types.ModuleType("aiohttp")
        aiohttp.ClientTimeout = lambda **_kwargs: object()

        class Session:
            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        aiohttp.ClientSession = Session
        quant = types.ModuleType("kairos_quant")
        recovery = types.ModuleType("kairos_quant.long_gap_recovery")
        attempts = {symbol: 0 for symbol in worker.SYMBOLS}
        publishes = []
        written = []
        response_queue = []

        class TestRecoveryError(Exception):
            pass

        class Event:
            def __init__(self, symbol, value):
                self.symbol = symbol
                self.value = value
                self.open_time_ms = 0
                self.close_time_ms = worker.MINUTE - 1

            def canonical_bar_bytes(self):
                return self.value.encode()

        class RecoveryStatus:
            def __init__(self, _emit):
                self.phase = "REST_GET_FIRST"
                self.total_appended_bars = 0

            def enter(self, phase, **_kwargs):
                self.phase = phase

        recovery.RecoveryError = TestRecoveryError
        recovery.RecoveryStatus = RecoveryStatus
        recovery.parse_page = lambda raw, **_kwargs: tuple(raw)

        async def fake_recover(anchor, *, fetch, publish, status, **_kwargs):
            symbol = anchor.symbol
            if symbol != worker.SYMBOLS[0]:
                return 0
            attempts[symbol] += 1
            attempt = attempts[symbol]
            stable_anchor = Event(symbol, "persisted-anchor")
            if case == "eventual" and attempt == 1:
                pages = (
                    [stable_anchor, Event(symbol, "unpublished-a")],
                    [stable_anchor, Event(symbol, "unpublished-b")],
                )
                for page in pages:
                    response_queue.append(page)
                    await fetch(symbol, 0, 2 * worker.MINUTE)
                status.phase = "CONFIRMATION_COMPARE"
                raise TestRecoveryError("confirmation differs")
            if case == "eventual" and attempt > 1:
                stable_page = [stable_anchor, Event(symbol, "stable-bar")]
                for page in (stable_page, stable_page):
                    response_queue.append(page)
                    await fetch(symbol, 0, 2 * worker.MINUTE)
                status.phase = "DURABLE_PUBLISH"
                status.total_appended_bars = 1
                await publish(stable_page[1])
                return 1
            if case == "exhausted":
                suffix = f"round-{attempt}"
                pages = (
                    [stable_anchor, Event(symbol, suffix + "-a")],
                    [stable_anchor, Event(symbol, suffix + "-b")],
                )
                for page in pages:
                    response_queue.append(page)
                    await fetch(symbol, 0, 2 * worker.MINUTE)
                status.phase = "CONFIRMATION_COMPARE"
                raise TestRecoveryError("confirmation differs")
            if case == "anchor-mismatch":
                pages = (
                    [Event(symbol, "wrong-anchor"), Event(symbol, "a")],
                    [Event(symbol, "wrong-anchor"), Event(symbol, "b")],
                )
                for page in pages:
                    response_queue.append(page)
                    await fetch(symbol, 0, 2 * worker.MINUTE)
                status.phase = "CONFIRMATION_COMPARE"
                raise TestRecoveryError("anchor mismatch")
            if case == "publish-failure":
                status.phase = "DURABLE_PUBLISH"
                await publish(Event(symbol, "outcome-unknown"))
                raise AssertionError("publish failure was expected")
            if case == "previously-appended":
                status.total_appended_bars = 1
                status.phase = "CONFIRMATION_COMPARE"
                raise TestRecoveryError("later page confirmation failed")
            raise AssertionError(case)

        async def fetch_response(*_args):
            return response_queue.pop(0)

        recovery.recover_symbol = fake_recover

        class FakeWriter:
            def __init__(self, _pool):
                pass

            async def append(self, event, *, publish):
                publishes.append((event, publish))
                if case == "publish-failure":
                    raise worker.EpochError("DURABLE_PUBLISH_UNKNOWN")

        anchor_map = {
            symbol: Event(symbol, "persisted-anchor") for symbol in worker.SYMBOLS
        }
        config = _catchup_config(
            end_exclusive_ms=2 * worker.MINUTE, producer_password="b" * 64
        )
        failure = None
        result = None
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                sys.modules,
                {
                    "asyncpg": asyncpg,
                    "aiohttp": aiohttp,
                    "kairos_quant": quant,
                    "kairos_quant.long_gap_recovery": recovery,
                    **self._writer_modules(),
                },
            ),
            mock.patch.object(worker, "EpochWriter", FakeWriter),
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
            mock.patch.object(
                worker, "anchors", new=mock.AsyncMock(return_value=anchor_map)
            ),
            mock.patch.object(worker, "required_bars", return_value=1),
            mock.patch.object(
                worker,
                "write_status",
                side_effect=lambda *a, **k: written.append((a, k)),
            ),
            mock.patch.object(
                worker,
                "fetch_closed_bar_page",
                new=mock.AsyncMock(side_effect=fetch_response),
            ),
        ):
            try:
                result = asyncio.run(
                    worker.recover(
                        config,
                        publish=True,
                        status_path=Path(directory) / "progress.json",
                    )
                )
            except Exception as exc:  # noqa: BLE001 - test captures the terminal exception.
                failure = exc
        return attempts, publishes, written, result, failure

    def test_unpublished_confirmation_retries_then_appends_once(self):
        attempts, publishes, written, result, failure = (
            self._run_confirmation_retry_case("eventual")
        )
        self.assertIsNone(failure)
        self.assertEqual(attempts[worker.SYMBOLS[0]], 2)
        self.assertEqual(len(publishes), 1)
        self.assertEqual(result["deferred_confirmation_rounds"][worker.SYMBOLS[0]], 1)
        self.assertTrue(
            any(
                args[1]
                .get("symbols", {})
                .get(worker.SYMBOLS[0], {})
                .get("deferred_confirmation_rounds")
                == 1
                for args, _kwargs in written
            )
        )

    def test_unpublished_confirmation_retry_cap_fails_without_publish(self):
        attempts, publishes, written, _result, failure = (
            self._run_confirmation_retry_case("exhausted")
        )
        self.assertIsInstance(failure, Exception)
        self.assertEqual(
            attempts[worker.SYMBOLS[0]],
            1 + worker.MAX_UNPUBLISHED_CONFIRMATION_RETRIES,
        )
        self.assertEqual(publishes, [])
        terminal = [
            args[1]
            for args, kwargs in written
            if kwargs.get("immutable")
            and args[0].name == "failure-" + worker.SYMBOLS[0] + ".json"
        ]
        self.assertEqual(len(terminal), 1)
        self.assertEqual(
            terminal[0]["deferred_confirmation_rounds"],
            worker.MAX_UNPUBLISHED_CONFIRMATION_RETRIES,
        )

    def test_anchor_mismatch_is_never_retried(self):
        attempts, publishes, _written, _result, failure = (
            self._run_confirmation_retry_case("anchor-mismatch")
        )
        self.assertIsInstance(failure, Exception)
        self.assertEqual(attempts[worker.SYMBOLS[0]], 1)
        self.assertEqual(publishes, [])

    def test_durable_publish_failure_is_never_retried(self):
        attempts, publishes, _written, _result, failure = (
            self._run_confirmation_retry_case("publish-failure")
        )
        self.assertIsInstance(failure, worker.EpochError)
        self.assertEqual(attempts[worker.SYMBOLS[0]], 1)
        self.assertEqual(len(publishes), 1)

    def test_confirmation_failure_after_append_is_never_retried(self):
        attempts, publishes, _written, _result, failure = (
            self._run_confirmation_retry_case("previously-appended")
        )
        self.assertIsInstance(failure, Exception)
        self.assertEqual(attempts[worker.SYMBOLS[0]], 1)
        self.assertEqual(publishes, [])

    def test_unknown_driver_error_is_not_leaked_to_status_file(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            output = Path(directory) / "output"
            config.write_text("{}", encoding="utf-8")

            async def fail(_mode, _config, _output):
                raise RuntimeError("postgres password=private-value")

            with mock.patch.object(worker, "dispatch", side_effect=fail):
                code = worker.main(
                    [
                        "--mode",
                        "prepare",
                        "--config",
                        str(config),
                        "--output",
                        str(output),
                    ]
                )
            report = json.loads((output / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 1)
            self.assertEqual(report["state"], "FAILED_CLOSED")
            self.assertEqual(
                report["reason"], "operation failed; private diagnostic withheld"
            )
            self.assertNotIn("private-value", json.dumps(report))
            self.assertEqual(
                report["failure_locations"][0]["error_type"], "RuntimeError"
            )
            self.assertNotIn(str(config), json.dumps(report["failure_locations"]))

    def test_recovery_failure_propagates_and_closes_pool(self):
        pool = _FakePool(_FakeOutboxConnection([]))
        asyncpg = types.ModuleType("asyncpg")

        async def create_pool(*_args, **_kwargs):
            return pool

        asyncpg.create_pool = create_pool
        aiohttp = types.ModuleType("aiohttp")

        class _ClientSession:
            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        aiohttp.ClientSession = _ClientSession
        aiohttp.ClientTimeout = lambda **_kwargs: object()
        quant = types.ModuleType("kairos_quant")
        recovery = types.ModuleType("kairos_quant.long_gap_recovery")
        recovery.RecoveryStatus = lambda emit: types.SimpleNamespace(emit=emit)

        async def fail_recover(*_args, **_kwargs):
            raise worker.EpochError("OFFICIAL_CLOSED_BAR_FETCH_FAILED")

        recovery.recover_symbol = fail_recover
        end = (int(time.time() * 1000) // worker.MINUTE - 1) * worker.MINUTE
        current = _catchup_config(end_exclusive_ms=end, maximum_bars=worker.MAX_BARS)
        status = Path("unused-progress.json")
        anchor_map = {
            symbol: types.SimpleNamespace(close_time_ms=end - worker.MINUTE - 1)
            for symbol in worker.SYMBOLS
        }
        with (
            mock.patch.dict(
                sys.modules,
                {
                    "asyncpg": asyncpg,
                    "aiohttp": aiohttp,
                    "kairos_quant": quant,
                    "kairos_quant.long_gap_recovery": recovery,
                    **self._writer_modules(),
                },
            ),
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
            mock.patch.object(
                worker, "anchors", new=mock.AsyncMock(return_value=anchor_map)
            ),
            mock.patch.object(worker, "required_bars", return_value=5),
            mock.patch.object(worker, "write_status") as status_writer,
            self.assertRaisesRegex(
                worker.EpochError, "OFFICIAL_CLOSED_BAR_FETCH_FAILED"
            ),
        ):
            asyncio.run(worker.recover(current, publish=False, status_path=status))
        self.assertTrue(pool.closed)
        self.assertEqual(status_writer.call_count, len(worker.SYMBOLS))
        self.assertTrue(
            all(
                call.kwargs.get("immutable") is True
                for call in status_writer.call_args_list
            )
        )

    def test_recovery_failure_cancels_and_awaits_siblings_before_teardown(self):
        sibling_started = asyncio.Event()
        recovery_tasks = []
        observed = {}
        end = (int(time.time() * 1000) // worker.MINUTE - 1) * worker.MINUTE

        class TrackingPool(_FakePool):
            async def close(self):
                observed["all_tasks_done_at_close"] = all(
                    task.done() for task in recovery_tasks
                )
                observed["session_closed_at_pool_close"] = session.closed
                await super().close()

        pool = TrackingPool(_FakeOutboxConnection([]))
        asyncpg = types.ModuleType("asyncpg")

        async def create_pool(*_args, **_kwargs):
            return pool

        asyncpg.create_pool = create_pool

        class Session:
            closed = False

            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                self.closed = True
                return False

        session = Session()
        aiohttp = types.ModuleType("aiohttp")
        aiohttp.ClientSession = lambda **_kwargs: session
        aiohttp.ClientTimeout = lambda **_kwargs: object()
        quant = types.ModuleType("kairos_quant")
        recovery = types.ModuleType("kairos_quant.long_gap_recovery")

        class RecoveryStatus:
            def __init__(self, _emit):
                self.phase = "REST_GET_FIRST"
                self.total_appended_bars = 0

        recovery.RecoveryStatus = RecoveryStatus

        async def fake_recover(anchor, *, status, **_kwargs):
            recovery_tasks.append(asyncio.current_task())
            if anchor.symbol == worker.SYMBOLS[0]:
                await sibling_started.wait()
                status.phase = "CONFIRMATION_COMPARE"
                raise worker.EpochError("PRIMARY_CONFIRMATION_FAILURE")
            status.phase = "DURABLE_PUBLISH"
            sibling_started.set()
            await asyncio.Future()

        recovery.recover_symbol = fake_recover
        anchors = {
            symbol: types.SimpleNamespace(
                symbol=symbol, close_time_ms=end - worker.MINUTE - 1
            )
            for symbol in worker.SYMBOLS
        }
        config = _catchup_config(end_exclusive_ms=end, producer_password="b" * 64)
        with (
            mock.patch.dict(
                sys.modules,
                {
                    "asyncpg": asyncpg,
                    "aiohttp": aiohttp,
                    "kairos_quant": quant,
                    "kairos_quant.long_gap_recovery": recovery,
                    **self._writer_modules(),
                },
            ),
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
            mock.patch.object(
                worker, "anchors", new=mock.AsyncMock(return_value=anchors)
            ),
            mock.patch.object(
                worker, "required_bars", return_value=len(worker.SYMBOLS)
            ),
            mock.patch.object(worker, "write_status") as status_writer,
            self.assertRaisesRegex(worker.EpochError, "PRIMARY_CONFIRMATION_FAILURE"),
        ):
            asyncio.run(
                worker.recover(
                    config,
                    publish=True,
                    status_path=Path("unused-progress.json"),
                )
            )

        self.assertTrue(pool.closed)
        self.assertTrue(observed["all_tasks_done_at_close"])
        self.assertTrue(observed["session_closed_at_pool_close"])
        failure_calls = [
            call
            for call in status_writer.call_args_list
            if call.kwargs.get("immutable")
        ]
        self.assertEqual(len(failure_calls), len(worker.SYMBOLS))
        primary = [
            call.args[1]
            for call in failure_calls
            if call.args[1]["symbol"] == worker.SYMBOLS[0]
        ]
        self.assertEqual(len(primary), 1)
        self.assertEqual(primary[0]["error_type"], "EpochError")
        self.assertEqual(primary[0]["phase"], "CONFIRMATION_COMPARE")
        cancelled = [
            call.args[1]
            for call in failure_calls
            if call.args[1]["error_type"] == "CancelledError"
        ]
        self.assertEqual(len(cancelled), len(worker.SYMBOLS) - 1)
        self.assertTrue(all(item["phase"] == "DURABLE_PUBLISH" for item in cancelled))
        self.assertTrue(all(item["publish_outcome_unknown"] for item in cancelled))
        self.assertTrue(all(item["trading_started"] is False for item in cancelled))

    def _run_chunked_recovery(self, chunks, *, content_length=None):
        pool = _FakePool(_FakeOutboxConnection([]))
        fetched = []
        chunk_sizes = []
        self._observed_chunk_sizes = chunk_sizes
        asyncpg = types.ModuleType("asyncpg")

        async def create_pool(*_args, **_kwargs):
            return pool

        asyncpg.create_pool = create_pool

        class Content:
            def __init__(self, values):
                self.values = values

            async def iter_chunked(self, size):
                chunk_sizes.append(size)
                for value in self.values:
                    yield value

        class Response:
            status = 200

            def __init__(self, values):
                self.content = Content(values)
                self.content_length = content_length

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

        class Session:
            def __init__(self, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def get(self, url, *, params, allow_redirects):
                self.last_request = (url, params, allow_redirects)
                return Response(chunks)

        aiohttp = types.ModuleType("aiohttp")
        aiohttp.ClientSession = Session
        aiohttp.ClientTimeout = lambda **_kwargs: object()
        quant = types.ModuleType("kairos_quant")
        recovery = types.ModuleType("kairos_quant.long_gap_recovery")
        recovery.RecoveryStatus = lambda emit: types.SimpleNamespace(emit=emit)

        async def fake_recover(anchor, *, end_exclusive, fetch, **_kwargs):
            result = await fetch("BTCUSDT", 0, worker.MINUTE)
            fetched.append(result)
            return 1

        recovery.recover_symbol = fake_recover
        end = (int(time.time() * 1000) // worker.MINUTE - 1) * worker.MINUTE
        config = _catchup_config(end_exclusive_ms=end)
        anchors = {
            symbol: types.SimpleNamespace(close_time_ms=end - worker.MINUTE - 1)
            for symbol in worker.SYMBOLS
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(
                sys.modules,
                {
                    "asyncpg": asyncpg,
                    "aiohttp": aiohttp,
                    "kairos_quant": quant,
                    "kairos_quant.long_gap_recovery": recovery,
                    **self._writer_modules(),
                },
            ),
            mock.patch.object(worker, "verify_schema", new=mock.AsyncMock()),
            mock.patch.object(
                worker, "anchors", new=mock.AsyncMock(return_value=anchors)
            ),
            mock.patch.object(
                worker, "required_bars", return_value=len(worker.SYMBOLS)
            ),
        ):
            result = asyncio.run(
                worker.recover(
                    config, publish=False, status_path=Path(directory) / "progress.json"
                )
            )
        self.assertEqual(result["state"], "AUDIT_ONLY_CATCHUP_COMPLETE")
        self.assertTrue(pool.closed)
        return fetched, chunk_sizes

    def test_recovery_reads_chunked_http_body_and_parses_complete_json(self):
        body = b'{"ok":true,"bars":[1,2]}'
        fetched, chunk_sizes = self._run_chunked_recovery(
            [body[:7], body[7:15], body[15:]], content_length=len(body)
        )
        self.assertEqual(fetched, [{"ok": True, "bars": [1, 2]}] * len(worker.SYMBOLS))
        self.assertEqual(chunk_sizes, [65536] * len(worker.SYMBOLS))

    def test_recovery_rejects_chunked_http_body_over_two_megabytes(self):
        chunks = [b"x" * 65536 for _ in range(40)]
        with self.assertRaisesRegex(worker.EpochError, "REST_RESPONSE_BOUND_EXCEEDED"):
            self._run_chunked_recovery(chunks)
        self.assertTrue(self._observed_chunk_sizes)
        self.assertTrue(all(size == 65536 for size in self._observed_chunk_sizes))

    @staticmethod
    def _writer_modules():
        package = types.ModuleType("kairos_persistence")
        package.__path__ = []
        repo_module = types.ModuleType("kairos_persistence.repository")
        repo_module.AuditRepository = type(
            "AuditRepository", (), {"__init__": lambda self, _pool: None}
        )
        runtime_module = types.ModuleType("kairos_persistence.runtime")
        runtime_module.canonical_payload = lambda value: (json.dumps(value), "0" * 64)
        return {
            "kairos_persistence": package,
            "kairos_persistence.repository": repo_module,
            "kairos_persistence.runtime": runtime_module,
        }


class RuntimeCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_cleanup_closes_all_resources_and_keeps_primary_failure(self):
        stop = asyncio.Event()
        task = asyncio.create_task(asyncio.sleep(60))
        producer = mock.Mock(
            aclose=mock.AsyncMock(side_effect=TimeoutError("private-driver-data"))
        )
        consumer = mock.Mock(aclose=mock.AsyncMock())
        supervisor = mock.Mock(aclose=mock.AsyncMock())
        pool = mock.Mock(aclose=mock.AsyncMock())
        with tempfile.TemporaryDirectory() as directory:
            await worker.close_runtime_resources(
                stop=stop,
                task=task,
                producer=producer,
                consumer_probe=consumer,
                supervisor=supervisor,
                pool=pool,
                output=Path(directory),
                primary_error=RuntimeError("original-private-driver-data"),
            )
            text = (Path(directory) / "cleanup-failure.json").read_text()
            report = json.loads(text)
            self.assertTrue(report["primary_failure_preserved"])
            self.assertNotIn("private-driver-data", text)
            for resource in (producer, consumer, supervisor, pool):
                resource.aclose.assert_awaited_once()
        self.assertTrue(stop.is_set())
        self.assertTrue(task.cancelled())

    async def test_cleanup_only_failure_is_not_silently_accepted(self):
        producer = mock.Mock(aclose=mock.AsyncMock(side_effect=TimeoutError()))
        pool = mock.Mock(aclose=mock.AsyncMock())
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaises(TimeoutError),
        ):
            await worker.close_runtime_resources(
                stop=asyncio.Event(),
                task=None,
                producer=producer,
                consumer_probe=None,
                supervisor=None,
                pool=pool,
                output=Path(directory),
                primary_error=None,
            )
        pool.aclose.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
