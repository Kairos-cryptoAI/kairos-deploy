"""Fixed incident targeting and no-retry publication boundary, offline only."""

from __future__ import annotations

import asyncio
import copy
import types
import unittest
from unittest import mock

from scripts import runtime_epoch_incident_worker as incident


def config(**changes):
    value = {
        "owner": incident.OWNER,
        "database": "kairos_epoch_" + incident.OWNER[:12],
        "pg_host": "kairos-epoch-" + incident.OWNER[:12] + "-pg",
        "redis_host": "kairos-epoch-" + incident.OWNER[:12] + "-redis",
        **{
            field: "a" * 64
            for field in (
                "admin_password",
                "producer_password",
                "consumer_password",
                "redis_producer_password",
                "redis_consumer_password",
            )
        },
    }
    value.update(changes)
    return value


class IncidentConfigTests(unittest.TestCase):
    def test_exact_observation_and_expected_drain_are_accepted(self):
        incident.validate_incident_config("incident-state", config())
        incident.validate_incident_config("incident-drain", config(expected_state={}))

    def test_legacy_foreign_targets_and_extra_fields_are_rejected_before_connect(self):
        for change in (
            {"database": "kairos"},
            {"pg_host": "kairos-paper-gate-timescaledb-1"},
            {"redis_host": "kairos-paper-gate-redis-1"},
            {"owner": "f" * 32},
            {"producer_password": "wrong"},
            {"trading_started": True},
        ):
            with (
                self.subTest(change=change),
                mock.patch.object(incident.epoch, "connect") as connect,
                self.assertRaises(incident.epoch.EpochError),
            ):
                asyncio.run(
                    incident.dispatch_incident("incident-state", config(**change), None)
                )
            connect.assert_not_called()

    def test_drain_without_full_expected_state_is_rejected(self):
        for value in (config(), config(expected_state=True)):
            with (
                self.subTest(value=value),
                self.assertRaises(incident.epoch.EpochError),
            ):
                incident.validate_incident_config("incident-drain", value)

    def test_only_observation_and_exact_one_row_drain_modes_exist(self):
        for mode in ("serve", "replay", "reset", "LIVE", "retry"):
            with self.subTest(mode=mode), self.assertRaises(incident.epoch.EpochError):
                incident.validate_incident_config(mode, config())

    def test_digest_is_order_independent_and_binds_all_fields(self):
        self.assertEqual(
            incident.digest({"a": 1, "b": 2}), incident.digest({"b": 2, "a": 1})
        )
        self.assertNotEqual(incident.digest({"a": 1}), incident.digest({"a": True}))

    def test_queue_refuses_wrong_counts_before_parsing_payload(self):
        core = types.ModuleType("kairos_core.contracts")
        core.ClosedBarEventV1 = mock.Mock()
        persistence = types.ModuleType("kairos_persistence.runtime")
        persistence.canonical_payload = mock.Mock()
        with (
            mock.patch.dict(
                "sys.modules",
                {
                    "kairos_core.contracts": core,
                    "kairos_persistence.runtime": persistence,
                },
            ),
            self.assertRaisesRegex(incident.epoch.EpochError, "EXACT_QUEUE_COUNTS"),
        ):
            incident.validate_incident_queue([], [], allow_pending=True)
        core.ClosedBarEventV1.model_validate.assert_not_called()

    def _queue_fixture(self, row_changes=None, *, completed=False):
        payload = {"message_id": incident.MESSAGE_ID}
        row = {
            "id": incident.OUTBOX_ID,
            "message_id": incident.MESSAGE_ID,
            "topic": incident.epoch.TOPIC,
            "producer": incident.epoch.SOURCE,
            "payload": payload,
            "payload_sha256": incident.PAYLOAD_SHA256,
            "published_at": "now" if completed else None,
            "publish_attempts": 1 if completed else 0,
            "last_error": None,
            "lease_owner": None,
            "lease_until": None,
            "dead_lettered_at": None,
            "reconciliation_state": "NONE",
        }
        row.update(row_changes or {})
        event = types.SimpleNamespace(
            message_id=incident.MESSAGE_ID,
            source=incident.epoch.SOURCE,
            symbol="BTCUSDT",
            open_time_ms=incident.OPEN_TIME_MS,
        )
        core = types.ModuleType("kairos_core.contracts")
        core.ClosedBarEventV1 = mock.Mock()
        core.ClosedBarEventV1.model_validate.return_value = event
        persistence = types.ModuleType("kairos_persistence.runtime")
        persistence.canonical_payload = mock.Mock(
            return_value=("{}", incident.PAYLOAD_SHA256)
        )
        inbox = (
            [
                {
                    "consumer": "kairos-epoch-consumer-"
                    + incident.OWNER[:12]
                    + ":bars",
                    "message_id": incident.MESSAGE_ID,
                    "topic": incident.epoch.TOPIC,
                    "payload_sha256": incident.PAYLOAD_SHA256,
                    "status": "COMPLETED",
                }
            ]
            if completed
            else []
        )
        with (
            mock.patch.dict(
                "sys.modules",
                {
                    "kairos_core.contracts": core,
                    "kairos_persistence.runtime": persistence,
                },
            ),
            mock.patch.dict(incident.EXPECTED_COUNTS, {"outbox": 1, "inbox": 0}),
        ):
            return incident.validate_incident_queue(
                [row], inbox, allow_pending=not completed
            )

    def test_exact_pending_and_completed_one_row_identities(self):
        queue, published = self._queue_fixture()
        self.assertEqual(queue["pending"][0]["message_id"], incident.MESSAGE_ID)
        self.assertEqual(published, {})
        queue, published = self._queue_fixture(completed=True)
        self.assertEqual(queue["pending"], [])
        self.assertEqual(set(published), {incident.MESSAGE_ID})

    def test_pending_rebinding_unknown_lease_or_hash_never_passes(self):
        for change in (
            {"id": 999},
            {"message_id": "b" * 64},
            {"payload_sha256": "c" * 64},
            {"producer": "other"},
            {"topic": "orders"},
            {"lease_owner": "old"},
            {"lease_until": "old"},
            {"dead_lettered_at": "old"},
            {"reconciliation_state": "UNKNOWN"},
            {"last_error": "old"},
            {"publish_attempts": 1},
        ):
            with (
                self.subTest(change=change),
                self.assertRaises(incident.epoch.EpochError),
            ):
                self._queue_fixture(change)

    def test_wrong_pending_id_or_hash_cannot_become_bulk_replay(self):
        self.assertEqual(incident.OUTBOX_ID, 4559)
        self.assertEqual(incident.OPEN_TIME_MS, 1_791_766_920_000)
        self.assertEqual(len(incident.MESSAGE_ID), 64)
        self.assertEqual(len(incident.PAYLOAD_SHA256), 64)
        self.assertEqual(
            incident.EXPECTED_COUNTS["outbox"] - incident.EXPECTED_COUNTS["inbox"], 1
        )

    def test_published_row_requires_durable_sql_ack(self):
        for attempts in (0, -1, True):
            with (
                self.subTest(attempts=attempts),
                self.assertRaises(incident.epoch.EpochError),
            ):
                self._queue_fixture({"publish_attempts": attempts}, completed=True)

    def test_exact_redis_delta_preserves_old_ids_payloads_and_receipts(self):
        before = {
            "pending_btc_receipt_absent": True,
            "btc_receipt": None,
            "published_receipts": 4545,
            "stream_entries": 4546,
            "stream_sha256": "a" * 64,
            "publication_receipts_sha256": "b" * 64,
        }
        after = {
            "pending_btc_receipt_absent": False,
            "btc_receipt": "1791769980000-0",
            "published_receipts": 4546,
            "stream_entries": 4547,
            "pending_deliveries": 0,
            "preserved_stream_sha256": "a" * 64,
            "preserved_publication_receipts_sha256": "b" * 64,
        }
        incident.validate_redis_drain_preservation(before, after, after["btc_receipt"])
        for field, value in (
            ("preserved_stream_sha256", "c" * 64),
            ("preserved_publication_receipts_sha256", "c" * 64),
            ("stream_entries", 4546),
            ("stream_entries", 4548),
            ("published_receipts", 4545),
            ("pending_deliveries", 1),
            ("btc_receipt", "1791769980000-1"),
        ):
            changed = {**after, field: value}
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(incident.epoch.EpochError),
            ):
                incident.validate_redis_drain_preservation(
                    before, changed, after["btc_receipt"]
                )

    def test_pending_clone_full_snapshot_and_expected_state_must_all_match(self):
        snapshot = {"state": "PASS_INCIDENT_STATE", "tables": {"x": "sha"}}
        for damage in (None, "clone", "expected"):
            with self.subTest(damage=damage):
                expected = copy.deepcopy(snapshot)
                clone = copy.deepcopy(snapshot)
                if damage == "clone":
                    clone["tables"]["x"] = "different"
                if damage == "expected":
                    expected["tables"]["x"] = "different"
                restored = mock.Mock()
                restored.close = mock.AsyncMock()
                asyncpg = types.ModuleType("asyncpg")
                asyncpg.connect = mock.AsyncMock(return_value=restored)

                async def snapshots(_config, clone=clone, **kwargs):
                    return (clone if kwargs.get("connection") else snapshot), {}

                value = config()
                for key in (
                    "producer_password",
                    "consumer_password",
                    "redis_producer_password",
                    "redis_consumer_password",
                ):
                    value.pop(key)
                value.update(
                    restore_host="kairos-epoch-" + incident.OWNER[:12] + "-restore",
                    restore_database="kairos_recovery_"
                    + incident.OWNER[:12]
                    + "_epochrestore",
                    restore_admin_password="f" * 64,
                    expected_seed={**expected, "redis": {"witness": True}},
                )
                with (
                    mock.patch.dict("sys.modules", {"asyncpg": asyncpg}),
                    mock.patch.object(incident, "incident_snapshot", new=snapshots),
                ):
                    if damage:
                        with self.assertRaisesRegex(
                            incident.epoch.EpochError, "FULL_STATE_CONFLICT"
                        ):
                            asyncio.run(
                                incident.dispatch_incident(
                                    "incident-verify-restore", value, None
                                )
                            )
                    else:
                        result = asyncio.run(
                            incident.dispatch_incident(
                                "incident-verify-restore", value, None
                            )
                        )
                        self.assertEqual(
                            result["state"], "PASS_INCIDENT_ISOLATED_RESTORE"
                        )
                restored.close.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
