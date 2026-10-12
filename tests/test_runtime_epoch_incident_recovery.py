"""Offline incident admission, immutable evidence and restore-before-dispatch order."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from scripts import runtime_epoch_incident_recovery as recovery
from tests.test_runtime_epoch_boot import state

boot = recovery.boot
epoch = recovery.epoch


def observation() -> dict:
    return {
        "result": "PASS_READONLY_INCIDENT_OBSERVATION",
        "owner": boot.OWNER,
        "trading_started": False,
        "comparisons": {
            symbol: {"pages_equal": True, "persisted_anchor_matches": True}
            for symbol in recovery.observation.SYMBOLS
        },
        "database_counts": {
            "audit_rows": 334355,
            "outbox_rows": 4546,
            "pending_outbox": 1,
            "inbox_rows": 4545,
            "unresolved_inbox": 0,
            "trading_rows": 0,
        },
        "preserved_failures": {"status": "frozen"},
    }


class IncidentRecoveryTests(unittest.TestCase):
    def test_every_worker_mode_is_launchable_with_fixed_paths(self):
        from scripts.runtime_epoch_worker import MODES

        for mode in MODES:
            with self.subTest(mode=mode):
                argv = epoch.build_worker_argv(
                    mode, epoch.CONFIG_PATH_IN_CONTAINER, epoch.OUTPUT_PATH_IN_CONTAINER
                )
                self.assertEqual(argv[4], mode)

    def test_plan_does_not_read_private_files_or_contact_services(self):
        with (
            mock.patch.object(recovery, "load_observation") as read,
            mock.patch.object(
                recovery.IncidentController, "run_incident_recovery"
            ) as run,
            mock.patch.object(boot, "verify_source") as verify,
        ):
            self.assertEqual(recovery.main([]), 0)
        read.assert_not_called()
        run.assert_not_called()
        verify.assert_not_called()

    def test_exact_observation_and_both_confirmations_are_required(self):
        for field in (None, "digest", "owner", "pending", "persisted", "second_page"):
            value = observation()
            if field == "owner":
                value["owner"] = "f" * 32
            elif field == "pending":
                value["database_counts"]["pending_outbox"] = 2
            elif field in {"persisted", "second_page"}:
                value["comparisons"]["SOLUSDT"][
                    "persisted_anchor_matches"
                    if field == "persisted"
                    else "pages_equal"
                ] = False
            with (
                self.subTest(field=field),
                mock.patch.object(
                    recovery.fresh,
                    "sha",
                    return_value=(
                        "0" * 64 if field == "digest" else recovery.OBSERVATION_SHA256
                    ),
                ),
                mock.patch.object(boot, "read_json", return_value=value),
            ):
                if field is None:
                    self.assertEqual(recovery.load_observation(), value)
                else:
                    with self.assertRaises(epoch.Rejected):
                        recovery.load_observation()

    def _flow(self, root: Path):
        controller = recovery.IncidentController.__new__(recovery.IncidentController)
        controller.names = epoch.resource_names(boot.OWNER)
        controller.expected_revision = "a" * 40
        controller.proofs = {}
        controller.work = root
        calls = []
        resources = {
            "legacy": {"state": "stopped"},
            "standby": {"left_untouched": True},
            "views": {
                key: {
                    "id": value,
                    "state": {"Status": "exited" if key == "serve" else "running"},
                }
                for key, value in boot.CONTAINERS.items()
            },
        }
        controller.validate_resources = mock.Mock(return_value=resources)
        controller.inspect_container = mock.Mock(
            side_effect=lambda identifier: next(
                view for view in resources["views"].values() if view["id"] == identifier
            )
        )
        controller.assert_legacy_sources_stopped = mock.Mock(
            return_value=resources["legacy"]
        )
        serving = {"owner": boot.OWNER}
        controller.load_private_inputs = mock.Mock(return_value=serving)
        controller._admin_password, controller._history_password = "a" * 64, "b" * 64
        controller.prepare_reviewed_snapshots = mock.Mock(
            side_effect=lambda: calls.append("snapshots")
        )
        controller.prepare_boot_restore_volume = mock.Mock(
            side_effect=lambda tag: calls.append("volume-" + tag)
        )
        controller.backup_and_verify = mock.Mock(
            side_effect=lambda **kwargs: (
                calls.append("restore-" + kwargs["verification_mode"]) or "d" * 64
            )
        )
        before = {"state": "PASS_INCIDENT_STATE", "anchors": {"synthetic": True}}

        def phase(mode, config, **_kwargs):
            calls.append(mode)
            return (
                copy.deepcopy(before)
                if mode == "incident-state"
                else {"state": "synthetic"}
            )

        controller.phase = mock.Mock(side_effect=phase)
        clean = state()
        controller.boot_state = mock.Mock(return_value=clean)
        controller.audit_only_tail = mock.Mock(
            side_effect=lambda baseline, suffix: (
                calls.append("audit-only-" + suffix)
                or (clean, {"state": "AUDIT_ONLY_CATCHUP_COMPLETE"})
            )
        )
        controller.start_new_generation = mock.Mock(
            side_effect=lambda config: (
                calls.append("new-generation") or {"name": recovery.GENERATION_NAME}
            )
        )
        lease = root / "lease"
        lease.write_text(boot.OWNER)
        patches = (
            mock.patch.object(recovery, "load_observation", return_value=observation()),
            mock.patch.object(epoch, "ACTIVE_LEASE", lease),
            mock.patch.object(
                recovery.fresh, "sha", return_value=boot.PARENT_RECEIPT_SHA256
            ),
            mock.patch.object(
                recovery, "preserved_inputs", return_value={"synthetic": "sha"}
            ),
            mock.patch.object(
                recovery.observation,
                "failure_snapshot",
                return_value=observation()["preserved_failures"],
            ),
        )
        return controller, calls, patches

    def test_full_path_has_clone_before_single_dispatch_and_second_clone_before_serve(
        self,
    ):
        with TemporaryDirectory() as directory:
            controller, calls, patches = self._flow(Path(directory))
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                result = controller.run_incident_recovery()
        self.assertEqual(result["result"], "PASS_NEW_NONTRADING_GENERATION")
        self.assertFalse(result["trading_started"])
        self.assertEqual(calls.count("incident-drain"), 1)
        self.assertEqual(calls.count("new-generation"), 1)
        self.assertLess(
            calls.index("restore-incident-verify-restore"),
            calls.index("incident-drain"),
        )
        self.assertLess(
            calls.index("restore-boot-verify-restore"), calls.index("new-generation")
        )
        self.assertLess(calls.index("boot-redis-state"), calls.index("new-generation"))
        before_args = controller.backup_and_verify.call_args_list[0].kwargs
        self.assertEqual(before_args["seed"]["state"], "PASS_INCIDENT_STATE")
        self.assertEqual(before_args["tag"], "bootbefore")
        self.assertEqual(
            controller.backup_and_verify.call_args_list[1].kwargs["tag"], "bootafter"
        )

    def test_no_unreviewed_or_arbitrary_failure_can_authorize_continuation(self):
        with (
            mock.patch.object(boot, "read_json") as read,
            mock.patch.object(recovery.fresh, "sha") as sha,
            self.assertRaisesRegex(epoch.Rejected, "EXACT_REVIEWED_PREBACKUP"),
        ):
            recovery.validate_reviewed_prebackup_failure("f" * 64)
        read.assert_not_called()
        sha.assert_not_called()

    def test_any_prior_dispatch_attempt_blocks_the_reviewed_prebackup_path(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            prior = root / "recovery-original"
            prior.mkdir()
            unknown = root / "recovery-unknown"
            unknown.mkdir()
            (unknown / "output-incident-drain").mkdir()

            def read(path):
                if path.name == "failure.json":
                    return {
                        "automatic_retry": False,
                        "phase": "incident-state-before",
                        "reason": "PRIVATE_CREATE_ONLY_EPOCH_DUMP_REQUIRED",
                        "result": "FAILED_CLOSED",
                        "trading_started": False,
                    }
                return {
                    "owner": boot.OWNER,
                    "run": "d97a2bf75ace41ed8ba498de2b1919f8",
                    "source_revision": "72c781c1aa15e97ac990bfede4c2ddf74ae85418",
                }

            def sha(path):
                return (
                    recovery.PREBACKUP_FAILURE_SHA256
                    if path.name == "failure.json"
                    else recovery.PREBACKUP_STATE_SHA256
                )

            with (
                mock.patch.object(recovery, "ROOT", root),
                mock.patch.object(recovery, "PREBACKUP_WORK", prior),
                mock.patch.object(boot, "read_json", side_effect=read),
                mock.patch.object(recovery.fresh, "sha", side_effect=sha),
                self.assertRaisesRegex(epoch.Rejected, "PRIOR_PUBLICATION_INTENT"),
            ):
                recovery.validate_reviewed_prebackup_failure(
                    recovery.PREBACKUP_FAILURE_SHA256
                )

    def test_clone_failure_or_prestate_change_never_dispatches(self):
        for failure in ("clone", "changed"):
            with TemporaryDirectory() as directory:
                controller, calls, patches = self._flow(Path(directory))
                if failure == "clone":
                    controller.backup_and_verify.side_effect = epoch.Rejected(
                        "CLONE_CONFLICT"
                    )
                else:
                    controller.phase.side_effect = [
                        {"state": "PASS_INCIDENT_STATE"},
                        {"state": "CHANGED"},
                    ]
                with (
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3],
                    patches[4],
                    self.assertRaises(epoch.Rejected),
                ):
                    controller.run_incident_recovery()
                self.assertNotIn("incident-drain", calls)
                controller.start_new_generation.assert_not_called()

    def test_changed_original_failure_blocks_before_credentials(self):
        with TemporaryDirectory() as directory:
            controller, _calls, patches = self._flow(Path(directory))
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                mock.patch.object(
                    recovery.observation,
                    "failure_snapshot",
                    return_value={"changed": True},
                ),
                self.assertRaisesRegex(epoch.Rejected, "FAILURE_CHANGED"),
            ):
                controller.run_incident_recovery()
        controller.load_private_inputs.assert_not_called()
        controller.phase.assert_not_called()

    def test_legacy_metadata_change_stops_receipt_acceptance(self):
        with TemporaryDirectory() as directory:
            controller, _calls, patches = self._flow(Path(directory))
            controller.assert_legacy_sources_stopped.return_value = {"state": "changed"}
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                self.assertRaisesRegex(epoch.Rejected, "LEGACY_CHANGED"),
            ):
                controller.run_incident_recovery()

    def test_history_only_tail_preserves_queues_and_fixed_cap(self):
        controller = recovery.IncidentController.__new__(recovery.IncidentController)
        controller.names = epoch.resource_names(boot.OWNER)
        controller._history_password = "b" * 64
        current = state()
        end = 1_791_780_000_000
        current["anchors"] = {
            symbol: {"last_close_time_ms": end - 60_001} for symbol in epoch.SYMBOLS
        }
        controller.boot_state = mock.Mock(return_value=current)
        controller.phase = mock.Mock(
            return_value={"state": "AUDIT_ONLY_CATCHUP_COMPLETE"}
        )
        with mock.patch.object(
            recovery.time, "time", return_value=(end + 65_000) / 1000
        ):
            controller.audit_only_tail(current, "fixture")
        mode, config = controller.phase.call_args.args
        self.assertEqual(mode, "boot-catchup")
        self.assertEqual(config["maximum_bars"], epoch.MAX_CATCHUP_BARS)
        self.assertNotIn("producer_password", config)
        self.assertNotIn("consumer_password", config)
        controller.phase.reset_mock()
        for anchor in current["anchors"].values():
            anchor["last_close_time_ms"] -= epoch.MAX_CATCHUP_BARS * epoch.MINUTE_MS
        with (
            mock.patch.object(
                recovery.time, "time", return_value=(end + 65_000) / 1000
            ),
            self.assertRaisesRegex(epoch.Rejected, "CAP_EXCEEDED"),
        ):
            controller.audit_only_tail(current, "fixture")
        controller.phase.assert_not_called()


if __name__ == "__main__":
    unittest.main()
