"""Offline identity and dispatch contracts for the accepted R7 boot generation."""

from __future__ import annotations

import contextlib
import io
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from scripts import runtime_epoch_boot as boot


def accepted_status():
    return {
        "state": "RUNNING_NONTRADING",
        "owner": boot.OWNER,
        "watermarks_ms": {symbol: 1_791_894_180_000 for symbol in boot.epoch.SYMBOLS},
        "PAPER_QUALIFIED": False,
        "ALPHA_READY": False,
        "LIVE_READY": False,
        "STRATEGY_POLICY": "REJECT_ALL",
        "pending_outbox": 0,
        "unresolved_inbox": 0,
        "uncompleted_publications": 0,
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "trading_started": False,
        "source_fresh": True,
    }


def accepted_r7dns_receipt():
    status = accepted_status()
    proofs = {
        "serve_container": boot.R7DNS_SERVE_NAME,
        "serve_start_intent": True,
        "failed_status_sha256": boot.R7DNS_FAILED_STATUS_SHA256,
        "operator_snapshot_sha256": boot.R7DNS_OPERATOR_SNAPSHOT_SHA256,
        "quant_snapshot_sha256": boot.R7DNS_QUANT_SNAPSHOT_SHA256,
        "resources_before": {
            "views": {
                "pg": {
                    "id": boot.epoch.CONTINUATION_04_TARGET_PG_ID,
                    "name": "/kairos-epoch-69893dc7b7c6-pg",
                },
                "redis": {
                    "id": boot.epoch.CONTINUATION_04_REDIS_ID,
                    "name": "/kairos-epoch-69893dc7b7c6-redis",
                },
                "serve": {
                    "id": boot.R7DNS_FAILED_SERVE_ID,
                    "name": "/" + boot.R7DNS_FAILED_SERVE_NAME,
                    "state": {"Status": "exited"},
                },
            },
        },
        "retained_cold_pg": {
            "state": "PASS_COLD_BYTE_COPY",
            "source_volume": "kairos-epoch-69893dc7b7c6-pg-data",
            "retained_volume": "kairos-epoch-69893dc7b7c6-r7-cold-pg-ae798c2c",
            "source_readonly": True,
            "source_unchanged": True,
            "restore_proven": False,
            "trading_started": False,
        },
        "retained_cold_redis": {
            "state": "PASS_COLD_BYTE_COPY",
            "source_volume": "kairos-epoch-69893dc7b7c6-redis-data",
            "retained_volume": "kairos-epoch-69893dc7b7c6-r7-cold-redis-ae798c2c",
            "source_readonly": True,
            "source_unchanged": True,
            "restore_proven": False,
            "trading_started": False,
        },
    }
    return {
        "state": "PASS_REVIEWED_NONTRADING_DNS_CONTINUATION",
        "source_revision": boot.R7DNS_SOURCE_REVISION,
        "failed_status_sha256": boot.R7DNS_FAILED_STATUS_SHA256,
        "legacy_unchanged": True,
        "trading_started": False,
        "serving_restart": False,
        "continuation": {
            "container": boot.R7DNS_SERVE_NAME,
            "container_id": boot.R7DNS_SERVE_ID,
            "graceful_restart_proven": True,
            "state": "PASS_REVIEWED_NONTRADING_DNS_CONTINUATION",
            "status": status,
            "trading_started": False,
        },
        "proofs": proofs,
    }


class R7BootTests(unittest.TestCase):
    def test_generation_binds_only_accepted_r7_receipt_and_container(self):
        names = (
            "ROOT",
            "SERVE_WORK",
            "SCOPE",
            "GENERATION",
            "RECEIPT_NAME",
            "PARENT_RECEIPT_SHA256",
            "CONTAINERS",
            "LEASE",
        )
        with contextlib.ExitStack() as stack:
            for name in names:
                stack.enter_context(patch.object(boot, name, getattr(boot, name)))
            before = boot.CONTAINERS.copy()
            boot.configure_generation_r7()
            self.assertEqual(boot.GENERATION, "r7")
            self.assertEqual(
                boot.ROOT.as_posix(), "D:/Kairos/runtime/epoch-boot-r7-20261013"
            )
            self.assertEqual(
                boot.SERVE_WORK.as_posix(),
                "D:/Kairos/runtime/runtime-incident-20261013/read-recovery-r7-cb1bc3984d8440aa965af5b928d2b4fa",
            )
            self.assertEqual(boot.SCOPE, "kairos-nontrading-runtime-epoch-boot-r7-v1")
            self.assertEqual(boot.RECEIPT_NAME, "receipt.json")
            self.assertEqual(
                boot.PARENT_RECEIPT_SHA256,
                "03b10208edd5d5d7957ceaf2d38a6d73b7acbef03bfd4f2a87e1fa8ef88cacb0",
            )
            self.assertEqual(boot.CONTAINERS["pg"], before["pg"])
            self.assertEqual(boot.CONTAINERS["redis"], before["redis"])
            self.assertEqual(
                boot.CONTAINERS["serve"],
                "c08f5b667a84febb2dc1639857b44a52208ea29f9836e14c11685d89ccd55ae0",
            )
            self.assertEqual(boot.LEASE, boot.ROOT / "boot.active")

    def test_constructor_uses_only_r7_and_transport08_names(self):
        def initialize(controller, *_args, **_kwargs):
            controller.names = boot.epoch.resource_names(boot.OWNER)

        with (
            patch.object(boot, "GENERATION", "r7"),
            patch.object(boot.epoch.EpochController, "__init__", new=initialize),
        ):
            controller = boot.BootController(boot.OWNER, expected_revision="a" * 40)
        self.assertEqual(
            controller.names["serve"], "kairos-epoch-69893dc7b7c6-serve-r7"
        )
        self.assertTrue(controller.names["restore_pg"].endswith("-transport08"))
        self.assertTrue(controller.names["restore_volume"].endswith("-transport08"))
        self.assertNotIn("transport07", controller.names["restore_pg"])

    def test_r7_lifecycle_requires_the_receipt_proven_source_and_trade_flags(self):
        value = accepted_status()
        self.assertIs(boot.validate_r7_lifecycle_status(value), value)
        for key, invalid in (
            ("trading_started", True),
            ("source_fresh", False),
            ("owner", "wrong-owner"),
        ):
            with self.subTest(key=key), self.assertRaises(boot.epoch.Rejected):
                boot.validate_r7_lifecycle_status({**value, key: invalid})

    def test_r7_accepts_only_the_shared_bounded_source_pause_contract(self):
        waiting = {
            **accepted_status(),
            "state": "WAITING_SOURCE_NONTRADING",
            "source_fresh": False,
            "source_wait_reason": "OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT",
            "source_transport": {
                "timeout_rounds": 1,
                "recoveries": 0,
                "consecutive_timeout_rounds": 1,
            },
        }
        catching_up = {
            **accepted_status(),
            "state": "CATCHING_UP_NONTRADING",
            "source_fresh": False,
            "source_wait_reason": None,
            "source_transport": {
                "timeout_rounds": 1,
                "recoveries": 0,
                "consecutive_timeout_rounds": 0,
            },
        }
        self.assertIs(boot.validate_r7_lifecycle_status(waiting), waiting)
        self.assertIs(boot.validate_r7_lifecycle_status(catching_up), catching_up)
        for key, invalid in (
            ("source_wait_reason", "INTEGRITY_ERROR"),
            ("pending_outbox", 1),
        ):
            with self.subTest(key=key), self.assertRaises(boot.epoch.Rejected):
                boot.validate_r7_lifecycle_status({**waiting, key: invalid})

    def test_r7_dns_source_pause_is_admitted_without_changing_r6_contract(self):
        waiting_dns = {
            **accepted_status(),
            "state": "WAITING_SOURCE_NONTRADING",
            "source_fresh": False,
            "source_wait_reason": "OFFICIAL_CLOSED_BAR_FETCH_DNS_FAILURE",
            "source_transport": {
                "timeout_rounds": 0,
                "recoveries": 0,
                "consecutive_timeout_rounds": 0,
                "dns_failure_rounds": 1,
                "consecutive_dns_failure_rounds": 1,
            },
        }
        self.assertIs(boot.validate_r7_lifecycle_status(waiting_dns), waiting_dns)
        with self.assertRaises(boot.epoch.Rejected):
            boot.validate_r6_lifecycle_status(waiting_dns)

        for circuit in (
            {
                **waiting_dns["source_transport"],
                "consecutive_timeout_rounds": 1,
            },
            {
                **waiting_dns["source_transport"],
                "consecutive_dns_failure_rounds": 2,
            },
            {
                **waiting_dns["source_transport"],
                "dns_failure_rounds": 0,
            },
            {
                "timeout_rounds": 0,
                "recoveries": 0,
                "consecutive_timeout_rounds": 0,
                "dns_failure_rounds": 1,
            },
        ):
            with self.subTest(circuit=circuit), self.assertRaises(boot.epoch.Rejected):
                boot.validate_r7_lifecycle_status(
                    {**waiting_dns, "source_transport": circuit}
                )

    def test_already_running_r7_pause_is_reported_without_restart_or_mutation(self):
        controller = boot.BootController.__new__(boot.BootController)
        controller.proofs = {}
        value = {
            **accepted_status(),
            "state": "WAITING_SOURCE_NONTRADING",
            "source_fresh": False,
            "source_wait_reason": "OFFICIAL_CLOSED_BAR_FETCH_TIMEOUT",
            "source_transport": {
                "timeout_rounds": 1,
                "recoveries": 0,
                "consecutive_timeout_rounds": 1,
            },
        }
        resources = {
            "standby": {"left_untouched": True},
            "views": {key: {"state": {"Status": "running"}} for key in boot.CONTAINERS},
        }
        with (
            patch.object(boot, "GENERATION", "r7"),
            patch.object(controller, "validate_resources", return_value=resources),
            patch.object(boot, "read_json", return_value=value),
            patch.object(controller, "docker") as docker,
            patch.object(controller, "phase") as phase,
        ):
            result = controller.run_boot()
        self.assertEqual(result["result"], "ALREADY_RUNNING_SOURCE_PAUSED_NONTRADING")
        self.assertIs(result["status"], value)
        docker.assert_not_called()
        phase.assert_not_called()

    def test_already_running_r7_is_validated_without_restart_or_mutation(self):
        controller = boot.BootController.__new__(boot.BootController)
        controller.proofs = {}
        value = accepted_status()
        resources = {
            "standby": {"left_untouched": True},
            "views": {key: {"state": {"Status": "running"}} for key in boot.CONTAINERS},
        }
        with (
            patch.object(boot, "GENERATION", "r7"),
            patch.object(controller, "validate_resources", return_value=resources),
            patch.object(boot, "read_json", return_value=value),
            patch.object(controller, "docker") as docker,
            patch.object(controller, "phase") as phase,
        ):
            result = controller.run_boot()
        self.assertEqual(result["result"], "ALREADY_RUNNING_NONTRADING")
        self.assertIs(result["status"], value)
        docker.assert_not_called()
        phase.assert_not_called()

    def test_explicit_r7_cli_does_not_change_default_generation(self):
        with (
            patch.object(boot, "configure_generation_r7") as configure,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(boot.main([]), 0)
            configure.assert_not_called()
            self.assertEqual(boot.main(["--generation", "r7"]), 0)
            configure.assert_called_once_with()

    def test_r7dns_binds_only_the_success_receipt_and_uses_separate_root(self):
        names = (
            "ROOT",
            "SERVE_WORK",
            "SCOPE",
            "GENERATION",
            "RECEIPT_NAME",
            "PARENT_RECEIPT_SHA256",
            "CONTAINERS",
            "LEASE",
        )
        with contextlib.ExitStack() as stack:
            for name in names:
                stack.enter_context(patch.object(boot, name, getattr(boot, name)))
            old_root = boot.ROOT
            old_containers = boot.CONTAINERS.copy()
            boot.configure_generation_r7dns()
            self.assertEqual(boot.GENERATION, "r7dns")
            self.assertEqual(
                boot.ROOT.as_posix(), "D:/Kairos/runtime/epoch-boot-r7dns-20261015"
            )
            self.assertEqual(
                boot.SERVE_WORK.as_posix(), boot.R7DNS_WORK.as_posix()
            )
            self.assertEqual(
                boot.SCOPE, "kairos-nontrading-runtime-epoch-boot-r7dns-v1"
            )
            self.assertEqual(
                boot.PARENT_RECEIPT_SHA256, boot.R7DNS_SUCCESS_RECEIPT_SHA256
            )
            self.assertEqual(boot.CONTAINERS["pg"], old_containers["pg"])
            self.assertEqual(boot.CONTAINERS["redis"], old_containers["redis"])
            self.assertEqual(boot.CONTAINERS["serve"], boot.R7DNS_SERVE_ID)
            self.assertEqual(boot.LEASE, boot.ROOT / "boot.active")
            self.assertNotEqual(boot.ROOT, old_root)

    def test_r7dns_admits_only_the_exact_nontrading_receipt(self):
        value = accepted_r7dns_receipt()
        self.assertIs(boot.validate_r7dns_admission_receipt(value), value)
        invalid_values = (
            {**value, "state": "FAILED_CLOSED"},
            {**value, "trading_started": True},
            {**value, "legacy_unchanged": False},
            {
                **value,
                "continuation": {**value["continuation"], "container_id": "f" * 64},
            },
            {
                **value,
                "continuation": {
                    **value["continuation"],
                    "graceful_restart_proven": False,
                },
            },
            {
                **value,
                "continuation": {
                    **value["continuation"],
                    "status": {
                        **value["continuation"]["status"],
                        "state": "FAILED_CLOSED",
                    },
                },
            },
            {
                **value,
                "proofs": {
                    **value["proofs"],
                    "operator_snapshot_sha256": "f" * 64,
                },
            },
            {
                **value,
                "proofs": {
                    **value["proofs"],
                    "resources_before": {
                        **value["proofs"]["resources_before"],
                        "views": {
                            **value["proofs"]["resources_before"]["views"],
                            "serve": {
                                **value["proofs"]["resources_before"]["views"]["serve"],
                                "id": "f" * 64,
                            },
                        },
                    },
                },
            },
            {
                **value,
                "proofs": {
                    **value["proofs"],
                    "retained_cold_pg": {
                        **value["proofs"]["retained_cold_pg"],
                        "source_unchanged": False,
                    },
                },
            },
        )
        for invalid in invalid_values:
            with self.subTest(state=invalid.get("state")), self.assertRaises(
                boot.epoch.Rejected
            ):
                boot.validate_r7dns_admission_receipt(invalid)

    def test_r7dns_admission_files_pin_receipt_signature_failed_status_and_inputs(self):
        names = (
            "ROOT",
            "SERVE_WORK",
            "SCOPE",
            "GENERATION",
            "RECEIPT_NAME",
            "PARENT_RECEIPT_SHA256",
            "CONTAINERS",
            "LEASE",
        )
        with contextlib.ExitStack() as stack:
            for name in names:
                stack.enter_context(patch.object(boot, name, getattr(boot, name)))
            boot.configure_generation_r7dns()
            receipt = accepted_r7dns_receipt()
            path_hashes = {
                (boot.SERVE_WORK / "receipt.json").as_posix(): boot.R7DNS_SUCCESS_RECEIPT_SHA256,
                (boot.SERVE_WORK / "receipt.json.asc").as_posix(): boot.R7DNS_SUCCESS_SIGNATURE_SHA256,
                boot.R7DNS_FAILED_STATUS_PATH.as_posix(): boot.R7DNS_FAILED_STATUS_SHA256,
                (boot.SERVE_WORK / "config-serve.json").as_posix(): boot.R7DNS_CONFIG_SHA256,
                (boot.SERVE_WORK / "operator.zip").as_posix(): boot.R7DNS_OPERATOR_ARCHIVE_SHA256,
                (boot.SERVE_WORK / "quant.zip").as_posix(): boot.R7DNS_QUANT_ARCHIVE_SHA256,
            }
            failed_status = {
                "state": "FAILED_CLOSED",
                "error_type": "ClientConnectorDNSError",
                "trading_started": False,
            }

            def read_json(path, **_kwargs):
                return failed_status if path == boot.R7DNS_FAILED_STATUS_PATH else receipt

            with (
                patch.object(boot.fresh, "safe", side_effect=lambda path: path),
                patch.object(
                    boot.fresh,
                    "sha",
                    side_effect=lambda path: path_hashes[path.as_posix()],
                ),
                patch.object(boot, "read_json", side_effect=read_json),
            ):
                self.assertIs(boot.validate_r7dns_admission_files(), receipt)

            with (
                patch.object(boot.fresh, "safe", side_effect=lambda path: path),
                patch.object(
                    boot.fresh,
                    "sha",
                    side_effect=lambda path: "0" * 64,
                ),
                self.assertRaises(boot.epoch.Rejected),
            ):
                boot.validate_r7dns_admission_files()

    def test_r7dns_uses_unique_serve_and_restore_names(self):
        def initialize(controller, *_args, **_kwargs):
            controller.names = boot.epoch.resource_names(boot.OWNER)

        with (
            patch.object(boot, "GENERATION", "r7dns"),
            patch.object(boot.epoch.EpochController, "__init__", new=initialize),
        ):
            controller = boot.BootController(
                boot.OWNER, expected_revision="a" * 40
            )
        self.assertEqual(controller.names["serve"], boot.R7DNS_SERVE_NAME)
        self.assertEqual(
            controller.names["restore_pg"],
            "kairos-epoch-69893dc7b7c6-restore-reviewed-b0a90145",
        )
        self.assertEqual(
            controller.names["restore_volume"],
            "kairos-epoch-69893dc7b7c6-restore-data-reviewed-b0a90145",
        )
        boot.epoch.validate_worker_config(
            {
                "owner": boot.OWNER,
                "database": "kairos_epoch_" + boot.OWNER[:12],
                "pg_host": controller.names["target_pg"],
                "redis_host": controller.names["redis"],
                "admin_password": "a" * 64,
                "restore_host": controller.names["restore_pg"],
                "restore_database": "kairos_recovery_"
                + boot.OWNER[:12]
                + "_epochrestore",
                "restore_admin_password": "b" * 64,
                "expected_seed": {"bars": 1},
            },
            mode="boot-verify-restore",
        )

    def test_r7dns_controller_mounts_the_receipt_bound_workdir(self):
        def initialize(controller, *_args, **_kwargs):
            controller.names = boot.epoch.resource_names(boot.OWNER)

        with (
            patch.object(boot, "GENERATION", "r7dns"),
            patch.object(boot.epoch.EpochController, "__init__", new=initialize),
        ):
            controller = boot.BootController(
                boot.OWNER, expected_revision="a" * 40
            )
        settings = {
            "pg": (boot.CONTAINERS["pg"], boot.epoch.PG_IMAGE, 4 * 1024**3, 1_000_000_000),
            "redis": (boot.CONTAINERS["redis"], boot.epoch.REDIS_IMAGE, 256 * 1024**2, 500_000_000),
            "serve": (
                boot.R7DNS_SERVE_ID,
                boot.epoch.WORKER_IMAGE,
                512 * 1024**2,
                1_000_000_000,
            ),
        }
        views = {}
        for key, (container_id, image, memory, cpus) in settings.items():
            name = controller.names["target_pg" if key == "pg" else key]
            views[name] = {
                "id": container_id,
                "image": image.split("@", 1)[-1],
                "network": controller.names["network"],
                "ports": {},
                "readonly": True,
                "caps": ["ALL"],
                "privileged": False,
                "networks": {controller.names["network"]: {}},
                "memory": memory,
                "swap": memory,
                "cpus": cpus,
                "labels": {
                    boot.epoch.EPOCH_LABEL: boot.OWNER,
                    "com.kairos.runtime-epoch.scope": boot.epoch.EPOCH_SCOPE,
                },
                "state": {"Status": "exited" if key == "serve" else "running"},
            }

        def docker(args, **_kwargs):
            return '{"Name":"no"}' if args[0] == "inspect" else (
                controller.names["target_pg"] + "\n" + controller.names["redis"]
            )

        profile_containers = {
            "pg": boot.epoch.CONTINUATION_04_TARGET_PG_ID,
            "redis": boot.epoch.CONTINUATION_04_REDIS_ID,
            "serve": boot.R7DNS_SERVE_ID,
        }
        with (
            patch.object(boot, "GENERATION", "r7dns"),
            patch.object(boot, "CONTAINERS", profile_containers),
            patch.object(boot, "SERVE_WORK", boot.R7DNS_WORK),
            patch.object(controller, "assert_legacy_sources_stopped", return_value={}),
            patch.object(controller, "inspect_container", side_effect=views.get),
            patch.object(controller, "docker", side_effect=docker),
            patch.object(controller, "require_mount_set") as require_mount_set,
        ):
            controller.validate_resources()

        serve_call = next(
            call
            for call in require_mount_set.call_args_list
            if call.args[0] == boot.R7DNS_SERVE_NAME
        )
        self.assertEqual(
            serve_call.args[1],
            {
                str(boot.R7DNS_WORK / "config-serve.json"): (
                    boot.epoch.CONFIG_PATH_IN_CONTAINER,
                    False,
                ),
                str(boot.R7DNS_WORK / "output-serve"): ("/output", True),
                str(boot.R7DNS_WORK / "operator"): ("/operator", False),
                str(boot.R7DNS_WORK / "runtime-wheelhouse"): ("/wheelhouse", False),
                str(boot.R7DNS_WORK / "quant"): ("/quant", False),
                str(boot.epoch.AUX_WHEELHOUSE): ("/aux-wheels", False),
            },
        )

    def test_already_running_r7dns_is_validated_without_restart_or_mutation(self):
        controller = boot.BootController.__new__(boot.BootController)
        controller.proofs = {}
        value = accepted_status()
        resources = {
            "standby": {"left_untouched": True},
            "views": {key: {"state": {"Status": "running"}} for key in boot.CONTAINERS},
        }
        with (
            patch.object(boot, "GENERATION", "r7dns"),
            patch.object(controller, "validate_resources", return_value=resources),
            patch.object(boot, "read_json", return_value=value),
            patch.object(controller, "docker") as docker,
            patch.object(controller, "phase") as phase,
        ):
            result = controller.run_boot()
        self.assertEqual(result["result"], "ALREADY_RUNNING_NONTRADING")
        self.assertIs(result["status"], value)
        docker.assert_not_called()
        phase.assert_not_called()

    def test_r7dns_recognizes_only_admitted_dns_pause_not_failed_latch(self):
        waiting = {
            **accepted_status(),
            "state": "WAITING_SOURCE_NONTRADING",
            "source_fresh": False,
            "source_wait_reason": "OFFICIAL_CLOSED_BAR_FETCH_DNS_FAILURE",
            "source_transport": {
                "timeout_rounds": 0,
                "recoveries": 0,
                "consecutive_timeout_rounds": 0,
                "dns_failure_rounds": 1,
                "consecutive_dns_failure_rounds": 1,
            },
        }
        self.assertIs(boot.validate_r7_lifecycle_status(waiting), waiting)
        for failed in (
            {**waiting, "state": "FAILED_CLOSED"},
            {**waiting, "trading_started": True},
        ):
            with self.subTest(state=failed["state"]), self.assertRaises(
                boot.epoch.Rejected
            ):
                boot.validate_r7_lifecycle_status(failed)

    def test_explicit_r7dns_cli_is_opt_in(self):
        with (
            patch.object(boot, "configure_generation_r7dns") as configure,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(boot.main([]), 0)
            configure.assert_not_called()
            self.assertEqual(boot.main(["--generation", "r7dns"]), 0)
            configure.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
