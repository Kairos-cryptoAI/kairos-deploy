"""Adversarial, provider-free tests of shadow authority migration boundaries."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "shadow_runtime_schema_upgrade.py"
spec = importlib.util.spec_from_file_location("shadow_schema_controller_test", SCRIPT)
assert spec is not None and spec.loader is not None
controller = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = controller
spec.loader.exec_module(controller)


def _snapshot(upgraded: bool = False) -> dict:
    value = {
        "database": "kairos",
        "migrations": list(controller.TARGET if upgraded else controller.LEGACY),
        "tables": {table: {"count": 20 if table == "source_usage_reservations" else 0, "row_digest": "a" * 64} for table in controller.TABLES},
        "schema_digest": ("c" if upgraded else "b") * 64,
        "public_sequences": {"public_execution_events_event_seq_seq": {"last_value": "1", "is_called": "false"}},
        "max_sequence": 0,
        "simulator_relations": 0,
        "runtime_relations": sorted(controller.NEW_TABLES) if upgraded else [],
        "nonpristine_reconciliation": 0,
        "reconciliation_columns": 4 if upgraded else 0,
    }
    if upgraded:
        value["runtime_rows"] = {table: {"count": 1 if table == "paper_canary_database_identity" else 0, "row_digest": "d" * 64} for table in controller.NEW_TABLES}
    return value


def _inspection() -> dict:
    return {
        "Id": "1" * 64,
        "Name": "/" + controller.SOURCE_CONTAINER,
        "Image": "sha256:" + "2" * 64,
        "State": {"Running": True},
        "HostConfig": {"Privileged": False, "PortBindings": {}},
        "Config": {"Labels": {"com.docker.compose.project": controller.SOURCE_PROJECT, "com.docker.compose.service": "timescaledb"}},
        "Mounts": [{"Destination": "/var/lib/postgresql/data", "Type": "volume", "Name": controller.SOURCE_VOLUME, "RW": True}],
        "NetworkSettings": {"Networks": {controller.SOURCE_NETWORK: {"NetworkID": "3" * 64}}},
    }


class ShadowRuntimeSchemaUpgradeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="shadow-schema-unit-")
        self.root = Path(self.temporary.name)
        self.dump = self.root / "kairos-shadow-gate-20261002T165244Z.dump"
        self.dump.write_bytes(b"immutable-unit-backup")
        self.manifest = {
            "schema_version": 1,
            "compose_project": controller.SOURCE_PROJECT,
            "database": controller.SOURCE_DATABASE,
            "created_at_utc": datetime.now(UTC).isoformat(),
            "file": self.dump.name,
            "bytes": self.dump.stat().st_size,
            "sha256": hashlib.sha256(self.dump.read_bytes()).hexdigest(),
            "checkpoints": {**{table: _snapshot()["tables"][table]["count"] for table in controller.TABLES}, "public_execution_events_max_sequence": 0},
            "timescaledb_bgw_owners": ["kairos"],
        }
        self.manifest_path = self.root / (self.dump.name + ".json")
        self._save_manifest()
        self.root_patch = mock.patch.object(controller, "BACKUP_ROOT", self.root)
        self.root_patch.start()

    def tearDown(self) -> None:
        self.root_patch.stop()
        self.temporary.cleanup()

    def _save_manifest(self) -> None:
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def _receipt(self) -> dict:
        after = _snapshot(True)
        return {"schema_version": controller.SCHEMA, "result": "PASS_CLONE_ONLY", "created_at_utc": datetime.now(UTC).isoformat(), **controller._code_identity(), "backup_manifest_sha256": controller._sha(self.manifest_path), "backup_sha256": self.manifest["sha256"], "runner_image": controller.RUNNER_IMAGE, "source_identity": {"container_id": "1" * 64}, "before": _snapshot(), "after": after, "second_pass": after, "restore": after, "runtime_profile": list(controller.TARGET), "provider_calls": 0, "primary_mutations": 0}

    def _args(self, *, apply: bool = False) -> argparse.Namespace:
        return argparse.Namespace(manifest_path=self.manifest_path, receipt_path=self.root / "result.json", confirm_paid_producers_stopped=True, migration_runner_image=controller.RUNNER_IMAGE, preflight=True, apply=apply, confirmation=controller.CONFIRMATION if apply else None, preflight_receipt_path=self.root / "preflight.json" if apply else None, expected_preflight_sha256=None)

    def test_valid_fresh_backup_preserves_historical_authority(self) -> None:
        manifest, dump = controller._backup(self.manifest_path)
        self.assertEqual(manifest, self.manifest)
        # tempfile may retain an 8.3 parent alias on Windows; _backup returns
        # the canonical path after enforcing the protected backup-root guard.
        self.assertEqual(dump, self.dump.resolve(strict=True))

    @unittest.skipUnless(sys.platform == "win32", "Windows 8.3 path aliases only")
    def test_short_backup_path_alias_resolves_to_the_same_protected_archive(self) -> None:
        from ctypes import WinDLL, create_unicode_buffer
        from ctypes.wintypes import DWORD, LPCWSTR, LPWSTR

        get_short_path = WinDLL("kernel32", use_last_error=True).GetShortPathNameW
        get_short_path.argtypes = (LPCWSTR, LPWSTR, DWORD)
        get_short_path.restype = DWORD
        required = get_short_path(str(self.manifest_path), None, 0)
        if not required:
            self.skipTest("Filesystem does not expose a Windows short path")
        buffer = create_unicode_buffer(required)
        written = get_short_path(str(self.manifest_path), buffer, required)
        self.assertGreater(written, 0)
        self.assertLess(written, required)
        alias = Path(buffer.value)
        if alias == self.manifest_path:
            self.skipTest("Filesystem does not expose an alternate 8.3 spelling")

        manifest, dump = controller._backup(alias)
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(dump, self.dump.resolve(strict=True))
        self.assertTrue(dump.samefile(self.dump))

        with mock.patch.object(controller, "BACKUP_ROOT", self.root / "unrelated"), self.assertRaises(controller.UpgradeError):
            controller._backup(alias)

    def test_wrong_project_database_and_incomplete_historical_rows_rejected(self) -> None:
        for field, value in (("compose_project", "kairos-paper-gate"), ("database", "kairos_sim"), ("bytes", self.dump.stat().st_size + 1), ("sha256", "0" * 64)):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.manifest)
                changed[field] = value
                self.manifest_path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaises(controller.UpgradeError):
                    controller._backup(self.manifest_path)
        self._save_manifest()
        self.manifest["checkpoints"]["source_usage_reservations"] = 19
        self._save_manifest()
        with self.assertRaises(controller.UpgradeError):
            controller._backup(self.manifest_path)

    def test_stale_future_naive_and_non_utc_timestamps_rejected(self) -> None:
        now = datetime.now(UTC)
        for instant in ((now - timedelta(hours=2, seconds=1)).isoformat(), (now + timedelta(minutes=6)).isoformat(), "2026-10-02T16:00:00", "2026-10-02T19:00:00+03:00"):
            with self.subTest(instant=instant), self.assertRaises(controller.UpgradeError):
                controller._fresh(instant, "evidence", now)

    def test_manifest_cannot_escape_protected_backup_root(self) -> None:
        with mock.patch.object(controller, "BACKUP_ROOT", self.root / "unrelated"), self.assertRaises(controller.UpgradeError):
            controller._backup(self.manifest_path)

    def test_valid_container_identity_uses_resolved_config_id_not_manifest_hash(self) -> None:
        source = _inspection()
        result = controller._identity(source, [source], source["Image"])
        self.assertEqual(result["container_id"], source["Id"])
        with self.assertRaises(controller.UpgradeError):
            controller._identity(source, [source], "sha256:" + "9" * 64)

    def test_wrong_identity_privileged_ports_volume_and_network_rejected(self) -> None:
        modifications = (
            lambda item: item["Config"]["Labels"].update({"com.docker.compose.project": "kairos-paper-gate"}),
            lambda item: item["Config"]["Labels"].update({"com.docker.compose.service": "aggregator"}),
            lambda item: item.update({"Name": "/another-timescaledb"}),
            lambda item: item["State"].update({"Running": False}),
            lambda item: item["HostConfig"].update({"Privileged": True}),
            lambda item: item["HostConfig"].update({"PortBindings": {"5432/tcp": [{"HostPort": "5432"}]}}),
            lambda item: item["Mounts"][0].update({"Name": "kairos-paper-gate_ts-data"}),
            lambda item: item["NetworkSettings"].update({"Networks": {"host": {"NetworkID": "3" * 64}}}),
        )
        for update in modifications:
            item = _inspection()
            update(item)
            with self.subTest(item=item), self.assertRaises(controller.UpgradeError):
                controller._identity(item, [item], item["Image"])

    def test_other_paid_producer_network_consumer_or_volume_mount_rejected(self) -> None:
        source = _inspection()
        for extra in (
            {"Id": "4" * 64, "Config": {"Labels": {"com.docker.compose.project": controller.SOURCE_PROJECT}}},
            {"Id": "4" * 64, "NetworkSettings": {"Networks": {controller.SOURCE_NETWORK: {}}}},
            {"Id": "4" * 64, "Mounts": [{"Name": controller.SOURCE_VOLUME}]},
        ):
            with self.subTest(extra=extra), self.assertRaises(controller.UpgradeError):
                controller._identity(source, [source, extra], source["Image"])

    def test_only_exact_legacy_baseline_without_future_ddl_is_accepted(self) -> None:
        controller._matches_backup(_snapshot(), self.manifest)
        for change in ({"migrations": list(controller.TARGET)}, {"runtime_relations": ["campaign_source_budgets"]}, {"max_sequence": 1}, {"nonpristine_reconciliation": 1}, {"reconciliation_columns": 4}):
            before = _snapshot()
            before.update(change)
            with self.subTest(change=change), self.assertRaises(controller.UpgradeError):
                controller._matches_backup(before, self.manifest)

    def test_same_count_but_changed_reservation_row_hash_rejected(self) -> None:
        before, after = _snapshot(), _snapshot(True)
        controller._preserved(before, after)
        after["tables"]["source_usage_reservations"]["row_digest"] = "f" * 64
        with self.assertRaises(controller.UpgradeError):
            controller._preserved(before, after)

    def test_same_durable_rows_but_changed_sequence_state_rejected(self) -> None:
        before, after = _snapshot(), _snapshot(True)
        after["public_sequences"]["public_execution_events_event_seq_seq"]["is_called"] = "true"
        with self.assertRaises(controller.UpgradeError):
            controller._preserved(before, after)

    def test_simulator_mixed_profile_or_nonpristine_new_tables_rejected(self) -> None:
        for change in ("simulator", "migration", "campaign", "reconciliation", "columns"):
            after = _snapshot(True)
            if change == "simulator":
                after["simulator_relations"] = 1
            elif change == "migration":
                after["migrations"].insert(16, "017_simulator_journal.sql")
            elif change == "campaign":
                after["runtime_rows"]["campaign_source_budgets"]["count"] = 1
            elif change == "reconciliation":
                after["nonpristine_reconciliation"] = 1
            else:
                after["reconciliation_columns"] = 3
            with self.subTest(change=change), self.assertRaises(controller.UpgradeError):
                controller._preserved(_snapshot(), after)

    def test_snapshot_uses_sha256_all_old_columns_and_separate_018_checks(self) -> None:
        sql = controller._snapshot_sql()
        self.assertNotIn("md5(", sql)
        self.assertIn("sha256(convert_to", sql)
        self.assertIn("reconciliation_state", sql)
        self.assertIn("nonpristine_reconciliation", sql)
        self.assertIn("runtime_relations", sql)

    def test_snapshot_psql_script_uses_stdin_for_one_readonly_transaction(self) -> None:
        with mock.patch.object(controller, "_docker", return_value=json.dumps(_snapshot())) as docker:
            self.assertEqual(controller._snapshot("source", "kairos"), _snapshot())
        args = docker.call_args.args[0]
        sql = docker.call_args.kwargs["data"]
        self.assertIn("--interactive", args)
        self.assertIn("--file=-", args)
        self.assertNotIn("--command", args)
        self.assertIn("BEGIN READ ONLY", sql)
        self.assertIn("\\gset\n\\if :runtime_profile", sql)
        self.assertEqual(sql.count("BEGIN READ ONLY"), 1)

    def test_verified_normal_primitive_is_transaction_guarded_and_no_provider_route(self) -> None:
        program = controller._runner_program("kairos_shadow_drill_123", _snapshot(), apply=False)
        compile(program, "shadow-migration-unit", "exec")
        self.assertIn("class GuardedDatabase(Database)", program)
        self.assertIn("await db.migrate()", program)
        self.assertIn("ACCESS EXCLUSIVE MODE", program)
        self.assertIn("authority snapshot changed under migration lock", program)
        self.assertIn("another authority database client connected during migration", program)
        self.assertIn("actual['runtime_rows']=json.loads(await connection.fetchval(CONFIG['runtime_sql']))", program)
        self.assertIn("non-loopback network access forbidden", program)
        self.assertNotIn("openai_api_key", program)
        self.assertNotIn("register_campaign", program)
        self.assertNotIn("quarantine_expired_outbox_exact", program)

    def test_receipt_requires_exact_code_backup_runner_source_and_both_clone_proofs(self) -> None:
        receipt = self._receipt()
        source = receipt["source_identity"]
        controller._receipt_valid(receipt, self.manifest_path, self.manifest, source, _snapshot())
        for field, value in (("controller_sha256", "0" * 64), ("catalog_sha256", "0" * 64), ("backup_sha256", "0" * 64), ("runner_image", "runner:latest"), ("source_identity", {"container_id": "5" * 64}), ("provider_calls", 1), ("primary_mutations", 1), ("restore", _snapshot()), ("second_pass", _snapshot())):
            changed = copy.deepcopy(receipt)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(controller.UpgradeError):
                controller._receipt_valid(changed, self.manifest_path, self.manifest, source, _snapshot())

    def test_missing_confirmation_and_invalid_output_fail_before_docker(self) -> None:
        cases = []
        missing = self._args()
        missing.confirm_paid_producers_stopped = False
        cases.append(missing)
        apply = self._args(apply=True)
        cases.append(apply)
        bad_output = self._args()
        bad_output.receipt_path = self.root / "outside" / "receipt.json"
        cases.append(bad_output)
        for args in cases:
            with mock.patch.object(controller, "_docker") as docker, self.assertRaises(controller.UpgradeError):
                controller.run(args)
            docker.assert_not_called()

    def test_existing_output_is_not_overwritten_and_no_source_action_occurs(self) -> None:
        args = self._args()
        args.receipt_path.write_text("existing immutable evidence", encoding="utf-8")
        with mock.patch.object(controller, "_source_identity") as identity, self.assertRaises(controller.UpgradeError):
            controller.run(args)
        identity.assert_not_called()
        self.assertEqual(args.receipt_path.read_text(), "existing immutable evidence")

    def test_mutable_or_different_runner_is_rejected_before_inspection(self) -> None:
        with mock.patch.object(controller, "_json") as probe, self.assertRaises(controller.UpgradeError):
            controller._runner_identity("kairos-runtime-schema-runner-local:latest")
        probe.assert_not_called()

    def test_cleanup_refuses_unowned_source_or_wrong_generated_object(self) -> None:
        source = _inspection()
        with mock.patch.object(controller, "_docker", return_value=json.dumps([source])) as docker, self.assertRaises(controller.UpgradeError):
            controller._cleanup(controller.SOURCE_CONTAINER, "123")
        self.assertEqual(docker.call_count, 1)

    def test_docker_errors_never_reflect_secret_stderr(self) -> None:
        result = subprocess.CompletedProcess([], 1, "", "secret-value-do-not-print")
        with mock.patch.object(controller.subprocess, "run", return_value=result), self.assertRaises(controller.UpgradeError) as caught:
            controller._docker(["inspect", "container"], "unit check")
        self.assertNotIn("secret-value", str(caught.exception))

    def test_clone_readiness_uses_final_tcp_server_and_three_stable_sql_results(self) -> None:
        database = "kairos_shadow_drill_0123456789ab"
        container = "kairos-shadow-schema-clone-0123456789ab"
        success = subprocess.CompletedProcess([], 0, "false|" + database + "\n", "")
        failure = subprocess.CompletedProcess([], 2, "", "temporary postmaster stopped")
        results = iter([failure, success, success, failure, success, success, success])
        def answer(command, **kwargs):
            return subprocess.CompletedProcess([], 0, "postgres\n", "") if "cat" in command else next(results)
        with mock.patch.object(controller.subprocess, "run", side_effect=answer) as probe, mock.patch.object(controller.time, "sleep"):
            controller._wait_clone_ready(container, database)
        self.assertEqual(probe.call_count, 14)
        for call in [call for call in probe.call_args_list if "psql" in call.args[0]]:
            self.assertIn("--host=127.0.0.1", call.args[0])
            self.assertIn("psql", call.args[0])
            self.assertNotIn("pg_isready", call.args[0])

    def test_clone_readiness_rejects_source_names_and_different_database(self) -> None:
        with mock.patch.object(controller.subprocess, "run") as probe, self.assertRaises(controller.UpgradeError):
            controller._wait_clone_ready(controller.SOURCE_CONTAINER, "kairos")
        probe.assert_not_called()
        wrong = subprocess.CompletedProcess([], 0, "false|wrong-db\n", "")
        with mock.patch.object(controller.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0, "postgres\n", ""), wrong]), mock.patch.object(controller.time, "monotonic", side_effect=[0, 1, 61]), mock.patch.object(controller.time, "sleep"), self.assertRaises(controller.UpgradeError):
            controller._wait_clone_ready("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab")

    def test_temporary_entrypoint_pid_one_shell_cannot_pass_readiness(self) -> None:
        shell = subprocess.CompletedProcess([], 0, "bash\n", "")
        with mock.patch.object(controller.subprocess, "run", return_value=shell) as probe, mock.patch.object(controller.time, "monotonic", side_effect=[0, 1, 61]), mock.patch.object(controller.time, "sleep"), self.assertRaises(controller.UpgradeError):
            controller._wait_clone_ready("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab")
        self.assertEqual(probe.call_count, 1)

    def test_clone_readiness_timeout_is_not_success(self) -> None:
        with mock.patch.object(controller.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 5)), mock.patch.object(controller.time, "monotonic", side_effect=[0, 1, 61]), mock.patch.object(controller.time, "sleep"), self.assertRaises(controller.UpgradeError):
            controller._wait_clone_ready("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab")

    def test_binary_restore_uses_verified_host_stdin_without_copy_staging(self) -> None:
        def restore(command, **kwargs):
            self.assertEqual(kwargs["stdin"].read(), self.dump.read_bytes())
            self.assertNotIn("text", kwargs)
            self.assertEqual(kwargs["timeout"], controller.ARCHIVE_TIMEOUT_SECONDS)
            self.assertIn("--interactive", command)
            self.assertNotIn("cp", command)
            self.assertFalse(any("/tmp/" in part for part in command))
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(controller.subprocess, "run", side_effect=restore) as process:
            controller._restore_stream("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab", self.dump)
        process.assert_called_once()

    def test_archive_helpers_reject_authority_or_mismatched_generated_names(self) -> None:
        for container, database in ((controller.SOURCE_CONTAINER, "kairos"), ("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_abcdef012345")):
            with self.subTest(container=container), mock.patch.object(controller.subprocess, "run") as process:
                with self.assertRaises(controller.UpgradeError):
                    controller._restore_stream(container, database, self.dump)
                with self.assertRaises(controller.UpgradeError):
                    controller._dump_stream(container, database, self.root / "upgraded-shadow.dump")
                process.assert_not_called()

    def test_restore_rejects_oversize_or_unprotected_archive_before_process(self) -> None:
        for changes in (("MAX_DUMP_BYTES", 1), ("BACKUP_ROOT", self.root / "elsewhere")):
            with self.subTest(changes=changes), mock.patch.object(controller, *changes), mock.patch.object(controller.subprocess, "run") as process, self.assertRaises(controller.UpgradeError):
                controller._restore_stream("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab", self.dump)
            process.assert_not_called()
        with mock.patch.object(controller, "MAX_DUMP_BYTES", 1), self.assertRaises(controller.UpgradeError):
            controller._backup(self.manifest_path)

    def test_binary_dump_uses_exclusive_host_stdout_and_no_container_staging(self) -> None:
        directory = self.root / "kairos-shadow-schema-unit"
        directory.mkdir()
        dump = directory / "upgraded-shadow.dump"
        def emit(command, **kwargs):
            self.assertNotIn("text", kwargs)
            self.assertNotIn("cp", command)
            self.assertFalse(any("--file=" in part or "/tmp/" in part for part in command))
            self.assertEqual(kwargs["timeout"], controller.ARCHIVE_TIMEOUT_SECONDS)
            kwargs["stdout"].write(b"PGDMP-binary-unit")
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(controller.subprocess, "run", side_effect=emit) as process:
            controller._dump_stream("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab", dump)
        process.assert_called_once()
        self.assertEqual(dump.read_bytes(), b"PGDMP-binary-unit")
        with mock.patch.object(controller.subprocess, "run") as process, self.assertRaises(FileExistsError):
            controller._dump_stream("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab", dump)
        process.assert_not_called()
        self.assertEqual(dump.read_bytes(), b"PGDMP-binary-unit")

    def test_binary_dump_refuses_unprotected_or_wrong_output_location(self) -> None:
        directory = self.root / "unrelated"
        directory.mkdir()
        with mock.patch.object(controller.subprocess, "run") as process, self.assertRaises(controller.UpgradeError):
            controller._dump_stream("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab", directory / "upgraded-shadow.dump")
        process.assert_not_called()

    def test_binary_archive_failures_and_timeouts_do_not_reflect_raw_logs(self) -> None:
        directory = self.root / "kairos-shadow-schema-unit"
        directory.mkdir()
        for outcome in (subprocess.CompletedProcess([], 1, b"", b"secret-do-not-reflect"), subprocess.TimeoutExpired([], 180, stderr=b"secret-do-not-reflect")):
            with self.subTest(outcome=type(outcome).__name__), mock.patch.object(controller.subprocess, "run", side_effect=outcome if isinstance(outcome, Exception) else None, return_value=outcome), self.assertRaises(controller.UpgradeError) as caught:
                controller._restore_stream("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab", self.dump)
            self.assertNotIn("secret-do-not-reflect", str(caught.exception))
            target = directory / "upgraded-shadow.dump"
            with mock.patch.object(controller.subprocess, "run", side_effect=outcome if isinstance(outcome, Exception) else None, return_value=outcome), self.assertRaises(controller.UpgradeError) as caught:
                controller._dump_stream("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab", target)
            self.assertNotIn("secret-do-not-reflect", str(caught.exception))
            target.unlink()

    def test_binary_dump_empty_or_oversized_output_is_not_accepted(self) -> None:
        directory = self.root / "kairos-shadow-schema-unit"
        directory.mkdir()
        for output in (b"", b"12345"):
            target = directory / "upgraded-shadow.dump"
            def emit(command, **kwargs):
                kwargs["stdout"].write(output)
                return subprocess.CompletedProcess(command, 0)
            with self.subTest(output=output), mock.patch.object(controller, "MAX_DUMP_BYTES", 4), mock.patch.object(controller.subprocess, "run", side_effect=emit), self.assertRaises(controller.UpgradeError):
                controller._dump_stream("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab", target)
            target.unlink()

    def test_clone_restore_staging_uses_only_binary_stream_and_constrained_owner(self) -> None:
        with mock.patch.object(controller, "_docker", return_value="") as docker, mock.patch.object(controller, "_wait_clone_ready"), mock.patch.object(controller, "_restore_stream") as restore:
            controller._clone(self.dump, ["kairos"], "0123456789ab")
        restore.assert_called_once_with("kairos-shadow-schema-clone-0123456789ab", "kairos_shadow_drill_0123456789ab", self.dump)
        self.assertFalse(any("cp" in call.args[0] for call in docker.call_args_list))
        owner_sql = next(call.args[0][-1] for call in docker.call_args_list if "--command" in call.args[0] and "CREATE ROLE" in call.args[0][-1])
        self.assertIn("NOINHERIT", owner_sql)
        self.assertIn("NOBYPASSRLS", owner_sql)

    def test_clone_failure_cannot_create_pass_receipt(self) -> None:
        args = self._args()
        with mock.patch.object(controller, "_source_identity", return_value={"container_id": "1" * 64}), mock.patch.object(controller, "_snapshot", return_value=_snapshot()), mock.patch.object(controller, "_runner_identity"), mock.patch.object(controller, "_clone", side_effect=controller.UpgradeError("clone proof failed")), mock.patch.object(controller, "_cleanup"), self.assertRaises(controller.UpgradeError):
            controller.run(args)
        self.assertFalse(args.receipt_path.exists())

    def test_apply_snapshot_drift_prevents_normal_migration(self) -> None:
        args = self._args(apply=True)
        receipt = self._receipt()
        args.preflight_receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        args.expected_preflight_sha256 = controller._sha(args.preflight_receipt_path)
        changed = _snapshot()
        changed["tables"]["source_usage_reservations"]["row_digest"] = "e" * 64
        with mock.patch.object(controller, "_source_identity", return_value=receipt["source_identity"]), mock.patch.object(controller, "_snapshot", side_effect=[_snapshot(), changed]), mock.patch.object(controller, "_runner_identity"), mock.patch.object(controller, "_migrate") as migrate, self.assertRaises(controller.UpgradeError):
            controller.run(args)
        migrate.assert_not_called()

    def test_controller_or_loaded_catalog_code_mutation_invalidates_operation(self) -> None:
        expected = controller._code_identity()
        for key in ("controller_sha256", "catalog_sha256"):
            changed = {**expected, key: "0" * 64}
            with mock.patch.object(controller, "_code_identity", return_value=changed), self.subTest(key=key), self.assertRaises(controller.UpgradeError):
                controller._assert_code_identity(expected)
        with mock.patch.object(controller, "_sha", side_effect=[expected["controller_sha256"], "0" * 64]), self.assertRaises(controller.UpgradeError):
            controller._code_identity()

    def test_apply_code_mutation_prevents_source_migration(self) -> None:
        args = self._args(apply=True)
        receipt = self._receipt()
        args.preflight_receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        args.expected_preflight_sha256 = controller._sha(args.preflight_receipt_path)
        with mock.patch.object(controller, "_source_identity", return_value=receipt["source_identity"]), mock.patch.object(controller, "_snapshot", return_value=_snapshot()), mock.patch.object(controller, "_runner_identity"), mock.patch.object(controller, "_assert_code_identity", side_effect=controller.UpgradeError("controller changed")), mock.patch.object(controller, "_migrate") as migrate, self.assertRaises(controller.UpgradeError):
            controller.run(args)
        migrate.assert_not_called()
        self.assertFalse(args.receipt_path.exists())


if __name__ == "__main__":
    unittest.main()
