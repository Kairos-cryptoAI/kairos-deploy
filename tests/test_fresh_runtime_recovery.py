"""Offline contracts for fresh runtime recovery; never launches native tools."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from scripts import fresh_runtime_recovery as recovery


class FreshRuntimeRecoveryTests(unittest.TestCase):
    def table_fixture(self):
        tables = [f"fixture_{number:02d}" for number in range(27)]
        rows = [{"table": table, "count": 0, "sha256": "a" * 64} for table in tables]
        return tables, rows

    def test_all_table_fingerprints_are_required_and_exactly_bound(self):
        tables, rows = self.table_fixture()
        encoded = "\n".join(json.dumps(row) for row in rows)
        self.assertEqual(recovery.parse_table_digests(encoded, tables), rows)
        for bad in (
            [],
            rows[:-1],
            rows + rows[:1],
            [rows[0]] * 27,
            list(reversed(rows)),
            [{**row, "count": True} for row in rows],
            [{**row, "count": -1} for row in rows],
            [{**row, "sha256": "not-a-hash"} for row in rows],
            [{**row, "extra": 1} for row in rows],
        ):
            with self.subTest(bad=bad), self.assertRaises(recovery.Rejected):
                recovery.parse_table_digests(
                    "\n".join(json.dumps(row) for row in bad), tables
                )

    def test_one_result_select_covers_all_tables_in_one_connection(self):
        tables, _ = self.table_fixture()
        query = recovery.full_table_query(tables)
        self.assertEqual(query.count(" UNION ALL "), 26)
        self.assertEqual(query.count("WITH row_hashes AS MATERIALIZED"), 27)
        self.assertEqual(query.count(";"), 1)
        self.assertTrue(query.startswith("SELECT fingerprint FROM ("))
        self.assertNotIn("COMMIT", query)
        for bad in (tables[:-1], [tables[0]] * 27, [*tables[:-1], 'unsafe"; DROP']):
            with self.subTest(tables=bad), self.assertRaises(recovery.Rejected):
                recovery.full_table_query(bad)
        controller = object.__new__(recovery.Controller)
        controller.owned = {"isolated": []}
        calls = []
        controller.docker = lambda args, **kwargs: calls.append((args, kwargs)) or ""
        controller.sql("isolated", "clone", ["BEGIN;", query, "COMMIT;"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            [arg for arg in calls[0][0] if arg.startswith("--command=")],
            ["--command=BEGIN;", "--command=" + query, "--command=COMMIT;"],
        )

    def test_linux_watchdog_has_fixed_own_pid1_target(self):
        self.assertEqual(recovery.WATCHDOG, "(sleep 1500; kill -TERM 1) &\n")
        self.assertEqual(recovery.SECONDS, 1500)

    def test_cold_fingerprint_rejects_upstream_pipeline_errors(self):
        self.assertTrue(recovery.FINGERPRINT.startswith("set -eu\nset -o pipefail\n"))
        self.assertIn("cluster_state=$(pg_controldata", recovery.FINGERPRINT)

    def test_supervisor_keeps_existing_git_identity_without_provider_secrets(self):
        with patch.dict(
            recovery.os.environ,
            {
                "USERPROFILE": "fixture-profile",
                "PATH": "fixture-bin",
                "OPENAI_API_KEY": "synthetic-do-not-inherit",
                "HTTPS_PROXY": "synthetic-do-not-inherit",
            },
            clear=True,
        ):
            self.assertEqual(
                recovery.supervisor_environment(),
                {"USERPROFILE": "fixture-profile", "PATH": "fixture-bin"},
            )

    def test_public_compose_plugin_config_contains_no_auth_or_shared_context(self):
        self.assertEqual(
            recovery.auth_free_docker_config(),
            {
                "cliPluginsExtraDirs": [
                    "C:/Program Files/Docker/Docker/resources/cli-plugins"
                ]
            },
        )

    def test_copy_compose_projection_matches_bounded_readonly_container(self):
        value = recovery.source_copy_compose(
            "a" * 32, "isolated-copy", Path("D:/owned"), "exec postgres $public_setting"
        )
        service = value["services"]["timescaledb"]
        self.assertEqual(service["image"], recovery.IMAGE)
        self.assertEqual(service["network_mode"], "none")
        self.assertTrue(service["read_only"])
        self.assertEqual(service["cap_drop"], ["ALL"])
        self.assertEqual(service["mem_limit"], "4g")
        self.assertEqual(service["memswap_limit"], "4g")
        self.assertEqual(service["command"], ["-c", "exec postgres $$public_setting"])
        self.assertTrue(service["volumes"][0]["read_only"])
        self.assertNotIn("environment", service)

    def test_copy_directory_times_are_restored_deepest_first(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.tar"
            with tarfile.open(path, "w") as archive:
                for name in (".", "./base", "./base/123"):
                    item = tarfile.TarInfo(name)
                    item.type = tarfile.DIRTYPE
                    item.mtime = 1791102419
                    archive.addfile(item)
            text = recovery.directory_times_script(path)
            self.assertLess(text.index("./base/123"), text.index(" ./base\n"))
            self.assertIn("export TZ=UTC", text)

    def test_cold_archive_member_escape_and_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, kind in (
                ("../escape", tarfile.DIRTYPE),
                ("/absolute", tarfile.DIRTYPE),
                ("./pg_wal/link", tarfile.SYMTYPE),
            ):
                path = Path(directory) / (str(len(name)) + str(kind) + ".tar")
                with tarfile.open(path, "w") as archive:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    archive.addfile(item)
                with self.subTest(name=name), self.assertRaises(recovery.Rejected):
                    recovery.directory_times_script(path)

    def make_manifest(self, directory: Path) -> tuple[dict, Path]:
        project = "kairos-recovery-copy-a1b2c3d4e5f6"
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dump = directory / f"{project}-{stamp}.dump"
        dump.write_bytes(b"PGDMP-offline-fixture")
        checkpoints = dict.fromkeys(recovery.CHECKPOINTS, 0)
        checkpoints["event_audit"] = 1
        value = {
            "schema_version": 1,
            "created_at_utc": datetime.now(UTC).isoformat(),
            "compose_project": project,
            "database": "kairos",
            "file": dump.name,
            "bytes": dump.stat().st_size,
            "sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
            "checkpoints": checkpoints,
            "timescaledb_bgw_owners": ["kairos"],
        }
        return value, dump

    def test_default_plan_does_not_construct_native_controller(self) -> None:
        output = io.StringIO()
        with (
            patch.object(
                recovery,
                "Controller",
                side_effect=AssertionError("native controller constructed"),
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(recovery.main([]), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["result"], "PLAN_ONLY")
        self.assertIs(plan["primary_start"], False)
        self.assertIs(plan["consumers"], False)

    def test_manifest_accepts_exact_official_shape_and_pgdmp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, dump = self.make_manifest(Path(directory))
            recovery.validate_manifest(manifest, dump, manifest["compose_project"])

    def test_manifest_rejects_missing_or_extra_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, dump = self.make_manifest(Path(directory))
            for bad in (
                {
                    key: value
                    for key, value in manifest.items()
                    if key != "created_at_utc"
                },
                {**manifest, "unexpected": "field"},
            ):
                with self.subTest(keys=set(bad)), self.assertRaises(recovery.Rejected):
                    recovery.validate_manifest(bad, dump, manifest["compose_project"])

    def test_manifest_rejects_bad_identity_hash_size_and_owner_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, dump = self.make_manifest(Path(directory))
            invalid = (
                {**manifest, "schema_version": True},
                {**manifest, "compose_project": "kairos-paper-gate"},
                {**manifest, "database": "other"},
                {**manifest, "file": "different.dump"},
                {**manifest, "bytes": True},
                {**manifest, "sha256": "0" * 64},
                {**manifest, "timescaledb_bgw_owners": "kairos"},
                {**manifest, "timescaledb_bgw_owners": ["kairos", "other"]},
            )
            for bad in invalid:
                with self.subTest(manifest=bad), self.assertRaises(recovery.Rejected):
                    recovery.validate_manifest(bad, dump, manifest["compose_project"])

    def test_manifest_rejects_incomplete_extra_or_invalid_checkpoints(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, dump = self.make_manifest(Path(directory))
            bad_checkpoints = (
                {},
                {**manifest["checkpoints"], "not_a_table": 0},
                {
                    key: value
                    for key, value in manifest["checkpoints"].items()
                    if key != "message_inbox"
                },
                {**manifest["checkpoints"], "event_audit": True},
                {**manifest["checkpoints"], "event_audit": -1},
                {**manifest["checkpoints"], "event_audit": 0},
            )
            for checkpoints in bad_checkpoints:
                with (
                    self.subTest(checkpoints=checkpoints),
                    self.assertRaises(recovery.Rejected),
                ):
                    recovery.validate_manifest(
                        {**manifest, "checkpoints": checkpoints},
                        dump,
                        manifest["compose_project"],
                    )

    def test_manifest_rejects_stale_or_malformed_timestamp_and_filename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, dump = self.make_manifest(Path(directory))
            for created in ("not-a-timestamp", "2000-01-01T00:00:00Z"):
                with (
                    self.subTest(created=created),
                    self.assertRaises(recovery.Rejected),
                ):
                    recovery.validate_manifest(
                        {**manifest, "created_at_utc": created},
                        dump,
                        manifest["compose_project"],
                    )
            with self.assertRaises(recovery.Rejected):
                recovery.validate_manifest(
                    {**manifest, "file": "unbound.dump"},
                    dump,
                    manifest["compose_project"],
                )

    def test_manifest_rejects_non_custom_archive_magic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest, dump = self.make_manifest(Path(directory))
            dump.write_bytes(b"not-a-pg-dump")
            manifest["bytes"] = dump.stat().st_size
            manifest["sha256"] = hashlib.sha256(dump.read_bytes()).hexdigest()
            with self.assertRaises(recovery.Rejected):
                recovery.validate_manifest(manifest, dump, manifest["compose_project"])

    def test_integrity_state_accepts_clean_and_rejects_corruption(self) -> None:
        value = {
            "inbox_failed": 0,
            "inbox_processing": 0,
            "pending": 10,
            "dead_lettered": 0,
            "active_leases": 0,
            "expired_leases": 1,
            "duplicate_audit": 0,
            "duplicate_outbox": 0,
            "orphan_outbox": 0,
            "effects": 0,
            "trades": 0,
            "invalid_indexes": 0,
            "unvalidated_constraints": 0,
        }
        recovery.validate_state(value)
        for field in (
            "inbox_failed",
            "inbox_processing",
            "dead_lettered",
            "active_leases",
            "duplicate_audit",
            "duplicate_outbox",
            "orphan_outbox",
            "invalid_indexes",
            "unvalidated_constraints",
        ):
            with self.subTest(field=field), self.assertRaises(recovery.Rejected):
                recovery.validate_state({**value, field: 1})
        for bad in (True, 1.0, -1, "1"):
            with self.subTest(bad=bad), self.assertRaises(recovery.Rejected):
                recovery.validate_state({**value, "pending": bad})

    def test_bars_require_five_ordered_contiguous_symbol_prefixes(self) -> None:
        symbols = ("BNBUSDT", "BTCUSDT", "ETHUSDT", "SOLUSDT", "XRPUSDT")
        rows = [
            {"symbol": symbol, "count": 2, "first": 0, "last": 60000, "gaps": 0}
            for symbol in symbols
        ]
        recovery.validate_bars(rows)
        invalid = (
            rows[:-1],
            list(reversed(rows)),
            [{**row, "last": 120000} for row in rows],
            [{**row, "gaps": 1} for row in rows],
            [{**row, "count": True} for row in rows],
        )
        for candidate in invalid:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(recovery.Rejected),
            ):
                recovery.validate_bars(candidate)

    def test_mount_identity_normalizes_windows_and_docker_desktop_aliases(self) -> None:
        expected = "d:/kairos/backups/restore.dump"
        for path in (
            r"D:\Kairos\backups\restore.dump",
            "D:/Kairos/backups/restore.dump",
            "/run/desktop/mnt/host/d/Kairos/backups/restore.dump",
            "/host_mnt/d/Kairos/backups/restore.dump",
        ):
            with self.subTest(path=path):
                self.assertEqual(recovery.mount_identity(path), expected)
        self.assertNotEqual(
            recovery.mount_identity("/other-host/d/Kairos/backups/restore.dump"),
            expected,
        )

    def test_mount_identity_rejects_parent_traversal(self) -> None:
        for path in ("D:/Kairos/../escape.dump", "/host_mnt/d/Kairos/../escape.dump"):
            with self.subTest(path=path), self.assertRaises(recovery.Rejected):
                recovery.mount_identity(path)

    def test_process_tree_proof_requires_assignment_and_verified_cleanup(self) -> None:
        good = {
            "assigned_before_resume": True,
            "tree_cleanup_verified": True,
            "active_owned_processes_after": 0,
        }
        self.assertIsNone(recovery.require_tree_proof(good))
        invalid = (
            {**good, "assigned_before_resume": False},
            {**good, "tree_cleanup_verified": False},
            {**good, "active_owned_processes_after": 1},
            {**good, "active_owned_processes_after": True},
            {
                key: value
                for key, value in good.items()
                if key != "tree_cleanup_verified"
            },
        )
        for proof in invalid:
            with self.subTest(proof=proof), self.assertRaises(recovery.Rejected):
                recovery.require_tree_proof(proof)


if __name__ == "__main__":
    unittest.main()
