"""Local-only regression tests for primary temporary-file cleanup proofs."""

from __future__ import annotations

import contextlib
import hashlib
import inspect
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import controlled_runtime_primary as primary

OWNER = "a" * 32
REVISION = "b" * 40


def _controller(root: Path) -> primary.PrimaryController:
    controller = object.__new__(primary.PrimaryController)
    controller.owner = OWNER
    controller.revision = REVISION
    controller.work = root
    controller.remote_owned_files = {}
    controller.remote_create_intents = {}
    controller.assert_primary_target = mock.Mock()
    controller._require_remote_absent = mock.Mock()
    controller.docker = mock.Mock(return_value="")
    return controller


def _intent(
    controller: primary.PrimaryController, purpose: str, source: Path | None = None
):
    controller._reserve_remote_file(purpose, local_sql=source)
    path, _ = primary.remote_artifact_specs(OWNER)[purpose]
    return path, controller.remote_create_intents[path]


class RemoteCreateIntentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.controller = _controller(self.root)

    def test_safe_paths_accept_missing_windows_attributes(self) -> None:
        metadata = SimpleNamespace(st_mode=self.root.stat().st_mode)
        with mock.patch.object(Path, "lstat", return_value=metadata):
            self.assertEqual(primary.fresh.safe(self.root), self.root.absolute())

    def test_safe_paths_reject_links_and_windows_reparse_attributes(self) -> None:
        with (
            mock.patch.object(Path, "is_symlink", return_value=True),
            self.assertRaisesRegex(primary.fresh.Rejected, "REPARSE_PATH_REJECTED"),
        ):
            primary.fresh.safe(self.root)
        metadata = SimpleNamespace(
            st_mode=self.root.stat().st_mode, st_file_attributes=0x400
        )
        with (
            mock.patch.object(Path, "lstat", return_value=metadata),
            self.assertRaisesRegex(primary.fresh.Rejected, "REPARSE_PATH_REJECTED"),
        ):
            primary.fresh.safe(self.root)

    def test_intent_is_durable_before_sql_copy_and_backup_dump(self) -> None:
        sql = self.root / "provision.sql"
        sql.write_bytes(b"synthetic SQL fixture")
        remote_sql, _ = primary.remote_artifact_specs(OWNER)["provision-sql"]
        seen: list[dict] = []

        def docker(args, **_kwargs):
            if args[0] == "cp":
                record = json.loads(
                    (self.root / "remote-create-provision-sql.json").read_text()
                )
                seen.append(record)
            if "sha256sum" in args:
                return f"{hashlib.sha256(sql.read_bytes()).hexdigest()}  {remote_sql}"
            return ""

        self.controller.docker.side_effect = docker
        self.controller._copy_sql(sql, remote_sql)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["remote_path"], remote_sql)
        self.assertEqual(seen[0]["expected_bytes"], len(sql.read_bytes()))
        self.assertTrue((self.root / "remote-create-provision-sql.json").is_file())

        # The backup caller reserves before issuing pg_dump; its create-only
        # record contains no dump contents or guessed digest.
        backup, _ = _intent(self.controller, "backup-after")
        record = json.loads((self.root / "remote-create-backup-after.json").read_text())
        self.assertEqual(record["remote_path"], backup)
        self.assertIsNone(record["expected_sha256"])
        self.assertIsNone(record["expected_bytes"])
        self.assertEqual(record["maximum_bytes"], primary.MAX_PRIMARY_TEMP_BYTES)
        source = inspect.getsource(primary.PrimaryController.run)
        self.assertLess(
            source.index('self._reserve_remote_file("backup-after")'),
            source.index('"pg_dump"'),
        )

    def test_failure_after_copy_keeps_durable_intent_for_cleanup(self) -> None:
        sql = self.root / "provision.sql"
        sql.write_bytes(b"synthetic SQL fixture")
        remote_sql, _ = primary.remote_artifact_specs(OWNER)["provision-sql"]
        calls: list[list[str]] = []

        def docker(args, **_kwargs):
            calls.append(args)
            if args[0] == "exec" and "chown" in args:
                raise primary.fresh.Rejected("fixture chown failure")
            return ""

        self.controller.docker.side_effect = docker
        with self.assertRaises(primary.fresh.Rejected):
            self.controller._copy_sql(sql, remote_sql)
        self.assertEqual(calls[0][0], "cp")
        self.assertIn(remote_sql, self.controller.remote_create_intents)
        evidence = primary.remote_artifact_cleanup_evidence(self.root, OWNER, REVISION)
        self.assertFalse(evidence["verified"])
        self.assertEqual(evidence["pending_purposes"], ["provision-sql"])

    def test_successful_copy_cleanup_records_owned_bytes_removed(self) -> None:
        data = b"synthetic SQL"
        sql = self.root / "provision.sql"
        sql.write_bytes(data)
        remote, _ = _intent(self.controller, "provision-sql", sql)
        state = f"1:2:{len(data)}:999:1:81a4"
        self.controller._remote_file_state = mock.Mock(side_effect=[state, state])
        self.controller.docker.side_effect = [
            "999",
            f"{hashlib.sha256(data).hexdigest()}  {remote}",
            "",
        ]
        self.controller._remove_owned_container_file(remote)
        evidence = primary.remote_artifact_cleanup_evidence(self.root, OWNER, REVISION)
        self.assertTrue(evidence["verified"])
        self.assertEqual(evidence["completed_count"], 1)
        self.assertNotIn(remote, self.controller.remote_create_intents)

    def test_absent_file_cleanup_is_verified_idempotently(self) -> None:
        sql = self.root / "provision.sql"
        sql.write_bytes(b"synthetic SQL")
        remote, _ = _intent(self.controller, "provision-sql", sql)
        self.controller._remote_file_state = mock.Mock(return_value="ABSENT")
        self.controller._remove_owned_container_file(remote)
        evidence = primary.remote_artifact_cleanup_evidence(self.root, OWNER, REVISION)
        self.assertTrue(evidence["verified"])
        removal = json.loads(
            (self.root / "remote-remove-provision-sql.json").read_text()
        )
        self.assertEqual(removal["outcome"], "ABSENT")
        self.assertIsNone(removal["observed_sha256"])

    def test_exact_partial_sql_prefix_is_removable(self) -> None:
        data = b"synthetic SQL fixture"
        sql = self.root / "provision.sql"
        sql.write_bytes(data)
        remote, _ = _intent(self.controller, "provision-sql", sql)
        partial = data[:7]
        state = f"4:9:{len(partial)}:0:1:81a4"
        self.controller._remote_file_state = mock.Mock(side_effect=[state, state])
        self.controller.docker.side_effect = [
            "999",
            f"{hashlib.sha256(partial).hexdigest()}  {remote}",
            "",
        ]
        self.controller._remove_owned_container_file(remote)
        removal = json.loads(
            (self.root / "remote-remove-provision-sql.json").read_text()
        )
        self.assertEqual(removal["outcome"], "OWNED_BYTES_REMOVED")
        self.assertEqual(removal["observed_bytes"], len(partial))

    def test_foreign_bytes_symlink_directory_uid_size_and_change_are_refused(
        self,
    ) -> None:
        data = b"synthetic SQL fixture"
        sql = self.root / "provision.sql"
        sql.write_bytes(data)
        remote, _ = _intent(self.controller, "provision-sql", sql)
        cases = (
            ("foreign bytes", f"1:2:{len(data)}:999:1:81a4", "0" * 64, ["999"]),
            ("symlink", "SYMLINK", None, []),
            ("directory", "DIRECTORY", None, []),
            ("foreign uid", f"1:2:{len(data)}:1234:1:81a4", None, ["999"]),
            ("oversize", f"1:2:{len(data) + 1}:999:1:81a4", None, ["999"]),
        )
        for label, state, digest, responses in cases:
            with self.subTest(label=label):
                self.controller.docker.reset_mock()
                self.controller.docker.side_effect = responses
                self.controller._remote_file_state = mock.Mock(return_value=state)
                if digest is not None:
                    self.controller.docker.side_effect = [
                        "999",
                        f"{digest}  {remote}",
                    ]
                with self.assertRaises(primary.fresh.Rejected):
                    self.controller._remove_owned_container_file(remote)
                self.assertFalse(
                    any(
                        call.args[0][0:4]
                        == ["exec", "--user=0", primary.fresh.SOURCE, "rm"]
                        for call in self.controller.docker.call_args_list
                    )
                )

        initial = f"1:2:{len(data)}:999:1:81a4"
        changed = f"1:3:{len(data)}:999:1:81a4"
        self.controller.docker.reset_mock()
        self.controller._remote_file_state = mock.Mock(side_effect=[initial, changed])
        self.controller.docker.side_effect = [
            "999",
            f"{hashlib.sha256(data).hexdigest()}  {remote}",
        ]
        with self.assertRaises(primary.fresh.Rejected):
            self.controller._remove_owned_container_file(remote)

    def test_partial_pgdmp_is_removed_and_non_pgdmp_is_rejected(self) -> None:
        remote, _ = _intent(self.controller, "backup-after")
        state = "1:2:3:999:1:81a4"
        self.controller._remote_file_state = mock.Mock(side_effect=[state, state])
        self.controller.docker.side_effect = [
            "999",
            "a" * 64 + "  " + remote,
            "PGD",
            "",
        ]
        self.controller._remove_owned_container_file(remote)
        evidence = primary.remote_artifact_cleanup_evidence(self.root, OWNER, REVISION)
        self.assertTrue(evidence["verified"])

        # A new run-scoped fixture models a file not proven to be a PGDMP dump.
        other = _controller(self.root / "other")
        other.work.mkdir()
        remote, _ = _intent(other, "backup-after")
        other._remote_file_state = mock.Mock(side_effect=[state])
        other.docker.side_effect = ["999", "b" * 64 + "  " + remote, "OTHER"]
        with self.assertRaises(primary.fresh.Rejected):
            other._remove_owned_container_file(remote)

    def test_intent_and_removal_journal_reject_owner_revision_hash_and_purpose_changes(
        self,
    ) -> None:
        sql = self.root / "provision.sql"
        sql.write_bytes(b"synthetic SQL")
        remote, _ = _intent(self.controller, "provision-sql", sql)
        intent_path = self.root / "remote-create-provision-sql.json"
        original = json.loads(intent_path.read_text())
        for field, value in (
            ("owner", "c" * 32),
            ("expected_revision", "d" * 40),
            ("expected_sha256", "not-a-sha"),
            ("purpose", "unknown-purpose"),
        ):
            with self.subTest(field=field):
                changed = dict(original)
                changed[field] = value
                intent_path.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaises(primary.fresh.Rejected):
                    primary.remote_artifact_cleanup_evidence(self.root, OWNER, REVISION)
                intent_path.write_text(
                    json.dumps(original, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8",
                )

        # Use a fresh controller/journal after the tampering cases so its
        # in-memory immutable intent hash matches the on-disk bytes.
        clean_root = self.root / "clean"
        clean_root.mkdir()
        clean = _controller(clean_root)
        clean_sql = clean_root / "provision.sql"
        clean_sql.write_bytes(b"synthetic SQL")
        remote, _ = _intent(clean, "provision-sql", clean_sql)
        clean._remote_file_state = mock.Mock(return_value="ABSENT")
        clean._remove_owned_container_file(remote)
        removal_path = clean_root / "remote-remove-provision-sql.json"
        removal = json.loads(removal_path.read_text())
        removal["create_intent_sha256"] = "0" * 64
        removal_path.write_text(json.dumps(removal), encoding="utf-8")
        with self.assertRaises(primary.fresh.Rejected):
            primary.remote_artifact_cleanup_evidence(clean_root, OWNER, REVISION)

    def test_unknown_intent_record_file_is_rejected(self) -> None:
        (self.root / "remote-create-unknown-purpose.json").write_text(
            "{}", encoding="utf-8"
        )
        with self.assertRaises(primary.fresh.Rejected):
            primary.remote_artifact_cleanup_evidence(self.root, OWNER, REVISION)

    def test_pending_intent_is_unverified_and_supervisor_refuses_pass(self) -> None:
        sql = self.root / "provision.sql"
        sql.write_bytes(b"synthetic SQL")
        _intent(self.controller, "provision-sql", sql)
        evidence = primary.remote_artifact_cleanup_evidence(self.root, OWNER, REVISION)
        self.assertFalse(evidence["verified"])
        self.assertEqual(evidence["pending_purposes"], ["provision-sql"])

        # The supervisor independently checks this same evidence before it
        # validates a successful child receipt.
        root = self.root / "root"
        root.mkdir()
        run = root / ("primary-run-" + OWNER)
        run.mkdir()
        for name in ("remote-create-provision-sql.json",):
            (run / name).write_bytes((self.root / name).read_bytes())
        old_root = primary.current.ROOT
        primary.current.ROOT = root
        self.addCleanup(setattr, primary.current, "ROOT", old_root)
        context_holder = {}

        def make_context(directory):
            directory.mkdir()
            context_holder["work"] = directory
            return SimpleNamespace(work=directory)

        job = SimpleNamespace(
            creation_flags=0,
            attach_and_resume=lambda _child: None,
            finish=lambda _child, cancel: {
                "assigned_before_resume": True,
                "tree_cleanup_verified": True,
                "active_owned_processes_after": 0,
            },
            close=lambda: None,
        )
        child_receipt = run / "primary-receipt.json"
        child_receipt.write_text("{}", encoding="utf-8")

        class Child:
            pid = 123
            returncode = 0

            def poll(self):
                return self.returncode

        def popen(_args, **kwargs):
            kwargs["stdout"].write(json.dumps({"receipt": str(child_receipt)}).encode())
            return Child()

        args = SimpleNamespace(
            supervisor_directory=None,
            clone_directory=root / ("run-" + OWNER),
            clone_supervisor_directory=root / ("supervisor-" + "f" * 32),
            expected_revision=REVISION,
            wheelhouse=root,
        )
        (root / ("run-" + OWNER)).mkdir()
        output = io.StringIO()
        with (
            mock.patch.object(primary, "SupervisorContext", side_effect=make_context),
            mock.patch.object(
                primary.fresh.bounded,
                "_job_module",
                return_value=SimpleNamespace(WindowsProcessJob=lambda: job),
            ),
            mock.patch.object(primary.subprocess, "Popen", side_effect=popen),
            mock.patch.object(
                primary, "_supervisor_stop_if_started", return_value=True
            ),
            mock.patch.object(primary.time, "sleep"),
            contextlib.redirect_stdout(output),
        ):
            code = primary.supervise_primary(args)
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        receipt = json.loads(Path(result["receipt"]).read_text())
        self.assertEqual(receipt["result"], "FAILED_CLOSED")
        self.assertFalse(receipt["remote_artifact_cleanup"]["verified"])

    def test_cleanup_continues_after_one_file_failure_and_stops_primary(self) -> None:
        # Use complete persisted intents but mock remote execution; no Docker API is called.
        for purpose in ("provision-sql", "cleanup-sql"):
            source = self.root / primary.remote_artifact_specs(OWNER)[purpose][1]
            source.write_bytes(b"synthetic SQL")
            _intent(self.controller, purpose, source)
        paths = list(self.controller.remote_create_intents)
        self.controller.started_source = True
        self.controller.provision_attempted = False
        self.controller.worker_cleanup_verified = True
        self.controller.proofs = {}
        self.controller.inspect = mock.Mock(
            return_value={
                "id": primary.fresh.SOURCE_ID,
                "image": primary.fresh.IMAGE_ID,
                "state": {"Status": "running"},
            }
        )
        self.controller.assert_primary_target = mock.Mock()
        cleanup_calls: list[str] = []

        def remove(path):
            cleanup_calls.append(path)
            if path == paths[0]:
                raise primary.fresh.Rejected("fixture cleanup refusal")
            self.controller.remote_create_intents.pop(path, None)

        self.controller._remove_owned_container_file = remove
        self.controller.docker = mock.Mock(return_value="")
        self.controller.assert_primary_stopped = mock.Mock()
        with self.assertRaises(primary.fresh.Rejected):
            self.controller.cleanup_primary()
        self.assertEqual(cleanup_calls, paths)
        self.assertTrue(
            any(
                call.args[0] == ["stop", "--time=30", primary.fresh.SOURCE]
                for call in self.controller.docker.call_args_list
            )
        )
        self.assertFalse(self.controller.started_source)


if __name__ == "__main__":
    unittest.main()
