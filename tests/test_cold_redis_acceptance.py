"""Offline boundary tests for cold Redis clone acceptance inspection."""

from __future__ import annotations

import hashlib
import io
import json
import runpy
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Self
from unittest import mock

from scripts import cold_redis_acceptance as cold


def _bulk(value: bytes) -> bytes:
    return b"$" + str(len(value)).encode("ascii") + b"\r\n" + value + b"\r\n"


def _array(values: list[bytes]) -> bytes:
    return b"*" + str(len(values)).encode("ascii") + b"\r\n" + b"".join(values)


def _entry(stream_id: str, payload: dict[str, object]) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    fields = _array([_bulk(b"data"), _bulk(encoded)])
    return _array([_bulk(stream_id.encode()), fields])


class _FakeConnection:
    def __init__(self, replies: list[bytes]) -> None:
        self.replies = bytearray(b"".join(replies))
        self.commands: list[bytes] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def settimeout(self, _seconds: float) -> None:
        return None

    def sendall(self, request: bytes) -> None:
        self.commands.append(request)

    def recv(self, size: int) -> bytes:
        chunk = bytes(self.replies[:size])
        del self.replies[:size]
        return chunk


class ColdRedisAcceptanceTests(unittest.TestCase):
    @staticmethod
    def _worker_rejection(
        *,
        stage: str = "copy_tree",
        exception_class: str = "PermissionError",
        **extra: object,
    ) -> str:
        return json.dumps(
            {
                "state": "COPY_REJECTED",
                "error": cold.WORKER_REJECTION_ERROR,
                "stage": stage,
                "exception_class": exception_class,
                "error_code": None,
                "diagnostic": None,
                **extra,
            }
        )

    @staticmethod
    def _git_results(
        *,
        revision: str = "a" * 40,
        branch: str = "main",
        signature: int = 0,
        tracked: int = 0,
        unchanged: int = 0,
    ) -> list[mock.Mock]:
        return [
            mock.Mock(returncode=0, stdout=revision + "\n"),
            mock.Mock(returncode=0, stdout=branch + "\n"),
            mock.Mock(returncode=signature, stdout=""),
            mock.Mock(returncode=tracked, stdout=""),
            mock.Mock(returncode=unchanged, stdout=""),
        ]

    def _verify_git_results(self, results: list[mock.Mock]) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            scripts = repository / "scripts"
            scripts.mkdir(parents=True)
            script = scripts / "cold_redis_acceptance.py"
            script.write_text("committed source", encoding="utf-8")
            with (
                mock.patch.object(cold, "__file__", str(script)),
                mock.patch.object(cold.subprocess, "run", side_effect=results),
            ):
                cold._verify_deploy_head("a" * 40)

    def test_deploy_verification_uses_one_exact_git_prefix_and_sanitized_env(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            scripts = repository / "scripts"
            scripts.mkdir(parents=True)
            script = scripts / "cold_redis_acceptance.py"
            script.write_text("committed source", encoding="utf-8")
            environment = {
                "SYSTEMROOT": "system-root",
                "WINDIR": "windows-root",
                "TEMP": "temp-dir",
                "TMP": "tmp-dir",
                "PATH": cold.os.environ.get("PATH", ""),
                "HOME": "must-not-be-inherited",
                "GIT_CONFIG_GLOBAL": "must-not-be-inherited",
            }
            with (
                mock.patch.object(cold, "__file__", str(script)),
                mock.patch.dict(cold.os.environ, environment, clear=True),
                mock.patch.object(
                    cold.subprocess,
                    "run",
                    side_effect=self._git_results(),
                ) as run,
            ):
                cold._verify_deploy_head("a" * 40)

            expected_prefix = cold._git_command_prefix(repository)
            self.assertEqual(run.call_count, 5)
            for call in run.call_args_list:
                arguments = call.args[0]
                self.assertEqual(arguments[: len(expected_prefix)], expected_prefix)
                self.assertEqual(call.kwargs["cwd"], repository.resolve())
                self.assertEqual(
                    call.kwargs["env"],
                    {
                        key: value
                        for key, value in environment.items()
                        if key in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH"}
                    },
                )
                self.assertFalse(call.kwargs["shell"])
            self.assertIn(
                f"safe.directory={repository.resolve().as_posix()}", expected_prefix
            )
            self.assertTrue(
                any(item.startswith("gpg.program=") for item in expected_prefix)
            )
            if cold.os.name == "nt":
                self.assertEqual(expected_prefix[0], str(cold.WINDOWS_GIT))
                self.assertEqual(
                    expected_prefix[-1], f"gpg.program={cold.WINDOWS_GPG.as_posix()}"
                )
            else:
                self.assertFalse(
                    any("Program Files" in item for item in expected_prefix)
                )

    def test_deploy_verification_rejects_bad_signature_branch_revision_and_source(
        self,
    ) -> None:
        cases = (
            ("signature", self._git_results(signature=1)),
            ("branch", self._git_results(branch="feature")),
            ("revision", self._git_results(revision="b" * 40)),
            ("untracked", self._git_results(tracked=1)),
            ("changed", self._git_results(unchanged=1)),
        )
        for label, results in cases:
            with self.subTest(label=label), self.assertRaises(cold.ColdRedisError):
                self._verify_git_results(results)

    def test_script_snapshot_change_blocks_native_work_before_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot.py"
            snapshot.write_bytes(b"signed implementation")
            native = mock.Mock()
            native.call.return_value = (0, "metadata")
            docker = cold.BoundedDocker(
                root,
                cold.time.monotonic() + 10,
                native,
                script_snapshot=snapshot,
                script_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
            )
            snapshot.write_bytes(b"changed implementation")
            with self.assertRaises(cold.ColdRedisError):
                docker.call(["inspect", "owned-fixture"])
            native.call.assert_not_called()

    def test_cleanup_has_a_reserved_bounded_interval_after_work_exhaustion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            native = mock.Mock()
            native.call.return_value = (0, "removed")
            work_deadline = cold.time.monotonic() - 1
            docker = cold.BoundedDocker(Path(temporary), work_deadline, native)
            with self.assertRaises(cold.ColdRedisError):
                docker.call(["inspect", "owned-fixture"])
            docker.begin_cleanup()
            self.assertEqual(docker.deadline, work_deadline + cold.CLEANUP_SECONDS)
            self.assertEqual(docker.call(["inspect", "owned-fixture"]), "removed")

    def test_worker_permission_rejection_is_staged_and_secret_free(self) -> None:
        data = mock.Mock()
        data.iterdir.return_value = iter(())
        output = io.StringIO()
        with (
            mock.patch.object(cold, "Path", return_value=data),
            mock.patch.object(
                cold.os,
                "chown",
                side_effect=PermissionError("secret /data path payload"),
                create=True,
            ),
            redirect_stdout(output),
        ):
            result = cold._copy_worker("prepare-target")

        rejection = json.loads(output.getvalue())
        self.assertEqual(result, 1)
        self.assertEqual(set(rejection), cold.WORKER_REJECTION_FIELDS)
        self.assertEqual(rejection["state"], "COPY_REJECTED")
        self.assertEqual(rejection["error"], cold.WORKER_REJECTION_ERROR)
        self.assertEqual(rejection["stage"], "prepare_target_chown")
        self.assertEqual(rejection["exception_class"], "PermissionError")
        self.assertNotIn("secret", output.getvalue())
        self.assertNotIn("/data", output.getvalue())
        data.chmod.assert_called_once_with(0o700)

    def test_copy_tree_permission_rejection_has_allowlisted_stage(self) -> None:
        source, target = mock.Mock(), mock.Mock()
        target.iterdir.return_value = iter(())
        output = io.StringIO()
        with (
            mock.patch.object(cold, "Path", side_effect=[source, target]),
            mock.patch.object(
                cold,
                "_manifest_tree",
                return_value={"file_count": 1, "total_bytes": 1},
            ),
            mock.patch.object(cold, "_persistence_layout", return_value={}),
            mock.patch.object(
                cold,
                "_copy_tree",
                side_effect=PermissionError("private path must not be emitted"),
            ),
            redirect_stdout(output),
        ):
            result = cold._copy_worker("copy-hash")

        rejection = json.loads(output.getvalue())
        self.assertEqual(result, 1)
        self.assertEqual(rejection["stage"], "copy_tree")
        self.assertEqual(rejection["exception_class"], "PermissionError")
        self.assertNotIn("private path", output.getvalue())

    def test_bounded_worker_start_captures_only_exact_rejection_record(self) -> None:
        owner = "a" * 32
        name = "kairos-cold-redis-copy-" + owner[:12]
        native = mock.Mock()
        native.call.side_effect = [
            (0, "created"),
            (1, self._worker_rejection(stage="copy_tree")),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            docker = cold.BoundedDocker(
                Path(temporary), cold.time.monotonic() + 30, native
            )
            with self.assertRaisesRegex(
                cold.ColdRedisError, "WORKER_REJECTED:copy_tree:PermissionError"
            ):
                cold._run_worker(
                    docker,
                    name=name,
                    owner=owner,
                    mode="copy-hash",
                    source=cold.SOURCE_VOLUME,
                    target="kairos-cold-redis-data-" + owner[:12],
                    user="999:999",
                )

        self.assertEqual(native.call.call_count, 2)
        self.assertFalse(native.call.call_args_list[0].kwargs["allow_failure"])
        self.assertTrue(native.call.call_args_list[1].kwargs["allow_failure"])

    def test_worker_rejection_capture_rejects_malformed_or_unexpected_json(
        self,
    ) -> None:
        owner = "b" * 12
        start = [
            "start",
            "--attach",
            "--interactive",
            "kairos-cold-redis-copy-" + owner,
        ]
        malformed = (
            "{secret token",
            self._worker_rejection(secret="PRIVATE_PAYLOAD"),
            self._worker_rejection(stage="/private/path"),
            self._worker_rejection(exception_class="SecretError"),
            json.dumps(
                {
                    "state": "COPY_VERIFIED",
                    "prepared": True,
                }
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for response in malformed:
                with self.subTest(response=response[:30]):
                    native = mock.Mock()
                    native.call.return_value = (1, response)
                    docker = cold.BoundedDocker(
                        Path(temporary), cold.time.monotonic() + 30, native
                    )
                    with self.assertRaises(cold.ColdRedisError) as raised:
                        docker.call(start, allow_worker_rejection=True)
                    self.assertNotIn("secret", str(raised.exception).lower())
                    self.assertNotIn("PRIVATE_PAYLOAD", str(raised.exception))

    def test_worker_persistence_reason_round_trips_only_safe_metadata(self) -> None:
        diagnostic = {
            "recognized_file_count": 0,
            "entry_count": 1,
            "filename": "appendonly.aof.7.base.rdb",
            "component_type": "base",
            "sequence": 7,
            "manifest_sha256": "a" * 64,
        }
        rejection = json.loads(
            self._worker_rejection(
                stage="copy_persistence_before",
                exception_class="ColdRedisError",
                error_code="COMPONENT_MISSING",
                diagnostic=diagnostic,
            )
        )
        native = mock.Mock()
        native.call.return_value = (1, json.dumps(rejection))
        with tempfile.TemporaryDirectory() as temporary:
            docker = cold.BoundedDocker(
                Path(temporary), cold.time.monotonic() + 30, native
            )
            with self.assertRaises(cold.ColdRedisError) as raised:
                docker.call(
                    [
                        "start",
                        "--attach",
                        "--interactive",
                        "kairos-cold-redis-copy-" + "a" * 12,
                    ],
                    allow_worker_rejection=True,
                )
        self.assertEqual(raised.exception.error_code, "COMPONENT_MISSING")
        self.assertEqual(raised.exception.diagnostic, diagnostic)
        self.assertIn("COMPONENT_MISSING", str(raised.exception))
        self.assertNotIn("PRIVATE", str(raised.exception))

    def test_copy_worker_persistence_error_never_emits_manifest_body(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            target = Path(temporary) / "target"
            source.mkdir()
            target.mkdir()
            (source / "appendonlydir").mkdir()
            (source / "appendonlydir" / "appendonly.aof.manifest").write_text(
                "PRIVATE MANIFEST BODY", encoding="ascii"
            )
            output = io.StringIO()
            with (
                mock.patch.object(cold, "Path", side_effect=[source, target]),
                mock.patch.object(
                    cold,
                    "_manifest_tree",
                    return_value={"file_count": 1, "total_bytes": 1},
                ),
                mock.patch.object(
                    cold,
                    "_persistence_layout",
                    side_effect=cold.ColdRedisError(
                        "sanitized failure",
                        error_code="MANIFEST_ENTRY_UNSUPPORTED",
                        diagnostic={"entry_count": 1, "recognized_file_count": 0},
                    ),
                ),
                redirect_stdout(output),
            ):
                result = cold._copy_worker("copy-hash")
        rejection = json.loads(output.getvalue())
        self.assertEqual(result, 1)
        self.assertEqual(rejection["error_code"], "MANIFEST_ENTRY_UNSUPPORTED")
        self.assertEqual(rejection["stage"], "copy_persistence_before")
        self.assertEqual(rejection["diagnostic"]["entry_count"], 1)
        self.assertNotIn("PRIVATE", output.getvalue())
        self.assertNotIn("BODY", output.getvalue())

    def test_nonzero_success_json_never_passes_and_nonworker_call_cannot_opt_in(
        self,
    ) -> None:
        owner = "c" * 12
        start = [
            "start",
            "--attach",
            "--interactive",
            "kairos-cold-redis-copy-" + owner,
        ]
        success = json.dumps({"state": "COPY_VERIFIED", "prepared": True})
        with tempfile.TemporaryDirectory() as temporary:
            native = mock.Mock()
            native.call.return_value = (1, success)
            docker = cold.BoundedDocker(
                Path(temporary), cold.time.monotonic() + 30, native
            )
            with self.assertRaises(cold.ColdRedisError):
                docker.call(start, allow_worker_rejection=True)

            native.reset_mock()
            with self.assertRaises(cold.ColdRedisError):
                docker.call(["inspect", "owned-fixture"], allow_worker_rejection=True)
            native.call.assert_not_called()

    def test_frozen_linux_worker_imports_without_sibling_deploy_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary) / "cold_redis_acceptance.py"
            snapshot.write_bytes(Path(cold.__file__).read_bytes())
            # Other discovery tests load the host adapter into sys.modules.
            # The single-file Linux snapshot has no such sibling dependency.
            with mock.patch.dict("sys.modules", {"buildkit_resource_gate": None}):
                namespace = runpy.run_path(
                    str(snapshot), run_name="cold_redis_worker_snapshot"
                )
            self.assertIsNone(namespace["bounded"])

    def test_plan_is_non_native_and_bounds_are_explicit(self) -> None:
        plan = cold.plan()
        self.assertEqual(plan["result"], "PLAN_ONLY_NO_NATIVE_CALLS")
        self.assertEqual(plan["clone"]["total_seconds"], 240)
        self.assertEqual(plan["clone"]["xrange_entries_max"], 120_000)
        self.assertEqual(plan["clone"]["xrange_response_bytes_max"], 128 * 1024**2)
        self.assertEqual(
            plan["result_policy"]["zero_matches"], "INCONCLUSIVE_NO_REPLAY"
        )

    def test_default_and_historical_plans_are_distinct_and_side_effect_free(
        self,
    ) -> None:
        output = io.StringIO()
        with (
            redirect_stdout(output),
            mock.patch.object(cold, "execute") as execute,
            mock.patch.object(cold, "_verify_deploy_head") as verify_head,
        ):
            self.assertEqual(cold.main([]), 0)
        execute.assert_not_called()
        verify_head.assert_not_called()
        default_plan = json.loads(output.getvalue())
        self.assertEqual(default_plan["kind"], cold.KIND)
        self.assertEqual(
            default_plan["persistence_identity"],
            "CURRENT_REDIS_PERSISTENCE_DEFAULT",
        )

        historical = cold.plan(historical_rdb_only=True)
        self.assertEqual(historical["kind"], cold.HISTORICAL_RDB_KIND)
        self.assertEqual(
            historical["persistence_identity"],
            "ROOT_DUMP_RDB_HISTORICAL_NOT_CURRENT_STATE",
        )
        self.assertTrue(
            historical["result_policy"]["historical_rdb_positive_is_observational_only"]
        )
        self.assertEqual(
            historical["result_policy"]["one_complete_scan_match"],
            "HISTORICAL_RDB_MATCH_OBSERVED_ONLY",
        )
        self.assertEqual(
            historical["native_execution_requires"], cold.HISTORICAL_RDB_CONFIRMATION
        )
        with self.assertRaises(cold.ColdRedisError):
            cold.plan(historical_rdb_only=1)

    def test_historical_root_rdb_docker_mode_is_readonly_and_explicit(self) -> None:
        current = cold._metadata_only_docker_command(
            "owner", "owned-volume", "owned-redis", cold.SOURCE_IMAGE_ID
        )
        self.assertEqual(current[current.index("--appendonly") + 1], "yes")
        self.assertNotIn("--dbfilename", current)
        self.assertIn("type=volume,src=owned-volume,dst=/data", current)

        historical = cold._metadata_only_docker_command(
            "owner",
            "owned-volume",
            "owned-redis",
            cold.SOURCE_IMAGE_ID,
            historical_rdb_only=True,
        )
        self.assertIn("type=volume,src=owned-volume,dst=/data,readonly", historical)
        self.assertEqual(historical[historical.index("--appendonly") + 1], "no")
        self.assertEqual(historical[historical.index("--dbfilename") + 1], "dump.rdb")
        self.assertEqual(historical[historical.index("--save") + 1], "")
        self.assertIn("--network=none", historical)
        self.assertIn("--read-only", historical)
        self.assertIn("127.0.0.1", historical)

        expected_cmd = historical[historical.index(cold.SOURCE_IMAGE_ID) + 1 :]
        self.assertEqual(expected_cmd[0], "-c")
        self.assertEqual(expected_cmd[expected_cmd.index("--appendonly") + 1], "no")
        self.assertEqual(
            expected_cmd[expected_cmd.index("--dbfilename") + 1], "dump.rdb"
        )

        class InspectDocker:
            def call(self, arguments: list[str], **_kwargs: object) -> str:
                self.asserted = arguments
                return "|".join(
                    (
                        "a" * 64,
                        cold.SOURCE_IMAGE_ID,
                        "false",
                        "none",
                        "true",
                        str(512 * 1024**2),
                        str(512 * 1024**2),
                        "1000000000",
                        "64",
                        json.dumps(
                            [
                                {
                                    "Destination": "/data",
                                    "Name": "owned-volume",
                                    "RW": False,
                                }
                            ]
                        ),
                        json.dumps(
                            {
                                cold.OWNER_LABEL: "owner",
                                cold.SCOPE_LABEL: cold.SCOPE,
                            }
                        ),
                        json.dumps(expected_cmd),
                    )
                )

        inspection = InspectDocker()
        clone = cold._validate_clone_metadata(
            inspection,
            "owned-redis",
            "owned-volume",
            "owner",
            expected_cmd=expected_cmd,
            historical_rdb_only=True,
        )
        self.assertEqual(clone["image_id"], cold.SOURCE_IMAGE_ID)
        self.assertIn(".Config.Cmd", inspection.asserted[2])
        raw = inspection.call([])
        for invalid in (
            raw.replace('"RW": false', '"RW": true'),
            raw.rsplit("|", 1)[0] + "|" + json.dumps(["-c", "redis-server"]),
        ):
            with (
                mock.patch.object(inspection, "call", return_value=invalid),
                self.assertRaises(cold.ColdRedisError),
            ):
                cold._validate_clone_metadata(
                    inspection,
                    "owned-redis",
                    "owned-volume",
                    "owner",
                    expected_cmd=expected_cmd,
                    historical_rdb_only=True,
                )

    def test_historical_root_rdb_requires_bounded_plain_valid_file_and_hashes_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body = b"REDIS0011PRIVATE_RDB_BODY"
            (root / "dump.rdb").write_bytes(body)
            metadata = cold._root_rdb_metadata(root, required=True)
            self.assertEqual(metadata["filename"], "dump.rdb")
            self.assertEqual(metadata["size_bytes"], len(body))
            self.assertEqual(metadata["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(
                metadata["identity"],
                "ROOT_DUMP_RDB_HISTORICAL_NOT_CURRENT_STATE",
            )
            self.assertNotIn("PRIVATE_RDB_BODY", json.dumps(metadata))

            bad = root / "bad"
            bad.mkdir()
            (bad / "dump.rdb").write_bytes(b"PRIVATE_INVALID_RDB")
            with self.assertRaises(cold.ColdRedisError):
                cold._root_rdb_metadata(bad, required=True)

            empty = root / "empty"
            empty.mkdir()
            (empty / "dump.rdb").write_bytes(b"")
            with self.assertRaises(cold.ColdRedisError):
                cold._root_rdb_metadata(empty, required=True)

            with self.assertRaises(cold.ColdRedisError):
                cold._root_rdb_metadata(root / "missing", required=True)
            oversized = root / "oversized"
            oversized.mkdir()
            (oversized / "dump.rdb").write_bytes(b"REDIS0011x")
            with (
                mock.patch.object(cold, "MAX_SOURCE_BYTES", 9),
                self.assertRaises(cold.ColdRedisError),
            ):
                cold._root_rdb_metadata(oversized, required=True)

    def test_historical_lineage_hashes_root_rdb_without_changing_default_aof(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            appendonly = root / "appendonlydir"
            appendonly.mkdir()
            (appendonly / "appendonly.aof.manifest").write_text(
                "file appendonly.aof.1.base.rdb seq 1 type b\n"
                "file appendonly.aof.1.incr.aof seq 1 type i\n",
                encoding="ascii",
            )
            (appendonly / "appendonly.aof.1.base.rdb").write_bytes(b"base")
            (appendonly / "appendonly.aof.1.incr.aof").write_bytes(b"increment")
            rdb = b"REDIS0011HISTORICAL"
            (root / "dump.rdb").write_bytes(rdb)

            default = cold._persistence_layout(root)
            self.assertEqual(default["format"], "REDIS_MULTIPART_AOF")
            self.assertNotIn("historical_root_rdb", default)

            historical = cold._persistence_layout(root, require_root_rdb=True)
            self.assertEqual(historical["format"], "REDIS_MULTIPART_AOF")
            self.assertEqual(
                historical["historical_root_rdb"]["sha256"],
                hashlib.sha256(rdb).hexdigest(),
            )
            self.assertEqual(
                historical["historical_root_rdb"]["identity"],
                "ROOT_DUMP_RDB_HISTORICAL_NOT_CURRENT_STATE",
            )

    def test_historical_positive_is_observational_and_partial_match_is_inconclusive(
        self,
    ) -> None:
        payload = {"message_id": "historical-target", "private": "DO_NOT_LEAK"}
        payload_hash = hashlib.sha256(cold._canonical(payload)).hexdigest()
        info = _bulk(b"run_id:" + b"d" * 40 + b"\r\n")
        complete = _FakeConnection([info, _array([_entry("1700000000000-0", payload)])])
        result = cold._inspect_stream(
            "kairos.paper.events",
            "historical-target",
            payload_hash,
            deadline=cold.time.monotonic() + 10,
            connect=lambda *_args, **_kwargs: complete,
            include_evidence=False,
        )
        self.assertEqual(result["state"], "POSITIVE_ACCEPTED")
        self.assertNotIn("evidence", result)
        self.assertEqual(
            cold._receipt_classification(result["state"], historical_rdb_only=True),
            "HISTORICAL_RDB_MATCH_OBSERVED_ONLY",
        )
        self.assertNotIn("evidence", result)
        self.assertEqual(
            cold._receipt_classification(result["state"], historical_rdb_only=False),
            "POSITIVE_ACCEPTED",
        )
        self.assertNotIn("DO_NOT_LEAK", json.dumps(result))

        partial = _FakeConnection([info, _array([_entry("1700000000000-0", payload)])])
        with mock.patch.object(cold, "MAX_XRANGE_ENTRIES", 1):
            result = cold._inspect_stream(
                "kairos.paper.events",
                "historical-target",
                payload_hash,
                deadline=cold.time.monotonic() + 10,
                connect=lambda *_args, **_kwargs: partial,
                include_evidence=False,
            )
        self.assertEqual(result["state"], "INCONCLUSIVE_SCAN_LIMIT")
        self.assertEqual(
            cold._receipt_classification(result["state"], historical_rdb_only=True),
            "HISTORICAL_RDB_INCONCLUSIVE_SCAN_LIMIT",
        )
        self.assertNotIn("evidence", result)

    def test_clone_receipt_and_private_target_are_exactly_hash_bound(self) -> None:
        payload = {"message_id": "legacy-unknown-1", "value": 7}
        payload_hash = hashlib.sha256(cold._canonical(payload)).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            plan = {
                "schema_version": 1,
                "kind": "controlled-runtime-transition-v1",
                "owner": "owner-1",
                "primary_authorized": False,
                "role_provision_authorized": True,
                "reconciliation_id": "controlled-runtime-owner-1",
            }
            binding = cold._digest(
                {
                    key: value
                    for key, value in plan.items()
                    if key != "primary_authorized"
                }
            )
            target_row = {
                "id": "row-1",
                "producer": "producer-1",
                "message_id": "legacy-unknown-1",
                "topic": "kairos.paper.events",
                "payload_sha256": payload_hash,
                "publish_attempts": 1,
                "payload": payload,
            }
            plan_path = directory / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            rehearsal_path = directory / "native-rehearsal.json"
            rehearsal_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "controlled-runtime-native-rehearsal-v1",
                        "result": "PASS",
                        "state": "COMMITTED_EXACT_READONLY",
                        "plan_binding_sha256": binding,
                        "private_target": target_row,
                    }
                ),
                encoding="utf-8",
            )
            inspection = directory / "native-inspection.json"
            inspection.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "controlled-runtime-native-inspection-v1",
                        "state": "INSPECTED",
                        "plan_binding_sha256": binding,
                        "plan_sha256": cold._digest(plan),
                        "private_target": target_row,
                    }
                ),
                encoding="utf-8",
            )
            receipt = directory / "clone-receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "controlled-runtime-transition-v1",
                        "result": "PASS_CURRENT_CONTROLLED_CLONE",
                        "cleanup_verified": True,
                        "primary_mutations": 0,
                        "primary_redis_contacted": False,
                        "proofs": {
                            "current_rehearsal_sha256": cold._file_sha256(
                                rehearsal_path
                            ),
                            "artifact_sha256": {
                                "plan.json": cold._file_sha256(plan_path),
                                "native-rehearsal.json": cold._file_sha256(
                                    rehearsal_path
                                ),
                                "native-inspection.json": cold._file_sha256(inspection),
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            target = cold._target_from_inspection(
                inspection, receipt, cold._file_sha256(receipt)
            )
            self.assertEqual(target["message_id"], "legacy-unknown-1")
            self.assertEqual(target["canonical_payload_sha256"], payload_hash)
            self.assertEqual(
                target["prospective_unknown_outcome"],
                "LEGACY_BASELINE_REQUIRES_PRIMARY_QUARANTINE",
            )
            self.assertNotIn("payload", target)
            with self.assertRaises(cold.ColdRedisError):
                cold._target_from_inspection(inspection, receipt, "0" * 64)

    def test_copy_manifest_hashes_contents_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "source", root / "target"
            source.mkdir()
            (source / "dump.rdb").write_bytes(b"cold redis image")
            before = cold._manifest_tree(source)
            cold._copy_tree(source, target)
            after = cold._manifest_tree(source)
            copied = cold._manifest_tree(target)
            self.assertEqual(before["content_sha256"], after["content_sha256"])
            self.assertEqual(before["content_sha256"], copied["content_sha256"])
            (source / "dump.rdb").write_bytes(b"changed")
            self.assertNotEqual(
                before["manifest_sha256"],
                cold._manifest_tree(source)["manifest_sha256"],
            )

    def test_redis_clone_is_loopback_only_and_resource_bounded(self) -> None:
        args = cold._metadata_only_docker_command(
            "owner", "owned-volume", "owned-redis", cold.SOURCE_IMAGE_ID
        )
        self.assertIn("--network=none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--memory=512m", args)
        self.assertIn("--memory-swap=512m", args)
        self.assertIn("--pids-limit=64", args)
        self.assertIn("127.0.0.1", args)
        self.assertIn("--user=999:999", args)
        self.assertIn("yes", args[args.index("--appendonly") + 1])
        self.assertIn("no", args[args.index("--aof-load-truncated") + 1])
        self.assertIn("0", args[args.index("--auto-aof-rewrite-percentage") + 1])

    def test_preparation_root_is_confined_to_owned_target_without_original_mount(self):
        target = "kairos-cold-redis-data-" + "a" * 12
        command = cold._worker_command("prepare-target", target=target)
        self.assertIn("--user=0:0", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertEqual(
            [value for value in command if value.startswith("--cap-add=")],
            ["--cap-add=CHOWN"],
        )
        self.assertIn("--network=none", command)
        self.assertIn("--read-only", command)
        self.assertIn(f"type=volume,src={target},dst=/data", command)
        self.assertTrue(all("dst=/source" not in value for value in command))
        self.assertNotIn(cold.SOURCE_VOLUME, " ".join(command))
        for kwargs in (
            {},
            {"source": cold.SOURCE_VOLUME, "target": target},
            {"target": cold.SOURCE_VOLUME},
            {"target": "foreign-volume"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(cold.ColdRedisError):
                cold._worker_command("prepare-target", **kwargs)

    def test_target_preparation_refuses_nonempty_volume_before_chmod(self):
        for entries in ([], ["existing.rdb"]):
            with self.subTest(entries=entries):
                data = mock.Mock()
                data.iterdir.return_value = iter(entries)
                with (
                    mock.patch.object(cold, "Path", return_value=data),
                    mock.patch("builtins.print"),
                    mock.patch.object(cold.os, "chown", create=True) as chown,
                ):
                    result = cold._copy_worker("prepare-target")
                if entries:
                    self.assertEqual(result, 1)
                    data.chmod.assert_not_called()
                    chown.assert_not_called()
                else:
                    self.assertEqual(result, 0)
                    data.chmod.assert_called_once_with(0o700)
                    chown.assert_called_once_with(data, 999, 999)

    def test_snapshot_volume_collisions_and_foreign_labels_block_writable_mount(self):
        owner = "a" * 32
        name = "kairos-cold-redis-data-" + owner[:12]
        attempted = set()
        docker = mock.Mock()
        docker.call.return_value = name
        with self.assertRaises(cold.ColdRedisError):
            cold._create_new_owned_volume(docker, name, owner, attempted)
        self.assertFalse(attempted)
        self.assertEqual(docker.call.call_count, 1)
        self.assertEqual(docker.call.call_args.args[0][:2], ["volume", "ls"])

        for labels, options in (
            ({cold.OWNER_LABEL: owner, cold.SCOPE_LABEL: cold.SCOPE}, {}),
            ({cold.OWNER_LABEL: "b" * 32, cold.SCOPE_LABEL: cold.SCOPE}, {}),
            ({}, {}),
            (
                {cold.OWNER_LABEL: owner, cold.SCOPE_LABEL: cold.SCOPE},
                {"device": "foreign"},
            ),
        ):
            docker = mock.Mock()
            docker.call.side_effect = [
                "",
                name,
                "|".join(
                    [
                        name,
                        "local",
                        "local",
                        "2026-10-10",
                        json.dumps(labels),
                        json.dumps(options),
                    ]
                ),
            ]
            attempted = set()
            if labels.get(cold.OWNER_LABEL) == owner and not options:
                cold._create_new_owned_volume(docker, name, owner, attempted)
            else:
                with self.assertRaises(cold.ColdRedisError):
                    cold._create_new_owned_volume(docker, name, owner, attempted)
            self.assertEqual(attempted, {"volume"})
            self.assertTrue(
                all(call.args[0][0] == "volume" for call in docker.call.call_args_list)
            )

    def test_persistence_inventory_requires_complete_multipart_aof_manifest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            appendonly = root / "appendonlydir"
            appendonly.mkdir()
            (appendonly / "appendonly.aof.manifest").write_text(
                "file appendonly.aof.1.base.rdb seq 1 type b\nfile appendonly.aof.1.incr.aof seq 1 type i\n",
                encoding="ascii",
            )
            (appendonly / "appendonly.aof.1.base.rdb").write_bytes(b"base")
            (appendonly / "appendonly.aof.1.incr.aof").write_bytes(b"increment")
            layout = cold._persistence_layout(root)
            self.assertEqual(layout["format"], "REDIS_MULTIPART_AOF")
            self.assertEqual(len(layout["aof_file_hashes"]), 2)
            (appendonly / "appendonly.aof.1.incr.aof").unlink()
            with self.assertRaises(cold.ColdRedisError):
                cold._persistence_layout(root)

    def test_persistence_manifest_accepts_canonical_incremental_offsets(self) -> None:
        layouts = []
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for name, suffix in (
                ("no-offsets", ""),
                ("start-only", " startoffset 0"),
                (
                    "start-end",
                    " startoffset 9223372036854775806 endoffset 9223372036854775807",
                ),
            ):
                with self.subTest(name=name):
                    root = parent / name
                    appendonly = root / "appendonlydir"
                    appendonly.mkdir(parents=True)
                    manifest = (
                        "file appendonly.aof.1.base.rdb seq 1 type b"
                        + chr(10)
                        + "file appendonly.aof.2.incr.aof seq 2 type i"
                        + suffix
                        + chr(10)
                    )
                    manifest_path = appendonly / "appendonly.aof.manifest"
                    manifest_path.write_text(manifest, encoding="ascii")
                    (appendonly / "appendonly.aof.1.base.rdb").write_bytes(b"base")
                    (appendonly / "appendonly.aof.2.incr.aof").write_bytes(b"incr")
                    layout = cold._persistence_layout(root)
                    self.assertEqual(layout["format"], "REDIS_MULTIPART_AOF")
                    self.assertEqual(
                        layout["aof_manifest_sha256"],
                        hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                    )
                    serialized = json.dumps(layout)
                    self.assertNotIn("startoffset", serialized)
                    self.assertNotIn("endoffset", serialized)
                    self.assertNotIn("9223372036854775806", serialized)
                    self.assertNotIn("9223372036854775807", serialized)
                    layouts.append(layout)
        self.assertEqual(layouts[0]["aof_file_hashes"], layouts[1]["aof_file_hashes"])
        self.assertEqual(layouts[1]["aof_file_hashes"], layouts[2]["aof_file_hashes"])

    def test_persistence_manifest_rejects_noncanonical_or_unsafe_offsets(self) -> None:
        invalid_lines = (
            "file appendonly.aof.2.incr.aof seq 2 type i endoffset 9",
            "file appendonly.aof.2.incr.aof seq 2 type i startoffset 1 startoffset 2",
            (
                "file appendonly.aof.2.incr.aof seq 2 type i "
                "startoffset 1 endoffset 2 endoffset 3"
            ),
            "file appendonly.aof.2.incr.aof seq 2 type i startoffset -1",
            "file appendonly.aof.2.incr.aof seq 2 type i startoffset 1.5",
            "file appendonly.aof.2.incr.aof seq 2 type i startoffset 01",
            (
                "file appendonly.aof.2.incr.aof seq 2 type i "
                "startoffset 9223372036854775808"
            ),
            "file appendonly.aof.2.incr.aof seq 2 type i startoffset 10 endoffset 9",
            "file appendonly.aof.2.incr.aof seq 2 type i startoffset 1 endoffset -1",
            "file appendonly.aof.2.incr.aof seq 2 type i startoffset 1 endoffset 1.5",
            (
                "file appendonly.aof.2.incr.aof seq 2 type i "
                "startoffset 1 endoffset 9223372036854775808"
            ),
            "file appendonly.aof.3.base.rdb seq 3 type b startoffset 1",
            "file appendonly.aof.2.incr.aof seq 2 type i startoffset 1 arbitrary value",
            "file appendonly.aof.2.incr.aof seq 2 type h",
            "file ../appendonly.aof.2.incr.aof seq 2 type i startoffset 1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for index, line in enumerate(invalid_lines):
                with self.subTest(line=line):
                    root = parent / str(index)
                    appendonly = root / "appendonlydir"
                    appendonly.mkdir(parents=True)
                    manifest = (
                        "file appendonly.aof.1.base.rdb seq 1 type b"
                        + chr(10)
                        + line
                        + chr(10)
                    )
                    (appendonly / "appendonly.aof.manifest").write_text(
                        manifest, encoding="ascii"
                    )
                    (appendonly / "appendonly.aof.1.base.rdb").write_bytes(b"base")
                    (appendonly / "appendonly.aof.2.incr.aof").write_bytes(b"incr")
                    with self.assertRaises(cold.ColdRedisError) as raised:
                        cold._persistence_layout(root)
                    self.assertIn(
                        raised.exception.error_code,
                        {
                            "MANIFEST_ENTRY_UNSUPPORTED",
                            "MANIFEST_OFFSETS_INVALID",
                        },
                    )
                    public = json.dumps(raised.exception.diagnostic)
                    self.assertNotIn("startoffset", public)
                    self.assertNotIn("endoffset", public)
                    self.assertNotIn("9223372036854775808", public)

    def test_persistence_lineage_failures_emit_only_allowlisted_diagnostics(
        self,
    ) -> None:
        def make_root(
            parent: Path,
            name: str,
            manifest: str | None,
            files: dict[str, bytes],
        ):
            root = parent / name
            directory = root / "appendonlydir"
            directory.mkdir(parents=True)
            if manifest is not None:
                (directory / "appendonly.aof.manifest").write_text(
                    manifest, encoding="ascii"
                )
            for filename, body in files.items():
                (directory / filename).write_bytes(body)
            return root

        cases = (
            (
                "malformed",
                "PRIVATE BODY TOKEN",
                {},
                "MANIFEST_ENTRY_UNSUPPORTED",
            ),
            (
                "missing",
                "file appendonly.aof.7.base.rdb seq 7 type b\n",
                {},
                "COMPONENT_MISSING",
            ),
            (
                "base",
                "file appendonly.aof.1.incr.aof seq 1 type i\n",
                {"appendonly.aof.1.incr.aof": b"PRIVATE AOF BODY"},
                "BASE_CARDINALITY",
            ),
            (
                "unreferenced",
                "file appendonly.aof.1.base.rdb seq 1 type b\n",
                {
                    "appendonly.aof.1.base.rdb": b"PRIVATE RDB BODY",
                    "appendonly.aof.2.incr.aof": b"PRIVATE AOF BODY",
                },
                "UNREFERENCED_COMPONENT",
            ),
            ("no-image", None, {}, "NO_PERSISTENCE_IMAGE"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            # The no-image case has no appendonlydir, so use a direct empty root.
            for name, manifest, files, expected_code in cases:
                with self.subTest(name=name):
                    root = parent / name
                    if name == "no-image":
                        root.mkdir()
                    else:
                        root = make_root(parent, name, manifest, files)
                    output = io.StringIO()
                    with (
                        redirect_stdout(output),
                        self.assertRaises(cold.ColdRedisError) as raised,
                    ):
                        cold._persistence_layout(root)
                    self.assertEqual(raised.exception.error_code, expected_code)
                    diagnostic = cold._validate_persistence_diagnostic(
                        raised.exception.diagnostic
                    )
                    serialized = json.dumps(diagnostic) + output.getvalue()
                    self.assertNotIn("PRIVATE", serialized)
                    self.assertNotIn("BODY", serialized)
                    self.assertNotIn("/", diagnostic.get("filename", ""))

    def test_unique_complete_exact_match_is_positive_and_payload_free(self) -> None:
        payload = {"message_id": "target-2", "value": "must-not-leak"}
        payload_hash = hashlib.sha256(cold._canonical(payload)).hexdigest()
        info = b"run_id:" + b"a" * 40 + b"\r\n"
        connection = _FakeConnection(
            [
                _bulk(info),
                _array([_entry("1700000000000-0", payload)]),
            ]
        )
        result = cold._inspect_stream(
            "kairos.paper.events",
            "target-2",
            payload_hash,
            deadline=cold.time.monotonic() + 10,
            connect=lambda *_args, **_kwargs: connection,
        )
        self.assertEqual(result["state"], "POSITIVE_ACCEPTED")
        self.assertEqual(result["stream_ids"], ["1700000000000-0"])
        self.assertEqual(result["evidence"]["match_count"], 1)
        self.assertEqual(result["xrange_limit"], cold.MAX_XRANGE_ENTRIES)
        self.assertEqual(result["xrange_response_bytes_limit"], cold.MAX_XRANGE_BYTES)
        self.assertGreater(result["response_bytes"], 0)
        self.assertNotIn("must-not-leak", json.dumps(result))
        self.assertEqual(len(connection.commands), 2)

    def test_zero_matches_are_never_absence_and_multiple_matches_conflict(self) -> None:
        payload = {"message_id": "target-3"}
        payload_hash = hashlib.sha256(cold._canonical(payload)).hexdigest()
        info = _bulk(b"run_id:" + b"b" * 40 + b"\r\n")
        zero = _FakeConnection([info, b"*0\r\n"])
        result = cold._inspect_stream(
            "kairos.paper.events",
            "target-3",
            payload_hash,
            deadline=cold.time.monotonic() + 10,
            connect=lambda *_args, **_kwargs: zero,
        )
        self.assertEqual(result["state"], "INCONCLUSIVE_ZERO_MATCH")
        self.assertNotIn("evidence", result)

        duplicate = _FakeConnection(
            [
                info,
                _array(
                    [
                        _entry("1700000000000-0", payload),
                        _entry("1700000000000-1", payload),
                    ]
                ),
            ]
        )
        result = cold._inspect_stream(
            "kairos.paper.events",
            "target-3",
            payload_hash,
            deadline=cold.time.monotonic() + 10,
            connect=lambda *_args, **_kwargs: duplicate,
        )
        self.assertEqual(result["state"], "CONFLICT")
        self.assertNotIn("evidence", result)

    def test_reaching_scan_cap_is_inconclusive_even_with_one_match(self) -> None:
        payload = {"message_id": "target-4"}
        payload_hash = hashlib.sha256(cold._canonical(payload)).hexdigest()
        connection = _FakeConnection(
            [
                _bulk(b"run_id:" + b"c" * 40 + b"\r\n"),
                _array([_entry("1700000000000-0", payload)]),
            ]
        )
        with mock.patch.object(cold, "MAX_XRANGE_ENTRIES", 1):
            result = cold._inspect_stream(
                "kairos.paper.events",
                "target-4",
                payload_hash,
                deadline=cold.time.monotonic() + 10,
                connect=lambda *_args, **_kwargs: connection,
            )
        self.assertEqual(result["state"], "INCONCLUSIVE_SCAN_LIMIT")
        self.assertIsNone(result["match_count"])
        self.assertEqual(result["entries_scanned"], 1)
        self.assertEqual(result["xrange_limit"], 1)
        self.assertEqual(result["xrange_response_bytes_limit"], cold.MAX_XRANGE_BYTES)
        self.assertFalse(result["scan_complete"])
        self.assertNotIn("evidence", result)
        self.assertNotIn("must-not-leak", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
