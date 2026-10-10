"""Offline boundary tests for cold Redis clone acceptance inspection."""

from __future__ import annotations

import hashlib
import json
import runpy
import tempfile
import unittest
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
        self.assertEqual(plan["clone"]["xrange_entries_max"], 20_000)
        self.assertEqual(
            plan["result_policy"]["zero_matches"], "INCONCLUSIVE_NO_REPLAY"
        )

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
        self.assertNotIn("evidence", result)


if __name__ == "__main__":
    unittest.main()
