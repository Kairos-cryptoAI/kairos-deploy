from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import cold_redis_acceptance as cold


class RedisAofCopyCapTests(unittest.TestCase):
    def test_worker_command_threads_only_allowlisted_caps(self):
        command = cold._worker_command(
            "copy-hash",
            source="source-volume",
            target="target-volume",
            script_path=Path("/private/cold.py"),
            max_source_bytes=32 * 1024 * 1024,
        )
        self.assertEqual(
            command[-2:], ["--max-source-bytes", str(32 * 1024 * 1024)]
        )
        with self.assertRaisesRegex(cold.ColdRedisError, "size profile is not allowlisted"):
            cold._worker_command(
                "copy-hash",
                source="source-volume",
                target="target-volume",
                max_source_bytes=256 * 1024 * 1024,
            )
        for invalid_cap in (True, float(8 * 1024 * 1024)):
            with self.subTest(invalid_cap=invalid_cap), self.assertRaisesRegex(
                cold.ColdRedisError, "size profile is not allowlisted"
            ):
                cold._worker_command(
                    "copy-hash",
                    source="source-volume",
                    target="target-volume",
                    max_source_bytes=invalid_cap,
                )

    def test_manifest_tree_applies_supplied_cap_before_hashing_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "small.aof").write_bytes(b"1234")
            with self.assertRaisesRegex(cold.ColdRedisError, "size bound"):
                cold._manifest_tree(root, max_total_bytes=3)

    def test_worker_rejects_nonallowlisted_copy_limit_without_host_io(self):
        with self.assertRaisesRegex(cold.ColdRedisError, "size profile is not allowlisted"):
            cold._copy_worker("manifest-only", max_source_bytes=16 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
