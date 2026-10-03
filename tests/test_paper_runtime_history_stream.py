"""Transport equivalence and fail-closed framing, not native recovery proof."""

from __future__ import annotations

import asyncio
import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import paper_runtime_history_stream as transport
import paper_runtime_snapshot_worker as snapshot


def encoded(rows: list[str]) -> bytes:
    return transport.HEADER + b"".join(
        b"\x00\x01" + len(data).to_bytes(4, "big", signed=True) + data
        for data in (row.encode("utf-8") for row in rows)
    ) + b"\xff\xff"


def original_digest(rows: list[str]) -> dict:
    digest = hashlib.sha256()
    for row in rows:
        data = row.encode("utf-8")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return {"count": len(rows), "row_digest_sha256": digest.hexdigest()}


class StreamTests(unittest.IsolatedAsyncioTestCase):
    async def consume(self, rows, chunks=None, budget=None):
        stream = transport.OrderedTextDigest(budget or snapshot.Budget())
        payload = encoded(rows)
        for chunk in chunks or [payload]:
            await stream.write(chunk)
        return stream.finish(f"COPY {len(rows)}")

    async def test_same_legacy_length_prefixed_digest_for_every_split(self):
        rows = sorted(["", "a\n\\\t\r", 'b{"id": 117625}', "a\n\\\t\r", "Я", "😀"], key=lambda row: row.encode("utf-8"))
        payload = encoded(rows)
        for split in range(len(payload) + 1):
            with self.subTest(split=split):
                self.assertEqual(await self.consume(rows, [payload[:split], payload[split:]]), original_digest(rows))
        self.assertEqual(await self.consume(rows, [bytes([byte]) for byte in payload]), original_digest(rows))

    async def test_empty_table(self):
        self.assertEqual(await self.consume([]), original_digest([]))

    async def test_native_bytearray_chunks_freeze_before_reuse(self):
        rows = ["", "a", "я"]
        payload = encoded(rows)
        for split in range(len(payload) + 1):
            with self.subTest(split=split):
                stream = transport.OrderedTextDigest(snapshot.Budget())
                prefix = bytearray(payload[:split])
                await stream.write(prefix)
                prefix[:] = b"overwritten by producer"
                suffix = bytearray(payload[split:])
                await stream.write(suffix)
                suffix[:] = b"overwritten by producer"
                self.assertEqual(stream.finish("COPY 3"), original_digest(rows))

    async def test_exact_row_limit_without_batch_buffering(self):
        row = "a" * snapshot.MAX_ROW_BYTES
        payload = encoded([row])
        stream = transport.OrderedTextDigest(snapshot.Budget())
        for offset in range(0, len(payload), 257):
            await stream.write(payload[offset:offset + 257])
            self.assertLessEqual(len(stream._pending), snapshot.MAX_ROW_BYTES)
        self.assertEqual(stream.finish("COPY 1"), original_digest([row]))

    async def test_all_truncations_rejected(self):
        payload = encoded(["a", "я"])
        for length in range(len(payload)):
            with self.subTest(length=length):
                stream = transport.OrderedTextDigest(snapshot.Budget())
                await stream.write(payload[:length])
                with self.assertRaises(snapshot.SnapshotError):
                    stream.finish("COPY 2")

    async def test_header_flags_extensions_and_signature_fail_closed(self):
        for offset in range(len(transport.HEADER)):
            payload = bytearray(encoded([]))
            payload[offset] ^= 1
            with self.subTest(offset=offset):
                stream = transport.OrderedTextDigest(snapshot.Budget())
                with self.assertRaises(snapshot.SnapshotError):
                    await stream.write(bytes(payload))

    async def test_invalid_field_count_and_length_rejected_before_body(self):
        for fields, length in [(0, 0), (2, 1), (-2, 0), (1, -1), (1, -2), (1, snapshot.MAX_ROW_BYTES + 1), (1, 2**31 - 1)]:
            payload = transport.HEADER + fields.to_bytes(2, "big", signed=True) + length.to_bytes(4, "big", signed=True)
            with self.subTest(fields=fields, length=length):
                stream = transport.OrderedTextDigest(snapshot.Budget())
                with self.assertRaises(snapshot.SnapshotError):
                    await stream.write(payload)
                self.assertLessEqual(len(stream._pending), len(transport.HEADER))

    async def test_invalid_utf8_and_order_rejected_without_raw_detail(self):
        invalid = transport.HEADER + b"\x00\x01\x00\x00\x00\x01\xff\xff\xff"
        for payload in [invalid, encoded(["b", "a"])]:
            stream = transport.OrderedTextDigest(snapshot.Budget())
            with self.assertRaises(snapshot.SnapshotError) as caught:
                await stream.write(payload)
            self.assertEqual(str(caught.exception), "ordered history COPY framing/bound differs")
            with self.assertRaises(snapshot.SnapshotError):
                stream.finish("COPY 2")

    async def test_wrong_status_or_trailing_bytes_never_seal(self):
        for status in ["COPY 0", "COPY 01", "COPY 2", "COPY 1 ", "SELECT 1", 1, None]:
            stream = transport.OrderedTextDigest(snapshot.Budget())
            await stream.write(encoded(["a"]))
            with self.assertRaises(snapshot.SnapshotError):
                stream.finish(status)
            with self.assertRaises(snapshot.SnapshotError):
                stream.finish("COPY 1")
        for suffix in [b"x", b"\xff\xff", b"\x00\x01"]:
            stream = transport.OrderedTextDigest(snapshot.Budget())
            with self.assertRaises(snapshot.SnapshotError):
                await stream.write(encoded([]) + suffix)

    async def test_seal_only_once_and_no_write_after_seal(self):
        stream = transport.OrderedTextDigest(snapshot.Budget())
        await stream.write(encoded([]))
        stream.finish("COPY 0")
        with self.assertRaises(snapshot.SnapshotError):
            stream.finish("COPY 0")
        with self.assertRaises(snapshot.SnapshotError):
            await stream.write(b"")

    async def test_callback_type_and_chunk_cap(self):
        for chunk in [memoryview(b""), None, b"x" * (transport.MAX_CHUNK_BYTES + 1), bytearray(transport.MAX_CHUNK_BYTES + 1)]:
            stream = transport.OrderedTextDigest(snapshot.Budget())
            with self.assertRaises(snapshot.SnapshotError):
                await stream.write(chunk)

    async def test_shared_original_row_byte_and_deadline_limits(self):
        budget = snapshot.Budget()
        budget.rows = snapshot.MAX_TOTAL_ROWS - 1
        self.assertEqual(await self.consume(["a"], budget=budget), original_digest(["a"]))
        with self.assertRaises(snapshot.SnapshotError):
            await self.consume(["b"], budget=budget)
        budget = snapshot.Budget()
        budget.bytes = snapshot.MAX_TOTAL_BYTES
        with self.assertRaises(snapshot.SnapshotError):
            await self.consume(["a"], budget=budget)
        budget = snapshot.Budget()
        budget.started -= snapshot.MAX_SECONDS + 1
        with self.assertRaises(snapshot.SnapshotError):
            await self.consume([], budget=budget)
        stream = transport.OrderedTextDigest(snapshot.Budget())
        await stream.write(encoded([]))
        stream.budget.started -= snapshot.MAX_SECONDS + 1
        with self.assertRaises(snapshot.SnapshotError):
            stream.finish("COPY 0")


class WorkerTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_query_args_connection_budget_and_fixed_copy_options(self):
        import paper_runtime_atomic_worker as worker

        rows = ["a", "я"]
        connection = mock.Mock()
        connection.is_in_transaction.return_value = True

        async def copying(query, *args, output, **options):
            self.assertEqual(query, "synthetic reviewed SELECT")
            self.assertEqual(args, (117625, '{"value":"я"}'))
            self.assertEqual(options, {"format": "binary", "encoding": "UTF8", "timeout": 120})
            await output(bytearray(encoded(rows)[:20]))
            await output(encoded(rows)[20:])
            return "COPY 2"

        connection.copy_from_query = mock.AsyncMock(side_effect=copying)
        budget = snapshot.Budget()
        self.assertEqual(await worker._digest_query(connection, "synthetic reviewed SELECT", budget, 117625, '{"value":"я"}'), original_digest(rows))
        self.assertEqual(budget.rows, 2)
        connection.cursor.assert_not_called()
        connection.transaction.assert_not_called()

    async def test_requires_existing_transaction_before_copy(self):
        import paper_runtime_atomic_worker as worker

        connection = mock.Mock()
        connection.is_in_transaction.return_value = False
        with self.assertRaises(worker.contract.AtomicError):
            await worker._digest_query(connection, "synthetic", snapshot.Budget())
        connection.copy_from_query.assert_not_called()

    async def test_driver_error_or_cancellation_never_returns_partial_digest(self):
        import paper_runtime_atomic_worker as worker

        for error in [OSError("synthetic; do not print"), asyncio.CancelledError()]:
            connection = mock.Mock()
            connection.is_in_transaction.return_value = True

            async def copying(query, *, output, _error=error, **options):
                await output(encoded(["a"])[:-2])
                raise _error

            connection.copy_from_query = mock.AsyncMock(side_effect=copying)
            with self.assertRaises(type(error)):
                await worker._digest_query(connection, "synthetic", snapshot.Budget())


if __name__ == "__main__":
    unittest.main()
