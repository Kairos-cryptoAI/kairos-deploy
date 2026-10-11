"""Offline contract tests for the bounded runtime epoch Redis AOF helper."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts import runtime_epoch_redis_aof as aof

OWNER = "69893dc7b7c647f49967387e7efca9fb"
STREAM_ID = "1780000000000-0"
MESSAGE_ID = "a" * 64


def _command(*args: bytes | str) -> bytes:
    encoded = [arg.encode("ascii") if isinstance(arg, str) else arg for arg in args]
    return (
        b"*"
        + str(len(encoded)).encode()
        + b"\r\n"
        + b"".join(
            b"$" + str(len(arg)).encode() + b"\r\n" + arg + b"\r\n" for arg in encoded
        )
    )


def _consumer(owner: str = OWNER) -> str:
    return f"consumer-{owner[:12]}-123"


class RuntimeEpochRedisAofTests(unittest.TestCase):
    def _file(self, data: bytes) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "incr.aof"
        path.write_bytes(data)
        return path

    def test_inventory_returns_only_sanitized_structural_metadata(self) -> None:
        payload = (
            b'{"secret":"do-not-print","message_id":"' + MESSAGE_ID.encode() + b'"}'
        )
        digest = hashlib.sha256(payload).hexdigest()
        aof_bytes = b"".join(
            (
                _command("SELECT", "0"),
                _command("XGROUP", "CREATE", aof.TOPIC, "bars", "0-0", "MKSTREAM"),
                _command("MULTI"),
                _command("XADD", aof.TOPIC, STREAM_ID, "data", payload),
                _command(
                    "HSET",
                    f"kairos.runtime.{OWNER}.publication",
                    MESSAGE_ID,
                    f'["{digest}","{STREAM_ID}"]',
                ),
                _command("EXEC"),
                _command(
                    "XGROUP", "SETID", aof.TOPIC, "bars", "0-0", "ENTRIESREAD", "1"
                ),
                _command(
                    "XCLAIM",
                    aof.TOPIC,
                    "bars",
                    _consumer(),
                    "0",
                    STREAM_ID,
                    "TIME",
                    "1780000000000",
                    "RETRYCOUNT",
                    "1",
                    "FORCE",
                    "JUSTID",
                    "LASTID",
                    STREAM_ID,
                ),
                _command("XACK", aof.TOPIC, "bars", STREAM_ID),
            )
        )
        report = aof.inventory_bytes(aof_bytes, OWNER)
        rendered = repr(report)
        self.assertEqual(report["bytes"], len(aof_bytes))
        self.assertEqual(report["dbs"], [0])
        self.assertEqual(report["xadd_count"], 1)
        self.assertEqual(report["ledger_fields"], 1)
        self.assertEqual(report["matched_receipt_count"], 1)
        self.assertEqual(report["first_publication_message_id"], MESSAGE_ID)
        self.assertEqual(report["last_publication_message_id"], MESSAGE_ID)
        self.assertEqual(report["receipt_count"], 1)
        self.assertEqual(
            report["publication_message_ids_sha256"],
            hashlib.sha256(f'["{MESSAGE_ID}"]'.encode("ascii")).hexdigest(),
        )
        self.assertTrue(report["actor_format_valid"])
        self.assertEqual(report["subcommand_counts"]["xgroup|setid"], 1)
        self.assertTrue(report["transactions_balanced"])
        self.assertNotIn("do-not-print", rendered)
        self.assertNotIn(payload.decode(), rendered)
        self.assertEqual(
            report["parsed_source_sha256"], hashlib.sha256(aof_bytes).hexdigest()
        )

    def test_rejects_nonzero_db_unknown_key_and_unbalanced_transaction(self) -> None:
        samples = (
            (_command("SELECT", "1"), "AOF_DB_INVALID"),
            (
                _command("XACK", aof.TOPIC, "other", STREAM_ID),
                "AOF_UNKNOWN_COMMAND_OR_KEY",
            ),
            (_command("MULTI"), "AOF_TRANSACTION_INVALID"),
            (
                _command("MULTI") + _command("SELECT", "0") + _command("EXEC"),
                "AOF_DB_INVALID",
            ),
        )
        for data, expected in samples:
            with (
                self.subTest(expected=expected),
                self.assertRaises(ValueError) as caught,
            ):
                aof.inventory_aof(self._file(data), OWNER)
            self.assertEqual(str(caught.exception), expected)

    def test_rejects_truncated_and_oversized_tokens(self) -> None:
        with self.assertRaisesRegex(ValueError, "AOF_MALFORMED_OR_TRUNCATED"):
            aof.inventory_aof(self._file(b"*1\r\n$4\r\nPING"), OWNER)
        oversized = b"*1\r\n$" + str(aof.MAX_TOKEN_BYTES + 1).encode() + b"\r\n"
        with self.assertRaisesRegex(ValueError, "AOF_LIMIT_EXCEEDED"):
            aof.inventory_aof(self._file(oversized), OWNER)

    def test_rejects_receipt_that_does_not_match_stream_write(self) -> None:
        data = b"".join(
            (
                _command("MULTI"),
                _command("XADD", aof.TOPIC, STREAM_ID, "data", b"{}"),
                _command(
                    "HSET",
                    f"kairos.runtime.{OWNER}.publication",
                    MESSAGE_ID,
                    '["' + "0" * 64 + '","' + STREAM_ID + '"]',
                ),
                _command("EXEC"),
            )
        )
        with self.assertRaisesRegex(ValueError, "AOF_RECEIPT_INVALID"):
            aof.inventory_aof(self._file(data), OWNER)

    def test_replay_acl_is_disabled_exact_two_keys_and_minimal_commands(self) -> None:
        line = aof.replay_default_acl(OWNER)
        self.assertEqual(
            line,
            "user default reset off resetpass ~kairos.market.closed_bar.v1 "
            f"~kairos.runtime.{OWNER}.publication "
            "+select +multi +exec +xadd +hset +xgroup|create +xgroup|setid +xclaim +xack",
        )
        self.assertNotIn("#", line)
        self.assertNotIn("~*", line)
        self.assertIn("reset off resetpass", line)

    def test_candidate_acl_replaces_first_line_only_and_preserves_crlf(self) -> None:
        original = (
            b"user default off\r\n"
            b"user kairos_epoch_admin on #private ~* +@all\r\n"
            b"user kairos_epoch_producer on #private ~stream +xadd\r\n"
            b"user kairos_epoch_consumer on #private ~stream +xreadgroup\r\n"
        )
        candidate = aof.candidate_acl(original, OWNER)
        replacement, rest = candidate.split(b"\r\n", 1)
        self.assertEqual(replacement.decode(), aof.replay_default_acl(OWNER))
        self.assertEqual(rest, original.split(b"\r\n", 1)[1])

    def test_candidate_acl_rejects_unexpected_named_user_or_default_line(self) -> None:
        valid = (
            b"user default off\n"
            b"user kairos_epoch_admin on #x ~* +@all\n"
            b"user kairos_epoch_producer on #x ~x +xadd\n"
            b"user kairos_epoch_consumer on #x ~x +xack\n"
        )
        with self.assertRaisesRegex(ValueError, "ACL_INPUT_INVALID"):
            aof.candidate_acl(
                valid.replace(b"user default off", b"user default on"), OWNER
            )
        with self.assertRaisesRegex(ValueError, "ACL_INPUT_INVALID"):
            aof.candidate_acl(valid + b"user attacker on #secret ~* +@all\n", OWNER)

    def test_rejects_symlink_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            link = Path(directory) / "link"
            target.write_bytes(_command("SELECT", "0"))
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(ValueError, "AOF_FILE_INVALID"):
                aof.inventory_aof(link, OWNER)

    def test_rejects_wrong_consumer_and_stream_id_reuse(self) -> None:
        claim = _command(
            "XCLAIM",
            aof.TOPIC,
            "bars",
            "kairos-epoch-consumer-foreign:bars",
            "0",
            STREAM_ID,
        )
        with self.assertRaisesRegex(ValueError, "AOF_CONSUMER_IDENTITY_INVALID"):
            aof.inventory_bytes(claim, OWNER)
        duplicate_stream = b"".join(
            (
                _command("XADD", aof.TOPIC, STREAM_ID, "data", b"{}"),
                _command("XADD", aof.TOPIC, STREAM_ID, "data", b"{}"),
            )
        )
        with self.assertRaisesRegex(ValueError, "AOF_STREAM_ID_REUSED"):
            aof.inventory_bytes(duplicate_stream, OWNER)

    def test_rejects_ledger_field_rewritten_and_hset_outside_transaction(self) -> None:
        payload = b"{}"
        digest = hashlib.sha256(payload).hexdigest()
        other_id = "b" * 64
        first = _command("XADD", aof.TOPIC, STREAM_ID, "data", payload)
        second_id = "1780000000001-0"
        second = _command("XADD", aof.TOPIC, second_id, "data", payload)
        rewrite = b"".join(
            (
                _command("MULTI"),
                first,
                _command(
                    "HSET",
                    f"kairos.runtime.{OWNER}.publication",
                    MESSAGE_ID,
                    f'["{digest}","{STREAM_ID}"]',
                ),
                _command("EXEC"),
                _command("MULTI"),
                second,
                _command(
                    "HSET",
                    f"kairos.runtime.{OWNER}.publication",
                    MESSAGE_ID,
                    f'["{digest}","{second_id}"]',
                ),
                _command("EXEC"),
            )
        )
        with self.assertRaisesRegex(ValueError, "AOF_RECEIPT_FIELD_REWRITTEN"):
            aof.inventory_bytes(rewrite, OWNER)
        outside = _command(
            "HSET",
            f"kairos.runtime.{OWNER}.publication",
            other_id,
            f'["{digest}","{STREAM_ID}"]',
        )
        with self.assertRaisesRegex(ValueError, "AOF_TRANSACTION_INVALID"):
            aof.inventory_bytes(outside, OWNER)

    def test_enforces_command_and_array_limits(self) -> None:
        with self.assertRaisesRegex(ValueError, "AOF_LIMIT_EXCEEDED"):
            aof.inventory_bytes(_command("SELECT", "0") * (aof.MAX_COMMANDS + 1), OWNER)
        too_many_args = _command("UNKNOWN", *([b"x"] * (aof.MAX_ARRAY_LENGTH + 1)))
        with self.assertRaisesRegex(ValueError, "AOF_LIMIT_EXCEEDED"):
            aof.inventory_bytes(too_many_args, OWNER)


if __name__ == "__main__":
    unittest.main()
