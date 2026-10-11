"""Bounded, read-only inventory and narrowly scoped Redis ACL helpers.

This module deliberately has no Redis client dependency and never exposes AOF
argument values in errors or its inventory result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path
from typing import Any

TOPIC = "kairos.market.closed_bar.v1"
OWNER = "69893dc7b7c647f49967387e7efca9fb"
MAX_AOF_BYTES = 8 * 1024 * 1024
MAX_COMMANDS = 50_000
MAX_ARRAY_LENGTH = 32
MAX_TOKEN_BYTES = 128 * 1024
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_STREAM_ID = re.compile(r"^(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$")
_OWNER = re.compile(r"^[0-9a-f]{32}$")
_CONSUMER = re.compile(r"^consumer-[0-9a-f]{12}-[1-9][0-9]*$")
_GROUP = "bars"


class _AofError(ValueError):
    """Internal error carrying only a sanitized stable code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise _AofError(code)


def _owner(owner: str) -> str:
    if not isinstance(owner, str) or not _OWNER.fullmatch(owner):
        _fail("OWNER_INVALID")
    return owner


def _key(owner: str) -> str:
    return f"kairos.runtime.{owner}.publication"


def _stream_id(value: bytes, *, allow_zero: bool = False) -> str:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        _fail("STREAM_ID_INVALID")
    if not _STREAM_ID.fullmatch(text):
        _fail("STREAM_ID_INVALID")
    parts = text.split("-", 1)
    if any(len(part) > 20 for part in parts):
        _fail("STREAM_ID_INVALID")
    ms, seq = (int(part) for part in parts)
    if ms > 2**64 - 1 or seq > 2**64 - 1 or (ms == 0 and seq == 0 and not allow_zero):
        _fail("STREAM_ID_INVALID")
    return text


def _unsigned(
    value: bytes, *, maximum: int, code: str = "AOF_MALFORMED_OR_TRUNCATED"
) -> int:
    if not value or len(value) > 20 or not value.isdigit():
        _fail("AOF_MALFORMED_OR_TRUNCATED")
    number = int(value)
    if number > maximum:
        _fail(code)
    return number


class _RespReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.commands = 0

    def _line(self) -> bytes:
        end = self.data.find(b"\r\n", self.offset)
        if end < 0:
            _fail("AOF_MALFORMED_OR_TRUNCATED")
        line = self.data[self.offset : end]
        self.offset = end + 2
        if len(line) > MAX_TOKEN_BYTES:
            _fail("AOF_LIMIT_EXCEEDED")
        return line

    def next_command(self) -> list[bytes] | None:
        if self.offset == len(self.data):
            return None
        if self.data[self.offset : self.offset + 1] != b"*":
            _fail("AOF_MALFORMED_OR_TRUNCATED")
        self.offset += 1
        raw_count = self._line()
        count = _unsigned(
            raw_count, maximum=MAX_ARRAY_LENGTH, code="AOF_LIMIT_EXCEEDED"
        )
        if count < 1 or count > MAX_ARRAY_LENGTH:
            _fail("AOF_LIMIT_EXCEEDED")
        command: list[bytes] = []
        for _ in range(count):
            if self.data[self.offset : self.offset + 1] != b"$":
                _fail("AOF_MALFORMED_OR_TRUNCATED")
            self.offset += 1
            raw_length = self._line()
            length = _unsigned(
                raw_length, maximum=MAX_TOKEN_BYTES, code="AOF_LIMIT_EXCEEDED"
            )
            if length > MAX_TOKEN_BYTES:
                _fail("AOF_LIMIT_EXCEEDED")
            end = self.offset + length
            if end + 2 > len(self.data) or self.data[end : end + 2] != b"\r\n":
                _fail("AOF_MALFORMED_OR_TRUNCATED")
            command.append(self.data[self.offset : end])
            self.offset = end + 2
        self.commands += 1
        if self.commands > MAX_COMMANDS:
            _fail("AOF_LIMIT_EXCEEDED")
        return command


def _ascii(value: bytes, code: str = "AOF_MALFORMED_OR_TRUNCATED") -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        _fail(code)


def _valid_group_args(args: list[bytes]) -> str:
    # Observed AOF forms: CREATE key group id MKSTREAM and
    # SETID key group id ENTRIESREAD n. Reject other shapes.
    if len(args) < 4 or args[1] != TOPIC.encode() or args[2] != _GROUP.encode():
        _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
    if args[0] == b"CREATE":
        if len(args) != 5 or args[4] != b"MKSTREAM":
            _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
    elif args[0] == b"SETID":
        if len(args) != 6 or args[4] != b"ENTRIESREAD":
            _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
        _unsigned(args[5], maximum=2**63 - 1)
    else:
        _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
    if args[3] not in (b"$", b"0"):
        _stream_id(args[3], allow_zero=True)
    return args[0].decode("ascii").lower()


def _valid_claim(args: list[bytes]) -> None:
    # XCLAIM key group consumer min-idle-time id [id ...] [options].
    if len(args) < 5 or args[0] != TOPIC.encode() or args[1] != _GROUP.encode():
        _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
    if not _CONSUMER.fullmatch(_ascii(args[2])):
        _fail("AOF_CONSUMER_IDENTITY_INVALID")
    _unsigned(args[3], maximum=2**63 - 1)
    i = 4
    ids = 0
    options = {b"TIME": 1, b"RETRYCOUNT": 1, b"FORCE": 0, b"JUSTID": 0, b"LASTID": 1}
    option_order = {name: i for i, name in enumerate(options)}
    last_option = -1
    while i < len(args) and args[i].upper() not in options:
        _stream_id(args[i])
        ids += 1
        i += 1
    if not ids:
        _fail("AOF_MALFORMED_OR_TRUNCATED")
    while i < len(args):
        opt = args[i].upper()
        if opt not in options:
            _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
        if option_order[opt] <= last_option:
            _fail("AOF_MALFORMED_OR_TRUNCATED")
        last_option = option_order[opt]
        arity = options[opt]
        if i + arity >= len(args):
            _fail("AOF_MALFORMED_OR_TRUNCATED")
        if arity:
            if opt == b"LASTID":
                _stream_id(args[i + 1], allow_zero=True)
            else:
                _unsigned(args[i + 1], maximum=2**63 - 1)
        i += 1 + arity


def inventory_aof(path: str | os.PathLike[str], owner: str) -> dict[str, Any]:
    """Parse a bounded RESP AOF and return only sanitized structural metadata."""
    owner = _owner(owner)
    candidate = Path(path)
    try:
        if candidate.is_symlink():
            _fail("AOF_FILE_INVALID")
        st = candidate.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_AOF_BYTES:
            _fail(
                "AOF_FILE_INVALID"
                if not stat.S_ISREG(st.st_mode)
                else "AOF_LIMIT_EXCEEDED"
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(candidate, flags)
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or fst.st_size > MAX_AOF_BYTES:
                _fail("AOF_FILE_INVALID")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(MAX_AOF_BYTES + 1)
        finally:
            os.close(fd)
    except _AofError:
        raise
    except (OSError, ValueError):
        _fail("AOF_FILE_INVALID")
    if len(data) > MAX_AOF_BYTES:
        _fail("AOF_LIMIT_EXCEEDED")

    return inventory_bytes(data, owner)


def inventory_bytes(data: bytes, owner: str) -> dict[str, Any]:
    """Parse already captured AOF bytes with the same strict bounded parser."""
    owner = _owner(owner)
    if not isinstance(data, bytes):
        _fail("AOF_INPUT_INVALID")
    if len(data) > MAX_AOF_BYTES:
        _fail("AOF_LIMIT_EXCEEDED")

    reader = _RespReader(data)
    counts: Counter[str] = Counter()
    dbs: set[int] = set()
    publication_ids: list[str] = []
    receipt_fields: dict[str, tuple[str, str]] = {}
    stream_receipts: dict[str, str] = {}
    in_multi = False
    transaction_streams: set[tuple[str, str]] = set()
    transaction_has_hset = False
    transaction_has_xadd = False
    exact_topic = TOPIC.encode()
    exact_key = _key(owner).encode()
    xadd_receipts: set[tuple[str, str]] = set()
    while (command := reader.next_command()) is not None:
        if not command:
            _fail("AOF_MALFORMED_OR_TRUNCATED")
        name = command[0].upper()
        args = command[1:]
        if name == b"MULTI":
            if args or in_multi:
                _fail("AOF_TRANSACTION_INVALID")
            in_multi = True
            transaction_streams = set()
            transaction_has_hset = False
            transaction_has_xadd = False
            counts["multi"] += 1
        elif name == b"EXEC":
            if args or not in_multi:
                _fail("AOF_TRANSACTION_INVALID")
            if transaction_has_hset != transaction_has_xadd:
                _fail("AOF_TRANSACTION_INVALID")
            in_multi = False
            counts["exec"] += 1
        elif name == b"SELECT":
            if in_multi:
                _fail("AOF_DB_INVALID")
            if len(args) != 1 or args[0] != b"0":
                _fail("AOF_DB_INVALID")
            dbs.add(0)
            counts["select"] += 1
        elif name == b"XADD":
            if len(args) != 4 or args[0] != exact_topic or args[2] != b"data":
                _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
            sid = _stream_id(args[1])
            digest = hashlib.sha256(args[3]).hexdigest()
            previous_digest = stream_receipts.get(sid)
            if previous_digest is not None:
                _fail("AOF_STREAM_ID_REUSED")
            stream_receipts[sid] = digest
            xadd_receipts.add((digest, sid))
            if in_multi:
                transaction_streams.add((digest, sid))
                transaction_has_xadd = True
            counts["xadd"] += 1
        elif name == b"HSET":
            if not in_multi:
                _fail("AOF_TRANSACTION_INVALID")
            if (
                len(args) != 3
                or args[0] != exact_key
                or not _HEX64.fullmatch(_ascii(args[1]))
            ):
                _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
            try:
                receipt = json.loads(args[2].decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                _fail("AOF_RECEIPT_INVALID")
            if (
                not isinstance(receipt, list)
                or len(receipt) != 2
                or not isinstance(receipt[0], str)
                or not _HEX64.fullmatch(receipt[0])
                or not isinstance(receipt[1], str)
            ):
                _fail("AOF_RECEIPT_INVALID")
            try:
                receipt_id = receipt[1].encode("ascii", "strict")
            except UnicodeEncodeError:
                _fail("AOF_RECEIPT_INVALID")
            receipt_stream_id = _stream_id(receipt_id)
            pair = (receipt[0].lower(), receipt_stream_id)
            if pair not in transaction_streams or pair not in xadd_receipts:
                _fail("AOF_RECEIPT_INVALID")
            message_id = _ascii(args[1]).lower()
            old_receipt = receipt_fields.get(message_id)
            receipt_pair = (receipt[0].lower(), receipt_stream_id)
            if old_receipt is not None and old_receipt != receipt_pair:
                _fail("AOF_RECEIPT_FIELD_REWRITTEN")
            if old_receipt is None:
                publication_ids.append(message_id)
            receipt_fields[message_id] = receipt_pair
            transaction_has_hset = True
            counts["hset"] += 1
        elif name == b"XGROUP":
            counts["xgroup|" + _valid_group_args(args).encode("ascii").decode()] += 1
        elif name == b"XCLAIM":
            _valid_claim(args)
            counts["xclaim"] += 1
        elif name == b"XACK":
            if len(args) < 3 or args[0] != exact_topic or args[1] != _GROUP.encode():
                _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
            for sid in args[2:]:
                _stream_id(sid)
            counts["xack"] += 1
        else:
            _fail("AOF_UNKNOWN_COMMAND_OR_KEY")
    if in_multi:
        _fail("AOF_TRANSACTION_INVALID")
    if not data:
        _fail("AOF_MALFORMED_OR_TRUNCATED")
    publication_message_ids_sha256 = hashlib.sha256(
        json.dumps(sorted(publication_ids), separators=(",", ":")).encode("ascii")
    ).hexdigest()
    return {
        "bytes": len(data),
        "parsed_source_sha256": hashlib.sha256(data).hexdigest(),
        "command_count": reader.commands,
        "dbs": sorted(dbs),
        "subcommand_counts": dict(sorted(counts.items())),
        "xadd_count": counts["xadd"],
        "ledger_fields": len(publication_ids),
        "receipt_count": counts["hset"],
        "publication_message_ids_sha256": publication_message_ids_sha256,
        "first_publication_message_id": publication_ids[0] if publication_ids else None,
        "last_publication_message_id": publication_ids[-1] if publication_ids else None,
        "matched_receipt_count": len(receipt_fields),
        "actor_format_valid": counts["xclaim"] > 0,
        "transactions_balanced": counts["multi"] == counts["exec"],
    }


def replay_default_acl(owner: str) -> str:
    """Return the disabled default user with only proven AOF replay commands."""
    owner = _owner(owner)
    return (
        "user default reset off resetpass ~"
        + TOPIC
        + " ~"
        + _key(owner)
        + " +select +multi +exec +xadd +hset +xgroup|create +xgroup|setid +xclaim +xack"
    )


def candidate_acl(original: bytes, owner: str) -> bytes:
    """Replace only a validated first default-user line, preserving all other bytes."""
    owner = _owner(owner)
    if not isinstance(original, bytes) or b"\x00" in original:
        _fail("ACL_INPUT_INVALID")
    newline = original.find(b"\n")
    first = original if newline < 0 else original[:newline]
    ending = b"\r\n" if first.endswith(b"\r") else b"\n"
    if ending == b"\r\n":
        first = first[:-1]
    try:
        first_text = first.decode("ascii")
        remainder = original[newline + 1 :] if newline >= 0 else b""
        lines = remainder.splitlines()
        decoded = [line.decode("ascii") for line in lines if line]
    except UnicodeDecodeError:
        _fail("ACL_INPUT_INVALID")
    if first_text != "user default off":
        _fail("ACL_INPUT_INVALID")
    expected = {"kairos_epoch_admin", "kairos_epoch_producer", "kairos_epoch_consumer"}
    found: list[str] = []
    for line in decoded:
        match = re.match(r"^user ([a-zA-Z0-9_]+) (?:on|off)(?: |$)", line)
        if not match or match.group(1) not in expected:
            _fail("ACL_INPUT_INVALID")
        found.append(match.group(1))
    if set(found) != expected or len(found) != len(expected):
        _fail("ACL_INPUT_INVALID")
    if newline < 0:
        _fail("ACL_INPUT_INVALID")
    return replay_default_acl(owner).encode("ascii") + ending + remainder


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aof-inventory", action="store_true")
    args = parser.parse_args(argv)
    if not args.aof_inventory:
        parser.error("--aof-inventory is required")
    try:
        report = inventory_aof("/source/appendonlydir/appendonly.aof.1.incr.aof", OWNER)
    except ValueError as exc:
        code = getattr(exc, "code", "AOF_INVENTORY_FAILED")
        print(
            json.dumps({"status": "FAIL_AOF_INVENTORY", "code": code}, sort_keys=True)
        )
        return 2
    print(json.dumps({"status": "PASS_AOF_INVENTORY", **report}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
