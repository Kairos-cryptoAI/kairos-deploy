"""Fail-closed, audit-only CLOSED_BAR history seed for a new runtime epoch.

This module deliberately has no database-driver or network dependency. The
controller supplies an async, bounded iterator over the read-only source query
and one already-connected target transaction. The source query binds each
event_audit row to its unique legacy outbox row for hash verification; no source
write API is used. The only target SQL in this module inserts the original
event_audit identity. In particular, this code never writes an outbox, inbox,
cursor, order, usage, or execution/effect table.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import AsyncIterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

TOPIC = "kairos.market.closed_bar.v1"
SOURCE = "kairos-quant-scouts"
SCHEMA_VERSION = "1.0"
CONTRACT_VERSION = "closed-bar.v1"
SYMBOLS = ("BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT")
MINUTE_MS = 60_000
MAX_ROWS = 200_000
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ROW_BYTES = 1 * 1024 * 1024
MAX_SECONDS = 900
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NEW_EPOCH_DB_RE = re.compile(r"^kairos_epoch_[a-f0-9]{12}$")

try:  # Exact parity with kairos-core's canonical_sha256 where available.
    import orjson
except ImportError:  # Keep the pure validator usable in minimal offline tests.
    orjson = None

# The source-side controller must run this under a read-only, pinned snapshot.
# Aggregating the legacy outbox by message_id makes duplicate outbox identities
# visible without multiplying audit rows. payload::text is only parsed; the
# hash is recomputed from canonical JSON, matching persistence.canonical_payload.
SOURCE_EXPORT_SQL = """
SELECT a.produced_at, a.message_id, a.topic, a.source, a.schema_version,
       a.correlation_id, a.causation_id, a.payload::text AS payload,
       legacy.outbox_count, legacy.topic AS outbox_topic,
       legacy.producer AS outbox_producer,
       legacy.payload::text AS outbox_payload,
       legacy.payload_sha256 AS stored_payload_sha256
  FROM public.event_audit AS a
  LEFT JOIN LATERAL (
       SELECT count(*) AS outbox_count,
              min(o.topic) AS topic,
              min(o.producer) AS producer,
              min(o.payload::text) AS payload,
              min(o.payload_sha256) AS payload_sha256
         FROM public.message_outbox AS o
        WHERE o.message_id = a.message_id
  ) AS legacy ON TRUE
 WHERE a.topic = $1 AND a.source = $2
 ORDER BY a.payload->>'symbol',
          (a.payload->>'open_time_ms')::bigint,
          a.produced_at, a.message_id
""".strip()

# Explicitly immutable scope: no generic table-name interpolation and no
# INSERT target other than event_audit.
TARGET_EMPTY_CHECK_SQL = """
SELECT (SELECT count(*) FROM public.event_audit) AS event_audit_rows,
       (SELECT count(*) FROM public.message_outbox) AS message_outbox_rows
""".strip()

TARGET_INSERT_SQL = """
INSERT INTO public.event_audit
    (produced_at, message_id, topic, source, schema_version,
     correlation_id, causation_id, payload)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
""".strip()

_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "message_id",
        "correlation_id",
        "causation_id",
        "produced_at",
        "source",
        "contract_version",
        "venue",
        "symbol",
        "timeframe",
        "open_time_ms",
        "close_time_ms",
        "open",
        "high",
        "low",
        "close",
        "base_volume",
        "quote_volume",
        "taker_buy_base_volume",
        "taker_buy_quote_volume",
        "is_closed",
        "bar_sha256",
    }
)
_BAR_IDENTITY_FIELDS = (
    "base_volume",
    "close",
    "close_time_ms",
    "contract_version",
    "high",
    "is_closed",
    "low",
    "open",
    "open_time_ms",
    "quote_volume",
    "symbol",
    "taker_buy_base_volume",
    "taker_buy_quote_volume",
    "timeframe",
    "venue",
)
_TARGET_FORBIDDEN_TABLES = (
    "message_inbox",
    "execution_orders",
    "execution_effects",
    "execution_effect_events",
    "source_usage_reservations",
)


class SeedError(ValueError):
    """Safe refusal; messages intentionally contain no candle payloads."""


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise SeedError("history row is not canonical JSON data") from None


def _contract_canonical_json(value: Mapping[str, Any]) -> bytes:
    """Match kairos-core canonical_json_bytes for the CLOSED_BAR identity."""
    normalized = {
        key: (0.0 if isinstance(item, float) and item == 0 else item)
        for key, item in value.items()
    }
    if orjson is not None:
        try:
            return orjson.dumps(normalized, option=orjson.OPT_SORT_KEYS)
        except (TypeError, ValueError):
            raise SeedError("closed-bar identity is not canonical JSON data") from None
    return canonical_json(normalized)


def _utc_datetime(value: Any, label: str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise SeedError(f"{label} is not an ISO-8601 timestamp") from None
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise SeedError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _payload(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(
                value, parse_constant=lambda _v: (_ for _ in ()).throw(ValueError())
            )
        except (json.JSONDecodeError, ValueError):
            raise SeedError("history payload is not valid JSON") from None
    if not isinstance(value, dict) or set(value) != _PAYLOAD_FIELDS:
        raise SeedError(
            "history payload does not match the exact CLOSED_BAR v1 envelope"
        )
    return value


def _finite_number(
    payload: Mapping[str, Any], name: str, *, positive: bool = False
) -> float:
    value = payload[name]
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise SeedError("history OHLCV values must be finite numbers")
    if positive and value <= 0:
        raise SeedError("history OHLC values must be positive")
    if not positive and value < 0:
        raise SeedError("history volumes must be non-negative")
    return float(value)


@dataclass(frozen=True)
class SourceIdentity:
    database_name: str
    epoch_id: str
    read_only: bool
    pinned_snapshot: bool


@dataclass(frozen=True)
class TargetIdentity:
    database_name: str
    epoch_id: str
    schema_verified: bool
    fresh_non_trading_epoch: bool
    protected_source_or_shadow: bool = False


@dataclass(frozen=True)
class Anchor:
    count: int
    first_open_time_ms: int
    last_open_time_ms: int
    last_close_time_ms: int


@dataclass(frozen=True)
class SeedExpectation:
    """Accepted source manifest values, supplied by the controller."""

    anchors: Mapping[str, Anchor]
    ordered_digest_sha256: str


@dataclass(frozen=True)
class SeedLimits:
    maximum_rows: int = MAX_ROWS
    maximum_bytes: int = MAX_TOTAL_BYTES
    maximum_seconds: int = MAX_SECONDS


DEFAULT_SEED_LIMITS = SeedLimits()


@dataclass(frozen=True)
class SeedReceipt:
    rows: int
    bytes: int
    ordered_digest_sha256: str
    anchors: Mapping[str, Anchor]
    target_database: str
    target_epoch_id: str
    target_outbox_rows_after: int


class TargetConnection(Protocol):
    def transaction(self) -> Any: ...
    async def fetchrow(self, query: str, *args: Any) -> Mapping[str, Any] | None: ...
    async def executemany(self, query: str, args: list[tuple[Any, ...]]) -> Any: ...


def validate_epoch_pair(source: SourceIdentity, target: TargetIdentity) -> None:
    if not source.read_only or not source.pinned_snapshot:
        raise SeedError("source must be read-only and pinned to one epoch snapshot")
    if not source.database_name or not source.epoch_id:
        raise SeedError("pinned source database and epoch identities are required")
    if (
        target.database_name == source.database_name
        or target.epoch_id == source.epoch_id
    ):
        raise SeedError("target must be a separately named database and epoch")
    if NEW_EPOCH_DB_RE.fullmatch(target.database_name) is None:
        raise SeedError("target database must have an explicitly new epoch name")
    if (
        not target.epoch_id
        or not target.schema_verified
        or not target.fresh_non_trading_epoch
    ):
        raise SeedError("target must be a verified, fresh non-trading epoch")
    if target.protected_source_or_shadow:
        raise SeedError("primary and preserved shadow targets are forbidden")


class _Accumulator:
    def __init__(
        self,
        expected_anchors: Mapping[str, Anchor],
        expected_digest: str | None,
        limits: SeedLimits,
    ) -> None:
        if set(expected_anchors) != set(SYMBOLS):
            raise SeedError("exact expected anchors for all five symbols are required")
        if expected_digest is not None and not SHA256_RE.fullmatch(expected_digest):
            raise SeedError("expected ordered source digest is invalid")
        if any(
            type(v) is not int or v <= 0
            for v in (limits.maximum_rows, limits.maximum_bytes, limits.maximum_seconds)
        ):
            raise SeedError("positive bounded seed limits are required")
        self.expected_anchors = dict(expected_anchors)
        self.expected_digest = expected_digest
        self.limits = limits
        self.started = time.monotonic()
        self.rows = 0
        self.bytes = 0
        self.digest = hashlib.sha256()
        self.seen_ids: set[str] = set()
        self.previous: dict[str, int] = {}
        self.first: dict[str, int] = {}
        self.last: dict[str, tuple[int, int]] = {}
        self.counts = {symbol: 0 for symbol in SYMBOLS}

    def add(self, raw: Mapping[str, Any]) -> tuple[Any, ...]:
        if time.monotonic() - self.started > self.limits.maximum_seconds:
            raise SeedError("history seed exceeded its time bound")
        required = {
            "produced_at",
            "message_id",
            "topic",
            "source",
            "schema_version",
            "correlation_id",
            "causation_id",
            "payload",
            "outbox_count",
            "outbox_topic",
            "outbox_producer",
            "outbox_payload",
            "stored_payload_sha256",
        }
        if not isinstance(raw, Mapping) or not required.issubset(raw):
            raise SeedError("source export row is incomplete")
        if (
            raw["topic"] != TOPIC
            or raw["source"] != SOURCE
            or raw["schema_version"] != SCHEMA_VERSION
        ):
            raise SeedError("source audit identity is not canonical CLOSED_BAR v1")
        produced_at = _utc_datetime(raw["produced_at"], "audit produced_at")
        payload = _payload(raw["payload"])
        if (
            payload["schema_version"] != SCHEMA_VERSION
            or payload["source"] != SOURCE
            or payload["contract_version"] != CONTRACT_VERSION
            or payload["venue"] != "BINANCE_UM"
            or payload["timeframe"] != "1m"
            or payload["is_closed"] is not True
            or payload["schema_version"] != raw["schema_version"]
            or payload["message_id"] != raw["message_id"]
            or payload["correlation_id"] != raw["correlation_id"]
            or payload["causation_id"] != raw["causation_id"]
            or _utc_datetime(payload["produced_at"], "payload produced_at")
            != produced_at
        ):
            raise SeedError("payload envelope does not match the source audit identity")
        symbol = payload["symbol"]
        if symbol not in SYMBOLS:
            raise SeedError("CLOSED_BAR symbol is outside the fixed five-symbol scope")
        if (
            type(payload["open_time_ms"]) is not int
            or type(payload["close_time_ms"]) is not int
        ):
            raise SeedError("bar timestamps must be integer milliseconds")
        open_ms, close_ms = payload["open_time_ms"], payload["close_time_ms"]
        if open_ms < 0 or open_ms % MINUTE_MS or close_ms != open_ms + MINUTE_MS - 1:
            raise SeedError("bar timestamps must be minute-aligned and final")
        open_price = _finite_number(payload, "open", positive=True)
        high = _finite_number(payload, "high", positive=True)
        low = _finite_number(payload, "low", positive=True)
        close = _finite_number(payload, "close", positive=True)
        base = _finite_number(payload, "base_volume")
        quote = _finite_number(payload, "quote_volume")
        taker_base = _finite_number(payload, "taker_buy_base_volume")
        taker_quote = _finite_number(payload, "taker_buy_quote_volume")
        if high < max(open_price, close) or low > min(open_price, close) or high < low:
            raise SeedError("bar OHLC geometry is invalid")
        if taker_base > base or taker_quote > quote:
            raise SeedError("bar taker-buy volume exceeds total volume")
        identity_payload = {name: payload[name] for name in _BAR_IDENTITY_FIELDS}
        bar_hash = hashlib.sha256(
            _contract_canonical_json(identity_payload)
        ).hexdigest()
        if payload["bar_sha256"] != bar_hash or raw["message_id"] != bar_hash:
            raise SeedError("bar identity hash or message_id differs")
        if not isinstance(raw["message_id"], str) or not raw["message_id"]:
            raise SeedError("source message_id is invalid")
        if raw["message_id"] in self.seen_ids:
            raise SeedError("source message_id is duplicated")
        if symbol in self.previous and open_ms != self.previous[symbol] + MINUTE_MS:
            raise SeedError("per-symbol CLOSED_BAR sequence is not contiguous")
        if type(raw["outbox_count"]) is not int or raw["outbox_count"] != 1:
            raise SeedError(
                "source row must have exactly one immutable legacy outbox identity"
            )
        if raw["outbox_topic"] != TOPIC or raw["outbox_producer"] != SOURCE:
            raise SeedError(
                "legacy outbox identity is not the matching CLOSED_BAR producer"
            )
        outbox_payload = _payload(raw["outbox_payload"])
        if outbox_payload != payload:
            raise SeedError("legacy outbox and event audit payloads differ")
        stored_hash = raw["stored_payload_sha256"]
        calculated_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
        if (
            not isinstance(stored_hash, str)
            or not SHA256_RE.fullmatch(stored_hash)
            or stored_hash != calculated_hash
        ):
            raise SeedError(
                "canonical payload hash differs from the stored outbox hash"
            )

        digest_row = {
            "produced_at": produced_at.isoformat(),
            "message_id": raw["message_id"],
            "topic": raw["topic"],
            "source": raw["source"],
            "schema_version": raw["schema_version"],
            "correlation_id": raw["correlation_id"],
            "causation_id": raw["causation_id"],
            "payload": payload,
            "stored_payload_sha256": stored_hash,
        }
        encoded = canonical_json(digest_row)
        self.rows += 1
        self.bytes += len(encoded)
        if (
            self.rows > self.limits.maximum_rows
            or self.bytes > self.limits.maximum_bytes
            or len(encoded) > MAX_ROW_BYTES
        ):
            raise SeedError("history seed exceeded its row or byte bound")
        self.digest.update(len(encoded).to_bytes(8, "big"))
        self.digest.update(encoded)
        self.seen_ids.add(raw["message_id"])
        self.first.setdefault(symbol, open_ms)
        self.last[symbol] = (open_ms, close_ms)
        self.previous[symbol] = open_ms
        self.counts[symbol] += 1
        return (
            produced_at,
            raw["message_id"],
            raw["topic"],
            raw["source"],
            raw["schema_version"],
            raw["correlation_id"],
            raw["causation_id"],
            canonical_json(payload).decode("utf-8"),
        )

    def finish(self) -> tuple[str, dict[str, Anchor]]:
        if time.monotonic() - self.started > self.limits.maximum_seconds:
            raise SeedError("history seed exceeded its time bound")
        actual: dict[str, Anchor] = {}
        for symbol in SYMBOLS:
            if self.counts[symbol] == 0:
                raise SeedError("source history is incomplete for a required symbol")
            last_open, last_close = self.last[symbol]
            actual[symbol] = Anchor(
                self.counts[symbol], self.first[symbol], last_open, last_close
            )
        digest = self.digest.hexdigest()
        if actual != self.expected_anchors or (
            self.expected_digest is not None and digest != self.expected_digest
        ):
            raise SeedError(
                "source history counts, final anchors, or ordered digest differ"
            )
        return digest, actual


async def measure_history(
    rows: AsyncIterable[Mapping[str, Any]],
    expected_anchors: Mapping[str, Anchor],
    limits: SeedLimits = DEFAULT_SEED_LIMITS,
) -> SeedExpectation:
    """Validate a pinned read-only source pass and compute its ordered digest.

    The caller can repeat SOURCE_EXPORT_SQL on a second cursor in the same
    repeatable-read snapshot, then pass this expectation to ``seed_history``.
    """
    accumulator = _Accumulator(expected_anchors, None, limits)
    async for raw in rows:
        accumulator.add(raw)
    digest, anchors = accumulator.finish()
    return SeedExpectation(anchors=anchors, ordered_digest_sha256=digest)


async def seed_history(
    rows: AsyncIterable[Mapping[str, Any]],
    target: TargetConnection,
    *,
    source: SourceIdentity,
    target_identity: TargetIdentity,
    expected: SeedExpectation,
    limits: SeedLimits = DEFAULT_SEED_LIMITS,
    batch_size: int = 1_000,
) -> SeedReceipt:
    """Validate and insert an entire bounded source stream atomically.

    The caller must provide `rows` from a read-only repeatable/pinned source
    query using SOURCE_EXPORT_SQL. Any validation or target mismatch raised
    before transaction exit rolls back all inserted audit rows.
    """
    validate_epoch_pair(source, target_identity)
    if type(batch_size) is not int or not 1 <= batch_size <= 1_000:
        raise SeedError("target insert batch must be bounded to 1..1000 rows")
    accumulator = _Accumulator(expected.anchors, expected.ordered_digest_sha256, limits)
    inserted = 0
    async with target.transaction():
        counts = await target.fetchrow(TARGET_EMPTY_CHECK_SQL)
        if (
            counts is None
            or int(counts["event_audit_rows"]) != 0
            or int(counts["message_outbox_rows"]) != 0
        ):
            raise SeedError(
                "fresh target must start with empty event_audit and message_outbox"
            )
        batch: list[tuple[Any, ...]] = []
        async for raw in rows:
            batch.append(accumulator.add(raw))
            if len(batch) == batch_size:
                await target.executemany(TARGET_INSERT_SQL, batch)
                inserted += len(batch)
                batch = []
        if batch:
            await target.executemany(TARGET_INSERT_SQL, batch)
            inserted += len(batch)
        digest, anchors = accumulator.finish()
        if inserted != accumulator.rows:
            raise SeedError("target audit insertion count is incomplete")
        after = await target.fetchrow(TARGET_EMPTY_CHECK_SQL)
        if (
            after is None
            or int(after["event_audit_rows"]) != inserted
            or int(after["message_outbox_rows"]) != 0
        ):
            raise SeedError("target post-seed audit/outbox counts differ")
    return SeedReceipt(
        rows=inserted,
        bytes=accumulator.bytes,
        ordered_digest_sha256=digest,
        anchors=anchors,
        target_database=target_identity.database_name,
        target_epoch_id=target_identity.epoch_id,
        target_outbox_rows_after=0,
    )
