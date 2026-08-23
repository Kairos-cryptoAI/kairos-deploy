#!/usr/bin/env python3
"""Build a secret-free acceptance report for the EVEDEX DEV technical canary.

The collector has no exchange client and performs no network mutation.  It reads a
single repeatable-read snapshot through ``docker compose exec -T timescaledb psql``.
The evaluator is deliberately pure: identical evidence produces identical report
bytes.  Raw account, trade, order and effect identities never enter the report.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

EVIDENCE_SCHEMA_VERSION = 1
REPORT_SCHEMA_VERSION = 1
GATE_NAME = "EVEDEX_DEV_TECHNICAL_CANARY_ACCEPTANCE"
CANARY_STRATEGY = "technical-canary"
CANARY_REVISION = "1"
EXPECTED_SYMBOLS = ("BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT")
EXPECTED_VENUE_SYMBOLS = {
    "BTCUSDT": "BTCUSD:DEV",
    "ETHUSDT": "ETHUSD:DEV",
    "SOLUSDT": "SOLUSD:DEV",
    "BNBUSDT": "BNBUSD:DEV",
    "XRPUSDT": "XRPUSD:DEV",
}
EXPECTED_ENVIRONMENTS = frozenset(
    {"paper:EVEDEX:DEV:PAPER", "paper-dev:EVEDEX:DEV:PAPER"}
)
TERMINAL_STATES = frozenset({"FLAT", "CANCELLED"})
REQUIRED_PROTECTION_EVENTS = frozenset(
    {
        "STOP_CREATED",
        "STOP_RECONCILED",
        "TARGET_CREATED",
        "TARGET_RECONCILED",
    }
)
REQUIRED_EXIT_REASONS = frozenset({"STOP", "TARGET", "TIMEOUT"})
FILL_EVENTS = frozenset({"ENTRY_FILLED", "ENTRY_PARTIAL_FILL"})
FORBIDDEN_PUBLIC_EVENTS = frozenset({"FAILED", "RECOVERY_BLOCKED", "EMERGENCY_CLOSE"})
ACCOUNT_PATTERN = re.compile(r"kairos-paper-dev-[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?")
DATABASE_IDENTIFIER_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,62}")


class EvidenceSchemaError(ValueError):
    """Durable evidence does not match the versioned evaluator input."""


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise EvidenceSchemaError(f"{label} has an unsupported shape")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceSchemaError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceSchemaError(f"{label} must be an array")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceSchemaError(f"{label} must be non-empty text")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceSchemaError(f"{label} must be boolean")
    return value


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceSchemaError(f"{label} must be a non-negative integer")
    return value


def _finite_nonnegative(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceSchemaError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise EvidenceSchemaError(f"{label} must be finite and non-negative")
    return result


def _text_set(value: Any, label: str) -> frozenset[str]:
    items = _list(value, label)
    if any(not isinstance(item, str) or not item for item in items):
        raise EvidenceSchemaError(f"{label} must contain non-empty text")
    if len(items) != len(set(items)):
        raise EvidenceSchemaError(f"{label} must not contain duplicates")
    return frozenset(items)


def _base_report(
    *,
    status: str,
    pending: Sequence[str],
    failures: Sequence[str],
    coverage: Mapping[str, Any],
    counters: Mapping[str, int],
) -> dict[str, Any]:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "gate": GATE_NAME,
        "status": status,
        "accepted": status == "PASS",
        "strategy": "technical-canary@1",
        "scope": {
            "trading_mode": "PAPER",
            "profile": "DEV",
            "exchange": "EVEDEX",
            "dedicated_account_namespace": True,
        },
        "coverage": dict(coverage),
        "counters": dict(counters),
        "pending_reasons": sorted(set(pending)),
        "failure_reasons": sorted(set(failures)),
        "contains_raw_identifiers": False,
        "contains_credentials": False,
    }


def invalid_evidence_report() -> dict[str, Any]:
    """Return a stable, secret-free failure without echoing malformed input."""

    return _base_report(
        status="FAIL",
        pending=(),
        failures=("EVIDENCE_SCHEMA_INVALID",),
        coverage={
            "protected_flat_symbols": [],
            "required_symbols": list(EXPECTED_SYMBOLS),
            "exit_reasons": [],
            "marketable_ioc_limit": False,
            "entry_cancel": False,
            "restart_recovery": False,
        },
        counters={
            "trades": 0,
            "real_fill_events": 0,
            "duplicate_client_order_ids": 0,
            "unresolved_effects": 0,
            "nonterminal_trades": 0,
            "failed_lifecycles": 0,
        },
    )


def collection_failure_report() -> dict[str, Any]:
    """Return a stable report when the read-only database snapshot cannot be read."""

    result = invalid_evidence_report()
    result["failure_reasons"] = ["READ_ONLY_EVIDENCE_COLLECTION_FAILED"]
    return result


def evaluate_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Purely evaluate one sanitized durable-evidence snapshot.

    Missing scenario coverage is ``PENDING``.  An invariant violation is ``FAIL``.
    The function never returns raw evidence or durable identities.
    """

    try:
        root = _mapping(evidence, "evidence")
        _exact_keys(
            root,
            {"schema_version", "scope", "recovery", "integrity", "trades"},
            "evidence",
        )
        if root["schema_version"] != EVIDENCE_SCHEMA_VERSION:
            raise EvidenceSchemaError("unsupported evidence schema")

        scope = _mapping(root["scope"], "scope")
        _exact_keys(
            scope,
            {
                "environment",
                "trading_mode",
                "profile",
                "exchange",
                "account_id",
            },
            "scope",
        )
        environment = _text(scope["environment"], "scope.environment")
        trading_mode = _text(scope["trading_mode"], "scope.trading_mode")
        profile = _text(scope["profile"], "scope.profile")
        exchange = _text(scope["exchange"], "scope.exchange")
        account_id = _text(scope["account_id"], "scope.account_id")
        account_namespace_valid = ACCOUNT_PATTERN.fullmatch(account_id) is not None

        recovery = _mapping(root["recovery"], "recovery")
        _exact_keys(
            recovery,
            {
                "present",
                "entries_blocked",
                "recovery_epoch",
                "completed",
                "protected_trade_crossed_epoch",
            },
            "recovery",
        )
        recovery_present = _boolean(recovery["present"], "recovery.present")
        entries_blocked = _boolean(
            recovery["entries_blocked"], "recovery.entries_blocked"
        )
        recovery_epoch = _integer(recovery["recovery_epoch"], "recovery.recovery_epoch")
        recovery_completed = _boolean(recovery["completed"], "recovery.completed")
        protected_trade_crossed_epoch = _boolean(
            recovery["protected_trade_crossed_epoch"],
            "recovery.protected_trade_crossed_epoch",
        )

        integrity = _mapping(root["integrity"], "integrity")
        _exact_keys(
            integrity,
            {
                "prepared_effects",
                "failed_effects",
                "duplicate_client_order_ids",
                "foreign_scope_trades",
                "foreign_scope_effects",
                "cancel_order_effects",
                "real_fill_events",
                "public_failure_events",
            },
            "integrity",
        )
        prepared_effects = _integer(integrity["prepared_effects"], "prepared_effects")
        failed_effects = _integer(integrity["failed_effects"], "failed_effects")
        duplicate_client_ids = _integer(
            integrity["duplicate_client_order_ids"], "duplicate_client_order_ids"
        )
        foreign_scope_trades = _integer(
            integrity["foreign_scope_trades"], "foreign_scope_trades"
        )
        foreign_scope_effects = _integer(
            integrity["foreign_scope_effects"], "foreign_scope_effects"
        )
        cancel_order_effects = _integer(
            integrity["cancel_order_effects"], "cancel_order_effects"
        )
        real_fill_events = _integer(integrity["real_fill_events"], "real_fill_events")
        public_failure_events = _integer(
            integrity["public_failure_events"], "public_failure_events"
        )

        trade_rows = _list(root["trades"], "trades")
        normalized_trades: list[dict[str, Any]] = []
        trade_keys = {
            "symbol",
            "venue_symbol",
            "trading_mode",
            "profile",
            "exchange",
            "strategy_id",
            "strategy_revision",
            "state",
            "filled_quantity",
            "marketable_ioc_limit",
            "next_bar_market",
            "decision_binding_valid",
            "event_types",
            "exit_reasons",
            "public_event_count",
            "expected_public_event_count",
            "public_sequence_contiguous",
            "public_scope_valid",
            "protected_sequence_valid",
            "internal_failure_count",
            "cancel_order_effects",
            "real_fill_event_count",
        }
        for index, raw_trade in enumerate(trade_rows):
            trade = _mapping(raw_trade, f"trades[{index}]")
            _exact_keys(trade, trade_keys, f"trades[{index}]")
            normalized_trades.append(
                {
                    "symbol": _text(trade["symbol"], "trade.symbol"),
                    "venue_symbol": _text(trade["venue_symbol"], "trade.venue_symbol"),
                    "trading_mode": _text(trade["trading_mode"], "trade.trading_mode"),
                    "profile": _text(trade["profile"], "trade.profile"),
                    "exchange": _text(trade["exchange"], "trade.exchange"),
                    "strategy_id": _text(trade["strategy_id"], "trade.strategy_id"),
                    "strategy_revision": _text(
                        trade["strategy_revision"], "trade.strategy_revision"
                    ),
                    "state": _text(trade["state"], "trade.state"),
                    "filled_quantity": _finite_nonnegative(
                        trade["filled_quantity"], "trade.filled_quantity"
                    ),
                    "marketable_ioc_limit": _boolean(
                        trade["marketable_ioc_limit"], "trade.marketable_ioc_limit"
                    ),
                    "next_bar_market": _boolean(
                        trade["next_bar_market"], "trade.next_bar_market"
                    ),
                    "decision_binding_valid": _boolean(
                        trade["decision_binding_valid"],
                        "trade.decision_binding_valid",
                    ),
                    "event_types": _text_set(trade["event_types"], "trade.event_types"),
                    "exit_reasons": _text_set(
                        trade["exit_reasons"], "trade.exit_reasons"
                    ),
                    "public_event_count": _integer(
                        trade["public_event_count"], "trade.public_event_count"
                    ),
                    "expected_public_event_count": _integer(
                        trade["expected_public_event_count"],
                        "trade.expected_public_event_count",
                    ),
                    "public_sequence_contiguous": _boolean(
                        trade["public_sequence_contiguous"],
                        "trade.public_sequence_contiguous",
                    ),
                    "public_scope_valid": _boolean(
                        trade["public_scope_valid"], "trade.public_scope_valid"
                    ),
                    "protected_sequence_valid": _boolean(
                        trade["protected_sequence_valid"],
                        "trade.protected_sequence_valid",
                    ),
                    "internal_failure_count": _integer(
                        trade["internal_failure_count"], "trade.internal_failure_count"
                    ),
                    "cancel_order_effects": _integer(
                        trade["cancel_order_effects"], "trade.cancel_order_effects"
                    ),
                    "real_fill_event_count": _integer(
                        trade["real_fill_event_count"], "trade.real_fill_event_count"
                    ),
                }
            )
    except (EvidenceSchemaError, KeyError, TypeError, ValueError):
        return invalid_evidence_report()

    pending: list[str] = []
    failures: list[str] = []

    if (
        environment not in EXPECTED_ENVIRONMENTS
        or trading_mode != "PAPER"
        or profile != "DEV"
        or exchange.casefold() != "evedex"
        or not account_namespace_valid
    ):
        failures.append("SCOPE_IS_NOT_DEDICATED_EVEDEX_DEV_PAPER")

    if not recovery_present:
        failures.append("RECOVERY_BARRIER_MISSING")
    elif entries_blocked or not recovery_completed:
        failures.append("RECOVERY_BARRIER_NOT_CLEAN")
    # An incremented epoch alone can be produced by a reconnect while flat.  It
    # is not evidence that recovery protected an in-flight trade.  Require one
    # fully protected fill before the latest epoch and its terminal exit during
    # or after that epoch as the durable restart/reconnect-recovery proof.
    restart_recovery = (
        recovery_present
        and recovery_completed
        and not entries_blocked
        and recovery_epoch >= 2
        and protected_trade_crossed_epoch
    )
    if not restart_recovery:
        pending.append("RESTART_RECOVERY_NOT_YET_PROVEN")

    unresolved_effects = prepared_effects + failed_effects
    if unresolved_effects:
        failures.append("UNRESOLVED_PREPARED_OR_FAILED_EFFECTS")
    if duplicate_client_ids:
        failures.append("DUPLICATE_CLIENT_ORDER_IDS")
    if foreign_scope_trades or foreign_scope_effects:
        failures.append("DEDICATED_ACCOUNT_HAS_FOREIGN_SCOPE_FACTS")
    if public_failure_events:
        failures.append("FAILED_OR_EMERGENCY_PUBLIC_LIFECYCLE_FACTS")

    protected_symbols: set[str] = set()
    observed_exit_reasons: set[str] = set()
    nonterminal_trades = 0
    failed_lifecycles = 0
    computed_real_fill_events = 0
    computed_cancel_effects = 0
    marketable_ioc_limit = bool(normalized_trades)

    for trade in normalized_trades:
        symbol = trade["symbol"]
        events = trade["event_types"]
        exits = trade["exit_reasons"]
        computed_real_fill_events += trade["real_fill_event_count"]
        computed_cancel_effects += trade["cancel_order_effects"]
        marketable_ioc_limit = (
            marketable_ioc_limit
            and trade["marketable_ioc_limit"]
            and trade["next_bar_market"]
        )

        if (
            symbol not in EXPECTED_VENUE_SYMBOLS
            or trade["venue_symbol"] != EXPECTED_VENUE_SYMBOLS.get(symbol)
            or trade["trading_mode"] != "PAPER"
            or trade["profile"] != "DEV"
            or trade["exchange"].casefold() != "evedex"
            or trade["strategy_id"] != CANARY_STRATEGY
            or trade["strategy_revision"] != CANARY_REVISION
            or not trade["decision_binding_valid"]
        ):
            failures.append("TRADE_LINEAGE_OUTSIDE_TECHNICAL_CANARY_V1")

        if trade["state"] not in TERMINAL_STATES:
            nonterminal_trades += 1
        if (
            trade["state"] == "FAILED_BLOCKED"
            or trade["internal_failure_count"]
            or events & FORBIDDEN_PUBLIC_EVENTS
        ):
            failed_lifecycles += 1
        if (
            trade["public_event_count"] != trade["expected_public_event_count"]
            or not trade["public_sequence_contiguous"]
            or not trade["public_scope_valid"]
        ):
            failures.append("PUBLIC_LIFECYCLE_FACTS_ARE_NOT_ATOMIC_AND_CONTIGUOUS")

        has_fill = trade["filled_quantity"] > 0 or trade["real_fill_event_count"] > 0
        fill_fact = bool(events & FILL_EVENTS)
        required_exits = exits & REQUIRED_EXIT_REASONS
        exit_attribution_valid = exits == required_exits and len(required_exits) == 1
        protected_flat = (
            trade["state"] == "FLAT"
            and has_fill
            and fill_fact
            and "DECISION_RECEIVED" in events
            and REQUIRED_PROTECTION_EVENTS <= events
            and "EXIT_TRIGGERED" in events
            and "EXIT_FILLED" in events
            and exit_attribution_valid
            and trade["protected_sequence_valid"]
        )
        if has_fill and not protected_flat:
            failures.append("FILLED_TRADE_LACKS_PROTECTED_FLAT_ROUND_TRIP")
        if protected_flat:
            protected_symbols.add(symbol)
            observed_exit_reasons.update(required_exits)

    if computed_real_fill_events != real_fill_events:
        failures.append("REAL_FILL_EVENT_AGGREGATE_MISMATCH")
    if computed_cancel_effects != cancel_order_effects:
        failures.append("CANCEL_EFFECT_AGGREGATE_MISMATCH")
    if nonterminal_trades:
        failures.append("NONTERMINAL_TRADE_LIFECYCLES")
    if failed_lifecycles:
        failures.append("FAILED_TRADE_LIFECYCLES")

    missing_symbols = sorted(set(EXPECTED_SYMBOLS) - protected_symbols)
    if missing_symbols:
        pending.append("PROTECTED_FLAT_ROUND_TRIPS_MISSING")
    missing_exits = sorted(REQUIRED_EXIT_REASONS - observed_exit_reasons)
    if missing_exits:
        pending.append("STOP_TARGET_TIMEOUT_COVERAGE_INCOMPLETE")
    if not marketable_ioc_limit:
        pending.append("MARKETABLE_IOC_LIMIT_COVERAGE_INCOMPLETE")
    entry_cancel = cancel_order_effects > 0
    if not entry_cancel:
        pending.append("ENTRY_CANCEL_COVERAGE_INCOMPLETE")
    if real_fill_events <= 0:
        pending.append("REAL_EVEDEX_DEV_FILL_NOT_OBSERVED")

    status = "FAIL" if failures else "PENDING" if pending else "PASS"
    return _base_report(
        status=status,
        pending=pending,
        failures=failures,
        coverage={
            "protected_flat_symbols": sorted(protected_symbols),
            "required_symbols": list(EXPECTED_SYMBOLS),
            "missing_symbols": missing_symbols,
            "exit_reasons": sorted(observed_exit_reasons),
            "missing_exit_reasons": missing_exits,
            "marketable_ioc_limit": marketable_ioc_limit,
            "entry_cancel": entry_cancel,
            "restart_recovery": restart_recovery,
        },
        counters={
            "trades": len(normalized_trades),
            "real_fill_events": real_fill_events,
            "duplicate_client_order_ids": duplicate_client_ids,
            "unresolved_effects": unresolved_effects,
            "nonterminal_trades": nonterminal_trades,
            "failed_lifecycles": failed_lifecycles,
        },
    )


def canonical_report_bytes(report: Mapping[str, Any]) -> bytes:
    """Serialize a report deterministically for audit and fixture comparison."""

    return (
        json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()


def _sql(environment: str, account_id: str) -> str:
    """Return the fixed, read-only aggregate query for a validated scope."""

    return f"""
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '30s';
WITH
scoped_trades AS (
    SELECT *
    FROM execution_trades
    WHERE environment = '{environment}' AND account_id = '{account_id}'
),
scoped_public_events AS (
    SELECT p.*
    FROM public_execution_events AS p
    JOIN scoped_trades AS t USING (trade_id)
),
scoped_internal_events AS (
    SELECT e.*
    FROM execution_trade_events AS e
    JOIN scoped_trades AS t USING (trade_id)
),
scoped_effects AS (
    SELECT *
    FROM execution_effects
    WHERE environment = '{environment}' AND account_id = '{account_id}'
),
lineage AS (
    SELECT trade_id, order_role, client_order_id
    FROM scoped_effects
    WHERE trade_id IS NOT NULL AND order_role IS NOT NULL AND client_order_id IS NOT NULL
    UNION
    SELECT trade_id, 'ENTRY', entry_client_order_id FROM scoped_trades
    UNION
    SELECT trade_id, 'STOP_LOSS', stop_client_order_id
    FROM scoped_trades WHERE stop_client_order_id IS NOT NULL
    UNION
    SELECT trade_id, 'TAKE_PROFIT', target_client_order_id
    FROM scoped_trades WHERE target_client_order_id IS NOT NULL
),
duplicate_lineage AS (
    SELECT client_order_id
    FROM lineage
    GROUP BY client_order_id
    HAVING count(DISTINCT trade_id || ':' || order_role) > 1
),
trade_evidence AS (
    SELECT jsonb_build_object(
        'symbol', t.symbol,
        'venue_symbol', t.venue_symbol,
        'trading_mode', t.trading_mode,
        'profile', t.profile,
        'exchange', t.exchange,
        'strategy_id', t.strategy_id,
        'strategy_revision', t.strategy_revision,
        'state', t.state,
        'filled_quantity', t.filled_quantity,
        'marketable_ioc_limit', EXISTS (
            SELECT 1
            FROM jsonb_array_elements(
                COALESCE(t.risk_decision_payload #> '{{intent,metadata}}', '[]'::jsonb)
            ) AS metadata(item)
            WHERE item ->> 0 = 'canary_entry_order'
              AND item ->> 1 = 'MARKETABLE_IOC_LIMIT'
        ),
        'next_bar_market', COALESCE(t.risk_decision_payload ->> 'entry_policy', '') =
            'NEXT_BAR_MARKET',
        'decision_binding_valid', COALESCE(
            t.risk_decision_payload ->> 'contract_version' = 'risk-trade-decision.v1'
            AND t.risk_decision_payload ->> 'decision_id' = t.risk_decision_id
            AND t.risk_decision_payload ->> 'trade_id' = t.trade_id
            AND t.risk_decision_payload -> 'approved' = 'true'::jsonb
            AND t.risk_decision_payload ->> 'trading_mode' = t.trading_mode
            AND t.risk_decision_payload ->> 'evedex_profile' = t.profile
            AND t.risk_decision_payload ->> 'account_id' = t.account_id
            AND t.risk_decision_payload ->> 'venue_symbol' = t.venue_symbol
            AND t.risk_decision_payload ->> 'entry_policy' = 'NEXT_BAR_MARKET'
            AND t.risk_decision_payload #>> '{{intent,intent_id}}' = t.strategy_intent_id
            AND t.risk_decision_payload #>> '{{intent,strategy_id}}' = t.strategy_id
            AND t.risk_decision_payload #>> '{{intent,strategy_revision}}' =
                t.strategy_revision
            AND t.risk_decision_payload #> '{{review,intent}}' =
                t.risk_decision_payload -> 'intent'
            AND t.risk_decision_payload #> '{{review,route,intent}}' =
                t.risk_decision_payload -> 'intent'
            AND t.risk_decision_payload -> 'exit_plan' =
                t.risk_decision_payload #> '{{intent,exit_plan}}',
            FALSE
        ),
        'event_types', COALESCE((
            SELECT jsonb_agg(event_type ORDER BY event_type)
            FROM (
                SELECT DISTINCT p.payload ->> 'event_type' AS event_type
                FROM scoped_public_events AS p
                WHERE p.trade_id = t.trade_id AND p.payload ->> 'event_type' IS NOT NULL
            ) AS distinct_events
        ), '[]'::jsonb),
        'exit_reasons', COALESCE((
            SELECT jsonb_agg(exit_reason ORDER BY exit_reason)
            FROM (
                SELECT DISTINCT p.payload ->> 'exit_reason' AS exit_reason
                FROM scoped_public_events AS p
                WHERE p.trade_id = t.trade_id
                  AND p.payload ->> 'exit_reason' IS NOT NULL
            ) AS distinct_exits
        ), '[]'::jsonb),
        'public_event_count', (
            SELECT count(*) FROM scoped_public_events AS p WHERE p.trade_id = t.trade_id
        ),
        'expected_public_event_count', t.state_version + 1,
        'public_sequence_contiguous', COALESCE((
            SELECT min(p.event_seq) = 1
               AND max(p.event_seq) = count(*)
               AND count(DISTINCT p.event_seq) = count(*)
            FROM scoped_public_events AS p WHERE p.trade_id = t.trade_id
        ), FALSE),
        'public_scope_valid', COALESCE((
            SELECT bool_and(
                (p.payload ->> 'contract_version' = 'trade-execution-event.v1') IS TRUE
                AND (p.payload ->> 'event_id' = p.event_id) IS TRUE
                AND (p.payload ->> 'message_id' = p.event_id) IS TRUE
                AND (p.payload ->> 'event_seq' = p.event_seq::text) IS TRUE
                AND (p.payload ->> 'trade_id' = t.trade_id) IS TRUE
                AND (p.payload ->> 'intent_id' = t.strategy_intent_id) IS TRUE
                AND (p.payload ->> 'risk_decision_id' = t.risk_decision_id) IS TRUE
                AND (p.payload ->> 'trading_mode' = 'PAPER') IS TRUE
                AND (p.payload ->> 'evedex_profile' = 'DEV') IS TRUE
                AND (p.payload ->> 'account_id' = t.account_id) IS TRUE
                AND (p.payload ->> 'venue_symbol' = t.venue_symbol) IS TRUE
                AND (p.payload ->> 'strategy_id' = t.strategy_id) IS TRUE
                AND (p.payload ->> 'strategy_revision' = t.strategy_revision) IS TRUE
            ) FROM scoped_public_events AS p WHERE p.trade_id = t.trade_id
        ), FALSE),
        'protected_sequence_valid', COALESCE((
            SELECT
                count(*) FILTER (
                    WHERE p.payload ->> 'event_type' = 'DECISION_RECEIVED'
                ) = 1
                AND count(*) FILTER (
                    WHERE p.payload ->> 'event_type' = 'STOP_CREATED'
                ) = 1
                AND count(*) FILTER (
                    WHERE p.payload ->> 'event_type' = 'STOP_RECONCILED'
                ) = 1
                AND count(*) FILTER (
                    WHERE p.payload ->> 'event_type' = 'TARGET_CREATED'
                ) = 1
                AND count(*) FILTER (
                    WHERE p.payload ->> 'event_type' = 'TARGET_RECONCILED'
                ) = 1
                AND count(*) FILTER (
                    WHERE p.payload ->> 'event_type' = 'EXIT_TRIGGERED'
                ) = 1
                AND count(*) FILTER (
                    WHERE p.payload ->> 'event_type' = 'EXIT_FILLED'
                ) = 1
                AND min(p.event_seq) FILTER (
                    WHERE p.payload ->> 'event_type' = 'DECISION_RECEIVED'
                ) = 1
                AND min(p.event_seq) FILTER (
                    WHERE p.payload ->> 'event_type' IN ('ENTRY_FILLED', 'ENTRY_PARTIAL_FILL')
                )
                    < min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'STOP_CREATED'
                    )
                AND min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'STOP_CREATED'
                    )
                    < min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'STOP_RECONCILED'
                    )
                AND min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'STOP_RECONCILED'
                    )
                    < min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'TARGET_CREATED'
                    )
                AND min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'TARGET_CREATED'
                    )
                    < min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'TARGET_RECONCILED'
                    )
                AND min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'TARGET_RECONCILED'
                    )
                    < min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'EXIT_TRIGGERED'
                    )
                AND min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'EXIT_TRIGGERED'
                    )
                    < min(p.event_seq) FILTER (
                        WHERE p.payload ->> 'event_type' = 'EXIT_FILLED'
                    )
                AND max(p.event_seq) = min(p.event_seq) FILTER (
                    WHERE p.payload ->> 'event_type' = 'EXIT_FILLED'
                )
                AND bool_and(
                    CASE p.payload ->> 'exit_reason'
                        WHEN 'STOP' THEN p.payload ->> 'lifecycle_state' IN (
                            'EXITING_STOP', 'FLAT'
                        )
                        WHEN 'TARGET' THEN p.payload ->> 'lifecycle_state' IN (
                            'EXITING_TARGET', 'FLAT'
                        )
                        WHEN 'TIMEOUT' THEN p.payload ->> 'lifecycle_state' IN (
                            'EXITING_TIMEOUT', 'FLAT'
                        )
                        ELSE FALSE
                    END
                ) FILTER (WHERE p.payload ->> 'exit_reason' IS NOT NULL)
                AND abs(
                    max((p.payload ->> 'filled_quantity')::double precision) FILTER (
                        WHERE p.payload ->> 'event_type' IN (
                            'ENTRY_FILLED', 'ENTRY_PARTIAL_FILL'
                        )
                    ) - t.filled_quantity
                ) <= greatest(1e-12, t.quantity * 1e-9)
            FROM scoped_public_events AS p WHERE p.trade_id = t.trade_id
        ), FALSE),
        'internal_failure_count', (
            SELECT count(*) FROM scoped_internal_events AS i
            WHERE i.trade_id = t.trade_id
              AND (i.to_state = 'FAILED_BLOCKED' OR i.event_type ILIKE '%FAIL%')
        ),
        'cancel_order_effects', (
            SELECT count(*) FROM scoped_effects AS e
            WHERE e.trade_id = t.trade_id
              AND e.effect_type = 'CANCEL_ORDER'
              AND e.order_role = 'ENTRY'
              AND e.status IN ('CONFIRMED', 'RECONCILED')
        ),
        'real_fill_event_count', (
            SELECT count(*) FROM scoped_public_events AS p
            WHERE p.trade_id = t.trade_id
              AND p.payload ->> 'event_type' IN ('ENTRY_FILLED', 'ENTRY_PARTIAL_FILL')
              AND COALESCE(NULLIF(p.payload ->> 'filled_quantity', '')::double precision, 0) > 0
        )
    ) AS evidence
    FROM scoped_trades AS t
),
recovery AS (
    SELECT entries_blocked, recovery_epoch, started_at, completed_at
    FROM execution_recovery_state
    WHERE environment = '{environment}'
      AND account_id = '{account_id}'
      AND exchange = 'evedex'
)
SELECT jsonb_build_object(
    'schema_version', {EVIDENCE_SCHEMA_VERSION},
    'scope', jsonb_build_object(
        'environment', '{environment}',
        'trading_mode', 'PAPER',
        'profile', 'DEV',
        'exchange', 'evedex',
        'account_id', '{account_id}'
    ),
    'recovery', COALESCE((
        SELECT jsonb_build_object(
            'present', TRUE,
            'entries_blocked', entries_blocked,
            'recovery_epoch', recovery_epoch,
            'completed', completed_at IS NOT NULL,
            'protected_trade_crossed_epoch', EXISTS (
                SELECT 1
                FROM scoped_trades AS t
                WHERE EXISTS (
                    SELECT 1 FROM scoped_public_events AS p
                    WHERE p.trade_id = t.trade_id
                      AND p.payload ->> 'event_type' IN (
                          'ENTRY_FILLED', 'ENTRY_PARTIAL_FILL'
                      )
                      AND p.created_at < recovery.started_at
                )
                  AND EXISTS (
                    SELECT 1 FROM scoped_public_events AS p
                    WHERE p.trade_id = t.trade_id
                      AND p.payload ->> 'event_type' = 'STOP_RECONCILED'
                      AND p.created_at < recovery.started_at
                )
                  AND EXISTS (
                    SELECT 1 FROM scoped_public_events AS p
                    WHERE p.trade_id = t.trade_id
                      AND p.payload ->> 'event_type' = 'TARGET_RECONCILED'
                      AND p.created_at < recovery.started_at
                )
                  AND EXISTS (
                    SELECT 1 FROM scoped_public_events AS p
                    WHERE p.trade_id = t.trade_id
                      AND p.payload ->> 'event_type' = 'EXIT_FILLED'
                      AND p.created_at >= recovery.started_at
                )
            )
        ) FROM recovery
    ), jsonb_build_object(
        'present', FALSE,
        'entries_blocked', TRUE,
        'recovery_epoch', 0,
        'completed', FALSE,
        'protected_trade_crossed_epoch', FALSE
    )),
    'integrity', jsonb_build_object(
        'prepared_effects', (
            SELECT count(*) FROM scoped_effects WHERE status = 'PREPARED'
        ),
        'failed_effects', (
            SELECT count(*) FROM scoped_effects WHERE status = 'FAILED'
        ),
        'duplicate_client_order_ids', (SELECT count(*) FROM duplicate_lineage),
        'foreign_scope_trades', (
            SELECT count(*) FROM execution_trades
            WHERE account_id = '{account_id}'
              AND (
                environment <> '{environment}' OR trading_mode <> 'PAPER'
                OR profile <> 'DEV' OR exchange <> 'evedex'
              )
        ),
        'foreign_scope_effects', (
            SELECT count(*) FROM execution_effects
            WHERE account_id = '{account_id}'
              AND (environment <> '{environment}' OR exchange <> 'evedex')
        ),
        'cancel_order_effects', (
            SELECT count(*) FROM scoped_effects
            WHERE effect_type = 'CANCEL_ORDER'
              AND order_role = 'ENTRY'
              AND status IN ('CONFIRMED', 'RECONCILED')
        ),
        'real_fill_events', (
            SELECT count(*) FROM scoped_public_events
            WHERE payload ->> 'event_type' IN ('ENTRY_FILLED', 'ENTRY_PARTIAL_FILL')
              AND COALESCE(NULLIF(payload ->> 'filled_quantity', '')::double precision, 0) > 0
        ),
        'public_failure_events', (
            SELECT count(*) FROM scoped_public_events
            WHERE payload ->> 'event_type' IN ('FAILED', 'RECOVERY_BLOCKED', 'EMERGENCY_CLOSE')
        )
    ),
    'trades', COALESCE((SELECT jsonb_agg(evidence) FROM trade_evidence), '[]'::jsonb)
)::text;
COMMIT;
""".strip()


def collect_evidence(
    *,
    compose_file: Path,
    env_file: Path,
    account_id: str,
    kairos_environment: str,
    database_user: str,
    database_name: str,
    timeout_seconds: int,
) -> Mapping[str, Any]:
    """Collect one read-only database snapshot without exposing process output."""

    if ACCOUNT_PATTERN.fullmatch(account_id) is None:
        raise ValueError("account must use the dedicated kairos-paper-dev-* namespace")
    if kairos_environment not in {"paper", "paper-dev"}:
        raise ValueError("Kairos environment must be paper or paper-dev")
    if DATABASE_IDENTIFIER_PATTERN.fullmatch(database_user) is None:
        raise ValueError("database user is not a safe PostgreSQL identifier")
    if DATABASE_IDENTIFIER_PATTERN.fullmatch(database_name) is None:
        raise ValueError("database name is not a safe PostgreSQL identifier")
    if timeout_seconds < 1 or timeout_seconds > 300:
        raise ValueError("timeout must be between 1 and 300 seconds")

    command = [
        "docker",
        "compose",
        "-p",
        "kairos-paper",
        "--env-file",
        str(env_file),
        "-f",
        str(compose_file),
        "exec",
        "-T",
        "timescaledb",
        "psql",
        "--no-psqlrc",
        "--quiet",
        "--tuples-only",
        "--no-align",
        "--set=ON_ERROR_STOP=1",
        f"--username={database_user}",
        f"--dbname={database_name}",
    ]
    environment = f"{kairos_environment}:EVEDEX:DEV:PAPER"
    completed = subprocess.run(
        command,
        input=_sql(environment, account_id),
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("read-only PostgreSQL evidence collection failed")
    output_lines = [
        line.strip() for line in completed.stdout.splitlines() if line.strip()
    ]
    if len(output_lines) != 1:
        raise RuntimeError("read-only PostgreSQL evidence was not one JSON document")
    try:
        result = json.loads(output_lines[0])
    except json.JSONDecodeError as exc:
        raise RuntimeError("read-only PostgreSQL evidence was not valid JSON") from exc
    return _mapping(result, "database evidence")


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    """Atomically write the canonical report without following a temporary link."""

    resolved_parent = path.expanduser().resolve().parent
    resolved_parent.mkdir(parents=True, exist_ok=True)
    destination = resolved_parent / path.name
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=resolved_parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_report_bytes(report))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _parser() -> argparse.ArgumentParser:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Evaluate durable EVEDEX DEV technical-canary acceptance evidence."
    )
    parser.add_argument(
        "--account-id",
        default=os.environ.get("KAIROS_PAPER_ACCOUNT_ID"),
        help="Dedicated local PAPER account ID (or KAIROS_PAPER_ACCOUNT_ID).",
    )
    parser.add_argument(
        "--kairos-environment", choices=("paper", "paper-dev"), default="paper"
    )
    parser.add_argument(
        "--compose-file", type=Path, default=repository / "docker-compose.paper.yml"
    )
    parser.add_argument("--env-file", type=Path, default=repository / ".env.paper")
    parser.add_argument("--database-user", default="kairos")
    parser.add_argument("--database-name", default="kairos")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument(
        "--output",
        type=Path,
        default=repository / "reports" / "paper-canary-acceptance.json",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.account_id:
        parser.error("--account-id or KAIROS_PAPER_ACCOUNT_ID is required")
    if not args.compose_file.is_file() or not args.env_file.is_file():
        parser.error("the PAPER Compose and env files must exist")

    try:
        evidence = collect_evidence(
            compose_file=args.compose_file.resolve(),
            env_file=args.env_file.resolve(),
            account_id=args.account_id,
            kairos_environment=args.kairos_environment,
            database_user=args.database_user,
            database_name=args.database_name,
            timeout_seconds=args.timeout_seconds,
        )
        report = evaluate_evidence(evidence)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError):
        report = collection_failure_report()

    write_report(args.output, report)
    print(
        f"{report['status']}: {len(report['pending_reasons'])} pending, "
        f"{len(report['failure_reasons'])} failed; sanitized report written"
    )
    return (
        0 if report["status"] == "PASS" else 2 if report["status"] == "PENDING" else 1
    )


if __name__ == "__main__":
    sys.exit(main())
