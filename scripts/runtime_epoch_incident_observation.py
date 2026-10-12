"""Read-only observation of the exact October 12 CLOSED_BAR epoch incident.

Only fixed new-epoch resources are queried. Legacy resources are inspected as
stopped metadata, never connected to. Public GET observations cannot admit a
restart, alter an anchor, retry a publication, or grant trading authority.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import runtime_epoch_boot as boot
else:
    import runtime_epoch_boot as boot

epoch = boot.epoch
fresh = epoch.fresh
ROOT = Path("D:/Kairos/runtime/runtime-incident-20261012")
FAILED_END = 1_791_766_980_000
FAILED_OPEN = FAILED_END - 60_000
SYMBOLS = ("BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT")
MAX_BODY = 128 * 1024
SQL = """BEGIN READ ONLY;
SET LOCAL statement_timeout='20s';
SELECT jsonb_build_object(
 'database',current_database(),'user',current_user,
 'audit_rows',(SELECT count(*) FROM event_audit),
 'outbox_rows',(SELECT count(*) FROM message_outbox),
 'pending_outbox',(SELECT count(*) FROM message_outbox WHERE published_at IS NULL),
 'inbox_rows',(SELECT count(*) FROM message_inbox),
 'unresolved_inbox',(SELECT count(*) FROM message_inbox WHERE status<>'COMPLETED'),
 'trading_rows',(SELECT count(*) FROM execution_orders)+(SELECT count(*) FROM execution_effects),
 'anchors',(SELECT jsonb_agg(r ORDER BY r.symbol) FROM
  (SELECT DISTINCT ON(payload->>'symbol') payload->>'symbol' symbol,payload
   FROM event_audit WHERE topic='kairos.market.closed_bar.v1' AND source='kairos-quant-scouts'
   ORDER BY payload->>'symbol',(payload->>'open_time_ms')::bigint DESC) r),
 'incident_rows',(SELECT jsonb_agg(r ORDER BY r.symbol) FROM
  (SELECT a.payload->>'symbol' symbol,a.message_id,a.payload,
   o.id outbox_id,o.payload_sha256,o.published_at IS NOT NULL published,
   o.lease_owner IS NOT NULL leased,o.reconciliation_state,
   EXISTS(SELECT 1 FROM message_inbox i WHERE i.consumer='kairos-epoch-consumer-69893dc7b7c6:bars'
    AND i.message_id=a.message_id AND i.status='COMPLETED') completed
   FROM event_audit a LEFT JOIN message_outbox o ON o.message_id=a.message_id AND o.topic=a.topic
   WHERE a.topic='kairos.market.closed_bar.v1' AND (a.payload->>'open_time_ms')::bigint=1791766920000) r));
COMMIT;"""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def bar_projection(row: object, symbol: str) -> dict:
    if (
        symbol not in SYMBOLS
        or not isinstance(row, list)
        or len(row) != 12
        or type(row[0]) is not int
        or type(row[6]) is not int
        or row[0] % 60_000
        or row[6] != row[0] + 59_999
    ):
        raise epoch.Rejected("INCIDENT_PUBLIC_BAR_GEOMETRY_REJECTED")
    result = {"symbol": symbol, "open_time_ms": row[0], "close_time_ms": row[6]}
    for field, index in (
        ("open", 1),
        ("high", 2),
        ("low", 3),
        ("close", 4),
        ("base_volume", 5),
        ("quote_volume", 7),
        ("taker_buy_base_volume", 9),
        ("taker_buy_quote_volume", 10),
    ):
        value = row[index]
        if not isinstance(value, str) or len(value) > 64:
            raise epoch.Rejected("INCIDENT_PUBLIC_BAR_NUMERIC_REJECTED")
        number = float(value)
        if not 0 <= number < 1e30:
            raise epoch.Rejected("INCIDENT_PUBLIC_BAR_NUMERIC_REJECTED")
        result[field] = number
    return result


def compare_pages(symbol: str, anchor: dict, first: object, second: object) -> dict:
    if (
        symbol not in SYMBOLS
        or anchor.get("symbol") != symbol
        or not isinstance(first, list)
        or not isinstance(second, list)
        or not 1 <= len(first) <= 2
        or len(first) != len(second)
    ):
        raise epoch.Rejected("INCIDENT_BOUNDED_PUBLIC_PAGE_REQUIRED")
    initial = [bar_projection(row, symbol) for row in first]
    confirmed = [bar_projection(row, symbol) for row in second]
    expected = list(range(anchor["open_time_ms"], FAILED_END, 60_000))
    if [row["open_time_ms"] for row in initial] != expected or [
        row["open_time_ms"] for row in confirmed
    ] != expected:
        raise epoch.Rejected("INCIDENT_EXACT_PUBLIC_WINDOW_REQUIRED")
    differing = sorted(
        field for field, value in confirmed[0].items() if anchor.get(field) != value
    )
    return {
        "pages_equal": initial == confirmed,
        "persisted_anchor_matches": not differing,
        "anchor_differing_fields": differing,
        "anchor_open_time_ms": anchor["open_time_ms"],
        "observed_end_exclusive_ms": FAILED_END,
        "historical_failure_reason_proven": False,
        "public_confirmation_sha256": fresh.digest(confirmed),
    }


def fetch_public_page(symbol: str, anchor: dict, destination: Path) -> object:
    if symbol not in SYMBOLS or anchor.get("symbol") != symbol:
        raise epoch.Rejected("EXACT_INCIDENT_SYMBOL_REQUIRED")
    query = urllib.parse.urlencode(
        {
            "symbol": symbol,
            "interval": "1m",
            "startTime": anchor["open_time_ms"],
            "endTime": FAILED_END - 1,
            "limit": 2,
        }
    )
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(
        "https://fapi.binance.com/fapi/v1/klines?" + query, timeout=30
    ) as response:
        if response.status != 200:
            raise epoch.Rejected("INCIDENT_OFFICIAL_GET_FAILED")
        body = response.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise epoch.Rejected("INCIDENT_OFFICIAL_RESPONSE_BOUND_EXCEEDED")
    value = json.loads(body)
    fresh.write(destination, body)
    return value


def failure_snapshot(directory: Path) -> dict:
    names = (
        "status.json",
        "progress.json",
        *("failure-" + s + ".json" for s in SYMBOLS),
    )
    if {path.name for path in directory.iterdir()} - set(names):
        raise epoch.Rejected("EXACT_INCIDENT_FAILURE_INVENTORY_REQUIRED")
    result = {}
    for name in names:
        path = fresh.safe(directory / name)
        if path.exists() and not path.is_file():
            raise epoch.Rejected("INCIDENT_FAILURE_SLOT_MUST_BE_REGULAR_FILE")
        result[name] = fresh.sha(path) if path.is_file() else None
    if any(
        result[name] is None
        for name in ("status.json", "progress.json", "failure-SOLUSDT.json")
    ):
        raise epoch.Rejected("INCIDENT_PRIMARY_FAILURE_REQUIRED")
    return result


def observe(revision: str) -> dict:
    boot.verify_source(revision)
    run = uuid.uuid4().hex
    work = ROOT / ("observation-" + run)
    epoch._private_directory(work)
    controller = boot.BootController(
        boot.OWNER,
        expected_revision=revision,
        workdir=work,
        continuation_attempt="incident-" + run[:8],
        deadline=time.monotonic() + 360,
    )
    before = controller.validate_resources(allow_running=True)
    if (before["views"]["serve"].get("state") or {}).get("Status") != "exited":
        raise epoch.Rejected("FAILED_SERVE_MUST_REMAIN_STOPPED")
    failure_dir = boot.SERVE_WORK / "output-serve"
    preserved = failure_snapshot(failure_dir)
    raw = controller.docker(
        [
            "exec",
            boot.CONTAINERS["pg"],
            "psql",
            "-X",
            "-w",
            "-q",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "kairos",
            "-d",
            "kairos_epoch_" + boot.OWNER[:12],
            "-c",
            SQL,
        ],
        seconds=45,
    )
    state = json.loads(raw)
    if (
        state.get("database") != "kairos_epoch_" + boot.OWNER[:12]
        or state.get("user") != "kairos"
        or state.get("trading_rows") != 0
        or state.get("unresolved_inbox") != 0
    ):
        raise epoch.Rejected("INCIDENT_NONTRADING_DATABASE_REQUIRED")
    fresh.save(work / "new-epoch-state.json", state)
    anchors = {row["symbol"]: row["payload"] for row in state["anchors"]}
    if set(anchors) != set(SYMBOLS):
        raise epoch.Rejected("INCIDENT_FIVE_ANCHORS_REQUIRED")
    first = {
        symbol: fetch_public_page(
            symbol, anchors[symbol], work / (symbol + "-first.json")
        )
        for symbol in SYMBOLS
    }
    time.sleep(5)
    second = {
        symbol: fetch_public_page(
            symbol, anchors[symbol], work / (symbol + "-second.json")
        )
        for symbol in SYMBOLS
    }
    comparisons = {
        s: compare_pages(s, anchors[s], first[s], second[s]) for s in SYMBOLS
    }
    after = controller.validate_resources(allow_running=True)
    if before != after or preserved != failure_snapshot(failure_dir):
        raise epoch.Rejected("INCIDENT_READONLY_PRESERVATION_CONFLICT")
    receipt = {
        "result": "PASS_READONLY_INCIDENT_OBSERVATION",
        "owner": boot.OWNER,
        "source_revision": revision,
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "observer_sha256": fresh.sha(Path(__file__)),
        "database_counts": {
            k: state[k]
            for k in (
                "audit_rows",
                "outbox_rows",
                "pending_outbox",
                "inbox_rows",
                "unresolved_inbox",
                "trading_rows",
            )
        },
        "incident_row_symbols": [
            row["symbol"] for row in state.get("incident_rows") or []
        ],
        "public_gets": 10,
        "comparisons": comparisons,
        "preserved_failures": preserved,
        "resources_unchanged": True,
        "legacy_metadata_only": True,
        "legacy_preservation": before["legacy"],
        "resource_snapshot_sha256": fresh.digest(before),
        "publication_attempts": 0,
        "restart_attempts": 0,
        "trading_started": False,
    }
    fresh.save(work / "receipt.json", receipt)
    return {
        "receipt": str(work / "receipt.json"),
        "sha256": fresh.sha(work / "receipt.json"),
        **receipt,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observe", action="store_true")
    parser.add_argument("--revision")
    args = parser.parse_args(argv)
    if not args.observe:
        print(json.dumps({"result": "PLAN_ONLY", "trading_started": False}))
        return 0
    try:
        print(json.dumps(observe(args.revision), sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001 - never expose native or HTTP error text.
        reason = str(exc) if isinstance(exc, epoch.Rejected) else type(exc).__name__
        print(
            json.dumps(
                {
                    "result": "FAILED_CLOSED",
                    "reason": reason,
                    "automatic_retry": False,
                    "trading_started": False,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
