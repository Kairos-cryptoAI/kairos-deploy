"""Fixed loopback-only synthetic receiver/driver for native state continuity.

No Telegram implementation, secret loader, market data or remote URL exists.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 19093
AM = "http://127.0.0.1:9093"
RECEIVER = "http://127.0.0.1:19093"
MAX_BYTES = 65_536
_COUNTS = {"firing": 0, "resolved": 0, "failures": 0, "requests": 0}
_FAIL_NEXT = False
_LOCK = threading.Lock()
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(url: str, value: object | None = None) -> object:
    if url not in {
        AM + "/-/ready",
        AM + "/api/v2/alerts",
        RECEIVER + "/counts",
        RECEIVER + "/fail-next",
    }:
        raise ValueError("fixed loopback URL required")
    data = None if value is None else json.dumps(value).encode()
    with _OPENER.open(
        urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        ),
        timeout=2,
    ) as response:
        body = response.read(MAX_BYTES + 1)
        if response.status != 200 or len(body) > MAX_BYTES:
            raise ValueError("bounded fixture response required")
    return None if not body or url == AM + "/-/ready" else json.loads(body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        pass

    def reply(self, code: int, value: object) -> None:
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/counts":
            self.reply(404, {})
            return
        with _LOCK:
            self.reply(200, dict(_COUNTS))

    def do_POST(self) -> None:
        global _FAIL_NEXT
        size = self.headers.get("Content-Length", "")
        if not size.isdigit() or not 0 < int(size) <= MAX_BYTES:
            self.reply(400, {})
            return
        try:
            value = json.loads(self.rfile.read(int(size)))
            if self.path == "/fail-next" and value == {"synthetic": True}:
                with _LOCK:
                    _FAIL_NEXT = True
                self.reply(200, {})
                return
            if (
                self.path != "/receive"
                or not isinstance(value, dict)
                or value.get("receiver") != "synthetic-only"
                or value.get("status") not in {"firing", "resolved"}
                or not isinstance(value.get("alerts"), list)
                or len(value["alerts"]) != 1
            ):
                raise ValueError("synthetic payload only")
            alert = value["alerts"][0]
            if alert.get("labels") != {
                "alertname": "KairosSyntheticStateGate",
                "scope": "synthetic-only",
            }:
                raise ValueError("no arbitrary alert data")
        except (ValueError, TypeError, AttributeError):
            self.reply(400, {})
            return
        with _LOCK:
            _COUNTS["requests"] += 1
            if _FAIL_NEXT:
                _FAIL_NEXT = False
                _COUNTS["failures"] += 1
                code = 503
            else:
                _COUNTS[value["status"]] += 1
                code = 200
        self.reply(code, {})


def counts() -> dict:
    value = request(RECEIVER + "/counts")
    if not isinstance(value, dict) or set(value) != set(_COUNTS):
        raise ValueError("fixture counts differ")
    return value


def alert(*, resolved: bool = False) -> list[dict]:
    now = datetime.now(UTC)
    # Stable startsAt preserves the same firing identity across AM processes.
    return [
        {
            "labels": {
                "alertname": "KairosSyntheticStateGate",
                "scope": "synthetic-only",
            },
            "annotations": {},
            "startsAt": "2026-01-01T00:00:00Z",
            "endsAt": (
                now - timedelta(seconds=1) if resolved else now + timedelta(minutes=10)
            ).isoformat(),
            "generatorURL": "",
        }
    ]


def wait_ready() -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            request(AM + "/-/ready")
            return
        except (OSError, ValueError):
            time.sleep(0.2)
    raise ValueError("AM readiness bound")


def wait_counts(expected: dict, *, seconds: int = 15) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = counts()
        if all(value[key] == count for key, count in expected.items()):
            return value
        if any(value[key] > count for key, count in expected.items()):
            raise ValueError("duplicate synthetic notification")
        time.sleep(0.2)
    raise ValueError("notification bound")


def driver(stage: str) -> dict:
    wait_ready()
    before = counts()
    if stage == "firing":
        if before != dict(_COUNTS):
            raise ValueError("fresh fixture required")
        request(RECEIVER + "/fail-next", {"synthetic": True})
        request(AM + "/api/v2/alerts", alert())
        after = wait_counts({"firing": 1, "resolved": 0, "failures": 1})
    elif stage == "restart-no-duplicate":
        if before["firing"] != 1 or before["resolved"] != 0 or before["failures"] != 1:
            raise ValueError("fixed acknowledged firing prerequisite")
        request(AM + "/api/v2/alerts", alert())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if counts() != before:
                raise ValueError("restart duplicate")
            time.sleep(0.2)
        after = counts()
    elif stage == "resolved":
        request(AM + "/api/v2/alerts", alert(resolved=True))
        after = wait_counts({"firing": 1, "resolved": 1, "failures": 1})
    elif stage == "resolved-no-duplicate":
        if before["firing"] != 1 or before["resolved"] != 1:
            raise ValueError("acknowledged resolved prerequisite")
        request(AM + "/api/v2/alerts", alert(resolved=True))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if counts() != before:
                raise ValueError("resolved restart duplicate")
            time.sleep(0.2)
        after = counts()
    else:
        raise ValueError("fixed stage required")
    return {
        "stage": stage,
        "before": before,
        "after": after,
        "synthetic_only": True,
        "forbidden_network_calls": 0,
        "telegram_calls": 0,
    }


def main() -> int:
    try:
        if sys.argv[1:] == ["receiver"]:
            HTTPServer(("127.0.0.1", PORT), Handler).serve_forever(poll_interval=0.2)
            return 0
        if len(sys.argv) != 3 or sys.argv[1] != "driver":
            raise ValueError("fixed invocation required")
        result = driver(sys.argv[2])
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(
            json.dumps(
                {"result": "FAILED_SYNTHETIC_FIXTURE", "category": type(error).__name__}
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
