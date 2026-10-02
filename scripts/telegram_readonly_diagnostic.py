"""One explicitly authorized, sanitized bot/test-chat diagnosis; never send."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

if __package__:
    from . import alert_delivery as delivery
else:
    import alert_delivery as delivery


def _error(category: str, http_status: int | None = None, api_error_code: int | None = None) -> dict[str, Any]:
    return {"error_category": category, "http_status": http_status, "api_error_code": api_error_code}


def classify(status: int, body: bytes) -> dict[str, Any]:
    code = None
    description = ""
    if len(body) <= delivery.MAX_RESPONSE:
        try:
            response = json.loads(body)
            if isinstance(response, dict):
                candidate = response.get("error_code")
                code = candidate if type(candidate) is int and 100 <= candidate <= 599 else None
                candidate = response.get("description")
                description = candidate.lower() if isinstance(candidate, str) else ""
        except (ValueError, UnicodeError):
            pass
    # Description is untrusted private material and is discarded after fixed
    # category matching. We never return it, response bodies, titles or URLs.
    if status == 429 or code == 429:
        category = "RATE_LIMIT"
    elif status == 401 or code == 401:
        category = "AUTHENTICATION_REJECTED"
    elif "chat not found" in description:
        category = "CHAT_NOT_FOUND"
    elif "bot is not a member" in description or "bot was kicked" in description:
        category = "BOT_NOT_MEMBER"
    elif status == 403 or code == 403 or "not enough rights" in description:
        category = "PERMISSION_DENIED"
    else:
        category = "API_REJECTED"
    return _error(category, status, code)


class ReadOnlyTransport:
    def __init__(self, token: str) -> None:
        self._token = token
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), delivery.NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def call(self, method: str, parameters: dict[str, Any]) -> dict[str, Any]:
        if method not in {"getMe", "getChat"} or parameters != ({} if method == "getMe" else {"chat_id": delivery.EXPECTED_TEST_CHAT}):
            return {"ok": False, **_error("READ_ONLY_METHOD_REJECTED")}
        request = urllib.request.Request(delivery.API_ROOT + "/bot" + self._token + "/" + method, data=delivery.canonical(parameters), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self._opener.open(request, timeout=delivery.TIMEOUT_SECONDS) as response:
                body = response.read(delivery.MAX_RESPONSE + 1)
                status = response.status
        except urllib.error.HTTPError as error:
            try:
                body = error.read(delivery.MAX_RESPONSE + 1)
            except Exception:
                body = b""
            return {"ok": False, **classify(error.code, body)}
        except delivery.DeliveryError:
            return {"ok": False, **_error("REDIRECT_REJECTED")}
        except urllib.error.URLError as error:
            return {"ok": False, **_error("TLS" if isinstance(error.reason, ssl.SSLError) else "TRANSPORT")}
        except ssl.SSLError:
            return {"ok": False, **_error("TLS")}
        except (OSError, ValueError):
            return {"ok": False, **_error("TRANSPORT")}
        if len(body) > delivery.MAX_RESPONSE:
            return {"ok": False, **_error("RESPONSE_TOO_LARGE", status)}
        try:
            parsed = json.loads(body)
        except (ValueError, UnicodeError):
            return {"ok": False, **_error("INVALID_RESPONSE", status)}
        if status != 200 or not isinstance(parsed, dict) or parsed.get("ok") is not True or not isinstance(parsed.get("result"), dict):
            return {"ok": False, **classify(status, body)}
        return {"ok": True, "result": parsed["result"], "http_status": status}


def diagnose(token_file: Path, *, authorize_readonly: bool, ops_root: Path = delivery.OPS_ROOT) -> dict[str, Any]:
    if authorize_readonly is not True:
        raise delivery.DeliveryError("EXPLICIT_READ_ONLY_AUTHORIZATION_REQUIRED")
    for path in (ops_root, token_file, ops_root / "receipts"):
        delivery._no_reparse(path)
        delivery._private_acl(path)
    if token_file.resolve(strict=True) != (ops_root / "secrets/telegram_bot_token").resolve(strict=True) or not token_file.is_file():
        raise delivery.DeliveryError("DEDICATED_TOKEN_FILE_REQUIRED")
    scope = hashlib.sha256(delivery.canonical({"bot": delivery.EXPECTED_BOT, "chat": delivery.EXPECTED_TEST_CHAT, "purpose": "read_only_diagnosis"})).hexdigest()
    journal = ops_root / "receipts" / ("telegram-readonly-diagnostic-" + scope + ".json")
    delivery._exclusive(journal, b'{"status":"RESERVED_READ_ONLY_DIAGNOSIS","send_attempts":0}\n')
    delivery._private_acl(journal)
    result: dict[str, Any] = {"schema_version": 1, "kind": "kairos.telegram.readonly-diagnostic.v1", "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "expected_bot_username": delivery.EXPECTED_BOT, "expected_test_chat_id": delivery.EXPECTED_TEST_CHAT, "status": "BLOCKED", "http_method_counts": {"getMe": 0, "getChat": 0}, "send_attempts": 0, "chat_identity_verified": False, "delivery_qualified": False, "trading_authority": False}
    try:
        if not 0 < token_file.stat().st_size <= 256:
            raise delivery.DeliveryError("INVALID_TOKEN_FILE")
        token = token_file.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{30,100}", token) is None:
            raise delivery.DeliveryError("INVALID_TOKEN_FILE")
        transport = ReadOnlyTransport(token)
        result["http_method_counts"]["getMe"] = 1
        identity = transport.call("getMe", {})
        if not identity["ok"]:
            result.update({k: v for k, v in identity.items() if k != "ok"})
        elif identity["result"].get("is_bot") is not True or identity["result"].get("username") != delivery.EXPECTED_BOT:
            result.update(_error("BOT_IDENTITY_MISMATCH", 200))
        else:
            result["http_method_counts"]["getChat"] = 1
            chat = transport.call("getChat", {"chat_id": delivery.EXPECTED_TEST_CHAT})
            if not chat["ok"]:
                result.update({k: v for k, v in chat.items() if k != "ok"})
            elif type(chat["result"].get("id")) is not int or chat["result"]["id"] != delivery.EXPECTED_TEST_CHAT or chat["result"].get("type") not in {"group", "supergroup"}:
                result.update(_error("CHAT_IDENTITY_MISMATCH", 200))
            else:
                result.update({"status": "PASS_READ_ONLY_IDENTITY_ONLY", "chat_identity_verified": True, "http_status": 200, "api_error_code": None})
    except delivery.DeliveryError as error:
        result.update(_error(error.category))
    except Exception:
        result.update(_error("LOCAL_FAILURE"))
    # Reserve file is immutable; append result to a distinct new file. A disk
    # error cannot erase the guard or permit an automatic second diagnosis.
    delivery._exclusive(journal.with_suffix(".result.json"), delivery.canonical(result) + b"\n")
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        parser = delivery.SafeParser(description=__doc__)
        parser.add_argument("--token-file", type=Path, required=True)
        parser.add_argument("--authorize-read-only-preflight", action="store_true")
        args = parser.parse_args(argv)
        result = diagnose(args.token_file, authorize_readonly=args.authorize_read_only_preflight)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["chat_identity_verified"] else 2
    except Exception as error:
        category = error.category if isinstance(error, delivery.DeliveryError) else "LOCAL_FAILURE"
        print(json.dumps({"status": "BLOCKED", "error_category": category, "send_attempts": 0}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
