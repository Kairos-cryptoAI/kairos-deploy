"""Native Telegram configuration and a guarded, explicitly authorized test send.

No runtime application, Docker lifecycle, trading or recovery actions exist here.
The parent/operator imports the dedicated token; this module accepts a FILE only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OPS_ROOT = Path("D:/Kairos/runtime/alert-delivery")
EXPECTED_BOT = "KairosCryptoAI_bot"
EXPECTED_CHAT = -5155583216
EXPECTED_TEST_CHAT = -100447580288
ALERTMANAGER_IMAGE = "prom/alertmanager:v0.34.1@sha256:e9733bafb1bdef9b00e25a21f8f99dc26a22224bf16641ad754d1649f4c3357a"
API_ROOT = "https://api.telegram.org"
MAX_RESPONSE = 65_536
TIMEOUT_SECONDS = 15
TEST_MESSAGE = "[KAIROS QUALIFICATION TEST] Проверка аварийного канала. Это тест, не торговый сигнал и не разрешение LIVE."
POLICY_FIELDS = {"schema_version", "enabled", "receiver", "profile", "source_sha256", "expected_bot_username", "expected_chat_id", "group_wait_seconds", "group_interval_seconds", "repeat_interval_seconds"}


class DeliveryError(Exception):
    """Only a fixed, public category; never retain transport exception text."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def policy_errors(policy: Any) -> list[str]:
    if not isinstance(policy, dict) or set(policy) != POLICY_FIELDS:
        return ["INVALID_POLICY_FIELDS"]
    errors: list[str] = []
    if policy["schema_version"] != 1 or type(policy["schema_version"]) is not int:
        errors.append("INVALID_POLICY_VERSION")
    if type(policy["enabled"]) is not bool:
        errors.append("INVALID_ENABLED")
    elif not policy["enabled"]:
        errors.append("DELIVERY_DISABLED")
    if policy["receiver"] != "telegram" or policy["expected_bot_username"] != EXPECTED_BOT or policy["expected_chat_id"] != EXPECTED_CHAT or type(policy["expected_chat_id"]) is not int:
        errors.append("RECEIVER_IDENTITY_MISMATCH")
    if policy["profile"] not in ("base", "paper"):
        errors.append("INVALID_PROFILE")
    source_hash = policy["source_sha256"]
    baseline = (ROOT / "monitoring" / "prometheus.yml").read_bytes()
    if not isinstance(source_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", source_hash) or source_hash != hashlib.sha256(baseline).hexdigest():
        errors.append("PROMETHEUS_SOURCE_UNBOUND")
    limits = {"group_wait_seconds": (1, 300), "group_interval_seconds": (1, 3_600), "repeat_interval_seconds": (1, 86_400)}
    for key, (low, high) in limits.items():
        if type(policy[key]) is not int or not low <= policy[key] <= high:
            errors.append("INVALID_" + key.upper())
    if all(type(policy[k]) is int for k in limits) and policy["repeat_interval_seconds"] < policy["group_interval_seconds"]:
        errors.append("REPEAT_BEFORE_GROUP_INTERVAL")
    return errors


def render_alertmanager(policy: dict[str, Any]) -> str:
    errors = policy_errors(policy)
    if errors:
        raise DeliveryError(errors[0])
    template = (ROOT / "monitoring" / "alertmanager.yml.template").read_text(encoding="utf-8")
    replacements = {"CHAT_ID": str(EXPECTED_CHAT), "GROUP_WAIT": str(policy["group_wait_seconds"]), "GROUP_INTERVAL": str(policy["group_interval_seconds"]), "REPEAT_INTERVAL": str(policy["repeat_interval_seconds"])}
    for name, value in replacements.items():
        template = template.replace("@@" + name + "@@", value)
    if "@@" in template:
        raise DeliveryError("INVALID_NATIVE_TEMPLATE")
    return template


def render_prometheus(policy: dict[str, Any]) -> str:
    errors = policy_errors(policy)
    if errors:
        raise DeliveryError(errors[0])
    source = (ROOT / "monitoring" / "prometheus.yml").read_text(encoding="utf-8")
    # Only the existing global stanza and a new notifier stanza change. Rules,
    # scrape target, job and evaluation semantics remain the actual baseline.
    labels = ("global:\n  external_labels:\n    kairos_project: kairos\n    kairos_environment: " + policy["profile"] + "\n    kairos_source_sha256: " + policy["source_sha256"] + "\n")
    if source.count("global:\n") != 1 or "alerting:" in source or "external_labels:" in source:
        raise DeliveryError("PROMETHEUS_BASELINE_DRIFT")
    source = source.replace("global:\n", labels, 1)
    return source + "\nalerting:\n  alertmanagers:\n    - api_version: v2\n      static_configs:\n        - targets: [kairos-ops-alertmanager:9093]\n"


def _no_reparse(path: Path) -> None:
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                raise DeliveryError("REPARSE_PATH_REJECTED")


def _private_acl(path: Path) -> None:
    if os.name != "nt":
        if path.stat().st_mode & 0o077:
            raise DeliveryError("PROTECTED_ACL_REQUIRED")
        return
    # Read ACL metadata only. No modification, token contents or account names
    # are emitted. Read access is limited to owner/operator, Admin and SYSTEM.
    command = "$ErrorActionPreference='Stop'; $a=Get-Acl -LiteralPath $env:KAIROS_ALERT_ACL_TARGET; $u=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $ok=@($u,'S-1-5-18','S-1-5-32-544'); $bad=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $ok }); if($bad.Count -gt 0){exit 2}; Write-Output SAFE"
    executable = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    env = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "COMSPEC"}}
    env["KAIROS_ALERT_ACL_TARGET"] = str(path)
    try:
        result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=10, env=env, shell=False)
    except (OSError, subprocess.SubprocessError):
        raise DeliveryError("ACL_VERIFICATION_FAILED") from None
    if result.returncode or result.stdout.strip() != "SAFE":
        raise DeliveryError("PROTECTED_ACL_REQUIRED")


def _exclusive(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    if os.name != "nt":
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def render_files(policy: dict[str, Any], directory: Path) -> dict[str, Any]:
    native = render_alertmanager(policy)
    prometheus = render_prometheus(policy)
    _no_reparse(directory)
    if directory.exists():
        raise DeliveryError("OUTPUT_MUST_BE_NEW")
    directory.mkdir(mode=0o700, parents=False)
    _exclusive(directory / "alertmanager.yml", native.encode("utf-8"))
    _exclusive(directory / "prometheus.yml", prometheus.encode("utf-8"))
    return {"status": "PREPARED_CONFIG_ONLY", "policy_sha256": hashlib.sha256(canonical(policy)).hexdigest(), "alertmanager_sha256": hashlib.sha256(native.encode("utf-8")).hexdigest(), "prometheus_sha256": hashlib.sha256(prometheus.encode("utf-8")).hexdigest(), "image": ALERTMANAGER_IMAGE, "operationally_qualified": False}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DeliveryError("REDIRECT_REJECTED")


class TelegramTransport:
    def __init__(self, token: str) -> None:
        self._token = token
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def call(self, method: str, parameters: dict[str, Any]) -> dict[str, Any]:
        if method not in {"getMe", "getChat", "sendMessage"}:
            raise DeliveryError("METHOD_REJECTED")
        request = urllib.request.Request(API_ROOT + "/bot" + self._token + "/" + method, data=canonical(parameters), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self._opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                if response.status != 200:
                    raise DeliveryError("HTTP_REJECTED")
                body = response.read(MAX_RESPONSE + 1)
            if len(body) > MAX_RESPONSE:
                raise DeliveryError("RESPONSE_TOO_LARGE")
            parsed = json.loads(body)
        except DeliveryError:
            raise
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError):
            # HTTPError/URLError text may contain the token-bearing request URL.
            raise DeliveryError("TRANSPORT_FAILED") from None
        if not isinstance(parsed, dict) or parsed.get("ok") is not True or not isinstance(parsed.get("result"), dict):
            raise DeliveryError("API_REJECTED")
        return parsed["result"]


def qualify(token_file: Path, *, authorize_one_test: bool, ops_root: Path = OPS_ROOT) -> dict[str, Any]:
    if not authorize_one_test:
        raise DeliveryError("EXPLICIT_TEST_AUTHORIZATION_REQUIRED")
    _no_reparse(ops_root)
    _no_reparse(token_file)
    if token_file.resolve(strict=True) != (ops_root / "secrets/telegram_bot_token").resolve(strict=True) or not token_file.is_file():
        raise DeliveryError("DEDICATED_TOKEN_FILE_REQUIRED")
    _private_acl(ops_root)
    _private_acl(token_file)
    receipt_root = ops_root / "receipts"
    _no_reparse(receipt_root)
    receipt_root.mkdir(mode=0o700, exist_ok=True)
    _private_acl(receipt_root)
    # Stable recipient guard: a config change or process restart cannot create
    # a second automatic test send. Never remove/rewrite a partial journal.
    scope = hashlib.sha256(canonical({"bot": EXPECTED_BOT, "chat": EXPECTED_TEST_CHAT})).hexdigest()
    journal = receipt_root / ("telegram-qualification-" + scope + ".jsonl")
    result: dict[str, Any] = {"schema_version": 1, "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "test_message_sha256": hashlib.sha256(TEST_MESSAGE.encode("utf-8")).hexdigest(), "expected_bot_username": EXPECTED_BOT, "expected_chat_id": EXPECTED_TEST_CHAT, "recipient_purpose": "qualification_test_only", "stage": "PRECHECK_STARTED", "send_attempts": 0, "http_method_counts": {"getMe": 0, "getChat": 0, "sendMessage": 0}, "transport_accepted": False, "human_acknowledged": False, "trading_authority": False}

    def record(stage: str, error: str | None = None) -> None:
        result["stage"] = stage
        result["error_category"] = error
        entry = {**result, "observed_at_utc": datetime.now(timezone.utc).isoformat()}
        with journal.open("ab") as stream:
            stream.write(canonical(entry) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

    try:
        _exclusive(journal, canonical(result) + b"\n")
    except FileExistsError:
        raise DeliveryError("EXISTING_QUALIFICATION_REQUIRES_REVIEW") from None
    _private_acl(journal)
    sending = False
    try:
        if token_file.stat().st_size > 256:
            raise DeliveryError("INVALID_TOKEN_FILE")
        token = token_file.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{30,100}", token):
            raise DeliveryError("INVALID_TOKEN_FILE")
        transport = TelegramTransport(token)
        result["http_method_counts"]["getMe"] = 1
        identity = transport.call("getMe", {})
        if identity.get("is_bot") is not True or identity.get("username") != EXPECTED_BOT:
            raise DeliveryError("BOT_IDENTITY_MISMATCH")
        result["http_method_counts"]["getChat"] = 1
        chat = transport.call("getChat", {"chat_id": EXPECTED_TEST_CHAT})
        if type(chat.get("id")) is not int or chat["id"] != EXPECTED_TEST_CHAT or chat.get("type") not in {"group", "supergroup"}:
            raise DeliveryError("CHAT_IDENTITY_MISMATCH")
        record("IDENTITY_VERIFIED")
        result["send_attempts"] = 1
        record("SEND_RESERVED")  # must durably complete before any send POST
        sending = True
        result["http_method_counts"]["sendMessage"] = 1
        sent = transport.call("sendMessage", {"chat_id": EXPECTED_TEST_CHAT, "text": TEST_MESSAGE, "disable_notification": False, "protect_content": True})
        if not isinstance(sent.get("chat"), dict) or type(sent["chat"].get("id")) is not int or sent["chat"]["id"] != EXPECTED_TEST_CHAT or type(sent.get("message_id")) is not int or sent["message_id"] <= 0:
            raise DeliveryError("SEND_RESPONSE_IDENTITY_MISMATCH")
        result["transport_accepted"] = True
        result["message_id"] = sent["message_id"]
        record("TRANSPORT_ACCEPTED")
    except DeliveryError as error:
        record("SEND_OUTCOME_UNKNOWN" if sending else "PRECHECK_FAILED", error.category)
    except Exception:
        # Includes disk errors: the already-created guard remains terminal even
        # when appending the final record is impossible. No resend or cleanup.
        result["stage"] = "SEND_OUTCOME_UNKNOWN" if sending else "PRECHECK_FAILED"
        result["transport_accepted"] = False
        result["error_category"] = "LOCAL_FAILURE"
        try:
            record(result["stage"], "LOCAL_FAILURE")
        except OSError:
            pass
    return result


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise DeliveryError("INVALID_ARGUMENTS")


def main(argv: list[str] | None = None) -> int:
    try:
        parser = SafeParser(description=__doc__)
        actions = parser.add_subparsers(dest="action", required=True, parser_class=SafeParser)
        render = actions.add_parser("render")
        render.add_argument("--policy", type=Path, required=True)
        render.add_argument("--new-output-directory", type=Path, required=True)
        test = actions.add_parser("qualify")
        test.add_argument("--token-file", type=Path, required=True)
        test.add_argument("--authorize-one-test", action="store_true")
        args = parser.parse_args(argv)
        if args.action == "render":
            if args.policy.stat().st_size > 8_192:
                raise DeliveryError("POLICY_TOO_LARGE")
            result = render_files(json.loads(args.policy.read_text(encoding="utf-8")), args.new_output_directory)
        else:
            result = qualify(args.token_file, authorize_one_test=args.authorize_one_test)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result.get("stage") in (None, "TRANSPORT_ACCEPTED") else 2
    except DeliveryError as error:
        print(json.dumps({"status": "BLOCKED", "error_category": error.category}))
    except Exception:
        print(json.dumps({"status": "BLOCKED", "error_category": "LOCAL_FAILURE"}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
