"""Strict offline preparation contracts; no remote backend is authorized."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .alert_delivery import DeliveryError, _no_reparse

ROOT = Path(__file__).resolve().parents[1]
BACKUPS = ROOT / "backups"
SIGNER = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
MAX_DUMP_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
POLICY_FIELDS = {"schema_version", "mode", "enabled", "profile", "destination", "repository_id", "managed_secret_reference", "retention", "rpo_seconds", "rto_seconds", "transfer_budget_usd"}
READINESS = {"paper_qualified": False, "alpha_ready": False, "live_ready": False, "strategy_policy": "REJECT_ALL"}
LOCK_FIELDS = {"schema_version", "tool", "version", "platform", "release_url", "archive_name", "archive_bytes", "archive_sha256", "checksums_sha256", "signature_sha256", "maintainer_fingerprint", "key_url", "executable_name", "metadata_basis", "native_signature_verified", "installed"}


class PreparationError(Exception):
    """Fixed sanitized category; never child output, keys or file contents."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha(path: Path, *, maximum: int) -> str:
    if not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise PreparationError("ARTIFACT_SIZE_REJECTED")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        count = 0
        while block := stream.read(1024 * 1024):
            count += len(block)
            if count > maximum:
                raise PreparationError("ARTIFACT_SIZE_REJECTED")
            digest.update(block)
    return digest.hexdigest()


def contained(path: Path, root: Path) -> Path:
    try:
        _no_reparse(root)
        _no_reparse(path)
        candidate = path.resolve(strict=True)
        boundary = root.resolve(strict=True)
        if not candidate.is_relative_to(boundary) or candidate == boundary or not candidate.is_file():
            raise PreparationError("ARTIFACT_BOUNDARY_REJECTED")
        return candidate
    except (OSError, DeliveryError):
        raise PreparationError("ARTIFACT_BOUNDARY_REJECTED") from None


def read_json(path: Path) -> dict[str, Any]:
    sha(path, maximum=MAX_METADATA_BYTES)
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (ValueError, OSError):
        raise PreparationError("INVALID_JSON_ARTIFACT") from None
    if not isinstance(value, dict):
        raise PreparationError("INVALID_JSON_ARTIFACT")
    return value


def policy_status(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != POLICY_FIELDS or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["mode"] != "offline-preparation" or value["enabled"] is not False or value["profile"] != "paper" or any(value[k] is not None for k in POLICY_FIELDS - {"schema_version", "mode", "enabled", "profile"}):
        raise PreparationError("OFFLINE_ONLY_POLICY_REQUIRED")
    return {"status": "BLOCKED_DESTINATION_UNCONFIGURED", "blockers": ["DESTINATION_UNCONFIGURED", "MANAGED_KEY_CUSTODY_UNCONFIGURED", "RETENTION_UNCONFIGURED", "RPO_RTO_UNCONFIGURED", "TRANSFER_BUDGET_UNCONFIGURED", "OFF_HOST_READBACK_AND_DATABASE_RESTORE_UNPROVEN"], "preparation_permitted": True, "offhost_qualified": False, "readiness": dict(READINESS)}


def lock() -> dict[str, Any]:
    value = read_json(ROOT / "operations/restic-toolchain.lock.json")
    # Lock changes require source review: no caller-selected tool/version/URL.
    if set(value) != LOCK_FIELDS or value.get("schema_version") != 1 or type(value.get("schema_version")) is not int or value.get("tool") != "restic" or value.get("version") != "0.19.1" or value.get("platform") != "windows/amd64" or value.get("release_url") != "https://github.com/restic/restic/releases/tag/v0.19.1" or value.get("key_url") != "https://restic.net/gpg-key-alex.asc" or value.get("metadata_basis") != "official_https_release_asset_metadata" or value.get("archive_name") != "restic_0.19.1_windows_amd64.zip" or type(value.get("archive_bytes")) is not int or value.get("archive_bytes") != 11_237_567 or value.get("executable_name") != "restic_0.19.1_windows_amd64.exe" or value.get("maintainer_fingerprint") != "CF8F18F2844575973F79D4E191A6868BD3F7A907" or any(SHA.fullmatch(str(value.get(k))) is None for k in ("archive_sha256", "checksums_sha256", "signature_sha256")) or value.get("installed") is not False or value.get("native_signature_verified") is not False:
        raise PreparationError("TOOLCHAIN_LOCK_REJECTED")
    return value
