"""Accepted backup inventory and verified Restic synthetic local restore only.

There is no remote transport, scheduler, primary dump/apply, retention mutation,
managed secret reader or automatic download/install/update function here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import zipfile
from pathlib import Path
from typing import Any

if __package__:
    from . import restic_contract as contract
    from .alert_delivery import DeliveryError, _exclusive, _no_reparse, _private_acl
else:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts import restic_contract as contract
    from scripts.alert_delivery import DeliveryError, _exclusive, _no_reparse, _private_acl

OPS_ROOT = Path("D:/Kairos/runtime/offhost-backup")
GPG = Path("C:/Program Files/Git/usr/bin/gpg.exe") if os.name == "nt" else Path("/usr/bin/gpg")
FIXTURE_BYTES = b"KAIROS fixed synthetic backup fixture; no runtime rows or secrets.\n" * 32
FIXTURE_NAME = "fixture.bin"
MAX_CHILD_OUTPUT = 1024 * 1024
CHILD_TIMEOUT = 120


def _run(command: list[str], *, cwd: Path, data: bytes | None = None, expect_failure: bool = False) -> bytes:
    env = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
    env.update({"GOMAXPROCS": "1", "GOMEMLIMIT": "256MiB"})
    try:
        result = subprocess.run(command, cwd=cwd, input=data, capture_output=True, env=env, shell=False, timeout=CHILD_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        raise contract.PreparationError("BOUNDED_TOOL_OPERATION_FAILED") from None
    if len(result.stdout) > MAX_CHILD_OUTPUT or len(result.stderr) > MAX_CHILD_OUTPUT:
        raise contract.PreparationError("TOOL_OUTPUT_BOUND_EXCEEDED")
    if (result.returncode == 0) == expect_failure:
        raise contract.PreparationError("AUTH_FAILURE_NOT_PROVEN" if expect_failure else "BOUNDED_TOOL_OPERATION_FAILED")
    if expect_failure:
        category = (result.stdout + result.stderr).lower()
        if b"wrong password" not in category and b"no key found" not in category:
            raise contract.PreparationError("AUTH_REJECTION_CATEGORY_UNPROVEN")
        return b"RESTIC_DECRYPTION_REJECTED"
    return result.stdout


def _signature(path: Path, signature: Path, *, signer: str, homedir: Path | None = None) -> None:
    if homedir is None:
        raise contract.PreparationError("EXPLICIT_PUBLIC_VERIFICATION_HOME_REQUIRED")
    _public_verification_home(homedir)
    options = [str(GPG), "--batch", "--no-options", "--no-auto-key-retrieve", "--no-auto-check-trustdb"]
    options += ["--homedir", _gpg_path(homedir)]
    result = _run(options + ["--status-fd", "1", "--verify", _gpg_path(signature), _gpg_path(path)], cwd=signature.parent)
    valid = [line.split() for line in result.decode("utf-8", errors="replace").splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if len(valid) != 1 or len(valid[0]) < 12 or valid[0][11] != signer:
        raise contract.PreparationError("SIGNATURE_IDENTITY_REJECTED")


def _gpg_path(path: Path) -> str:
    # Git-for-Windows GPG is MSYS: backslash path operands may be interpreted
    # as relative keyblock names. Forward-slash absolute paths retain identity.
    return path.resolve().as_posix()


def _public_verification_home(path: Path) -> None:
    _no_reparse(path)
    _no_reparse(OPS_ROOT)
    if not path.is_absolute() or not path.is_dir() or path.resolve() == OPS_ROOT.resolve() or not path.resolve().is_relative_to(OPS_ROOT.resolve(strict=True)):
        raise contract.PreparationError("OWNED_PUBLIC_VERIFICATION_HOME_REQUIRED")
    _private_acl(path)
    private = path / "private-keys-v1.d"
    _no_reparse(private)
    # Metadata only: never open private material. GPG may create an empty dir.
    if private.exists() and (not private.is_dir() or next(private.iterdir(), None) is not None):
        raise contract.PreparationError("PRIVATE_MATERIAL_IN_VERIFICATION_HOME")
    legacy_private = path / "secring.gpg"
    _no_reparse(legacy_private)
    if legacy_private.exists():
        raise contract.PreparationError("PRIVATE_MATERIAL_IN_VERIFICATION_HOME")


def prepare_inventory(manifest_path: Path, receipt_path: Path, signature_path: Path, policy: dict[str, Any], *, backups: Path = contract.BACKUPS, verification_homedir: Path | None = None) -> dict[str, Any]:
    status = contract.policy_status(policy)
    manifest_path = contract.contained(manifest_path, backups)
    receipt_path = contract.contained(receipt_path, backups)
    signature_path = contract.contained(signature_path, backups)
    if signature_path != receipt_path.with_suffix(".json.asc") or re.fullmatch(r"paper-runtime-readonly-preflight-[0-9]{8}T[0-9]{6}Z\.json", receipt_path.name) is None:
        raise contract.PreparationError("ACCEPTED_PAPER_RECEIPT_REQUIRED")
    evidence_hashes = {p: contract.sha(p, maximum=contract.MAX_METADATA_BYTES) for p in (manifest_path, receipt_path, signature_path)}
    _signature(receipt_path, signature_path, signer=contract.SIGNER, homedir=verification_homedir)
    manifest = contract.read_json(manifest_path)
    receipt = contract.read_json(receipt_path)
    fields = {"schema_version", "created_at_utc", "compose_project", "database", "file", "bytes", "sha256", "checkpoints", "timescaledb_bgw_owners"}
    if set(manifest) != fields or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or manifest["compose_project"] != "kairos-paper-gate" or manifest["database"] != "kairos" or re.fullmatch(r"kairos-paper-gate-[0-9]{8}T[0-9]{6}Z\.dump", str(manifest["file"])) is None or type(manifest["bytes"]) is not int or not 0 < manifest["bytes"] <= contract.MAX_DUMP_BYTES or contract.SHA.fullmatch(str(manifest["sha256"])) is None:
        raise contract.PreparationError("FIXED_BACKUP_MANIFEST_REQUIRED")
    if manifest_path.name != manifest["file"] + ".json":
        raise contract.PreparationError("MANIFEST_FILENAME_UNBOUND")
    archive = contract.contained(manifest_path.parent / manifest["file"], backups)
    if archive.parent != manifest_path.parent or archive.stat().st_size != manifest["bytes"] or contract.sha(archive, maximum=contract.MAX_DUMP_BYTES) != manifest["sha256"]:
        raise contract.PreparationError("BACKUP_HASH_OR_SIZE_MISMATCH")
    # Reuse only reviewed pure snapshot validators and code hashes. No runner,
    # Docker, source connection, migration or quarantine function is invoked.
    from scripts import paper_runtime_schema_upgrade as paper
    if receipt.get("schema_version") != 1 or type(receipt.get("schema_version")) is not int or receipt.get("classification") != "PAPER_RUNTIME_READONLY_TARGET_ROLE_AND_RESTORE_BINDING" or receipt.get("result") != "PASS_READ_ONLY_PRIMARY_AND_CLONE" or receipt.get("source_backup_sha256") != manifest["sha256"] or receipt.get("source_manifest_sha256") != evidence_hashes[manifest_path] or receipt.get("readiness") != contract.READINESS or receipt.get("primary_apply_implemented") is not False or receipt.get("consumer_restart_permitted") is not False or receipt.get("redis_contacted") is not False or any(type(receipt.get(k)) is not int or receipt[k] != 0 for k in ("primary_mutations", "consumers_started", "publisher_calls")):
        raise contract.PreparationError("ACCEPTED_HISTORY_BOUNDARY_MISMATCH")
    if any(type(receipt["readiness"].get(k)) is not bool for k in ("paper_qualified", "alpha_ready", "live_ready")):
        raise contract.PreparationError("ACCEPTED_HISTORY_BOUNDARY_MISMATCH")
    identity = receipt.get("source_identity")
    fixed_identity = {"compose_project": paper.SOURCE_PROJECT, "database": paper.SOURCE_DATABASE, "volume": paper.SOURCE_VOLUME, "network": paper.SOURCE_NETWORK}
    if not isinstance(identity, dict) or any(identity.get(k) != v for k, v in fixed_identity.items()) or receipt.get("immutable_runner") != paper.CATALOG.EXPECTED_MIGRATION_RUNNER_IMAGE:
        raise contract.PreparationError("ACCEPTED_FIXED_SOURCE_IDENTITY_MISMATCH")
    if receipt.get("receipt_sha256") != hashlib.sha256(contract.canonical({k: v for k, v in receipt.items() if k != "receipt_sha256"})).hexdigest():
        raise contract.PreparationError("RECEIPT_CONTENT_HASH_MISMATCH")
    if any(receipt.get(k) != v for k, v in paper._code_identity().items()):
        raise contract.PreparationError("ACCEPTED_HISTORY_SOURCE_DRIFT")
    try:
        source = paper._validate_snapshot(receipt["source_snapshot"], primary=True)
        restored = paper._validate_snapshot(receipt["restored_snapshot"], primary=False)
        paper._checkpoints(source, manifest)
        paper._checkpoints(restored, manifest)
    except Exception:
        raise contract.PreparationError("ACCEPTED_FULL_HISTORY_PROOF_REJECTED") from None
    if source["history"] != restored["history"]:
        raise contract.PreparationError("FULL_HISTORY_RESTORE_MISMATCH")
    if any(contract.sha(p, maximum=contract.MAX_METADATA_BYTES) != digest for p, digest in evidence_hashes.items()) or contract.sha(archive, maximum=contract.MAX_DUMP_BYTES) != manifest["sha256"]:
        raise contract.PreparationError("SOURCE_ARTIFACT_CHANGED_DURING_PREPARATION")
    files = [{"path": str(p.relative_to(backups.resolve())).replace("\\", "/"), "bytes": p.stat().st_size, "sha256": manifest["sha256"] if p == archive else evidence_hashes[p]} for p in (archive, manifest_path, receipt_path, signature_path)]
    inventory = {"schema_version": 1, "kind": "kairos.restic.accepted-file-inventory.v1", "profile": "paper", "files": sorted(files, key=lambda f: f["path"]), "history_sha256": hashlib.sha256(contract.canonical(source["history"])).hexdigest(), "accepted_signer": contract.SIGNER, "signing_required_before_transfer": True, "remote_transfer_implemented": False, **status}
    inventory["inventory_sha256"] = hashlib.sha256(contract.canonical(inventory)).hexdigest()
    return inventory


def _new_directory(path: Path, *, ops_root: Path = OPS_ROOT) -> None:
    _no_reparse(path)
    _no_reparse(ops_root)
    if not path.is_absolute() or not path.resolve().is_relative_to(ops_root.resolve(strict=True)) or path.resolve() == ops_root.resolve():
        raise contract.PreparationError("OWNED_OFFLINE_WORKSPACE_REQUIRED")
    if path.exists():
        raise contract.PreparationError("EXCLUSIVELY_NEW_TARGET_REQUIRED")
    _private_acl(path.parent)
    path.mkdir(mode=0o777 if os.name == "nt" else 0o700)
    _private_acl(path)


def verify_tool_bundle(bundle: Path, new_directory: Path, *, ops_root: Path = OPS_ROOT) -> dict[str, Any]:
    _no_reparse(bundle)
    if not bundle.is_absolute() or str(bundle).startswith(("\\\\", "//")) or not bundle.resolve(strict=True).is_relative_to(ops_root.resolve(strict=True)) or not bundle.is_dir():
        raise contract.PreparationError("OWNED_LOCAL_TOOL_BUNDLE_REQUIRED")
    tool = contract.lock()
    paths = {"archive": bundle / tool["archive_name"], "checksums": bundle / "SHA256SUMS", "signature": bundle / "SHA256SUMS.asc", "key": bundle / "maintainer.asc"}
    for key, path in paths.items():
        _no_reparse(path)
        maximum = 12 * 1024 * 1024 if key == "archive" else contract.MAX_METADATA_BYTES
        digest = contract.sha(path, maximum=maximum)
        if key != "key" and digest != tool[key + "_sha256"]:
            raise contract.PreparationError("PUBLISHED_TOOL_HASH_MISMATCH")
    if paths["archive"].stat().st_size != tool["archive_bytes"]:
        raise contract.PreparationError("PUBLISHED_TOOL_SIZE_MISMATCH")
    _new_directory(new_directory, ops_root=ops_root)
    # Verify and extract from private snapshots, not mutable caller paths.
    # We hash the actual copied bytes; a swapped input never reaches GPG/exec.
    verified_inputs = new_directory / "signed-inputs"
    verified_inputs.mkdir(mode=0o777 if os.name == "nt" else 0o700)
    for key, path in paths.items():
        content = path.read_bytes()
        if len(content) > (12 * 1024 * 1024 if key == "archive" else contract.MAX_METADATA_BYTES) or (key != "key" and hashlib.sha256(content).hexdigest() != tool[key + "_sha256"]):
            raise contract.PreparationError("TOOL_INPUT_CHANGED_DURING_VERIFICATION")
        snapshot = verified_inputs / path.name
        _exclusive(snapshot, content)
        paths[key] = snapshot
    keyring = new_directory / "verification-keyring"
    keyring.mkdir(mode=0o777 if os.name == "nt" else 0o700)
    _run([str(GPG), "--batch", "--no-options", "--homedir", _gpg_path(keyring), "--import", _gpg_path(paths["key"])], cwd=new_directory)
    _signature(paths["checksums"], paths["signature"], signer=tool["maintainer_fingerprint"], homedir=keyring)
    lines = paths["checksums"].read_text(encoding="ascii").splitlines()
    expected_line = tool["archive_sha256"] + "  " + tool["archive_name"]
    if lines.count(expected_line) != 1:
        raise contract.PreparationError("SIGNED_CHECKSUM_BINDING_REJECTED")
    with zipfile.ZipFile(paths["archive"]) as archive:
        entries = archive.infolist()
        if len(entries) != 1 or entries[0].filename != tool["executable_name"] or not 0 < entries[0].file_size <= 32 * 1024 * 1024 or entries[0].is_dir():
            raise contract.PreparationError("TOOL_ARCHIVE_SHAPE_REJECTED")
        executable = new_directory / tool["executable_name"]
        _exclusive(executable, archive.read(entries[0]))
    version = _run([str(executable), "version"], cwd=new_directory)
    if re.fullmatch(rb"restic 0\.19\.1 compiled with go[0-9.]+ on windows/amd64\s*", version) is None:
        raise contract.PreparationError("NATIVE_TOOL_VERSION_REJECTED")
    return {"kind": "kairos.restic.verified-tool.v1", "executable": str(executable.resolve()), "executable_sha256": contract.sha(executable, maximum=32 * 1024 * 1024), "archive_sha256": tool["archive_sha256"], "maintainer_signature_verified": True, "maintainer_fingerprint": tool["maintainer_fingerprint"], "version": tool["version"], "toolchain_lock_sha256": contract.sha(contract.ROOT / "operations/restic-toolchain.lock.json", maximum=contract.MAX_METADATA_BYTES), "offhost_qualified": False}


def local_fixture(bundle: Path, new_directory: Path, *, ops_root: Path = OPS_ROOT) -> dict[str, Any]:
    # No caller-supplied verification boolean/receipt can authorize execution.
    # Independently reverify the signed, pinned bundle inside this exact new
    # fixture, then execute only its privately extracted allowlisted binary.
    if not isinstance(bundle, Path):
        raise contract.PreparationError("SIGNED_NATIVE_BUNDLE_REQUIRED")
    _new_directory(new_directory, ops_root=ops_root)
    tool_receipt = verify_tool_bundle(bundle, new_directory / "verified-tool", ops_root=ops_root)
    executable = Path(tool_receipt["executable"])
    _no_reparse(executable)
    if not executable.is_absolute() or contract.sha(executable, maximum=32 * 1024 * 1024) != tool_receipt.get("executable_sha256"):
        raise contract.PreparationError("NATIVE_EXECUTABLE_CHANGED")
    repository = new_directory / "repository"
    password = new_directory / "ephemeral-password"
    wrong_password = new_directory / "wrong-ephemeral-password"
    _exclusive(password, secrets.token_hex(32).encode("ascii"))
    _exclusive(wrong_password, secrets.token_hex(32).encode("ascii"))
    _private_acl(password)
    _private_acl(wrong_password)
    prefix = [str(executable), "--repo", str(repository), "--password-file", str(password), "--no-cache", "--json"]
    counts: dict[str, int] = {}

    def command(arguments: list[str], *, data: bytes | None = None) -> bytes:
        counts[arguments[0]] = counts.get(arguments[0], 0) + 1
        return _run(prefix + arguments, cwd=new_directory, data=data)

    command(["init"])
    config = json.loads(command(["cat", "config"]))
    if not isinstance(config, dict) or contract.SHA.fullmatch(str(config.get("id"))) is None:
        raise contract.PreparationError("LOCAL_REPOSITORY_IDENTITY_REJECTED")
    output = command(["backup", "--stdin", "--stdin-filename", FIXTURE_NAME, "--host", "kairos-offline-fixture", "--tag", "kairos-offline-fixture-v1"], data=FIXTURE_BYTES)
    summaries = [item for line in output.splitlines() if isinstance(item := json.loads(line), dict) and item.get("message_type") == "summary"]
    if len(summaries) != 1 or contract.SHA.fullmatch(str(summaries[0].get("snapshot_id"))) is None:
        raise contract.PreparationError("LITERAL_SNAPSHOT_ID_REQUIRED")
    snapshot_id = summaries[0]["snapshot_id"]
    selected = json.loads(command(["snapshots", snapshot_id]))
    if not isinstance(selected, list) or len(selected) != 1 or selected[0].get("id") != snapshot_id:
        raise contract.PreparationError("EXACT_SNAPSHOT_BINDING_REJECTED")
    command(["check", "--read-data"])
    # A nonzero exit is required but does not by itself establish crypto auth.
    # Restrict evidence to the native repository-decryption rejection category.
    rejected = _run([str(executable), "--repo", str(repository), "--password-file", str(wrong_password), "--no-cache", "--json", "cat", "config"], cwd=new_directory, expect_failure=True)
    if rejected != b"RESTIC_DECRYPTION_REJECTED":
        raise contract.PreparationError("AUTH_REJECTION_CATEGORY_UNPROVEN")
    restored = new_directory / "restored"
    if restored.exists():
        raise contract.PreparationError("EXCLUSIVELY_NEW_TARGET_REQUIRED")
    command(["restore", snapshot_id, "--target", str(restored), "--overwrite", "never", "--verify"])
    payloads = list(restored.rglob("*"))
    if len(payloads) != 1 or payloads[0].name != FIXTURE_NAME or not payloads[0].is_file() or payloads[0].is_symlink() or payloads[0].read_bytes() != FIXTURE_BYTES:
        raise contract.PreparationError("RESTORED_EXACT_FILE_HASH_MISMATCH")
    _no_reparse(payloads[0])
    result = {"kind": "kairos.restic.local-fixture.v1", "status": "PASS_OFFLINE_SYNTHETIC_FILE_ONLY", "repository_id": config["id"], "snapshot_id": snapshot_id, "tool_sha256": tool_receipt["executable_sha256"], "fixture_sha256": hashlib.sha256(FIXTURE_BYTES).hexdigest(), "restored_sha256": contract.sha(payloads[0], maximum=64 * 1024), "full_authenticated_data_check": True, "wrong_password_rejected": True, "new_restore_target": True, "commands": counts, "remote_requests": 0, "real_runtime_data_used": False, "database_restore_proven": False, "offhost_qualified": False, "readiness": dict(contract.READINESS)}
    _exclusive(new_directory / "fixture-receipt.json", contract.canonical(result) + b"\n")
    return result


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise contract.PreparationError("INVALID_ARGUMENTS")


def main(argv: list[str] | None = None) -> int:
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument("--policy", type=Path, required=True)
        parser.add_argument("--manifest", type=Path)
        parser.add_argument("--accepted-history-receipt", type=Path)
        parser.add_argument("--accepted-history-signature", type=Path)
        parser.add_argument("--verification-homedir", type=Path)
        parser.add_argument("--native-fixture-bundle", type=Path)
        parser.add_argument("--new-fixture-directory", type=Path)
        parser.add_argument("--authorize-local-synthetic-fixture", action="store_true")
        args = parser.parse_args(argv)
        policy = contract.read_json(args.policy)
        supplied = [args.manifest, args.accepted_history_receipt, args.accepted_history_signature]
        fixture = [args.native_fixture_bundle, args.new_fixture_directory, args.authorize_local_synthetic_fixture]
        if any(fixture):
            contract.policy_status(policy)
            if any(supplied) or args.verification_homedir is not None or not all(fixture):
                raise contract.PreparationError("EXPLICIT_LOCAL_SYNTHETIC_SCOPE_REQUIRED")
            result = local_fixture(args.native_fixture_bundle, args.new_fixture_directory)
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0
        if any(supplied) and not all(supplied):
            raise contract.PreparationError("COMPLETE_ACCEPTED_ARTIFACT_SET_REQUIRED")
        if args.verification_homedir is not None and not all(supplied):
            raise contract.PreparationError("COMPLETE_ACCEPTED_ARTIFACT_SET_REQUIRED")
        result = prepare_inventory(*supplied, policy, verification_homedir=args.verification_homedir) if all(supplied) else contract.policy_status(policy)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        # Even prepared inventory is not remote operational qualification.
        return 2
    except contract.PreparationError as error:
        category = str(error)
    except Exception:
        category = "LOCAL_PREPARATION_FAILED"
    print(json.dumps({"status": "BLOCKED", "error_category": category, "offhost_qualified": False}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
