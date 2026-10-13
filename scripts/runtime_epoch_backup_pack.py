"""Create-only local encrypted pack for one accepted non-trading R7 epoch.

The default is PLAN_ONLY. The only executable input set is the detached-signature
accepted receipt plus the two receipt-bound full epoch dumps. This is a local
encrypted copy, not an off-host backup or disaster-recovery qualification.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__:
    from . import restic_contract as contract
    from . import restic_preparation as preparation
    from .alert_delivery import DeliveryError, _exclusive, _no_reparse, _private_acl
else:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts import restic_contract as contract
    from scripts import restic_preparation as preparation
    from scripts.alert_delivery import (
        DeliveryError,
        _exclusive,
        _no_reparse,
        _private_acl,
    )

RUNTIME_ROOT = Path("D:/Kairos/runtime/runtime-incident-20261013")
OWNER = "69893dc7b7c647f49967387e7efca9fb"
SIGNER = contract.SIGNER
WORK_PREFIX = "read-recovery-r7-"
RECEIPT_NAME = "receipt.json"
ACCEPTED_NAME = "accepted.json"
SIGNATURE_NAME = "receipt.json.asc"
BEFORE_NAME = "epoch-history-bootbefore.dump"
AFTER_NAME = "epoch-history-bootafter.dump"
REPOSITORY_NAME = "restic-local-repository"
PASSWORD_NAME = "restic-repository-password"
WRONG_PASSWORD_NAME = "restic-negative-test-password"
CLAIM_NAME = "restic-r7-create-only-claim.json"
RESULT_NAME = "restic-r7-pack-receipt.json"
RESTORE_NAME = "restic-r7-verified-restore"
MAX_DUMP_BYTES = contract.MAX_DUMP_BYTES
SHA = contract.SHA
REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
REQUIRED_RECEIPT_FIELDS = {
    "result",
    "recovery_kind",
    "owner",
    "source_revision",
    "prebackup_sha256",
    "postcatchup_backup_sha256",
    "cold_backups",
    "generation",
    "redis_proof",
    "final_state_sha256",
    "completed_at_utc",
    "trading_started",
    "PAPER_QUALIFIED",
    "ALPHA_READY",
    "LIVE_READY",
    "STRATEGY_POLICY",
}


def _safe_file(path: Path, *, maximum: int) -> str:
    """Hash a regular, single-link file with no reparse ancestors."""
    try:
        _no_reparse(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise contract.PreparationError("REGULAR_UNLINKED_FILE_REQUIRED")
        return contract.sha(path, maximum=maximum)
    except (OSError, DeliveryError):
        raise contract.PreparationError("REGULAR_UNLINKED_FILE_REQUIRED") from None


def _read_json(path: Path) -> dict[str, Any]:
    _safe_file(path, maximum=contract.MAX_METADATA_BYTES)
    return contract.read_json(path)


def _workdir(path: Path, *, runtime_root: Path = RUNTIME_ROOT) -> Path:
    try:
        _no_reparse(runtime_root)
        _no_reparse(path)
        root = runtime_root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        suffix = resolved.name.removeprefix(WORK_PREFIX)
        parsed = uuid.UUID(suffix)
        if (
            not resolved.is_dir()
            or resolved.parent != root
            or parsed.hex != suffix
            or resolved.name != WORK_PREFIX + suffix
        ):
            raise contract.PreparationError("EXACT_R7_WORK_DIRECTORY_REQUIRED")
        return resolved
    except (OSError, ValueError, DeliveryError):
        raise contract.PreparationError("EXACT_R7_WORK_DIRECTORY_REQUIRED") from None


def _validate_generation(receipt: dict[str, Any]) -> None:
    generation = receipt.get("generation")
    if not isinstance(generation, dict):
        raise contract.PreparationError("R7_GENERATION_PROOF_REQUIRED")
    expected_name = "kairos-epoch-" + OWNER[:12] + "-serve-r7"
    container_id = generation.get("container_id")
    status = generation.get("status")
    proof = generation.get("graceful_restart_proof")
    if proof is None:
        proof = generation
    status_value = status if isinstance(status, dict) else {"state": status}
    proof_digest = proof.get("graceful_stop_receipt_sha256") if isinstance(proof, dict) else None
    if proof_digest is None and isinstance(proof, dict):
        proof_digest = proof.get("receipt_sha256")
    if proof_digest is None and isinstance(proof, dict):
        proof_digest = proof.get("stop_receipt_sha256")
    if (
        generation.get("name") != expected_name
        or not isinstance(container_id, str)
        or SHA.fullmatch(container_id) is None
        or status_value.get("state") != "RUNNING_NONTRADING"
        or status_value.get("owner") != OWNER
        or status_value.get("trading_started") is not False
        or not isinstance(proof, dict)
        or not (proof.get("controlled_restart") is True or proof.get("graceful_restart_proven") is True)
        or not isinstance(proof_digest, str)
        or SHA.fullmatch(proof_digest) is None
    ):
        raise contract.PreparationError("R7_GENERATION_PROOF_REJECTED")


def validate_accepted_inputs(
    workdir: Path,
    *,
    accepted_receipt_sha256: str,
    source_revision: str,
    verify_signature: Callable[[Path, Path, str], None],
    runtime_root: Path = RUNTIME_ROOT,
) -> dict[str, Any]:
    """Validate the signed R7 acceptance and exact two dump bindings."""
    work = _workdir(workdir, runtime_root=runtime_root)
    if SHA.fullmatch(accepted_receipt_sha256) is None or REVISION.fullmatch(source_revision) is None:
        raise contract.PreparationError("EXPLICIT_ACCEPTED_HASH_AND_REVISION_REQUIRED")
    receipt_path = work / RECEIPT_NAME
    accepted_path = work / ACCEPTED_NAME
    signature_path = work / SIGNATURE_NAME
    before_path = work / BEFORE_NAME
    after_path = work / AFTER_NAME
    for path in (receipt_path, accepted_path, signature_path, before_path, after_path):
        _no_reparse(path)
        if path.parent != work:
            raise contract.PreparationError("EXACT_R7_ARTIFACT_BOUNDARY_REQUIRED")

    receipt_sha = _safe_file(receipt_path, maximum=contract.MAX_METADATA_BYTES)
    if receipt_sha != accepted_receipt_sha256:
        raise contract.PreparationError("ACCEPTED_RECEIPT_HASH_MISMATCH")
    _safe_file(signature_path, maximum=contract.MAX_METADATA_BYTES)
    verify_signature(receipt_path, signature_path, SIGNER)
    accepted = _read_json(accepted_path)
    receipt = _read_json(receipt_path)
    if (
        accepted.get("state") != "ACCEPTED"
        or accepted.get("owner") != OWNER
        or accepted.get("source_revision") != source_revision
        or accepted.get("receipt_sha256") != receipt_sha
        or accepted.get("trading_started") is not False
    ):
        raise contract.PreparationError("R7_ACCEPTED_RECORD_MISMATCH")
    if (
        not REQUIRED_RECEIPT_FIELDS.issubset(receipt)
        or receipt.get("result") != "PASS_NEW_NONTRADING_GENERATION"
        or receipt.get("recovery_kind") != "R7_REDIS_TRANSPORT_RECOVERY"
        or receipt.get("owner") != OWNER
        or receipt.get("source_revision") != source_revision
        or receipt.get("trading_started") is not False
        or any(receipt.get(key) is not False for key in ("PAPER_QUALIFIED", "ALPHA_READY", "LIVE_READY"))
        or receipt.get("STRATEGY_POLICY") != "REJECT_ALL"
        or not isinstance(receipt.get("cold_backups"), (dict, list))
        or not receipt["cold_backups"]
        or not isinstance(receipt.get("redis_proof"), dict)
        or not receipt["redis_proof"]
        or SHA.fullmatch(str(receipt.get("final_state_sha256", ""))) is None
    ):
        raise contract.PreparationError("R7_ACCEPTED_SCOPE_OR_PROOF_REJECTED")
    _validate_generation(receipt)

    before_sha = _safe_file(before_path, maximum=MAX_DUMP_BYTES)
    after_sha = _safe_file(after_path, maximum=MAX_DUMP_BYTES)
    if (
        SHA.fullmatch(str(receipt.get("prebackup_sha256", ""))) is None
        or SHA.fullmatch(str(receipt.get("postcatchup_backup_sha256", ""))) is None
        or before_sha != receipt["prebackup_sha256"]
        or after_sha != receipt["postcatchup_backup_sha256"]
    ):
        raise contract.PreparationError("R7_FULL_DUMP_HASH_BINDING_REJECTED")
    return {
        "workdir": str(work),
        "owner": OWNER,
        "source_revision": source_revision,
        "receipt_sha256": receipt_sha,
        "signature_sha256": _safe_file(signature_path, maximum=contract.MAX_METADATA_BYTES),
        "files": {
            BEFORE_NAME: {"bytes": before_path.stat().st_size, "sha256": before_sha},
            AFTER_NAME: {"bytes": after_path.stat().st_size, "sha256": after_sha},
            RECEIPT_NAME: {"bytes": receipt_path.stat().st_size, "sha256": receipt_sha},
        },
        "source_paths": [str(before_path), str(after_path), str(receipt_path)],
        "trading_authority": False,
    }


def _local_repository(path: Path, workdir: Path) -> Path:
    if not path.is_absolute() or str(path).startswith(("\\\\", "//")):
        raise contract.PreparationError("EXPLICIT_LOCAL_REPOSITORY_REQUIRED")
    try:
        _no_reparse(path)
        resolved = path.resolve(strict=False)
        expected = (workdir / REPOSITORY_NAME).resolve(strict=False)
        if resolved != expected or resolved.exists() or resolved.parent != workdir:
            raise contract.PreparationError("CREATE_ONLY_LOCAL_REPOSITORY_REQUIRED")
        return resolved
    except (OSError, DeliveryError):
        raise contract.PreparationError("CREATE_ONLY_LOCAL_REPOSITORY_REQUIRED") from None


def plan_pack(
    workdir: Path,
    repository: Path,
    *,
    accepted_receipt_sha256: str,
    source_revision: str,
    verify_signature: Callable[[Path, Path, str], None],
    runtime_root: Path = RUNTIME_ROOT,
) -> dict[str, Any]:
    work = _workdir(workdir, runtime_root=runtime_root)
    evidence = validate_accepted_inputs(
        work,
        accepted_receipt_sha256=accepted_receipt_sha256,
        source_revision=source_revision,
        verify_signature=verify_signature,
        runtime_root=runtime_root,
    )
    repository_path = _local_repository(repository, work)
    return {
        "kind": "kairos.runtime-epoch-restic-plan.v1",
        "mode": "PLAN_ONLY",
        "repository": str(repository_path),
        "snapshot_inputs": evidence["source_paths"],
        "input_sha256": evidence["files"],
        "receipt_sha256": evidence["receipt_sha256"],
        "signature_verified": True,
        "network_requests": 0,
        "trading_authority": False,
        "offhost_qualified": False,
        "creates_run_claim": False,
        "native_restic_calls": 0,
    }


def _native_run(
    executable: Path,
    repository: Path,
    password_file: Path,
    arguments: list[str],
    *,
    cwd: Path,
    run_process: Callable[..., bytes],
    data: bytes | None = None,
    expect_failure: bool = False,
) -> bytes:
    command = [
        str(executable),
        "--repo",
        str(repository),
        "--password-file",
        str(password_file),
        "--no-cache",
        "--json",
        *arguments,
    ]
    return run_process(command, cwd=cwd, data=data, expect_failure=expect_failure)


def create_local_pack(
    workdir: Path,
    repository: Path,
    tool_bundle: Path,
    *,
    accepted_receipt_sha256: str,
    source_revision: str,
    verify_signature: Callable[[Path, Path, str], None],
    tool_verifier: Callable[..., dict[str, Any]] = preparation.verify_tool_bundle,
    run_process: Callable[..., bytes] = preparation._run,
    runtime_root: Path = RUNTIME_ROOT,
) -> dict[str, Any]:
    """Create one authenticated encrypted local snapshot and exact restore."""
    work = _workdir(workdir, runtime_root=runtime_root)
    evidence = validate_accepted_inputs(
        work,
        accepted_receipt_sha256=accepted_receipt_sha256,
        source_revision=source_revision,
        verify_signature=verify_signature,
        runtime_root=runtime_root,
    )
    if (work / CLAIM_NAME).exists() or (work / CLAIM_NAME).is_symlink():
        raise contract.PreparationError("R7_RESTIC_CLAIM_ALREADY_EXISTS_NO_RETRY")
    repo = _local_repository(repository, work)
    tool = tool_verifier(tool_bundle, work / "restic-verified-tool", ops_root=runtime_root)
    executable = Path(str(tool.get("executable", "")))
    if (
        not executable.is_absolute()
        or _safe_file(executable, maximum=32 * 1024 * 1024) != tool.get("executable_sha256")
    ):
        raise contract.PreparationError("VERIFIED_RESTIC_EXECUTABLE_REJECTED")
    # The claim is durable and create-only before repository/password writes.
    claim = {
        "kind": "kairos.runtime-epoch-restic-create-only-claim.v1",
        "owner": OWNER,
        "source_revision": source_revision,
        "receipt_sha256": evidence["receipt_sha256"],
        "repository": str(repo),
        "automatic_retry": False,
        "trading_authority": False,
    }
    _exclusive(work / CLAIM_NAME, contract.canonical(claim) + b"\n")
    password = work / PASSWORD_NAME
    wrong_password = work / WRONG_PASSWORD_NAME
    _exclusive(password, secrets.token_hex(32).encode("ascii"))
    _exclusive(wrong_password, secrets.token_hex(32).encode("ascii"))
    _private_acl(password)
    _private_acl(wrong_password)

    counts: dict[str, int] = {}

    def command(arguments: list[str], *, expect_failure: bool = False) -> bytes:
        counts[arguments[0]] = counts.get(arguments[0], 0) + 1
        return _native_run(
            executable,
            repo,
            password,
            arguments,
            cwd=work,
            run_process=run_process,
            expect_failure=expect_failure,
        )

    command(["init"])
    config = json.loads(command(["cat", "config"]))
    if not isinstance(config, dict) or SHA.fullmatch(str(config.get("id", ""))) is None:
        raise contract.PreparationError("LOCAL_REPOSITORY_IDENTITY_REJECTED")
    source_paths = [work / BEFORE_NAME, work / AFTER_NAME, work / RECEIPT_NAME]
    backup_output = command(
        [
            "backup",
            "--host",
            "kairos-r7-accepted-runtime",
            "--tag",
            "kairos-r7-accepted-v1",
            *[str(path) for path in source_paths],
        ]
    )
    summaries = [
        item
        for line in backup_output.splitlines()
        if line.strip()
        and isinstance(item := json.loads(line), dict)
        and item.get("message_type") == "summary"
    ]
    if len(summaries) != 1 or SHA.fullmatch(str(summaries[0].get("snapshot_id", ""))) is None:
        raise contract.PreparationError("LITERAL_SNAPSHOT_ID_REQUIRED")
    snapshot_id = summaries[0]["snapshot_id"]
    selected = json.loads(command(["snapshots", snapshot_id]))
    if not isinstance(selected, list) or len(selected) != 1 or selected[0].get("id") != snapshot_id:
        raise contract.PreparationError("EXACT_SNAPSHOT_BINDING_REJECTED")
    command(["check", "--read-data"])
    rejected = _native_run(
        executable,
        repo,
        wrong_password,
        ["cat", "config"],
        cwd=work,
        run_process=run_process,
        expect_failure=True,
    )
    if rejected != b"RESTIC_DECRYPTION_REJECTED":
        raise contract.PreparationError("AUTH_REJECTION_CATEGORY_UNPROVEN")

    restored = work / RESTORE_NAME
    if restored.exists() or restored.is_symlink():
        raise contract.PreparationError("EXCLUSIVELY_NEW_RESTORE_TARGET_REQUIRED")
    command(["restore", snapshot_id, "--target", str(restored), "--overwrite", "never", "--verify"])
    expected = {name: values["sha256"] for name, values in evidence["files"].items()}
    restored_files: list[Path] = []
    for parent, directories, files in os.walk(restored, followlinks=False):
        parent_path = Path(parent)
        _no_reparse(parent_path)
        for name in directories:
            _no_reparse(parent_path / name)
        for name in files:
            candidate = parent_path / name
            _no_reparse(candidate)
            restored_files.append(candidate)
    if len(restored_files) != len(expected) or {path.name for path in restored_files} != set(expected):
        raise contract.PreparationError("RESTORED_FILE_SET_REJECTED")
    restored_hashes: dict[str, str] = {}
    for path in restored_files:
        digest = _safe_file(path, maximum=MAX_DUMP_BYTES if path.name.endswith(".dump") else contract.MAX_METADATA_BYTES)
        if digest != expected[path.name]:
            raise contract.PreparationError("RESTORED_FILE_HASH_MISMATCH")
        restored_hashes[path.name] = digest
    result = {
        "kind": "kairos.runtime-epoch-restic-pack.v1",
        "status": "PASS_LOCAL_ENCRYPTED_R7_PACK_AND_RESTORE",
        "owner": OWNER,
        "source_revision": source_revision,
        "receipt_sha256": evidence["receipt_sha256"],
        "repository_id": config["id"],
        "snapshot_id": snapshot_id,
        "tool_sha256": tool["executable_sha256"],
        "input_sha256": evidence["files"],
        "restored_sha256": restored_hashes,
        "full_authenticated_data_check": True,
        "wrong_password_rejected": True,
        "create_only_claim": True,
        "commands": counts,
        "network_requests": 0,
        "offhost_qualified": False,
        "database_restore_proven": False,
        "trading_authority": False,
    }
    _exclusive(work / RESULT_NAME, contract.canonical(result) + b"\n")
    return result


class SafeParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise contract.PreparationError("INVALID_ARGUMENTS")


def main(argv: list[str] | None = None) -> int:
    try:
        parser = SafeParser(description=__doc__)
        parser.add_argument("--workdir", type=Path, required=True)
        parser.add_argument("--repository", type=Path, required=True)
        parser.add_argument("--accepted-receipt-sha256", required=True)
        parser.add_argument("--source-revision", required=True)
        parser.add_argument("--verification-homedir", type=Path, required=True)
        parser.add_argument("--restic-tool-bundle", type=Path)
        parser.add_argument("--execute-create-only", action="store_true")
        args = parser.parse_args(argv)
        verifier = lambda path, signature, signer: preparation._signature(
            path, signature, signer=signer, homedir=args.verification_homedir
        )
        if not args.execute_create_only:
            result = plan_pack(
                args.workdir,
                args.repository,
                accepted_receipt_sha256=args.accepted_receipt_sha256,
                source_revision=args.source_revision,
                verify_signature=verifier,
                runtime_root=RUNTIME_ROOT,
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True))
            return 0
        if args.restic_tool_bundle is None:
            raise contract.PreparationError("SIGNED_LOCAL_RESTIC_BUNDLE_REQUIRED")
        result = create_local_pack(
            args.workdir,
            args.repository,
            args.restic_tool_bundle,
            accepted_receipt_sha256=args.accepted_receipt_sha256,
            source_revision=args.source_revision,
            verify_signature=verifier,
            runtime_root=RUNTIME_ROOT,
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except contract.PreparationError as error:
        category = str(error)
    except Exception:  # noqa: BLE001 - emit only a fixed sanitized category.
        category = "LOCAL_R7_PACK_OPERATION_FAILED"
    print(json.dumps({"result": "BLOCKED", "error_category": category, "trading_authority": False}))
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
