"""Create/validate local Docker secret files without printing secret values."""

from __future__ import annotations

import argparse
import csv
import getpass
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path

GENERATED = ("redis_password", "postgres_password", "grafana_admin_password")
DERIVED = ("redis_url", "persistence_database_url")
EXTERNAL = ("deepseek_api_key", "openai_api_key", "x_bearer_token")
LIVE = ("evedex_jwt", "evedex_private_key")
PROMPTABLE = (*EXTERNAL, *LIVE)
PRIVATE_KEY = re.compile(r"^0x[0-9A-Fa-f]{64}$")
IMPORT_LABELS = {
    "deepseek_api_key": {"deepseek", "deepseekapi", "deepseekapikey"},
    "openai_api_key": {"openai", "openaiapi", "openaiapikey"},
    "x_bearer_token": {
        "twitter",
        "twitterapi",
        "twitterbearertoken",
        "xapi",
        "xapibearertoken",
        "xbearertoken",
    },
}


def _write_exclusive(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def harden_permissions(directory: Path) -> None:
    """Restrict a secret tree to the operator, administrators and the OS."""
    root = directory.resolve(strict=True)
    if os.name != "nt":
        root.chmod(0o700)
        for path in root.iterdir():
            if path.is_file():
                path.chmod(0o600)
        return

    identity = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        check=True,
        capture_output=True,
        text=True,
    )
    rows = list(csv.reader(identity.stdout.splitlines()))
    if len(rows) != 1 or len(rows[0]) < 2 or not rows[0][1].startswith("S-1-"):
        raise RuntimeError("could not resolve the current Windows user SID")
    current_sid = rows[0][1]
    subprocess.run(
        [
            "icacls",
            str(root),
            "/inheritance:r",
            "/T",
            "/C",
            "/Q",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "icacls",
            str(root),
            "/grant:r",
            f"*{current_sid}:F",
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
            "/T",
            "/C",
            "/Q",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "icacls",
            str(root),
            "/grant:r",
            f"*{current_sid}:(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/C",
            "/Q",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def initialize(directory: Path) -> None:
    root = directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    generated = {name: secrets.token_urlsafe(48) for name in GENERATED}
    values = {
        **generated,
        "redis_url": f"redis://:{generated['redis_password']}@redis:6379/0",
        "persistence_database_url": (
            "postgresql://kairos:"
            f"{generated['postgres_password']}@timescaledb:5432/kairos"
        ),
    }
    existing = [
        root / name for name in (*GENERATED, *DERIVED) if (root / name).exists()
    ]
    if existing:
        raise FileExistsError("refusing to replace existing generated secret files")
    for name, value in values.items():
        _write_exclusive(root / name, value)
    harden_permissions(root)


def prompt_secrets(directory: Path, names: list[str]) -> None:
    root = directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    for name in names:
        value = getpass.getpass(f"{name}: ").strip()
        if not value or "\n" in value or "\r" in value:
            raise ValueError(f"{name} must contain exactly one non-empty line")
        if name == "evedex_private_key" and not PRIVATE_KEY.fullmatch(value):
            raise ValueError(
                "evedex_private_key must be 0x followed by 64 hexadecimal characters"
            )
        if name == "evedex_jwt" and len(value) < 20:
            raise ValueError("evedex_jwt is unexpectedly short")
        _write_exclusive(root / name, value)
    harden_permissions(root)


def _normalized_label(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def import_labelled_secrets(directory: Path, source: Path, names: list[str]) -> None:
    """Import selected provider values without printing or accepting positional secrets."""
    requested = tuple(dict.fromkeys(names))
    if not requested:
        raise ValueError("at least one import name is required")
    unsupported = sorted(set(requested) - set(EXTERNAL))
    if unsupported:
        raise ValueError(f"unsupported import names: {', '.join(unsupported)}")

    matches: dict[str, list[str]] = {name: [] for name in requested}
    for number, raw in enumerate(
        source.resolve().read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line:
            continue
        colon = line.find(":")
        equals = line.find("=")
        positions = [position for position in (colon, equals) if position >= 0]
        if not positions:
            continue
        position = min(positions)
        label = _normalized_label(line[:position])
        value = line[position + 1 :].strip()
        for name in requested:
            if label in IMPORT_LABELS[name]:
                if not value or "\n" in value or "\r" in value:
                    raise ValueError(
                        f"{name} at line {number} must contain one non-empty value"
                    )
                matches[name].append(value)

    for name, values in matches.items():
        if len(values) != 1:
            raise ValueError(
                f"{name} must have exactly one labelled value in the import file"
            )

    root = directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    existing = [root / name for name in requested if (root / name).exists()]
    if existing:
        raise FileExistsError("refusing to replace existing imported secret files")
    for name in requested:
        _write_exclusive(root / name, matches[name][0])
    harden_permissions(root)


def _read(path: Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"{path.name} is empty")
    if "\n" in value or "\r" in value:
        raise ValueError(f"{path.name} must contain exactly one line")
    return value


def validate(directory: Path, *, live: bool) -> list[str]:
    root = directory.resolve()
    required = (*GENERATED, *DERIVED, *EXTERNAL, *(LIVE if live else ()))
    errors: list[str] = []
    values: dict[str, str] = {}
    for name in required:
        path = root / name
        try:
            values[name] = _read(path)
        except (OSError, ValueError) as exc:
            errors.append(f"{name}: {exc}")
            continue
        if os.name != "nt":
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                errors.append(f"{name}: permissions must not grant group/other access")
    if len({values.get(name) for name in GENERATED if name in values}) != len(
        [name for name in GENERATED if name in values]
    ):
        errors.append("generated infrastructure passwords must be distinct")
    if "redis_password" in values and values.get("redis_url") != (
        f"redis://:{values['redis_password']}@redis:6379/0"
    ):
        errors.append("redis_url does not match redis_password")
    if "postgres_password" in values and values.get("persistence_database_url") != (
        f"postgresql://kairos:{values['postgres_password']}@timescaledb:5432/kairos"
    ):
        errors.append("persistence_database_url does not match postgres_password")
    if (
        live
        and "evedex_private_key" in values
        and not PRIVATE_KEY.fullmatch(values["evedex_private_key"])
    ):
        errors.append(
            "evedex_private_key must be 0x followed by 64 hexadecimal characters"
        )
    if live and 0 < len(values.get("evedex_jwt", "")) < 20:
        errors.append("evedex_jwt is unexpectedly short")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secrets-dir", type=Path, default=Path("secrets"))
    parser.add_argument("--initialize-infrastructure", action="store_true")
    parser.add_argument("--prompt", action="append", choices=PROMPTABLE)
    parser.add_argument("--import-labelled-file", type=Path)
    parser.add_argument("--import-name", action="append", choices=EXTERNAL)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.prompt and args.import_labelled_file:
            raise ValueError(
                "--prompt and --import-labelled-file are mutually exclusive"
            )
        if args.initialize_infrastructure:
            initialize(args.secrets_dir)
            print("Generated infrastructure secret files; add provider keys separately")
            return 0
        if args.prompt:
            names = list(dict.fromkeys(args.prompt))
            prompt_secrets(args.secrets_dir, names)
            print("Stored requested secret files without echoing their values")
            return 0
        if args.import_labelled_file:
            import_labelled_secrets(
                args.secrets_dir,
                args.import_labelled_file,
                args.import_name or list(EXTERNAL),
            )
            print(
                "Imported requested provider secret files without echoing their values"
            )
            return 0
        if args.import_name:
            raise ValueError("--import-name requires --import-labelled-file")
        errors = validate(args.secrets_dir, live=args.live)
    except (OSError, ValueError) as exc:
        print(f"secret provisioning failed: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Kairos secret directory validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
