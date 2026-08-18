"""Create/validate local Docker secret files without printing secret values."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import secrets
import stat
import sys
from pathlib import Path

GENERATED = ("redis_password", "postgres_password", "grafana_admin_password")
DERIVED = ("redis_url", "persistence_database_url")
EXTERNAL = ("deepseek_api_key", "openai_api_key")
LIVE = ("evedex_jwt", "evedex_private_key")
PROMPTABLE = (*EXTERNAL, *LIVE)
PRIVATE_KEY = re.compile(r"^0x[0-9A-Fa-f]{64}$")


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
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.initialize_infrastructure:
            initialize(args.secrets_dir)
            print("Generated infrastructure secret files; add provider keys separately")
            return 0
        if args.prompt:
            names = list(dict.fromkeys(args.prompt))
            prompt_secrets(args.secrets_dir, names)
            print("Stored requested secret files without echoing their values")
            return 0
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
