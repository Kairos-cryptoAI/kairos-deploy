"""CI-only explicit empty PG/Redis preparation and exact no-skip result gate.

The synthetic disposable PG16 service is independently started by CI. This
command cannot start services, contact providers, arm an operator or create a
canary session. Local primary targets and normal deployment are not accepted.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys

# Only bounded UTF-8 JUnit without DTD/entities is parsed below.
import xml.etree.ElementTree as ET  # nosec B405
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

GATE_ROOT = Path(__file__).resolve().parents[1] / "tests" / "text_macro_router_gate"
sys.path.insert(0, str(GATE_ROOT))
native_policy = importlib.import_module("native_policy")
BOOTSTRAP_DATABASE = native_policy.BOOTSTRAP_DATABASE
DATABASE_ENV, REDIS_ENV = native_policy.DATABASE_ENV, native_policy.REDIS_ENV
REPORT, TARGET = native_policy.REPORT, native_policy.TARGET
CompositionBoundaryError, require_targets = (
    native_policy.CompositionBoundaryError,
    native_policy.require_targets,
)

PREPARE_TIMEOUT_S = 90.0
CLOSE_TIMEOUT_S = 5.0
FAILURE_CATEGORIES = frozenset(
    {
        "EXPLICIT_DISPOSABLE_TARGETS_REQUIRED",
        "FRESH_PG16_REDIS_REQUIRED",
        "EMPTY_PREPARED_SCHEMA_REQUIRED",
        "NATIVE_RESULT_REQUIRED",
        "INVALID_NATIVE_RESULT",
        "EXACT_NATIVE_PASS_REQUIRED",
        "INVALID_COMMAND",
    }
)


async def prepare(database_url: str | None, redis_url: str | None) -> None:
    name = require_targets(database_url, redis_url)
    from kairos_core.bus.redis_streams import RedisStreamsBus
    from kairos_persistence import Database, MigrationProfile, PersistenceSettings
    from kairos_persistence.database_target import connect_verified_database

    parsed = urlsplit(database_url)
    bootstrap_url = urlunsplit(parsed._replace(path=f"/{BOOTSTRAP_DATABASE}"))
    settings = {
        "_env_file": None,
        "pool_min_size": 1,
        "pool_max_size": 1,
        "command_timeout_s": 5.0,
    }
    bootstrap = Database(PersistenceSettings(database_url=bootstrap_url, **settings))
    database = Database(
        PersistenceSettings(database_url=database_url, **settings),
        migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
    )
    redis = RedisStreamsBus(redis_url)
    try:
        async with asyncio.timeout(PREPARE_TIMEOUT_S):
            await connect_verified_database(
                bootstrap, BOOTSTRAP_DATABASE, local_only=True
            )
            facts = await bootstrap.pool.fetchrow(
                """SELECT current_user AS role_name,
                   current_setting('server_version_num')::integer AS server_version,
                   (SELECT count(*) FROM pg_database WHERE NOT datistemplate
                     AND datname NOT IN ('postgres',$1)) AS other_databases,
                   (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                     WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S')) AS objects""",
                BOOTSTRAP_DATABASE,
            )
            if (
                facts is None
                or facts["role_name"] != "kairos"
                or not 160000 <= facts["server_version"] < 170000
                or facts["other_databases"] != 0
                or facts["objects"] != 0
                or await redis._redis.dbsize() != 0
            ):
                raise CompositionBoundaryError("FRESH_PG16_REDIS_REQUIRED")
            # name is an exact UUID4-derived simple identifier, never user SQL.
            await bootstrap.pool.execute(f'CREATE DATABASE "{name}"')
            await connect_verified_database(database, name, local_only=True)
            await database.migrate()
            await database.verify_schema()
            if await database.pool.fetchval("SELECT count(*) FROM event_audit") != 0:
                raise CompositionBoundaryError("EMPTY_PREPARED_SCHEMA_REQUIRED")
    finally:
        async with asyncio.timeout(CLOSE_TIMEOUT_S):
            await asyncio.gather(redis.close(), database.close(), bootstrap.close())


def check_result(report: Path = Path(REPORT)) -> None:
    if (
        report.is_symlink()
        or not report.is_file()
        or report.stat().st_size > 1024 * 1024
    ):
        raise CompositionBoundaryError("NATIVE_RESULT_REQUIRED")
    try:
        with report.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        text = raw.decode("utf-8")
        if (
            len(raw) > 1024 * 1024
            or "\x00" in text
            or any(token in text.upper() for token in ("<!DOCTYPE", "<!ENTITY"))
        ):
            raise CompositionBoundaryError("INVALID_NATIVE_RESULT")
        # Strict UTF-8, no DTD/entities and at most1MiB: no XML expansion path.
        document = ET.fromstring(text)  # nosec B314
    except (ET.ParseError, OSError, UnicodeDecodeError):
        raise CompositionBoundaryError("INVALID_NATIVE_RESULT") from None
    cases = list(document.iter("testcase"))
    if (
        len(cases) != 1
        or cases[0].get("name") != TARGET
        or any(
            True for tag in ("skipped", "failure", "error") for _ in document.iter(tag)
        )
    ):
        raise CompositionBoundaryError("EXACT_NATIVE_PASS_REQUIRED")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        if args == ["prepare"]:
            asyncio.run(
                prepare(os.environ.get(DATABASE_ENV), os.environ.get(REDIS_ENV))
            )
        elif args == ["check-result"]:
            check_result()
        else:
            raise CompositionBoundaryError("INVALID_COMMAND")
    except CompositionBoundaryError as exc:
        category = str(exc)
        print(
            "COMPOSITION_NATIVE_CI_FAILED",
            category if category in FAILURE_CATEGORIES else "OPERATION_FAILED",
        )
        return 1
    except Exception:  # noqa: BLE001 -- deliberately suppress all raw driver exceptions
        print("COMPOSITION_NATIVE_CI_FAILED OPERATION_FAILED")
        return 1
    print("COMPOSITION_NATIVE_CI_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
