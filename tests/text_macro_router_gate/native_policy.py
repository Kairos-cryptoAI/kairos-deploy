"""Public, fixed native composition boundaries; never operator configuration."""

from __future__ import annotations

from urllib.parse import urlsplit
from uuid import UUID

DATABASE_ENV = "KAIROS_COMPOSITION_TEST_DATABASE_URL"
REDIS_ENV = "KAIROS_COMPOSITION_TEST_REDIS_URL"
DATABASE_PREFIX = "kairos_composition_test_"
BOOTSTRAP_DATABASE = "kairos_composition_bootstrap"
TARGET = "test_real_producers_router_review_risk_durable_replay_on_disposable_pg_redis"
CLASSIFICATION = "ISOLATED_NATIVE_COMPOSITION_ENGINEERING_ONLY"
REPORT = "composition-native.xml"


class CompositionBoundaryError(ValueError):
    """Fixed category only; no URL, credentials or backend exception text."""


def require_targets(database_url: str | None, redis_url: str | None) -> str:
    try:
        if not isinstance(database_url, str) or not isinstance(redis_url, str):
            raise ValueError
        if (
            not database_url.isascii()
            or any(ord(char) <= 32 or ord(char) == 127 for char in database_url)
            or any(char in database_url for char in "\\?#")
            or not database_url.startswith("postgresql://")
            or redis_url != "redis://127.0.0.1:6379/0"
        ):
            raise ValueError
        database, redis = urlsplit(database_url), urlsplit(redis_url)
        name = database.path.removeprefix("/")
        suffix = name.removeprefix(DATABASE_PREFIX)
        owner = UUID(hex=suffix)
        if (
            database.scheme != "postgresql"
            or database.hostname != "127.0.0.1"
            or database.port != 5432
            or database.username != "kairos"
            or not database.password
            or database.netloc.count("@") != 1
            or database.query
            or database.fragment
            or database.path != f"/{name}"
            or not name.startswith(DATABASE_PREFIX)
            or owner.version != 4
            or owner.hex != suffix
            or len(name) > 63
            or redis.scheme != "redis"
            or redis.hostname != "127.0.0.1"
            or redis.port != 6379
            or redis.path != "/0"
            or redis.username is not None
            or redis.password is not None
            or redis.query
            or redis.fragment
        ):
            raise ValueError
        return name
    except (ValueError, TypeError, AttributeError):
        raise CompositionBoundaryError("EXPLICIT_DISPOSABLE_TARGETS_REQUIRED") from None


def allowed_address(address: object) -> bool:
    """Only two fixture loopback endpoints, no DNS or provider exception."""
    return (
        isinstance(address, tuple)
        and len(address) == 2
        and address[0] == "127.0.0.1"
        and type(address[1]) is int
        and address[1] in {5432, 6379}
    )
