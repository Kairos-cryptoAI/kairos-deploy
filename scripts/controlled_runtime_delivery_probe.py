"""Bounded real PostgreSQL/Redis delivery probe for a fresh clone database.

This script never starts services. It only connects to the explicitly named
probe database and Redis on loopback, refuses existing rows/keys, and writes a
small sanitized receipt into the caller-provided evidence directory.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

DATABASE_PATTERN = re.compile(r"kairos_runtime_probe_([0-9a-f]{12})\Z")
RUNTIME_ROLE_PATTERN = re.compile(r"kairos_probe_runtime_[0-9a-f]{12}\Z")
REDIS_URL = "redis://127.0.0.1:6379/0"
PROBE_TIMEOUT_S = 90.0
DELIVERY_TIMEOUT_S = 8.0
POLL_INTERVAL_S = 0.025
FAILURE_CATEGORIES = frozenset(
    {
        "INVALID_TARGET",
        "EVIDENCE_DIRECTORY_INVALID",
        "DATABASE_NOT_EMPTY",
        "REDIS_NOT_EMPTY",
        "ADMIN_ROLE_INVALID",
        "OPERATOR_ROLE_INVALID",
        "RUNTIME_ROLE_EXISTS",
        "RUNTIME_PRIVILEGES_INVALID",
        "SCHEMA_PROFILE_INVALID",
        "DELIVERY_COMMIT_NOT_VISIBLE_BEFORE_ACK",
        "DUPLICATE_NOT_SUPPRESSED",
        "AMBIGUOUS_PUBLISH_RETRIED",
        "FIXTURE_DATA_BOUNDARY_INVALID",
        "OPERATION_FAILED",
    }
)
PROBE_STAGES = frozenset(
    {
        "ADMISSION",
        "IMPORTS",
        "ADMIN_CONNECT",
        "EMPTY_DATABASE",
        "SCHEMA_MIGRATE",
        "SCHEMA_VERIFY",
        "ROLE_PROVISION",
        "RUNTIME_SETTINGS",
        "OBSERVER_CONNECT",
        "REDIS_EMPTY",
        "BUS_START",
        "GROUP_CREATION",
        "COMMITTED_DELIVERY",
        "DUPLICATE_SUPPRESSION",
        "UNKNOWN_QUARANTINE",
        "BUS_RESTART",
        "REDIS_EVIDENCE_RESOLUTION",
        "FIXTURE_COUNTS",
        "EVIDENCE_WRITE",
    }
)
SAFE_ERROR_TYPES = frozenset(
    {
        "ProbeError",
        "AttributeError",
        "ConnectionError",
        "ConnectionRefusedError",
        "ConnectionResetError",
        "DatatypeMismatchError",
        "FeatureNotSupportedError",
        "ImportError",
        "IndeterminateDatatypeError",
        "InsufficientPrivilegeError",
        "InvalidAuthorizationSpecificationError",
        "InvalidCatalogNameError",
        "InvalidParameterValueError",
        "InvalidPasswordError",
        "InvalidSchemaNameError",
        "InvalidTextRepresentationError",
        "KeyError",
        "ModuleNotFoundError",
        "ObjectNotInPrerequisiteStateError",
        "PostgresSyntaxError",
        "RuntimeError",
        "TimeoutError",
        "TypeError",
        "UndefinedFunctionError",
        "UndefinedTableError",
        "UniqueViolationError",
        "ValidationError",
        "ValueError",
    }
)
BASE_RUNTIME_TABLE_GRANTS = (
    ("schema_migrations", ("SELECT",)),
    ("event_audit", ("SELECT", "INSERT")),
    ("message_inbox", ("SELECT", "INSERT", "UPDATE")),
    ("message_outbox", ("SELECT", "INSERT", "UPDATE")),
)
OPERATOR_CONTROL_MINIMUM_GRANTS = (
    (
        "SELECT",
        (
            "operator_controls",
            "operator_control_commands",
            "operator_control_admissions",
            "operator_control_dispatch_claims",
        ),
    ),
    ("INSERT", ("operator_control_admissions", "operator_control_dispatch_claims")),
)


class ProbeError(ValueError):
    """Safe fixed-category probe failure; never carries driver text."""

    def __init__(self, category: str):
        super().__init__(
            category if category in FAILURE_CATEGORIES else "OPERATION_FAILED"
        )
        self.category = (
            category if category in FAILURE_CATEGORIES else "OPERATION_FAILED"
        )


def require_database_name(value: object) -> tuple[str, str]:
    if not isinstance(value, str):
        raise ProbeError("INVALID_TARGET")
    match = DATABASE_PATTERN.fullmatch(value)
    if match is None:
        raise ProbeError("INVALID_TARGET")
    return value, match.group(1)


def require_evidence_directory(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        raise ProbeError("EVIDENCE_DIRECTORY_INVALID")
    path = Path(value)
    if path.is_symlink() or not path.is_dir():
        raise ProbeError("EVIDENCE_DIRECTORY_INVALID")
    return path.resolve(strict=True)


def database_url(database_name: str, role: str = "kairos") -> str:
    require_database_name(database_name)
    if role != "kairos" and RUNTIME_ROLE_PATTERN.fullmatch(role) is None:
        raise ProbeError("INVALID_TARGET")
    return f"postgresql://{role}@127.0.0.1:5432/{database_name}"


def _identifier(value: str) -> str:
    """Quote only identifiers generated from the fixed probe-name grammar."""
    if re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) is None:
        raise ProbeError("INVALID_TARGET")
    return f'"{value}"'


def _evidence_file(directory: Path, owner12: str) -> Path:
    path = directory / f"controlled-runtime-delivery-{owner12}.json"
    if path.exists() or path.is_symlink():
        raise ProbeError("EVIDENCE_DIRECTORY_INVALID")
    return path


def _write_evidence(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    try:
        with path.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
    except OSError:
        raise ProbeError("EVIDENCE_DIRECTORY_INVALID") from None


def failure_diagnostic(exc: Exception, diagnostics: dict[str, str]) -> dict[str, str]:
    """Only fixed stage/type names; never exception strings, SQL or payloads."""
    error_type = type(exc).__name__
    stage = diagnostics.get("stage")
    return {
        "error_type": error_type if error_type in SAFE_ERROR_TYPES else "OTHER",
        "stage": stage if stage in PROBE_STAGES else "ADMISSION",
    }


def _stage(diagnostics: dict[str, str], value: str) -> None:
    if value not in PROBE_STAGES:
        raise ProbeError("OPERATION_FAILED")
    diagnostics["stage"] = value


def canonical_database_payload(value: object) -> str:
    """asyncpg's default JSONB codec returns text, not a decoded object."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ProbeError("OPERATION_FAILED") from None
    if not isinstance(value, dict):
        raise ProbeError("OPERATION_FAILED")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def operator_control_grant_sql(runtime_role: str) -> tuple[str, ...]:
    if RUNTIME_ROLE_PATTERN.fullmatch(runtime_role) is None:
        raise ProbeError("INVALID_TARGET")
    quoted_runtime = _identifier(runtime_role)
    return tuple(
        f"GRANT {privilege} ON TABLE {','.join(tables)} TO {quoted_runtime}"
        for privilege, tables in OPERATOR_CONTROL_MINIMUM_GRANTS
    )


def fixture_payload(owner12: str, run_id: str, phase: str) -> dict[str, Any]:
    if (
        re.fullmatch(r"[0-9a-f]{12}", owner12) is None
        or re.fullmatch(r"[0-9a-f]{32}", run_id) is None
    ):
        raise ProbeError("INVALID_TARGET")
    suffix = {"committed-delivery": "success", "publish-db-ack-loss": "ack-loss"}.get(
        phase
    )
    if suffix is None:
        raise ProbeError("INVALID_TARGET")
    return {
        "message_id": f"probe-{run_id}-{suffix}",
        "source": f"probe-producer-{owner12}",
        "schema_version": "1.0",
        "produced_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "probe_namespace": owner12,
        "probe_phase": phase,
        "synthetic_fixture": True,
    }


def require_fixture_counts(value: dict[str, Any]) -> None:
    # Two durable identities create two audit rows. Re-delivery has the same
    # (produced_at, message_id) and must not manufacture a third audit event.
    expected = {
        "outbox_rows": 2,
        "inbox_rows": 2,
        "audit_rows": 2,
        "execution_orders": 0,
    }
    if value != expected or any(type(count) is not int for count in value.values()):
        raise ProbeError("FIXTURE_DATA_BOUNDARY_INVALID")


async def _provision_probe_roles(admin: Any, database_name: str, owner12: str) -> str:
    from kairos_persistence.operator_control import OperatorControlRefused

    runtime_role = f"kairos_probe_runtime_{owner12}"
    admin_facts = await admin.pool.fetchrow(
        """SELECT current_database() AS database_name,current_user AS role_name,
                  r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolbypassrls
             FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"""
    )
    if (
        admin_facts is None
        or admin_facts["database_name"] != database_name
        or admin_facts["role_name"] != "kairos"
        or not admin_facts["rolsuper"]
    ):
        raise ProbeError("ADMIN_ROLE_INVALID")

    runtime_exists = await admin.pool.fetchrow(
        "SELECT rolname FROM pg_catalog.pg_roles WHERE rolname=$1", runtime_role
    )
    if runtime_exists is not None:
        raise ProbeError("RUNTIME_ROLE_EXISTS")
    operator = await admin.pool.fetchrow(
        """SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
             FROM pg_catalog.pg_roles WHERE rolname='kairos_operator'"""
    )
    if operator is None:
        await admin.pool.execute(
            'CREATE ROLE "kairos_operator" NOLOGIN NOSUPERUSER NOBYPASSRLS '
            "NOCREATEDB NOCREATEROLE NOREPLICATION"
        )
    elif (
        operator["rolcanlogin"]
        or operator["rolsuper"]
        or operator["rolbypassrls"]
        or operator["rolcreaterole"]
        or operator["rolcreatedb"]
        or operator["rolreplication"]
    ):
        raise ProbeError("OPERATOR_ROLE_INVALID")

    quoted_database, quoted_runtime = (
        _identifier(database_name),
        _identifier(runtime_role),
    )
    await admin.pool.execute(
        f"CREATE ROLE {quoted_runtime} LOGIN NOSUPERUSER NOBYPASSRLS "
        "NOCREATEDB NOCREATEROLE NOREPLICATION"
    )
    await admin.pool.execute(
        f"GRANT CONNECT ON DATABASE {quoted_database} TO {quoted_runtime}"
    )
    await admin.pool.execute(f"GRANT USAGE ON SCHEMA public TO {quoted_runtime}")

    # Exact grants needed by the durable producer/consumer and the operator
    # control API. The runtime never receives latch/command writes or table ownership.
    for table, privileges in BASE_RUNTIME_TABLE_GRANTS:
        await admin.pool.execute(
            f"GRANT {','.join(privileges)} ON TABLE {table} TO {quoted_runtime}"
        )
    await admin.pool.execute(
        f"GRANT USAGE,SELECT ON SEQUENCE message_outbox_id_seq TO {quoted_runtime}"
    )
    for statement in operator_control_grant_sql(runtime_role):
        await admin.pool.execute(statement)

    runtime_url = database_url(database_name, runtime_role)
    from kairos_persistence import Database, MigrationProfile, PersistenceSettings
    from kairos_persistence.operator_control import OperatorControlRepository

    settings = PersistenceSettings(
        database_url=runtime_url,
        _env_file=None,
        pool_min_size=1,
        pool_max_size=1,
        command_timeout_s=5.0,
        migration_profile="controlled-runtime",
    )
    runtime = Database(settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME)
    try:
        await runtime.connect()
        await runtime.verify_schema()
        await OperatorControlRepository(runtime.pool).verify_runtime_access()
    except OperatorControlRefused:
        raise ProbeError("RUNTIME_PRIVILEGES_INVALID") from None
    except Exception:  # noqa: BLE001 -- suppress driver details from evidence/terminal
        raise ProbeError("RUNTIME_PRIVILEGES_INVALID") from None
    finally:
        await runtime.close()
    return runtime_role


async def _check_empty_target(admin: Any, database_name: str) -> None:
    facts = await admin.pool.fetchrow(
        """SELECT current_database() AS database_name,
                  current_setting('server_version_num')::integer AS server_version,
                  (SELECT count(*) FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                   WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S')) AS objects,
                  to_regclass('public.schema_migrations') IS NOT NULL AS has_migration_history"""
    )
    if (
        facts is None
        or facts["database_name"] != database_name
        or not 160000 <= facts["server_version"] < 170000
        or facts["objects"] != 0
        or facts["has_migration_history"]
    ):
        raise ProbeError("DATABASE_NOT_EMPTY")


async def _wait_for(predicate, *, timeout_s: float = DELIVERY_TIMEOUT_S) -> Any:
    async with asyncio.timeout(timeout_s):
        while True:
            value = await predicate()
            if value:
                return value
            await asyncio.sleep(POLL_INTERVAL_S)


async def _topic_has_group(redis_client: Any, topic: str) -> bool:
    from redis.exceptions import ResponseError

    try:
        return bool(await redis_client.xinfo_groups(topic))
    except ResponseError as exc:
        # XINFO GROUPS on a not-yet-created stream returns Redis' exact
        # missing-key response. Other command errors must not be retried away.
        if "no such key" in str(exc).lower():
            return False
        raise


@dataclass(frozen=True)
class AckObservation:
    topic: str
    message_id: str
    inbox_status: str
    audit_rows: int


class AckWitnessRedis:
    """Thin witness around the real Redis Streams transport; never fakes I/O."""

    def __init__(self, redis: Any, observer: Any, consumer_key: str):
        self.redis = redis
        self.observer = observer
        self.consumer_key = consumer_key
        self.observations: list[AckObservation] = []

    async def publish(self, topic: str, message: Any) -> str:
        return await self.redis.publish(topic, message)

    async def subscribe(self, topic: str, *, group=None, consumer=None):
        async for envelope in self.redis.subscribe(
            topic,
            group=group,
            consumer=consumer,
            block_ms=50,
            reclaim_idle_ms=0,
            reclaim_every_s=0.05,
        ):
            yield envelope

    async def ack(self, topic: str, envelope: Any, *, group=None) -> None:
        message_id = envelope.payload.get("message_id")
        row = await self.observer.pool.fetchrow(
            "SELECT status FROM message_inbox WHERE consumer=$1 AND message_id=$2",
            self.consumer_key,
            message_id,
        )
        audit_rows = await self.observer.pool.fetchval(
            "SELECT count(*) FROM event_audit WHERE message_id=$1", message_id
        )
        if row is None or row["status"] != "COMPLETED" or audit_rows < 1:
            raise ProbeError("DELIVERY_COMMIT_NOT_VISIBLE_BEFORE_ACK")
        self.observations.append(
            AckObservation(topic, message_id, row["status"], int(audit_rows))
        )
        await self.redis.ack(topic, envelope, group=group)

    async def close(self) -> None:
        await self.redis.close()


async def _wait_outbox(
    observer: Any,
    producer: str,
    message_id: str,
    *,
    expected_states: frozenset[str],
) -> Any:
    if not expected_states:
        raise ProbeError("OPERATION_FAILED")

    async def read_row():
        row = await observer.pool.fetchrow(
            """SELECT id,publish_attempts,published_at,reconciliation_state
                 FROM message_outbox WHERE producer=$1 AND message_id=$2""",
            producer,
            message_id,
        )
        if row is None or row["reconciliation_state"] not in expected_states:
            return None
        return row

    return await _wait_for(read_row)


async def _resolve_redis_acceptance(
    admin: Any,
    raw_redis: Any,
    topic: str,
    producer: str,
    message_id: str,
    probe_run_id: str,
) -> dict[str, Any]:
    """Exercise evidence resolution only for the probe's synthetic unknown row."""
    from kairos_persistence.redis_acceptance_evidence import RedisAcceptanceEvidenceV1
    from kairos_persistence.repository import (
        AuditRepository,
        OfflineOutboxIdentity,
        OfflineOutboxTransportResolutionState,
    )

    row = await admin.pool.fetchrow(
        """SELECT id,producer,message_id,topic,payload,payload_sha256,publish_attempts,
                  reconciliation_id,reconciliation_state
             FROM message_outbox WHERE producer=$1 AND message_id=$2""",
        producer,
        message_id,
    )
    if row is None or row["reconciliation_state"] != "PUBLISH_OUTCOME_UNKNOWN":
        raise ProbeError("OPERATION_FAILED")
    identity = OfflineOutboxIdentity(
        id=row["id"],
        producer=row["producer"],
        message_id=row["message_id"],
        topic=row["topic"],
        payload_sha256=row["payload_sha256"],
        publish_attempts=row["publish_attempts"],
    )
    canonical_payload = canonical_database_payload(row["payload"])
    payload_sha256 = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
    if payload_sha256 != identity.payload_sha256 or identity.topic != topic:
        raise ProbeError("OPERATION_FAILED")

    server_info = await raw_redis._redis.info("server")
    redis_server_run_id = server_info.get("run_id")
    if (
        not isinstance(redis_server_run_id, str)
        or re.fullmatch(r"[0-9a-f]{40}", redis_server_run_id) is None
    ):
        raise ProbeError("OPERATION_FAILED")
    entries = await raw_redis._redis.xrange(topic, min="-", max="+")
    matches: list[str] = []
    for stream_id, fields in entries:
        try:
            payload = json.loads(fields["data"])
        except (KeyError, TypeError, json.JSONDecodeError):
            continue
        if payload.get("message_id") == message_id:
            entry_json = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            if (
                hashlib.sha256(entry_json.encode("utf-8")).hexdigest()
                == identity.payload_sha256
            ):
                matches.append(stream_id)
    if len(matches) != 1:
        # A missing stream entry may have been trimmed/deleted; it must stay
        # UNKNOWN. Multiple exact matches are a conflict. Neither is repaired
        # by a guessed absence or by replaying the message.
        raise ProbeError("OPERATION_FAILED")

    probed_at = datetime.now(UTC)
    base_evidence = {
        "redis_server_run_id": redis_server_run_id,
        "probe_run_id": probe_run_id,
        "probed_at_utc": probed_at,
        "topic": identity.topic,
        "message_id": identity.message_id,
        "canonical_payload_sha256": identity.payload_sha256,
    }
    repository = AuditRepository(admin.pool)
    exact = RedisAcceptanceEvidenceV1(
        **base_evidence, match_count=1, stream_ids=(matches[0],)
    )
    resolved = await repository.resolve_unknown_outbox_from_redis_evidence(
        identity, reconciliation_id=row["reconciliation_id"], evidence=exact
    )
    repeated = await repository.resolve_unknown_outbox_from_redis_evidence(
        identity, reconciliation_id=row["reconciliation_id"], evidence=exact
    )
    if (
        resolved.state is not OfflineOutboxTransportResolutionState.RESOLVED
        or repeated.state is not OfflineOutboxTransportResolutionState.ALREADY_RESOLVED
    ):
        raise ProbeError("OPERATION_FAILED")
    conflicting = RedisAcceptanceEvidenceV1(
        **base_evidence,
        match_count=1,
        stream_ids=(
            "9999999999999-0" if matches[0] != "9999999999999-0" else "9999999999998-0",
        ),
    )
    rejected = await repository.resolve_unknown_outbox_from_redis_evidence(
        identity, reconciliation_id=row["reconciliation_id"], evidence=conflicting
    )
    if rejected.state is not OfflineOutboxTransportResolutionState.REJECTED:
        raise ProbeError("OPERATION_FAILED")
    return {
        "unique_match_count": exact.match_count,
        "resolved_state": resolved.state.value,
        "repeat_state": repeated.state.value,
        "conflicting_evidence_state": rejected.state.value,
        "evidence": exact.document(),
    }


async def _wait_ack_count(witness: AckWitnessRedis, topic: str, count: int) -> None:
    async def current():
        return (
            len([item for item in witness.observations if item.topic == topic]) >= count
        )

    await _wait_for(current)


async def _probe(
    database_name: str,
    owner12: str,
    directory: Path,
    diagnostics: dict[str, str],
) -> dict[str, Any]:
    _stage(diagnostics, "IMPORTS")
    from kairos_core.bus.redis_streams import RedisStreamsBus
    from kairos_persistence import (
        Database,
        DurableMessageBus,
        MigrationProfile,
        PersistenceSettings,
    )
    from kairos_persistence.database_target import connect_verified_database

    _stage(diagnostics, "ADMIN_CONNECT")
    admin_settings = PersistenceSettings(
        database_url=database_url(database_name),
        _env_file=None,
        pool_min_size=1,
        pool_max_size=1,
        command_timeout_s=5.0,
        migration_profile="controlled-runtime",
    )
    admin = Database(
        admin_settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME
    )
    await connect_verified_database(admin, database_name, local_only=True)
    producer = None
    consumer = None
    restarted_producer = None
    observer = None
    raw_redis = None
    consume_tasks: list[asyncio.Task] = []
    try:
        _stage(diagnostics, "EMPTY_DATABASE")
        await _check_empty_target(admin, database_name)
        _stage(diagnostics, "SCHEMA_MIGRATE")
        await admin.migrate()
        _stage(diagnostics, "SCHEMA_VERIFY")
        await admin.verify_schema()
        _stage(diagnostics, "ROLE_PROVISION")
        await _provision_probe_roles(admin, database_name, owner12)

        _stage(diagnostics, "RUNTIME_SETTINGS")
        runtime_role = f"kairos_probe_runtime_{owner12}"
        runtime_url = database_url(database_name, runtime_role)
        runtime_settings = PersistenceSettings(
            database_url=runtime_url,
            _env_file=None,
            pool_min_size=1,
            pool_max_size=1,
            command_timeout_s=5.0,
            migration_profile="controlled-runtime",
            outbox_poll_s=0.05,
            outbox_lease_s=0.25,
            outbox_retry_base_s=0.05,
            outbox_retry_max_s=0.05,
            shutdown_timeout_s=1.0,
        )
        _stage(diagnostics, "OBSERVER_CONNECT")
        observer = Database(
            runtime_settings,
            migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
            read_only=True,
        )
        await observer.connect()
        await observer.verify_schema()
        if await observer.pool.fetchval("SELECT count(*) FROM event_audit") != 0:
            raise ProbeError("DATABASE_NOT_EMPTY")

        _stage(diagnostics, "REDIS_EMPTY")
        raw_redis = RedisStreamsBus(REDIS_URL)
        await raw_redis._redis.ping()
        if await raw_redis._redis.dbsize() != 0:
            raise ProbeError("REDIS_NOT_EMPTY")

        run_id = uuid4().hex
        success_topic = f"kairos.runtime.probe.{owner12}.{run_id}.success"
        ambiguous_topic = f"kairos.runtime.probe.{owner12}.{run_id}.ambiguous"
        consumer_service = f"probe-consumer-{owner12}"
        producer_service = f"probe-producer-{owner12}"
        group = f"probe-group-{owner12}"
        consumer_key = f"{consumer_service}:{group}"
        witness = AckWitnessRedis(RedisStreamsBus(REDIS_URL), observer, consumer_key)
        consumer_db = Database(
            runtime_settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME
        )
        consumer = DurableMessageBus(
            witness,
            service_name=consumer_service,
            settings=runtime_settings,
            database=consumer_db,
            verify_schema_only=True,
            required_migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
        )
        producer_db = Database(
            runtime_settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME
        )
        producer = DurableMessageBus(
            raw_redis,
            service_name=producer_service,
            settings=runtime_settings,
            database=producer_db,
            verify_schema_only=True,
            required_migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
        )
        _stage(diagnostics, "BUS_START")
        await consumer.start()
        await producer.start()

        delivered: dict[str, int] = {success_topic: 0, ambiguous_topic: 0}

        async def consume(topic: str) -> None:
            async for envelope in consumer.subscribe(
                topic, group=group, consumer=consumer_service
            ):
                delivered[topic] += 1
                await consumer.ack(topic, envelope, group=group)

        _stage(diagnostics, "GROUP_CREATION")
        consume_tasks = [
            asyncio.create_task(consume(success_topic)),
            asyncio.create_task(consume(ambiguous_topic)),
        ]
        for topic in (success_topic, ambiguous_topic):

            async def group_exists(topic=topic):
                return await _topic_has_group(raw_redis._redis, topic)

            await _wait_for(group_exists)

        _stage(diagnostics, "COMMITTED_DELIVERY")
        success_payload = fixture_payload(owner12, run_id, "committed-delivery")
        success_id = success_payload["message_id"]
        await producer.publish(success_topic, success_payload)
        success_row = await _wait_outbox(
            observer,
            producer_service,
            success_id,
            expected_states=frozenset({"ACKNOWLEDGED"}),
        )
        if (
            success_row["reconciliation_state"] != "ACKNOWLEDGED"
            or success_row["published_at"] is None
        ):
            raise ProbeError("OPERATION_FAILED")
        await _wait_ack_count(witness, success_topic, 1)
        if delivered[success_topic] != 1:
            raise ProbeError("OPERATION_FAILED")

        # A second Redis entry with the same durable identity must be skipped
        # by the already-COMPLETED inbox row and acknowledged without re-running
        # the handler. This duplicate is injected through real XADD via the bus.
        _stage(diagnostics, "DUPLICATE_SUPPRESSION")
        await raw_redis.publish(success_topic, success_payload)
        await _wait_ack_count(witness, success_topic, 2)
        if delivered[success_topic] != 1:
            raise ProbeError("DUPLICATE_NOT_SUPPRESSED")

        _stage(diagnostics, "UNKNOWN_QUARANTINE")
        ambiguous_payload = fixture_payload(owner12, run_id, "publish-db-ack-loss")
        ambiguous_id = ambiguous_payload["message_id"]

        async def lose_ack_before_commit(_record, _worker_id):
            raise RuntimeError("FIXTURE_ACK_COMMIT_RESPONSE_LOST")

        producer.repository.mark_published = lose_ack_before_commit
        await producer.publish(ambiguous_topic, ambiguous_payload)
        ambiguous_row = await _wait_outbox(
            observer,
            producer_service,
            ambiguous_id,
            expected_states=frozenset({"PUBLISH_OUTCOME_UNKNOWN"}),
        )
        if ambiguous_row["reconciliation_state"] not in {
            "PUBLISH_OUTCOME_UNKNOWN",
            "PUBLISHING",
        }:
            raise ProbeError("AMBIGUOUS_PUBLISH_RETRIED")
        if (
            ambiguous_row["publish_attempts"] != 1
            or ambiguous_row["published_at"] is not None
        ):
            raise ProbeError("AMBIGUOUS_PUBLISH_RETRIED")
        await _wait_ack_count(witness, ambiguous_topic, 1)
        if delivered[ambiguous_topic] != 1:
            raise ProbeError("OPERATION_FAILED")
        ambiguous_xlen = await raw_redis._redis.xlen(ambiguous_topic)
        if ambiguous_xlen != 1:
            raise ProbeError("AMBIGUOUS_PUBLISH_RETRIED")

        _stage(diagnostics, "BUS_RESTART")
        await producer.close()
        producer = None
        await asyncio.sleep(runtime_settings.outbox_lease_s * 2 + 0.1)
        restarted_producer = DurableMessageBus(
            RedisStreamsBus(REDIS_URL),
            service_name=producer_service,
            settings=runtime_settings,
            database=Database(
                runtime_settings, migration_profile=MigrationProfile.CONTROLLED_RUNTIME
            ),
            verify_schema_only=True,
            required_migration_profile=MigrationProfile.CONTROLLED_RUNTIME,
        )
        await restarted_producer.start()
        await asyncio.sleep(runtime_settings.outbox_lease_s * 2 + 0.1)
        after_restart = await _wait_outbox(
            observer,
            producer_service,
            ambiguous_id,
            expected_states=frozenset({"PUBLISH_OUTCOME_UNKNOWN"}),
        )
        final_xlen = await restarted_producer.transport._redis.xlen(ambiguous_topic)
        if (
            final_xlen != 1
            or after_restart["publish_attempts"] != 1
            or after_restart["reconciliation_state"]
            not in {"PUBLISH_OUTCOME_UNKNOWN", "PUBLISHING"}
        ):
            raise ProbeError("AMBIGUOUS_PUBLISH_RETRIED")
        if after_restart["reconciliation_state"] != "PUBLISH_OUTCOME_UNKNOWN":
            raise ProbeError("OPERATION_FAILED")
        _stage(diagnostics, "REDIS_EVIDENCE_RESOLUTION")
        resolution = await _resolve_redis_acceptance(
            admin,
            restarted_producer.transport,
            ambiguous_topic,
            producer_service,
            ambiguous_id,
            f"probe-{run_id}",
        )

        _stage(diagnostics, "FIXTURE_COUNTS")
        fixture_counts = await observer.pool.fetchrow(
            """SELECT (SELECT count(*) FROM message_outbox) AS outbox_rows,
                      (SELECT count(*) FROM message_inbox) AS inbox_rows,
                      (SELECT count(*) FROM event_audit) AS audit_rows"""
        )
        fixture_counts = dict(fixture_counts.items())
        fixture_counts["execution_orders"] = await admin.pool.fetchval(
            "SELECT count(*) FROM execution_orders"
        )
        require_fixture_counts(fixture_counts)
        return {
            "schema_version": 1,
            "classification": "ISOLATED_CONTROLLED_RUNTIME_DELIVERY_ENGINEERING_ONLY",
            "status": "PASS",
            "database": database_name,
            "profile": "controlled-runtime",
            "migrations": list(
                Database.migration_names(MigrationProfile.CONTROLLED_RUNTIME)
            ),
            "runtime_role": runtime_role,
            "redis_url": REDIS_URL,
            "producer_service": producer_service,
            "consumer_service": consumer_service,
            "consumer_group": group,
            "topics": {"committed": success_topic, "ambiguous": ambiguous_topic},
            "message_ids": {"committed": success_id, "ambiguous": ambiguous_id},
            "committed_delivery": {
                "redis_stream_entries_after_duplicate": await witness.redis._redis.xlen(
                    success_topic
                ),
                "ack_observations": [
                    asdict(item)
                    for item in witness.observations
                    if item.topic == success_topic
                ],
                "handler_invocations": delivered[success_topic],
            },
            "ambiguous_publish": {
                "redis_stream_entries_before_restart": ambiguous_xlen,
                "redis_stream_entries_after_restart": final_xlen,
                "outbox_state": after_restart["reconciliation_state"],
                "publish_attempts": after_restart["publish_attempts"],
                "handler_invocations": delivered[ambiguous_topic],
                "evidence_resolution": resolution,
                "restart_boundary": "new_bus_instance_same_process; not an OS-process-crash proof",
            },
            "fixture_counts": {
                key: int(value) for key, value in fixture_counts.items()
            },
            "strategy_orders_llm_or_external_api_used": False,
        }
    finally:
        for task in consume_tasks:
            task.cancel()
        if consume_tasks:
            await asyncio.gather(*consume_tasks, return_exceptions=True)
        for bus in (restarted_producer, producer, consumer):
            if bus is not None:
                try:
                    await bus.close()
                except Exception:  # noqa: BLE001,S110 -- preserve the original probe failure
                    pass
        if observer is not None:
            try:
                await observer.close()
            except Exception:  # noqa: BLE001,S110 -- preserve the original probe failure
                pass
        if raw_redis is not None:
            try:
                await raw_redis.close()
            except Exception:  # noqa: BLE001,S110 -- preserve the original probe failure
                pass
        try:
            await admin.close()
        except Exception:  # noqa: BLE001,S110 -- preserve the original probe failure
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--directory", required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    evidence_path: Path | None = None
    owner12: str | None = None
    diagnostics = {"stage": "ADMISSION"}
    try:
        database_name, owner12 = require_database_name(args.database)
        directory = require_evidence_directory(args.directory)
        evidence_path = _evidence_file(directory, owner12)
        evidence = asyncio.run(
            asyncio.wait_for(
                _probe(database_name, owner12, directory, diagnostics),
                timeout=PROBE_TIMEOUT_S,
            )
        )
        _stage(diagnostics, "EVIDENCE_WRITE")
        _write_evidence(evidence_path, evidence)
    except ProbeError as exc:
        if evidence_path is not None and owner12 is not None:
            try:
                _write_evidence(
                    evidence_path,
                    {
                        "schema_version": 1,
                        "classification": "ISOLATED_CONTROLLED_RUNTIME_DELIVERY_ENGINEERING_ONLY",
                        "database": args.database,
                        "status": "FAILED",
                        "failure_category": exc.category,
                        **failure_diagnostic(exc, diagnostics),
                    },
                )
            except ProbeError:
                pass
        print(f"CONTROLLED_RUNTIME_DELIVERY_PROBE_FAILED {exc.category}")
        return 1
    except Exception as exc:  # noqa: BLE001 -- sanitize backend and filesystem exceptions
        diagnostic = failure_diagnostic(exc, diagnostics)
        if evidence_path is not None and owner12 is not None:
            try:
                _write_evidence(
                    evidence_path,
                    {
                        "schema_version": 1,
                        "classification": "ISOLATED_CONTROLLED_RUNTIME_DELIVERY_ENGINEERING_ONLY",
                        "database": args.database,
                        "status": "FAILED",
                        "failure_category": "OPERATION_FAILED",
                        **diagnostic,
                    },
                )
            except ProbeError:
                pass
        print(
            "CONTROLLED_RUNTIME_DELIVERY_PROBE_FAILED OPERATION_FAILED "
            + diagnostic["stage"]
            + " "
            + diagnostic["error_type"]
        )
        return 1
    print(f"CONTROLLED_RUNTIME_DELIVERY_PROBE_PASS {evidence_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
