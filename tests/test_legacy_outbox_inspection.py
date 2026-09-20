from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL_ROOT = ROOT / "tests" / "legacy_outbox_inspection"


def _load_module(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


runner = _load_module("kairos_legacy_outbox_runner", TOOL_ROOT / "runner.py")
policy = _load_module("kairos_legacy_outbox_policy", TOOL_ROOT / "policy.py")
receipt_verifier = _load_module(
    "kairos_legacy_outbox_receipt_verifier",
    ROOT / "scripts" / "verify_legacy_outbox_receipt.py",
)

_T0 = datetime(2026, 9, 20, 3, 0, tzinfo=UTC)


def _payload() -> dict[str, object]:
    return {"kind": "kairos.market.closed_bar.v1", "message_id": "legacy-message-1", "symbol": "BTCUSDT"}


def _identity() -> runner.ExactIdentity:
    canonical = runner.canonical_json(_payload())
    return runner.ExactIdentity(
        id=117625,
        producer="kairos-quant-scouts",
        message_id="legacy-message-1",
        topic="kairos.market.closed_bar.v1",
        payload_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        publish_attempts=1,
    )


def _expectation() -> runner.LegacyExpectation:
    return runner.LegacyExpectation(identity=_identity(), reconciliation_id="legacy-clone-rehearsal-1")


def _source_backup() -> runner.SourceBackup:
    return runner.SourceBackup.from_values(
        manifest_sha256="a" * 64,
        backup_sha256="b" * 64,
        created_at_utc="2026-09-20T03:00:00.0000000Z",
    )


def _row(**updates: object) -> dict[str, object]:
    identity = _identity()
    result: dict[str, object] = {
        **runner.identity_payload(identity),
        "payload": _payload(),
        "published_at": None,
        "dead_lettered_at": None,
        "lease_owner": "legacy-worker-identity",
        "lease_until": _T0,
        "lease_expired": True,
        "available": True,
    }
    result.update(updates)
    return result


def _audit_rows(*, count: int = 1, payload: object | None = None) -> list[dict[str, object]]:
    return [
        {"topic": _identity().topic, "payload": _payload() if payload is None else payload}
        for _ in range(count)
    ]


class LegacyOutboxPolicyTests(unittest.TestCase):
    def test_sealed_sources_and_docker_context_are_accepted(self) -> None:
        lock = json.loads((ROOT / "legacy-outbox-inspection.sources.lock.json").read_text(encoding="utf-8"))
        packaged = json.loads((TOOL_ROOT / "source-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock, packaged)
        self.assertEqual(policy.validate_source_lock(lock), [])
        self.assertEqual(policy.validate_dockerfile((TOOL_ROOT / "Dockerfile").read_text(encoding="utf-8")), [])
        self.assertEqual(policy.validate_dockerignore((TOOL_ROOT / ".dockerignore").read_text(encoding="utf-8")), [])
        self.assertEqual(receipt_verifier.RUNNER_PATH, TOOL_ROOT / "runner.py")
        runner.assert_runner_integrity()

    def test_tampered_scope_or_runtime_route_is_rejected(self) -> None:
        lock = json.loads((TOOL_ROOT / "source-lock.json").read_text(encoding="utf-8"))
        lock["profile"]["required_migrations"] = list(policy.LEGACY_MIGRATIONS[:-1])
        self.assertIn(
            "legacy outbox profile must remain the exact 001--012 read-only profile",
            policy.validate_source_lock(lock),
        )
        self.assertTrue(
            any("must not reference redis" in error for error in policy.validate_dockerfile("redis"))
        )


class LegacyOutboxReceiptTests(unittest.TestCase):
    def test_eligible_receipt_is_redacted_and_clone_only(self) -> None:
        receipt = runner.build_inspection_receipt(
            _expectation(),
            source_backup=_source_backup(),
            database_name=policy.EXPECTED_DATABASE,
            migrations=policy.LEGACY_MIGRATIONS,
            schema_fingerprint_sha256=policy.EXPECTED_SCHEMA_FINGERPRINT,
            row=_row(),
            audit_rows=_audit_rows(),
            has_unpublished_predecessor=False,
            inspected_at=_T0,
        )
        self.assertEqual(receipt["kind"], "kairos.legacy-outbox-inspection.v1")
        self.assertEqual(receipt["classification"], "LEGACY_RUNTIME_001_012_READ_ONLY")
        self.assertEqual(receipt["inspection"]["result"], "ELIGIBLE_FOR_CLONE_REHEARSAL")
        self.assertEqual(receipt["inspection"]["schema_profile"], "RUNTIME_001_012")
        self.assertEqual(
            receipt["receipt_sha256"],
            runner.sha256_json({key: value for key, value in receipt.items() if key != "receipt_sha256"}),
        )
        encoded = runner.canonical_json(receipt)
        self.assertNotIn("legacy-worker-identity", encoded)
        self.assertNotIn('"payload"', encoded)
        self.assertNotIn("postgres://", encoded)
        self.assertEqual(
            receipt["source_backup"]["created_at_utc"],
            "2026-09-20T03:00:00.0000000Z",
        )
        self.assertEqual(
            runner.verify_inspection_receipt(
                receipt,
                expectation=_expectation(),
                source_backup=_source_backup(),
                require_eligible=True,
            ),
            receipt,
        )

    def test_duplicate_audit_or_mutated_payload_rejects_but_does_not_raise(self) -> None:
        for audit_rows in (_audit_rows(count=2), _audit_rows(payload={"message_id": "wrong"})):
            with self.subTest(audit_rows=audit_rows):
                receipt = runner.build_inspection_receipt(
                    _expectation(),
                    source_backup=_source_backup(),
                    database_name=policy.EXPECTED_DATABASE,
                    migrations=policy.LEGACY_MIGRATIONS,
                    schema_fingerprint_sha256=policy.EXPECTED_SCHEMA_FINGERPRINT,
                    row=_row(),
                    audit_rows=audit_rows,
                    has_unpublished_predecessor=False,
                    inspected_at=_T0,
                )
                self.assertEqual(receipt["inspection"]["result"], "REJECTED")

    def test_backlog_is_observed_not_authorization_for_a_publish(self) -> None:
        receipt = runner.build_inspection_receipt(
            _expectation(),
            source_backup=_source_backup(),
            database_name=policy.EXPECTED_DATABASE,
            migrations=policy.LEGACY_MIGRATIONS,
            schema_fingerprint_sha256=policy.EXPECTED_SCHEMA_FINGERPRINT,
            row=_row(),
            audit_rows=_audit_rows(),
            has_unpublished_predecessor=True,
            inspected_at=_T0,
        )
        self.assertTrue(receipt["inspection"]["observations"]["has_earlier_unpublished_predecessor"])
        self.assertEqual(receipt["inspection"]["result"], "ELIGIBLE_FOR_CLONE_REHEARSAL")
        self.assertNotIn("APPLY", runner.canonical_json(receipt))

    def test_raw_lease_owner_or_payload_is_rejected_before_write(self) -> None:
        for invalid in (
            {"lease_owner": "not-redacted"},
            {"payload": {"message_id": "not-redacted"}},
            {"dsn": "postgres://not-redacted"},
            {"note": "postgresql://not-redacted"},
            {"note": "rediss://not-redacted"},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(runner.LegacyInspectionInputError):
                    runner.assert_receipt_redacted(invalid)

    def test_rejected_receipt_cannot_be_promoted_to_clone_eligibility(self) -> None:
        receipt = runner.build_inspection_receipt(
            _expectation(),
            source_backup=_source_backup(),
            database_name=policy.EXPECTED_DATABASE,
            migrations=policy.LEGACY_MIGRATIONS,
            schema_fingerprint_sha256=policy.EXPECTED_SCHEMA_FINGERPRINT,
            row=_row(lease_expired=False),
            audit_rows=_audit_rows(),
            has_unpublished_predecessor=False,
            inspected_at=_T0,
        )
        self.assertEqual(receipt["inspection"]["result"], "REJECTED")
        self.assertEqual(
            runner.verify_inspection_receipt(
                receipt,
                expectation=_expectation(),
                source_backup=_source_backup(),
                require_eligible=False,
            ),
            receipt,
        )
        with self.assertRaises(runner.LegacyInspectionInputError):
            runner.verify_inspection_receipt(
                receipt,
                expectation=_expectation(),
                source_backup=_source_backup(),
                require_eligible=True,
            )


class _Transaction:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *args: object) -> None:
        return None


class _Connection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, tuple[object, ...]]] = []
        self.transaction_kwargs: dict[str, object] | None = None
        self.closed = False

    def transaction(self, **kwargs: object) -> _Transaction:
        self.transaction_kwargs = kwargs
        return _Transaction()

    async def fetchval(self, sql: str, *params: object) -> object:
        self.calls.append(("fetchval", " ".join(sql.split()), params))
        if sql == "SELECT current_database()":
            return policy.EXPECTED_DATABASE
        if "string_agg" in sql:
            return "fixture-inventory"
        if "SELECT EXISTS" in sql:
            return True
        raise AssertionError(f"unexpected fetchval: {sql}")

    async def fetch(self, sql: str, *params: object) -> list[dict[str, object]]:
        self.calls.append(("fetch", " ".join(sql.split()), params))
        if "FROM schema_migrations" in sql:
            return [{"version": value} for value in policy.LEGACY_MIGRATIONS]
        if "FROM event_audit" in sql:
            return _audit_rows()
        raise AssertionError(f"unexpected fetch: {sql}")

    async def fetchrow(self, sql: str, *params: object) -> dict[str, object]:
        self.calls.append(("fetchrow", " ".join(sql.split()), params))
        if "FROM message_outbox" in sql:
            return _row()
        raise AssertionError(f"unexpected fetchrow: {sql}")

    async def close(self) -> None:
        self.closed = True


class _Asyncpg:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.connect_kwargs: dict[str, object] | None = None

    async def connect(self, _database_url: str, **kwargs: object) -> _Connection:
        self.connect_kwargs = kwargs
        return self.connection


class LegacyOutboxDatabaseTests(unittest.TestCase):
    def test_database_inspection_is_serializable_read_only_and_bounded(self) -> None:
        connection = _Connection()
        fake = _Asyncpg(connection)
        with mock.patch.object(runner, "asyncpg", fake):
            receipt = asyncio.run(
                runner.inspect_database(
                    _expectation(),
                    "postgres://fixture",
                    source_backup=_source_backup(),
                )
            )
        self.assertEqual(fake.connect_kwargs, {"server_settings": {"default_transaction_read_only": "on"}, "command_timeout": 15})
        self.assertEqual(connection.transaction_kwargs, {"isolation": "serializable", "readonly": True, "deferrable": True})
        self.assertTrue(connection.closed)
        queries = "\n".join(sql for _kind, sql, _params in connection.calls)
        self.assertIn("LIMIT 2", queries)
        self.assertNotIn("FOR UPDATE", queries)
        self.assertNotIn("UPDATE ", queries)
        self.assertNotIn("INSERT ", queries)
        self.assertNotIn("reconciliation_state", queries)
        self.assertNotIn("redis", queries.casefold())
        self.assertTrue(receipt["inspection"]["observations"]["has_earlier_unpublished_predecessor"])
        self.assertIn("E'\\\\n'", runner._SCHEMA_FINGERPRINT_QUERY)
        for marker in ("pg_index", "pg_trigger", "pg_sequence", "con.contype::text"):
            self.assertIn(marker, runner._SCHEMA_FINGERPRINT_QUERY)


class LegacyOutboxWrapperTests(unittest.TestCase):
    def test_wrapper_is_inspect_only_and_does_not_expose_a_bus_or_apply_route(self) -> None:
        wrapper = (ROOT / "scripts" / "Invoke-LegacyOutboxInspection.ps1").read_text(encoding="utf-8")
        self.assertIn("function Get-SafeInspectionFailure", wrapper)
        self.assertIn("LEGACY_RUNTIME_001_012_READ_ONLY", wrapper)
        self.assertIn("run --rm --no-deps", wrapper)
        self.assertIn("Assert-IsolatedDataNetwork", wrapper)
        self.assertIn("Get-VerifiedBackupIdentity", wrapper)
        self.assertIn("Verified source backup is not a fresh two-hour runtime verification", wrapper)
        self.assertIn("$ComposeProject -cne $expectedSourceProject", wrapper)
        self.assertIn("$DataNetwork -cne $expectedDataNetwork", wrapper)
        self.assertIn('$expectedDataNetwork = $expectedSourceProject + "_paper-data"', wrapper)
        self.assertIn("--pull never", wrapper)
        self.assertIn("verify_legacy_outbox_receipt.py", wrapper)
        self.assertIn("Kairos source backup root", wrapper)
        self.assertIn("--source-lock $sourceLockFile", wrapper)
        self.assertIn("--project-directory $root", wrapper)
        self.assertIn("build --pull --no-cache legacy-outbox-inspector", wrapper)
        self.assertIn("docker image inspect", wrapper)
        self.assertIn("--status-fd 1 --verify", wrapper)
        self.assertNotIn("SignReceipt", wrapper)
        self.assertNotIn("-Arm", wrapper)
        self.assertNotIn("redis_url", wrapper.casefold())
        self.assertNotIn("BusNetwork", wrapper)
        self.assertNotIn("docker compose up", wrapper.casefold())
        self.assertNotIn("Write-Output $output", wrapper)


if __name__ == "__main__":
    unittest.main()
