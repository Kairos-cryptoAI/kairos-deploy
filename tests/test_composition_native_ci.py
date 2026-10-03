"""Pure, no-service checks for the isolated installed composition CI envelope."""

from __future__ import annotations

import contextlib
import importlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "composition_native_ci", ROOT / "scripts/composition_native_ci.py"
)
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)
allowed_address = importlib.import_module("native_policy").allowed_address

DATABASE = "postgresql://kairos:synthetic@127.0.0.1:5432/kairos_composition_test_6f5b98d03b52490fbd3ae334ca4b62e7"
REDIS = "redis://127.0.0.1:6379/0"


class CompositionNativeBoundaryTests(unittest.TestCase):
    def test_accepts_only_explicit_uuid4_fixture(self):
        self.assertEqual(
            ci.require_targets(DATABASE, REDIS), DATABASE.rsplit("/", 1)[-1]
        )

    def test_database_aliases_ambient_primary_and_driver_overrides_fail_closed(self):
        changes = [
            None,
            "",
            DATABASE.replace("127.0.0.1", "localhost"),
            DATABASE.replace("127.0.0.1", "timescaledb"),
            DATABASE.replace(":5432", ":55434"),
            DATABASE.replace("kairos:synthetic", "other:synthetic"),
            DATABASE.replace("kairos:synthetic", "kairos:"),
            DATABASE.replace("kairos:synthetic", "kairos:synthetic@foreign"),
            DATABASE.replace(
                "6f5b98d03b52490fbd3ae334ca4b62e7", "6f5b98d03b52190fbd3ae334ca4b62e7"
            ),
            DATABASE.replace(
                "6f5b98d03b52490fbd3ae334ca4b62e7", "6F5B98D03B52490FBD3AE334CA4B62E7"
            ),
            DATABASE.rsplit("/", 1)[0] + "/kairos",
            DATABASE + "?sslmode=disable",
            DATABASE + "#override",
            "\n" + DATABASE,
            DATABASE.replace("synthetic", "syn\tthetic"),
            DATABASE.replace("postgresql://", "POSTGRESQL://"),
        ]
        for value in changes:
            with (
                self.subTest(index=changes.index(value)),
                self.assertRaises(ci.CompositionBoundaryError) as caught,
            ):
                ci.require_targets(value, REDIS)
            self.assertEqual(
                str(caught.exception), "EXPLICIT_DISPOSABLE_TARGETS_REQUIRED"
            )

    def test_redis_has_no_other_host_database_credential_or_option(self):
        for value in (
            None,
            "",
            REDIS.replace("127.0.0.1", "localhost"),
            REDIS.replace(":6379", ":6380"),
            REDIS.replace("/0", "/1"),
            REDIS + "?socket_timeout=1",
            REDIS + "#x",
            REDIS.replace("redis://", "redis://user:synthetic@"),
            REDIS.replace(":6379", ":06379"),
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(ci.CompositionBoundaryError),
            ):
                ci.require_targets(DATABASE, value)

    def test_socket_exception_is_only_literal_two_service_endpoints(self):
        self.assertTrue(allowed_address(("127.0.0.1", 5432)))
        self.assertTrue(allowed_address(("127.0.0.1", 6379)))
        for value in (
            ("localhost", 5432),
            ("127.0.0.1", "5432"),
            ("127.0.0.1", True),
            ("127.0.0.1", 443),
            ("127.0.0.1", 5432, 0),
            ["127.0.0.1", 5432],
            None,
        ):
            self.assertFalse(allowed_address(value))

    def test_missing_target_fails_before_any_kairos_import_or_acquisition(self):
        with (
            patch.dict("os.environ", {}, clear=True),
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            self.assertEqual(ci.main(["prepare"]), 1)
        self.assertEqual(
            stdout.getvalue().strip(),
            "COMPOSITION_NATIVE_CI_FAILED EXPLICIT_DISPOSABLE_TARGETS_REQUIRED",
        )

    def test_result_requires_exact_one_native_non_skip_pass(self):
        target = ci.TARGET
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.xml"
            good = f'<testsuites><testsuite><testcase name="{target}"/></testsuite></testsuites>'
            report.write_text(good, encoding="utf-8")
            ci.check_result(report)
            for xml in (
                good.replace("/>", "><skipped/></testcase>"),
                good.replace("/>", "><failure/></testcase>"),
                good.replace("/>", "><error/></testcase>"),
                good.replace(target, "unrelated"),
                good.replace(
                    "</testsuite>", f'<testcase name="{target}"/></testsuite>'
                ),
                "<testsuites/>",
                "not-xml",
            ):
                report.write_text(xml, encoding="utf-8")
                with self.assertRaises(ci.CompositionBoundaryError):
                    ci.check_result(report)

    def test_missing_and_oversized_results_are_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.xml"
            with self.assertRaises(ci.CompositionBoundaryError):
                ci.check_result(report)
            report.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaises(ci.CompositionBoundaryError):
                ci.check_result(report)

    def test_dtd_entity_and_utf16_bypass_cannot_expand_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.xml"
            for content in (
                b'<!DOCTYPE a [<!ENTITY e "fixture">]><a>&e;</a>',
                b'<!ENTITY fixture "not-allowed"><a/>',
                b"\xff\xfe<\x00a\x00/\x00>\x00",
            ):
                report.write_bytes(content)
                with self.assertRaises(ci.CompositionBoundaryError):
                    ci.check_result(report)

    def test_unknown_failures_do_not_disclose_provider_or_driver_messages(self):
        with (
            patch.object(
                ci, "check_result", side_effect=RuntimeError("synthetic-do-not-log")
            ),
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            self.assertEqual(ci.main(["check-result"]), 1)
        self.assertEqual(
            stdout.getvalue().strip(), "COMPOSITION_NATIVE_CI_FAILED OPERATION_FAILED"
        )
        with (
            patch.object(
                ci,
                "check_result",
                side_effect=ci.CompositionBoundaryError("synthetic-do-not-log"),
            ),
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            self.assertEqual(ci.main(["check-result"]), 1)
        self.assertEqual(
            stdout.getvalue().strip(), "COMPOSITION_NATIVE_CI_FAILED OPERATION_FAILED"
        )

    def test_native_wiring_and_no_authority_properties_are_preserved(self):
        source = (
            ROOT / "tests/text_macro_router_gate/test_native_composition.py"
        ).read_text(encoding="utf-8")
        fixture = (ROOT / "tests/text_macro_router_gate/conftest.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("timeout_placeholder", source)
        self.assertIn("delivered_and_acked", source)
        self.assertIn("reclaim_idle_ms=0", source)
        self.assertIn("operator_control_admissions", source)
        self.assertIn("strategy_not_paper_approved", source)
        self.assertIn("operator_control_unavailable", source)
        self.assertIn(
            'monkeypatch.setattr(kairos_llm.gateway.LLMGateway, "__init__", denied)',
            fixture,
        )
        self.assertIn(
            "Native composition requires verified non-editable installed packages",
            fixture,
        )

    def test_hosted_ci_is_pinned_bounded_native_and_retains_source_receipt(self):
        workflow = (ROOT / ".github/workflows/composition-native.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("uv sync --locked --no-editable", workflow)
        self.assertIn(
            "--native-composition --junitxml=composition-native.xml --tb=no --show-capture=no",
            workflow,
        )
        self.assertIn(ci.TARGET, workflow)
        self.assertIn("composition_native_ci.py check-result", workflow)
        self.assertIn(
            "--cpus 1 --memory 1g --memory-swap 1g --pids-limit 128", workflow
        )
        self.assertIn(
            "--cpus 0.25 --memory 256m --memory-swap 256m --pids-limit 64", workflow
        )
        self.assertIn("127.0.0.1:5432:5432", workflow)
        self.assertIn("127.0.0.1:6379:6379", workflow)
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", workflow
        )
        self.assertIn("tests/text_macro_router_gate/composition-native.xml", workflow)
        self.assertIn("tests/text_macro_router_gate/source-lock.json", workflow)
        self.assertIn("if-no-files-found: error", workflow)
        self.assertNotIn("docker compose", workflow)
        self.assertNotIn("--source-checkout-preliminary", workflow)
        self.assertNotIn("secrets.", workflow)


if __name__ == "__main__":
    unittest.main()
