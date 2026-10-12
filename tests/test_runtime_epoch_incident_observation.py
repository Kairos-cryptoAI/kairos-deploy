"""Offline geometry and authority guards for the fixed incident observer."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from scripts import runtime_epoch_incident_observation as observation


def page(symbol="SOLUSDT", *, rows=2):
    start = observation.FAILED_END - rows * 60_000
    raw = [
        [
            start + i * 60_000,
            "10",
            "12",
            "8",
            "11",
            "4",
            start + i * 60_000 + 59_999,
            "40",
            9,
            "2",
            "20",
            "0",
        ]
        for i in range(rows)
    ]
    return observation.bar_projection(raw[0], symbol), raw


class ObservationTests(unittest.TestCase):
    def test_existing_nonfile_failure_slot_is_not_reported_as_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "status.json").mkdir()
            with self.assertRaisesRegex(
                observation.epoch.Rejected,
                "INCIDENT_FAILURE_SLOT_MUST_BE_REGULAR_FILE",
            ):
                observation.failure_snapshot(root)

    def test_fixed_window_matches_actual_failure_and_sql_minute(self):
        self.assertEqual(
            datetime.fromtimestamp(observation.FAILED_END / 1000, UTC).isoformat(),
            "2026-10-12T01:03:00+00:00",
        )
        self.assertEqual(observation.FAILED_OPEN, 1_791_766_920_000)
        self.assertIn(str(observation.FAILED_OPEN), observation.SQL)

    def test_default_is_plan_only_without_git_native_http_or_files(self):
        with (
            mock.patch.object(observation, "observe") as observe,
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(observation.main([]), 0)
        observe.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["result"], "PLAN_ONLY")

    def test_observation_verifies_source_before_creating_any_workspace(self):
        with (
            mock.patch.object(
                observation.boot, "verify_source", side_effect=ValueError
            ),
            mock.patch.object(observation.epoch, "_private_directory") as mkdir,
            self.assertRaises(ValueError),
        ):
            observation.observe("bad")
        mkdir.assert_not_called()

    def test_matching_pages_confirm_anchor_but_never_authorize_restart(self):
        anchor, raw = page()
        result = observation.compare_pages("SOLUSDT", anchor, raw, copy.deepcopy(raw))
        self.assertTrue(result["pages_equal"])
        self.assertTrue(result["persisted_anchor_matches"])
        self.assertFalse(result["historical_failure_reason_proven"])
        self.assertNotIn("restart_allowed", result)

    def test_mutable_unpublished_row_is_distinct_from_persisted_anchor_conflict(self):
        anchor, raw = page()
        revised = copy.deepcopy(raw)
        revised[1][4] = "11.5"
        result = observation.compare_pages("SOLUSDT", anchor, raw, revised)
        self.assertFalse(result["pages_equal"])
        self.assertTrue(result["persisted_anchor_matches"])
        revised[0][7] = "41"
        result = observation.compare_pages("SOLUSDT", anchor, revised, revised)
        self.assertTrue(result["pages_equal"])
        self.assertFalse(result["persisted_anchor_matches"])
        self.assertEqual(result["anchor_differing_fields"], ["quote_volume"])

    def test_exact_one_row_btc_window_is_allowed(self):
        anchor, raw = page("BTCUSDT", rows=1)
        self.assertTrue(
            observation.compare_pages("BTCUSDT", anchor, raw, raw)["pages_equal"]
        )

    def test_page_shape_time_symbol_and_extra_rows_are_rejected(self):
        anchor, raw = page()
        changed = copy.deepcopy(raw)
        changed[0][6] -= 1
        for symbol, first, second in (
            ("UNKNOWN", raw, raw),
            ("SOLUSDT", {}, raw),
            ("SOLUSDT", [], []),
            ("SOLUSDT", raw * 2, raw * 2),
            ("SOLUSDT", raw, raw[:1]),
            ("SOLUSDT", changed, changed),
            ("SOLUSDT", list(reversed(raw)), raw),
        ):
            with (
                self.subTest(symbol=symbol, first=first),
                self.assertRaises(observation.epoch.Rejected),
            ):
                observation.compare_pages(symbol, anchor, first, second)

    def test_nonfinite_negative_oversized_and_nonstring_numbers_are_rejected(self):
        _, raw = page()
        for value in ("nan", "inf", "-1", "9" * 65, True, 10):
            changed = copy.deepcopy(raw[0])
            changed[1] = value
            with (
                self.subTest(value=value),
                self.assertRaises((observation.epoch.Rejected, ValueError)),
            ):
                observation.bar_projection(changed, "SOLUSDT")

    def test_redirects_are_not_followed(self):
        self.assertIsNone(
            observation.NoRedirect().redirect_request(
                None, None, None, None, None, None
            )
        )

    def test_queries_are_exact_new_epoch_readonly_and_no_legacy_names(self):
        self.assertTrue(observation.SQL.startswith("BEGIN READ ONLY;"))
        for forbidden in (
            "UPDATE ",
            "DELETE ",
            "INSERT ",
            "TRUNCATE ",
            "ALTER ",
            "CREATE ",
            "kairos_paper",
            "kairos-paper",
        ):
            self.assertNotIn(
                forbidden,
                observation.SQL.upper() if forbidden.isupper() else observation.SQL,
            )


if __name__ == "__main__":
    unittest.main()
