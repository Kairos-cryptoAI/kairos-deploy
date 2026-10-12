"""Offline tests for the one-shot reviewed R6 admission continuation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import runtime_epoch_feed_recovery as controller

epoch = controller.epoch


def retained_inventory() -> dict[str, str]:
    return {
        name: (
            controller.R6_RETAINED_FAILURE_SHA256
            if name == "failure.json"
            else "a" * 64
        )
        for name in controller.R6_RETAINED_INVENTORY_PATHS
    }


def valid_evidence() -> dict:
    return {
        "explicit_flag": True,
        "failure": dict(controller.R6_RETAINED_FAILURE),
        "failure_sha256": controller.R6_RETAINED_FAILURE_SHA256,
        "original_latch": dict(controller.R6_RETAINED_LATCH),
        "original_latch_sha256": controller.R6_ORIGINAL_LATCH_SHA256,
        "inventory": retained_inventory(),
    }


def validate(evidence: dict, expected_inventory_sha256: str | None = None) -> dict:
    claim = expected_inventory_sha256 or controller.fresh.digest(evidence["inventory"])
    with patch.object(controller, "R6_RETAINED_INVENTORY_SHA256", claim):
        return controller.validate_reviewed_continuation(**evidence)


class FeedRecoveryAdmissionTests(unittest.TestCase):
    def test_reviewed_main_claim_precedes_existing_work_constructor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            claim_dir = root / "continuation-claim"
            claim = claim_dir / "latch.json"
            writes = []

            class OfflineController:
                def __init__(self, *_args, workdir, **_kwargs):
                    self.assert_directory = workdir.is_dir()
                    if not self.assert_directory or not writes or writes[0] != claim:
                        raise AssertionError("claim and work must precede constructor")

                def validate_resources(self, **_kwargs):
                    return {
                        "views": {
                            "serve": {"state": {"Status": "exited"}},
                            "pg": {"state": {"Status": "running"}},
                            "redis": {"state": {"Status": "running"}},
                        }
                    }

                def docker(self, *_args):
                    return ""

                def run_recovery(self, **_kwargs):
                    return {"trading_started": False}

            with (
                patch.object(controller.boot, "configure_generation_r5"),
                patch.object(controller.boot, "verify_source"),
                patch.object(controller, "validate_r5_failure"),
                patch.object(controller, "require_continuation_latch_absent"),
                patch.object(
                    controller,
                    "read_reviewed_continuation",
                    return_value={"verified": True},
                ),
                patch.object(controller, "ROOT", root),
                patch.object(controller, "R6_CONTINUATION_LATCH_DIR", claim_dir),
                patch.object(controller, "R6_CONTINUATION_LATCH", claim),
                patch.object(
                    controller.uuid, "uuid4", return_value=SimpleNamespace(hex="f" * 32)
                ),
                patch.object(
                    controller.epoch,
                    "_private_directory",
                    side_effect=lambda path: path.mkdir(),
                ),
                patch.object(
                    controller.fresh,
                    "save",
                    side_effect=lambda path, _value: writes.append(path),
                ),
                patch.object(controller.fresh, "sha", return_value="e" * 64),
                patch.object(controller, "R6FeedRecoveryController", OfflineController),
            ):
                result = controller.main(
                    [
                        "--execute",
                        "--expected-revision",
                        "b" * 40,
                        "--failed-r5-status-sha256",
                        controller.R5_STATUS_SHA256,
                        "--reviewed-admission-continuation",
                    ]
                )
            self.assertEqual(result, 0)
            self.assertEqual(writes[0], claim)
            self.assertNotIn(controller.R6_LATCH, writes)

    def test_hash_only_inventory_retains_new_r5_graceful_stop_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "status.json").write_text("{}", encoding="utf-8")
            (root / "serve-stop-123.json").write_text("{}", encoding="utf-8")
            with patch.object(controller.fresh, "safe", side_effect=lambda path: path):
                inventory = controller.clean.inventory_files(root)
            self.assertEqual(set(inventory), {"status.json", "serve-stop-123.json"})
            self.assertTrue(all(len(value) == 64 for value in inventory.values()))

    def test_exact_reviewed_inventory_and_original_latch_are_bound(self):
        evidence = valid_evidence()
        proof = validate(evidence)
        self.assertEqual(
            proof["original_inventory_sha256"],
            controller.fresh.digest(evidence["inventory"]),
        )
        self.assertEqual(
            proof["original_latch_sha256"], controller.R6_ORIGINAL_LATCH_SHA256
        )
        self.assertFalse(proof["automatic_retry"])

    def test_missing_original_attempt_or_latch_is_rejected(self):
        for field in ("failure", "original_latch"):
            evidence = valid_evidence()
            evidence[field] = None
            with self.subTest(field=field), self.assertRaises(epoch.Rejected):
                validate(evidence)

    def test_unexpected_or_missing_prior_artifact_is_rejected(self):
        evidence = valid_evidence()
        evidence["inventory"]["operator.zip"] = "b" * 64
        with self.assertRaises(epoch.Rejected):
            validate(evidence)
        evidence = valid_evidence()
        evidence["inventory"].pop("cli-015.stderr")
        with self.assertRaises(epoch.Rejected):
            validate(evidence)

    def test_failure_hash_and_original_latch_hash_must_match(self):
        for field in ("failure_sha256", "original_latch_sha256"):
            evidence = valid_evidence()
            evidence[field] = "f" * 64
            with self.subTest(field=field), self.assertRaises(epoch.Rejected):
                validate(evidence)

    def test_inventory_failure_hash_must_match_retained_failure(self):
        evidence = valid_evidence()
        evidence["inventory"]["failure.json"] = "b" * 64
        with self.assertRaises(epoch.Rejected):
            validate(evidence)

    def test_validly_formatted_changed_artifact_hash_is_rejected(self):
        evidence = valid_evidence()
        original_claim = controller.fresh.digest(evidence["inventory"])
        evidence["inventory"]["cli-001.stdout"] = "b" * 64
        with self.assertRaises(epoch.Rejected):
            validate(evidence, original_claim)

    def test_symlink_in_retained_inventory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "cli-001.stdout"
            path.write_text("offline test only", encoding="utf-8")
            with (
                patch.object(
                    Path,
                    "is_symlink",
                    autospec=True,
                    side_effect=lambda item: item == path,
                ),
                self.assertRaises(controller.fresh.Rejected),
            ):
                controller.clean.inventory_files(root)

    def test_partial_continuation_latch_is_never_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "continuation-latch"
            directory.mkdir()
            latch = directory / "latch.json"
            latch.write_text("{", encoding="utf-8")
            with self.assertRaises(epoch.Rejected):
                controller.require_continuation_latch_absent(latch)

    def test_exact_prior_latch_is_rejected_without_explicit_review_flag(self):
        evidence = valid_evidence()
        evidence["explicit_flag"] = False
        with self.assertRaises(epoch.Rejected):
            validate(evidence)

    def test_symlinked_continuation_latch_slot_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linked = root / "linked"
            linked.mkdir()
            with (
                patch.object(
                    Path,
                    "is_symlink",
                    autospec=True,
                    side_effect=lambda item: item == linked,
                ),
                self.assertRaises(epoch.Rejected),
            ):
                controller.require_continuation_latch_absent(linked / "latch.json")


if __name__ == "__main__":
    unittest.main()
