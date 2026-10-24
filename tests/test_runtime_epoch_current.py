from __future__ import annotations

import copy
import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import runtime_epoch_current as current


class CurrentProfileTests(unittest.TestCase):
    def setUp(self):
        self.value = {
            "schema": "kairos.current-nontrading-profile.v1",
            "deploy_revision": "a" * 40,
            "runner_recipe_revision": "9" * 40,
            "core_revision": "b" * 40,
            "persistence_revision": "c" * 40,
            "quant_revision": "d" * 40,
            "runner_receipt": "D:/Kairos/runtime/test/receipt.json",
            "runner_receipt_sha256": "e" * 64,
            "wheelhouse": "D:/Kairos/runtime/test/wheels",
            "wheel_manifest_sha256": "f" * 64,
            "subnet": "10.254.251.64/28",
        }
        self.migrations = {"028_news_processing.sql": "1" * 64}
        self.runner = {
            "schema_version": 1,
            "local_image_id": "sha256:" + "2" * 64,
            "source": {
                "repository": "https://github.com/Kairos-cryptoAI/kairos-persistence",
                "revision": "c" * 40,
            },
            "recipe": {
                "repository": "https://github.com/Kairos-cryptoAI/kairos-deploy",
                "revision": "9" * 40,
            },
            "workflow": {
                "repository": "Kairos-cryptoAI/kairos-deploy",
                "commit": "9" * 40,
            },
            "runtime": {"python": "3.11.15", "aiohttp": "3.14.5", "multidict": "6.9.1"},
            "migrations": self.migrations,
        }
        self.release = {
            "repositories": [
                {"name": name, "revision": self.value[field]}
                for name, field in (
                    ("kairos-deploy", "deploy_revision"),
                    ("kairos-core", "core_revision"),
                    ("kairos-persistence", "persistence_revision"),
                    ("kairos-quant-scouts", "quant_revision"),
                )
            ]
        }

    def validate(self, value=None, runner=None, release=None):
        with patch.object(current, "migration_hashes", return_value=self.migrations):
            return current.validate_profile(
                value or self.value, runner or self.runner, release or self.release
            )

    def test_exact_current_source_profile_is_not_trading_permission(self):
        profile = self.validate()
        self.assertEqual(profile.schema_profile, "current-controlled-v1")
        self.assertEqual(profile.worker_image, self.runner["local_image_id"])
        self.assertEqual(
            profile.wheel_revisions,
            {"kairos-core": "b" * 40, "kairos-persistence": "c" * 40},
        )
        self.assertFalse(hasattr(profile, "LIVE_READY"))
        with self.assertRaises(AttributeError):
            profile.persistence_revision = "0" * 40

    def test_old_or_wrong_runner_cannot_be_current(self):
        for field in (
            "source",
            "recipe",
            "workflow",
            "runtime",
            "migrations",
            "local_image_id",
        ):
            bad = copy.deepcopy(self.runner)
            bad[field] = {} if field != "local_image_id" else "image:latest"
            with (
                self.subTest(field=field),
                self.assertRaises(
                    (current.CurrentEpochRejected, current.epoch.Rejected)
                ),
            ):
                self.validate(runner=bad)

    def test_profile_cannot_select_another_release(self):
        bad = copy.deepcopy(self.release)
        bad["repositories"][0]["revision"] = "0" * 40
        with self.assertRaises(current.CurrentEpochRejected):
            self.validate(release=bad)

    def test_runner_recipe_revision_must_match_receipt_not_current_deploy(self):
        self.assertNotEqual(
            self.value["runner_recipe_revision"], self.value["deploy_revision"]
        )
        for bad_value, bad_runner in (
            ({**self.value, "runner_recipe_revision": "8" * 40}, self.runner),
            (
                self.value,
                {
                    **self.runner,
                    "workflow": {
                        "repository": "Kairos-cryptoAI/kairos-deploy",
                        "commit": "a" * 40,
                    },
                },
            ),
        ):
            with (
                self.subTest(value=bad_value, runner=bad_runner),
                self.assertRaises(current.CurrentEpochRejected),
            ):
                self.validate(value=bad_value, runner=bad_runner)

    def _fake_git_blobs(self, contents):
        blobs = {hashlib.sha1(data).hexdigest(): data for data in contents.values()}

        def run(args, **kwargs):
            if args[3] == "ls-tree":
                revision, path = args[5], args[7]
                data = contents[(revision, path)]
                object_id = hashlib.sha1(data).hexdigest()
                mode = current.RECIPE_INPUT_MODES[path]
                return SimpleNamespace(
                    returncode=0,
                    stdout=f"{mode} blob {object_id}\t{path}\0".encode(),
                )
            if args[3:5] == ["cat-file", "blob"]:
                return SimpleNamespace(returncode=0, stdout=blobs[args[-1]])
            raise AssertionError("unexpected mocked Git command")

        return run

    def test_recipe_build_input_git_blob_bytes_must_match_current_deploy(self):
        recipe, deploy = "9" * 40, "a" * 40
        contents = {
            (revision, path): path.encode("utf-8")
            for revision in (recipe, deploy)
            for path in current.RECIPE_INPUT_MODES
        }
        with patch.object(
            current.subprocess, "run", side_effect=self._fake_git_blobs(contents)
        ):
            current.verify_runner_recipe_inputs(
                current.Path("unused-test-repo"), recipe, deploy
            )
        contents[(deploy, "docker/Dockerfile")] = b"different reviewed recipe bytes"
        with (
            patch.object(
                current.subprocess, "run", side_effect=self._fake_git_blobs(contents)
            ),
            self.assertRaisesRegex(
                current.CurrentEpochRejected,
                "RUNNER_RECIPE_INPUT_DIFFERS_FROM_CURRENT_DEPLOY",
            ),
        ):
            current.verify_runner_recipe_inputs(
                current.Path("unused-test-repo"), recipe, deploy
            )

    def test_nonancestor_recipe_commit_is_refused(self):
        with (
            patch.object(
                current.subprocess, "run", return_value=SimpleNamespace(returncode=1)
            ) as run,
            self.assertRaisesRegex(
                current.CurrentEpochRejected,
                "SIGNED_RUNNER_RECIPE_NOT_ANCESTOR_OF_CURRENT_DEPLOY",
            ),
        ):
            current.verify_runner_recipe_ancestor(
                current.Path("unused-test-repo"), "9" * 40, "a" * 40
            )
        self.assertIn("merge-base", run.call_args.args[0])

    def test_unsigned_or_wrongly_signed_recipe_commit_is_refused(self):
        def untrusted_git_result(repo, *args, capture=True):
            if args[0] == "log":
                return "B " + current.previous.epoch.fresh.SIGNER
            return ""

        with (
            patch.object(
                current.previous, "_run_git", side_effect=untrusted_git_result
            ),
            self.assertRaisesRegex(
                current.CurrentEpochRejected,
                "TRUSTED_RUNNER_RECIPE_SIGNATURE_REQUIRED",
            ),
        ):
            current.verify_runner_recipe(self.value)

    def test_public_subnet_and_unexpected_fields_are_refused(self):
        for field, value in (
            ("subnet", "8.8.8.0/28"),
            ("LIVE_READY", True),
            ("deploy_revision", "main"),
        ):
            bad = {**self.value, field: value}
            with (
                self.subTest(field=field),
                self.assertRaises(current.CurrentEpochRejected),
            ):
                self.validate(value=bad)

    def test_duplicate_json_fields_are_refused(self):
        with self.assertRaises(current.CurrentEpochRejected):
            current.unique_object([("schema", "one"), ("schema", "two")])

    def test_historical_controller_defaults_are_unchanged(self):
        controller = object.__new__(current.epoch.EpochController)
        self.assertIsNone(controller.build_profile)
        self.assertEqual(controller.worker_image, current.epoch.WORKER_IMAGE)


if __name__ == "__main__":
    unittest.main()
