from __future__ import annotations

import copy
import hashlib
import io
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

from scripts import prepare_controlled_runtime_wheels as wheels
from scripts import runtime_epoch_current as current


class CurrentProfileTests(unittest.TestCase):
    def setUp(self):
        self.value = {
            "schema": "kairos.current-nontrading-profile.v1",
            "deploy_revision": "a" * 40,
            "runner_recipe_revision": "9" * 40,
            "worker_image_id": "sha256:" + "2" * 64,
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

    def test_containerd_manifest_locator_does_not_replace_config_digest(self):
        runner = copy.deepcopy(self.runner)
        manifest = "sha256:" + "3" * 64
        runner["archive_identity"] = {
            "format": "oci-layout",
            "manifest_digest": manifest,
            "config_digest": runner["local_image_id"],
        }
        value = {**self.value, "worker_image_id": manifest}
        self.assertEqual(self.validate(value=value, runner=runner).worker_image, manifest)
        self.assertNotEqual(runner["local_image_id"], manifest)
        runner["archive_identity"]["config_digest"] = "sha256:" + "4" * 64
        with self.assertRaises(current.CurrentEpochRejected):
            self.validate(value=value, runner=runner)

    def test_unrelated_or_mutable_imported_image_is_refused(self):
        for identifier in ("image:latest", "sha256:" + "f" * 64):
            with self.subTest(identifier=identifier), self.assertRaises(current.CurrentEpochRejected):
                self.validate(value={**self.value, "worker_image_id": identifier})

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

    def test_migration_archive_disables_windows_eol_conversion(self):
        raw_sql = b"CREATE TABLE test_rows (id integer);\n"
        expected = {"028_news_processing.sql": hashlib.sha256(raw_sql).hexdigest()}

        def windows_git_archive(args, **kwargs):
            self.assertIn("-c", args)
            self.assertIn("core.autocrlf=false", args)
            self.assertIn("core.eol=lf", args)
            self.assertLess(args.index("core.autocrlf=false"), args.index("archive"))
            data = (
                raw_sql
                if "core.autocrlf=false" in args
                else raw_sql.replace(b"\n", b"\r\n")
            )
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr(
                    "kairos_persistence/migrations/028_news_processing.sql", data
                )
            return SimpleNamespace(returncode=0, stdout=output.getvalue())

        with patch.object(current.subprocess, "run", side_effect=windows_git_archive):
            self.assertEqual(current.migration_hashes("c" * 40), expected)

    def test_current_wheel_source_archive_disables_windows_eol_conversion(self):
        command = wheels.source_archive_command(
            current.Path("repo"), "c" * 40, current.Path("source.zip")
        )
        self.assertEqual(
            command[2:6], ["-c", "core.autocrlf=false", "-c", "core.eol=lf"]
        )
        self.assertGreater(command.index("archive"), command.index("core.eol=lf"))

    def test_release_gate_uses_explicit_shell_without_elevated_path_dependency(self):
        revisions = {
            "kairos-deploy": self.value["deploy_revision"],
            "kairos-core": self.value["core_revision"],
            "kairos-persistence": self.value["persistence_revision"],
            "kairos-quant-scouts": self.value["quant_revision"],
        }

        def git_output(repo, *args):
            if args == ("status", "--porcelain"):
                return ""
            if args == ("branch", "--show-current"):
                return "main"
            if args[0] == "rev-parse":
                return revisions[repo.name]
            if args == ("remote", "get-url", "origin"):
                return f"https://github.com/Kairos-cryptoAI/{repo.name}.git"
            raise AssertionError("Unexpected source admission command")

        with tempfile.TemporaryDirectory() as temporary:
            shell = current.Path(temporary) / "pwsh.exe"
            shell.write_bytes(b"synthetic path-selection fixture; never executed")
            with (
                patch.object(current, "RELEASE_POWERSHELL", shell),
                patch.object(current.previous, "_run_git", side_effect=git_output),
                patch.object(current.previous, "_verify_signed_commit"),
                patch.object(current, "verify_runner_recipe"),
                patch.object(
                    current.epoch.fresh,
                    "supervisor_environment",
                    return_value={"PATH": "unchanged-parent-path"},
                ),
                patch.object(
                    current.subprocess, "run", return_value=SimpleNamespace(returncode=0)
                ) as run,
            ):
                current.verify_clean_signed_sources(self.value)
                self.assertEqual(run.call_args.args[0][0], str(shell))
                self.assertEqual(
                    run.call_args.kwargs["env"]["PATH"],
                    str(current.epoch.GIT.parent) + current.os.pathsep + "unchanged-parent-path",
                )
                shell.unlink()
                run.reset_mock()
                with self.assertRaisesRegex(
                    current.CurrentEpochRejected, "EXACT_RELEASE_POWERSHELL_REQUIRED"
                ):
                    current.verify_clean_signed_sources(self.value)
                run.assert_not_called()

    def test_canonical_git_snapshot_reads_raw_blob_and_default_keeps_archive_path(self):
        revision = "b" * 40
        raw_source = b"line_one = 1\nline_two = 2\n"
        object_id = hashlib.sha1(raw_source).hexdigest()

        def raw_blob_git(args, **kwargs):
            if args[3] == "ls-tree":
                return SimpleNamespace(
                    returncode=0,
                    stdout=f"100644 blob {object_id}\tkairos_core/source.py\0".encode(),
                )
            if args[-1] == "--batch-check":
                return SimpleNamespace(
                    returncode=0,
                    stdout=f"{object_id} blob {len(raw_source)}\n".encode(),
                )
            if args[-1] == "--batch":
                header = f"{object_id} blob {len(raw_source)}\n".encode()
                return SimpleNamespace(returncode=0, stdout=header + raw_source + b"\n")
            raise AssertionError("canonical extraction must use Git tree/blob plumbing")

        with tempfile.TemporaryDirectory() as temporary:
            root = current.Path(temporary)
            canonical = root / "canonical"
            with patch.object(
                current.epoch.subprocess, "run", side_effect=raw_blob_git
            ):
                manifest = current.epoch.extract_git_snapshot(
                    current.Path("repo"),
                    revision,
                    ("kairos_core",),
                    canonical,
                    canonical_blobs=True,
                )
            extracted = canonical / "kairos_core" / "source.py"
            self.assertEqual(extracted.read_bytes(), raw_source)
            self.assertEqual(
                manifest["kairos_core/source.py"],
                hashlib.sha256(raw_source).hexdigest(),
            )
            self.assertFalse((root / "canonical.zip").exists())

            historical = root / "historical"

            def historical_archive(args, **kwargs):
                self.assertIn("archive", args)
                self.assertNotIn("ls-tree", args)
                archive_path = next(
                    item.split("=", 1)[1]
                    for item in args
                    if item.startswith("--output=")
                )
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr("scripts/source.py", b"historical\r\n")
                return SimpleNamespace(returncode=0, stdout=b"")

            with patch.object(
                current.epoch.subprocess, "run", side_effect=historical_archive
            ):
                current.epoch.extract_git_snapshot(
                    current.Path("repo"),
                    revision,
                    ("scripts/source.py",),
                    historical,
                    strip_prefix="scripts",
                )
            self.assertEqual((historical / "source.py").read_bytes(), b"historical\r\n")

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
