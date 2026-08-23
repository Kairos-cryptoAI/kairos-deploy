from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from scripts.provision_secrets import (
    harden_permissions,
    import_labelled_secrets,
    initialize,
    prompt_secrets,
    validate,
)


class SecretProvisioningTests(unittest.TestCase):
    @patch("scripts.provision_secrets.getpass.getpass")
    def test_prompts_without_echo_and_refuses_overwrite(self, prompt) -> None:
        prompt.return_value = "provider-secret"
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            prompt_secrets(root, ["deepseek_api_key"])
            self.assertEqual(
                (root / "deepseek_api_key").read_text().strip(), "provider-secret"
            )
            with self.assertRaises(FileExistsError):
                prompt_secrets(root, ["deepseek_api_key"])

    def test_initialization_is_exclusive_and_derived_urls_match(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            initialize(root)
            for name, value in {
                "deepseek_api_key": "deepseek\n",
                "openai_api_key": "openai\n",
                "x_bearer_token": "x-token\n",
            }.items():
                path = root / name
                path.write_text(value, encoding="utf-8")
                path.chmod(0o600)

            self.assertEqual(validate(root, live=False), [])
            with self.assertRaises(FileExistsError):
                initialize(root)

    def test_validation_rejects_missing_external_and_mismatched_derived_secret(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            initialize(root)
            (root / "redis_url").write_text("redis://wrong\n", encoding="utf-8")

            errors = validate(root, live=False)

            self.assertTrue(any("deepseek_api_key" in error for error in errors))
            self.assertTrue(
                any("redis_url does not match" in error for error in errors)
            )

    def test_live_static_secret_provisioning_is_retired(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            initialize(root)
            with self.assertRaisesRegex(ValueError, "static LIVE credential"):
                validate(root, live=True)

    def test_paper_requires_only_dev_credentials_and_never_static_jwt(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            initialize(root)
            (root / "evedex_dev_api_key").write_text("dev-api-key\n", encoding="utf-8")
            (root / "evedex_dev_private_key").write_text(
                f"0x{'a' * 64}\n", encoding="utf-8"
            )

            self.assertEqual(validate(root, live=False, paper=True), [])
            self.assertFalse((root / "evedex_jwt").exists())
            self.assertFalse((root / "evedex_private_key").exists())

            (root / "evedex_jwt").write_text("stale-static-token\n", encoding="utf-8")
            errors = validate(root, live=False, paper=True)
            self.assertTrue(any("must be removed" in error for error in errors))
            (root / "evedex_jwt").unlink()

            (root / "evedex_dev_private_key").write_text("invalid\n", encoding="utf-8")
            errors = validate(root, live=False, paper=True)
            self.assertTrue(any("evedex_dev_private_key" in error for error in errors))

            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                validate(root, live=True, paper=True)

    def test_labelled_import_is_explicit_exclusive_and_does_not_copy_unknowns(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "providers.txt"
            destination = root / "secrets"
            source.write_text(
                "OpenAI API: openai-value\n"
                "DeepSeek API: deepseek-value\n"
                "EVEDEX = deliberately-ignored\n"
                "EVEDEX DEV API Key = dev-api-value\n"
                f"EVEDEX DEV Private Key = 0x{'b' * 64}\n"
                "X Bearer Token: x-value\n",
                encoding="utf-8",
            )

            import_labelled_secrets(
                destination,
                source,
                ["openai_api_key", "deepseek_api_key", "x_bearer_token"],
            )

            self.assertEqual(
                (destination / "openai_api_key").read_text().strip(), "openai-value"
            )
            self.assertEqual(
                (destination / "deepseek_api_key").read_text().strip(), "deepseek-value"
            )
            self.assertEqual(
                (destination / "x_bearer_token").read_text().strip(), "x-value"
            )
            self.assertEqual(
                sorted(path.name for path in destination.iterdir()),
                ["deepseek_api_key", "openai_api_key", "x_bearer_token"],
            )
            with self.assertRaises(FileExistsError):
                import_labelled_secrets(destination, source, ["x_bearer_token"])

            paper_destination = root / "paper-secrets"
            import_labelled_secrets(
                paper_destination,
                source,
                ["evedex_dev_api_key", "evedex_dev_private_key"],
            )
            self.assertEqual(
                sorted(path.name for path in paper_destination.iterdir()),
                ["evedex_dev_api_key", "evedex_dev_private_key"],
            )

    def test_labelled_import_rejects_missing_or_duplicate_provider(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "providers.txt"
            source.write_text(
                "X API: first\nX Bearer Token: second\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "exactly one"):
                import_labelled_secrets(root / "secrets", source, ["x_bearer_token"])
            with self.assertRaisesRegex(ValueError, "exactly one"):
                import_labelled_secrets(root / "other", source, ["openai_api_key"])

            malformed = root / "malformed.txt"
            malformed.write_text(
                "EVEDEX DEV Private Key: not-a-key\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "64 hexadecimal"):
                import_labelled_secrets(
                    root / "paper", malformed, ["evedex_dev_private_key"]
                )

    @patch("scripts.provision_secrets.subprocess.run")
    def test_windows_permissions_use_sids_and_remove_inheritance(self, run) -> None:
        run.side_effect = [
            Mock(stdout='"desktop\\operator","S-1-5-21-123"\n'),
            Mock(stdout=""),
            Mock(stdout=""),
            Mock(stdout=""),
        ]
        with TemporaryDirectory() as temporary:
            # Construct the native path before selecting the simulated Windows
            # branch. Patching os.name first makes pathlib create a WindowsPath
            # for a real POSIX temporary directory on Linux CI.
            root = Path(temporary).resolve(strict=True)
            with patch("scripts.provision_secrets.os.name", "nt"):
                harden_permissions(root)

        remove_inheritance = run.call_args_list[1].args[0]
        recursive_grant = run.call_args_list[2].args[0]
        root_grant = run.call_args_list[3].args[0]
        self.assertIn("/inheritance:r", remove_inheritance)
        self.assertIn("/T", remove_inheritance)
        self.assertIn("*S-1-5-21-123:F", recursive_grant)
        self.assertIn("*S-1-5-21-123:(OI)(CI)F", root_grant)
        self.assertIn("*S-1-5-18:(OI)(CI)F", root_grant)
        self.assertIn("*S-1-5-32-544:(OI)(CI)F", root_grant)


if __name__ == "__main__":
    unittest.main()
