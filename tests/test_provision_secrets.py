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

    def test_live_validation_requires_well_formed_exchange_secrets(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            initialize(root)
            for name in ("deepseek_api_key", "openai_api_key", "x_bearer_token"):
                (root / name).write_text("provider-key\n", encoding="utf-8")
            (root / "evedex_jwt").write_text("short\n", encoding="utf-8")
            (root / "evedex_private_key").write_text("invalid\n", encoding="utf-8")

            errors = validate(root, live=True)

            self.assertTrue(any("unexpectedly short" in error for error in errors))
            self.assertTrue(any("64 hexadecimal" in error for error in errors))

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

    @patch("scripts.provision_secrets.subprocess.run")
    @patch("scripts.provision_secrets.os.name", "nt")
    def test_windows_permissions_use_sids_and_remove_inheritance(self, run) -> None:
        run.side_effect = [
            Mock(stdout='"desktop\\operator","S-1-5-21-123"\n'),
            Mock(stdout=""),
            Mock(stdout=""),
            Mock(stdout=""),
        ]
        with TemporaryDirectory() as temporary:
            harden_permissions(Path(temporary))

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
