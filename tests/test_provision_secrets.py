from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.provision_secrets import initialize, prompt_secrets, validate


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
            for name in ("deepseek_api_key", "openai_api_key"):
                (root / name).write_text("provider-key\n", encoding="utf-8")
            (root / "evedex_jwt").write_text("short\n", encoding="utf-8")
            (root / "evedex_private_key").write_text("invalid\n", encoding="utf-8")

            errors = validate(root, live=True)

            self.assertTrue(any("unexpectedly short" in error for error in errors))
            self.assertTrue(any("64 hexadecimal" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
