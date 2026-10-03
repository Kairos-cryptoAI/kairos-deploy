from __future__ import annotations

import copy
import unittest
from pathlib import Path

from scripts import alert_state as state
from scripts import validate_alert_delivery as legacy


class DurableStateTests(unittest.TestCase):
    volume = "kairos-ops-alerts-state-0123456789abcdef"

    def fixture(self) -> dict:
        root = state.OPS_ROOT
        binds = [
            {
                "type": "bind",
                "source": str(root / source),
                "target": target,
                "read_only": True,
                "bind": {"create_host_path": False},
            }
            for source, target in (
                ("config/unit/alertmanager.yml", "/etc/alertmanager/alertmanager.yml"),
                ("secrets/telegram_bot_token", "/run/secrets/telegram_bot_token"),
            )
        ]
        service = {
            "image": legacy.ALERTMANAGER_IMAGE,
            "platform": "linux/amd64",
            "profiles": ["alert-delivery-durable"],
            "user": "65534:65534",
            "read_only": True,
            "init": True,
            "restart": "no",
            "pids_limit": 64,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "command": state.DURABLE_COMMAND,
            "tmpfs": legacy.TMPFS[:1],
            "mem_limit": 134_217_728,
            "cpus": 0.25,
            "networks": {
                "alert-input": {"aliases": ["kairos-ops-alertmanager"]},
                "alert-egress": {},
            },
            "volumes": binds
            + [
                {
                    "type": "volume",
                    "source": "alert-state",
                    "target": "/alertmanager",
                    "read_only": False,
                    "volume": {"nocopy": True},
                }
            ],
        }
        return {
            "name": "kairos-ops-alerts",
            "services": {"alertmanager": service},
            "networks": {
                "alert-input": {"external": True, "name": "kairos_observability"},
                "alert-egress": {"driver": "bridge"},
            },
            "volumes": {"alert-state": {"external": True, "name": self.volume}},
        }

    def check(self, config: dict, **kwargs) -> list[str]:
        return state.validate_durable_topology(
            config, profile="base", state_volume=self.volume, **kwargs
        )

    def test_only_reviewed_persistent_delta_is_accepted_without_mutating_input(
        self,
    ) -> None:
        config = self.fixture()
        original = copy.deepcopy(config)
        self.assertEqual(self.check(config), [])
        self.assertEqual(config, original)

    def test_old_validator_still_rejects_persistent_topology(self) -> None:
        self.assertTrue(legacy.validate(self.fixture(), profile="base"))

    def test_state_mount_and_provisioning_cannot_be_generalized(self) -> None:
        for key, value in (("external", False), ("name", "arbitrary"), ("external", 1)):
            config = self.fixture()
            config["volumes"]["alert-state"][key] = value
            self.assertTrue(self.check(config))
        for key, value in (
            ("type", "bind"),
            ("source", "/"),
            ("read_only", 0),
            ("volume", {"nocopy": False}),
            ("volume", {"nocopy": 1}),
        ):
            config = self.fixture()
            config["services"]["alertmanager"]["volumes"][-1][key] = value
            self.assertTrue(self.check(config))

    def test_all_old_capability_guards_are_retained(self) -> None:
        for key, value in (
            ("privileged", True),
            ("ports", ["9093:9093"]),
            ("restart", "always"),
            ("mem_limit", "1g"),
            ("cpus", 1),
            ("user", "root"),
            ("profiles", ["alert-delivery"]),
            ("entrypoint", ["/bin/sh"]),
        ):
            config = self.fixture()
            config["services"]["alertmanager"][key] = value
            self.assertTrue(self.check(config), key)

    def test_source_bind_and_state_identity_remain_exact(self) -> None:
        config = self.fixture()
        config["services"]["alertmanager"]["volumes"][1]["source"] = str(
            Path("C:/other/token")
        )
        self.assertTrue(self.check(config))
        self.assertTrue(
            state.validate_durable_topology(
                self.fixture(), profile="base", state_volume="/"
            )
        )

    def test_state_metadata_rejects_remote_driver_options_and_unowned_volumes(
        self,
    ) -> None:
        value = {
            "Name": self.volume,
            "Driver": "local",
            "Scope": "local",
            "Options": None,
            "Labels": {
                "com.kairos.scope": state.SCOPE,
                "com.kairos.alert-policy-sha256": "a" * 64,
            },
        }
        self.assertEqual(
            state.validate_state_metadata(
                value, volume_name=self.volume, policy_sha256="a" * 64
            ),
            [],
        )
        for key, bad in (
            ("Driver", "nfs"),
            ("Options", {"device": "/"}),
            ("Labels", {}),
            ("Name", "other"),
        ):
            changed = copy.deepcopy(value)
            changed[key] = bad
            self.assertTrue(
                state.validate_state_metadata(
                    changed, volume_name=self.volume, policy_sha256="a" * 64
                )
            )


if __name__ == "__main__":
    unittest.main()
