"""Opt-in persistent Alertmanager topology; never starts services or sends alerts.

An external, explicitly provisioned volume replaces only Alertmanager's tmpfs.
This is restart continuity, not exactly-once delivery or host-loss protection.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

if __package__:
    from . import validate_alert_delivery as legacy
    from .alert_delivery import OPS_ROOT
else:
    import validate_alert_delivery as legacy
    from alert_delivery import OPS_ROOT


SCOPE = "alertmanager-durable-state-v1"
VOLUME_PATTERN = re.compile(r"kairos-ops-alerts-state-[a-f0-9]{16}\Z")
DURABLE_COMMAND = legacy.COMMAND + [
    "--data.maintenance-interval=5s",
    "--silences.max-silences=100",
    "--silences.max-silence-size-bytes=4096",
    "--alerts.per-alertname-limit=100",
]
STATE_LABELS = {"com.kairos.scope", "com.kairos.alert-policy-sha256"}


def validate_durable_topology(
    config: Any,
    *,
    profile: str,
    state_volume: str,
    ops_root: Path = OPS_ROOT,
    compose_version: str | None = None,
) -> list[str]:
    """Accept only the reviewed persistent delta, then reuse all old guards."""
    if not isinstance(state_volume, str) or not VOLUME_PATTERN.fullmatch(state_volume):
        return ["EXACT_OWNED_STATE_VOLUME_REQUIRED"]
    if not isinstance(config, dict) or set(config) != {
        "name",
        "services",
        "networks",
        "volumes",
    }:
        return ["INVALID_DURABLE_TOPOLOGY"]
    if config["volumes"] not in (
        {"alert-state": {"external": True, "name": state_volume}},
        {"alert-state": {"external": True, "name": state_volume, "labels": {}}},
    ):
        return ["EXTERNAL_STATE_VOLUME_IDENTITY_CHANGED"]
    if type(config["volumes"]["alert-state"]["external"]) is not bool:
        return ["EXTERNAL_STATE_VOLUME_IDENTITY_CHANGED"]
    normalized = copy.deepcopy(config)
    services = normalized.get("services")
    if not isinstance(services, dict) or set(services) != {"alertmanager"}:
        return ["ONLY_NATIVE_ALERTMANAGER_PERMITTED"]
    service = services["alertmanager"]
    if not isinstance(service, dict):
        return ["INVALID_DURABLE_SERVICE"]
    if service.get("profiles") != ["alert-delivery-durable"]:
        return ["EXPLICIT_DURABLE_PROFILE_REQUIRED"]
    if (
        service.get("command") != DURABLE_COMMAND
        or service.get("tmpfs") != legacy.TMPFS[:1]
    ):
        return ["DURABLE_STORAGE_COMMAND_CHANGED"]
    mounts = service.get("volumes")
    if not isinstance(mounts, list) or len(mounts) != 3:
        return ["DURABLE_MOUNT_SET_CHANGED"]
    state = [
        m for m in mounts if isinstance(m, dict) and m.get("target") == "/alertmanager"
    ]
    expected = {
        "type": "volume",
        "source": "alert-state",
        "target": "/alertmanager",
        "read_only": False,
        "volume": {"nocopy": True},
    }
    if (
        state != [expected]
        or type(state[0].get("read_only")) is not bool
        or state[0].get("volume", {}).get("nocopy") is not True
    ):
        return ["UNSAFE_DURABLE_STATE_MOUNT"]
    del normalized["volumes"]
    service["volumes"] = [m for m in mounts if m != expected]
    service["command"] = legacy.COMMAND
    service["tmpfs"] = legacy.TMPFS
    service["profiles"] = ["alert-delivery"]
    return legacy.validate(
        normalized, profile=profile, ops_root=ops_root, compose_version=compose_version
    )


def validate_state_metadata(
    value: Any, *, volume_name: str, policy_sha256: str
) -> list[str]:
    """Metadata only. Never read a token, volume data, or Docker credentials."""
    if (
        not isinstance(volume_name, str)
        or not VOLUME_PATTERN.fullmatch(volume_name)
        or not isinstance(policy_sha256, str)
        or not re.fullmatch(r"[a-f0-9]{64}", policy_sha256)
    ):
        return ["INVALID_STATE_BINDING"]
    if not isinstance(value, dict) or set(value) != {
        "Name",
        "Driver",
        "Scope",
        "Options",
        "Labels",
    }:
        return ["INVALID_STATE_METADATA"]
    if (
        value["Name"] != volume_name
        or value["Driver"] != "local"
        or value["Scope"] != "local"
        or value["Options"] not in (None, {})
    ):
        return ["STATE_DRIVER_OR_IDENTITY_CHANGED"]
    labels = value["Labels"]
    if (
        not isinstance(labels, dict)
        or set(labels) != STATE_LABELS
        or labels.get("com.kairos.scope") != SCOPE
        or labels.get("com.kairos.alert-policy-sha256") != policy_sha256
    ):
        return ["STATE_OWNERSHIP_OR_POLICY_CHANGED"]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-json", type=Path, required=True)
    parser.add_argument("--profile", choices=("base", "paper"), required=True)
    parser.add_argument("--state-volume", required=True)
    parser.add_argument("--compose-version")
    args = parser.parse_args(argv)
    try:
        if args.compose_json.stat().st_size > 65_536:
            raise ValueError("bounded config required")
        errors = validate_durable_topology(
            json.loads(args.compose_json.read_text(encoding="utf-8")),
            profile=args.profile,
            state_volume=args.state_volume,
            compose_version=args.compose_version,
        )
    except (OSError, ValueError, TypeError, KeyError):
        errors = ["INVALID_DURABLE_INPUT"]
    print(
        json.dumps(
            {
                "status": "BLOCKED" if errors else "DURABLE_TOPOLOGY_ONLY_PASS",
                "errors": errors,
                "operationally_qualified": False,
                "exactly_once_delivery": False,
                "host_loss_qualified": False,
                "storage_hard_quota_qualified": False,
            }
        )
    )
    return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
