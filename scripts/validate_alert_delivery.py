"""Exact standalone operational Alertmanager topology; no business authority."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

if __package__:
    from .alert_delivery import ALERTMANAGER_IMAGE, OPS_ROOT, DeliveryError, _no_reparse
else:
    from alert_delivery import ALERTMANAGER_IMAGE, OPS_ROOT, DeliveryError, _no_reparse


COMMAND = ["--config.file=/etc/alertmanager/alertmanager.yml", "--storage.path=/alertmanager", "--web.listen-address=:9093", "--cluster.listen-address=", "--data.retention=24h"]
TMPFS = ["/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777", "/alertmanager:rw,noexec,nosuid,nodev,size=8m,uid=65534,gid=65534,mode=0700"]
SERVICE_KEYS = {"image", "platform", "profiles", "user", "read_only", "init", "restart", "mem_limit", "cpus", "pids_limit", "cap_drop", "security_opt", "command", "tmpfs", "volumes", "networks"}
# Exact hosted renderers whose compose-go bool/omitempty JSON omits false.
# Newer OptOut encoders can omit true instead, so unknown versions fail closed.
LEGACY_OMITTED_FALSE_COMPOSE_VERSIONS = frozenset({"2.38.2", "2.40.3"})


def _safe_bind_options(bind: Any, compose_version: str | None) -> bool:
    if not isinstance(bind, dict):
        return False
    if set(bind) == {"create_host_path"}:
        return bind["create_host_path"] is False
    return not bind and isinstance(compose_version, str) and compose_version.removeprefix("v") in LEGACY_OMITTED_FALSE_COMPOSE_VERSIONS


def validate(config: Any, *, profile: str, ops_root: Path = OPS_ROOT, compose_version: str | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(config, dict) or set(config) != {"name", "services", "networks"}:
        return ["INVALID_OPERATIONAL_TOPOLOGY"]
    if profile not in {"base", "paper"} or config["name"] != "kairos-ops-alerts":
        errors.append("INVALID_OPERATIONAL_PROJECT")
    services = config["services"]
    if not isinstance(services, dict) or set(services) != {"alertmanager"} or not isinstance(services["alertmanager"], dict):
        return errors + ["ONLY_NATIVE_ALERTMANAGER_PERMITTED"]
    service = services["alertmanager"]
    if set(service) not in (SERVICE_KEYS, SERVICE_KEYS | {"entrypoint"}) or ("entrypoint" in service and service["entrypoint"] is not None):
        errors.append("UNAPPROVED_SERVICE_CAPABILITY")
    exact = {"image": ALERTMANAGER_IMAGE, "platform": "linux/amd64", "profiles": ["alert-delivery"], "user": "65534:65534", "read_only": True, "init": True, "restart": "no", "pids_limit": 64, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "command": COMMAND, "tmpfs": TMPFS}
    for key, expected in exact.items():
        if service.get(key) != expected or (key in {"read_only", "init"} and type(service.get(key)) is not bool) or (key == "pids_limit" and type(service.get(key)) is not int):
            errors.append("INVALID_" + key.upper())
    memory = service.get("mem_limit")
    cpus = service.get("cpus")
    if memory not in ("128m", "134217728", 134_217_728) or type(memory) not in {str, int} or type(cpus) not in {int, float} or not math.isfinite(cpus) or cpus != 0.25:
        errors.append("RESOURCE_BOUNDS_CHANGED")
    if service.get("networks") != {"alert-input": {"aliases": ["kairos-ops-alertmanager"]}, "alert-egress": {}}:
        errors.append("SERVICE_NETWORKS_CHANGED")
    networks = config["networks"]
    expected_input = "kairos_observability" if profile == "base" else "kairos-paper_paper-observability"
    if not isinstance(networks, dict) or set(networks) != {"alert-input", "alert-egress"}:
        errors.append("NETWORK_SET_CHANGED")
    else:
        input_network = networks["alert-input"]
        egress_network = networks["alert-egress"]
        # Compose normalizes an absent IPAM block to {}. Accept only that
        # empty default, never custom subnet/driver/options or attachments.
        allowed_inputs = ({"external": True, "name": expected_input}, {"external": True, "name": expected_input, "ipam": {}})
        if input_network not in allowed_inputs or not isinstance(input_network, dict) or type(input_network.get("external")) is not bool:
            errors.append("INPUT_NETWORK_IDENTITY_CHANGED")
        allowed_egress = ({"driver": "bridge"}, {"name": "kairos-ops-alerts_alert-egress", "driver": "bridge"}, {"name": "kairos-ops-alerts_alert-egress", "driver": "bridge", "ipam": {}})
        if egress_network not in allowed_egress:
            errors.append("EGRESS_NETWORK_CHANGED")
    mounts = service.get("volumes")
    if not isinstance(mounts, list) or len(mounts) != 2:
        errors.append("MOUNT_SET_CHANGED")
        return errors
    targets = {"/etc/alertmanager/alertmanager.yml", "/run/secrets/telegram_bot_token"}
    if {item.get("target") for item in mounts if isinstance(item, dict)} != targets:
        errors.append("MOUNT_TARGET_CHANGED")
    for mount in mounts:
        if not isinstance(mount, dict) or set(mount) != {"type", "source", "target", "read_only", "bind"} or mount.get("type") != "bind" or mount.get("read_only") is not True or not _safe_bind_options(mount.get("bind"), compose_version):
            errors.append("UNSAFE_MOUNT")
            continue
        if not isinstance(mount["source"], str):
            errors.append("INVALID_MOUNT_SOURCE")
            continue
        candidate = Path(mount["source"])
        try:
            _no_reparse(candidate)
        except DeliveryError:
            errors.append("MOUNT_REPARSE_REJECTED")
            continue
        source = candidate.resolve()
        if mount["target"] == "/run/secrets/telegram_bot_token":
            if source != (ops_root / "secrets/telegram_bot_token").resolve():
                errors.append("DEDICATED_TOKEN_MOUNT_REQUIRED")
        elif not source.is_relative_to((ops_root / "config").resolve()) or source.name != "alertmanager.yml":
            errors.append("GENERATED_CONFIG_MOUNT_REQUIRED")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-json", type=Path, required=True)
    parser.add_argument("--profile", choices=("base", "paper"), required=True)
    parser.add_argument("--compose-version", help="Version metadata from the same native offline renderer; unknown versions cannot omit false")
    args = parser.parse_args()
    try:
        if args.compose_json.stat().st_size > 65_536:
            raise ValueError()
        errors = validate(json.loads(args.compose_json.read_text(encoding="utf-8")), profile=args.profile, compose_version=args.compose_version)
    except Exception:
        errors = ["INVALID_COMPOSE_INPUT"]
    print(json.dumps({"status": "BLOCKED" if errors else "TOPOLOGY_ONLY_PASS", "errors": errors, "operationally_qualified": False}))
    return 2 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
