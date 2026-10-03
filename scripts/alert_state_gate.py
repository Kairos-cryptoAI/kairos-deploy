"""Plan-only by default; bounded native synthetic Alertmanager restart proof.

No production configuration/token, Telegram, DB, business network or host port.
The one-shot fixture proves continuity AFTER a notification-log checkpoint, not
exactly-once delivery in the unknown-send/before-checkpoint crash window.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__:
    from . import alert_state
    from .alert_delivery import ALERTMANAGER_IMAGE
else:
    import alert_state
    from alert_delivery import ALERTMANAGER_IMAGE

ROOT = Path(__file__).resolve().parents[1]
PROOF_ROOT = Path("D:/Kairos/runtime/alert-state-proof-20261003")
HELPER = Path("D:/Kairos/runtime/runtime-transport-20261003/run_transport_golden.py")
HELPER_SHA = "6457008049611da3843bfa9fedd02de844da1cc19c493f009965558bd19d0d29"
RUNNER = "ghcr.io/kairos-cryptoai/kairos-runtime-schema-profile-runner@sha256:2e10e9e936eae3a4a411f65d8b0bd14670ba808368eeff94b4e24021aa291077"
DOCKER = Path("C:/Program Files/Docker/Docker/resources/bin/docker.exe")
ENDPOINT = "npipe:////./pipe/dockerDesktopLinuxEngine"
CONFIRMATION = "ONE_BOUNDED_SYNTHETIC_ALERT_STATE_RESTART_PROOF"
SCOPE = "synthetic-alert-state-20261003"
LABEL = "com.kairos.synthetic.scope"
OWNER = "com.kairos.synthetic.owner"
VIEW = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
    '"Labels":{{json (index .Config "Labels")}},"State":{{json .State}},'
    '"User":{{json (index .Config "User")}},"Command":{{json .Config.Cmd}},'
    '"Entrypoint":{{json .Config.Entrypoint}},'
    '"Networks":{{json .NetworkSettings.Networks}},'
    '"Host":{{json .HostConfig}},"Mounts":{{json .Mounts}}}'
)
CONFIG = """global:
  resolve_timeout: 1m
route:
  receiver: synthetic-only
  group_by: [alertname, scope]
  group_wait: 1s
  group_interval: 1s
  repeat_interval: 1h
receivers:
  - name: synthetic-only
    webhook_configs:
      - url: http://127.0.0.1:19093/receive
        send_resolved: true
        max_alerts: 1
        http_config:
          follow_redirects: false
          proxy_from_environment: false
"""


class StateGateError(RuntimeError):
    pass


def sha(path: Path) -> str:
    safe_path(path)
    if path.stat().st_size > 512 * 1024:
        raise StateGateError("SOURCE_TOO_LARGE")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_path(path: Path) -> Path:
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            if item.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise StateGateError("REPARSE_PATH_REJECTED")
    return path.resolve(strict=True)


def sources() -> dict[str, str]:
    return {
        name: sha(ROOT / "scripts" / name)
        for name in (
            "alert_delivery.py",
            "alert_state.py",
            "alert_state_fixture.py",
            "alert_state_gate.py",
            "validate_alert_delivery.py",
        )
    }


def save_new(path: Path, value: object) -> None:
    safe_path(path.parent)
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(data) > 128 * 1024:
        raise StateGateError("RECEIPT_TOO_LARGE")
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def spec() -> dict[str, Any]:
    return {
        "kind": "SYNTHETIC_ALERT_STATE_RESTART_ONLY",
        "result": "PLAN_ONLY_NO_LAUNCH",
        "source_sha256": sources(),
        "images": [ALERTMANAGER_IMAGE, RUNNER],
        "maximum_seconds": 120,
        "cleanup_seconds": 10,
        "server_memory_bytes": 134_217_728,
        "server_cpus": 0.25,
        "server_pids": 64,
        "receiver_memory_bytes": 134_217_728,
        "receiver_cpus": 0.25,
        "receiver_pids": 64,
        "network": "loopback_only_namespace",
        "synthetic_state_volume": True,
        "exactly_once_delivery": False,
        "before_checkpoint_crash_qualified": False,
        "host_loss_qualified": False,
        "telegram_qualified": False,
        "trading_authority": False,
    }


def helper():
    if sha(HELPER) != HELPER_SHA:
        raise StateGateError("REVIEWED_PROCESS_JOB_HELPER_CHANGED")
    module_spec = importlib.util.spec_from_file_location(
        "kairos_alert_state_process_job", HELPER
    )
    if module_spec is None or module_spec.loader is None:
        raise StateGateError("PROCESS_JOB_HELPER_UNAVAILABLE")
    module = importlib.util.module_from_spec(module_spec)
    sys.path.insert(0, str(HELPER.parent))
    try:
        module_spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class Native:
    def __init__(self, directory: Path, owner: str, *, started: float) -> None:
        self.directory, self.owner = directory, owner
        self.deadline = started + 120
        self.cleanup_deadline = started + 130
        self.call_count = 0
        self.jobs: list[dict] = []
        self.owned: dict[str, str] = {}
        self.expected: dict[str, dict] = {}
        self.volume = "kairos-ops-alerts-state-" + owner[:16]
        self.volume_intent = False
        self.native = helper().native

    def command(
        self, args: list[str], *, allow_failure: bool = False, seconds: int = 20
    ) -> str:
        self.call_count += 1
        result = self.native(
            DOCKER,
            [
                "--config",
                str(self.directory / "docker-config"),
                "--host",
                ENDPOINT,
                *args,
            ],
            self.directory,
            "docker-" + str(self.call_count),
            seconds,
            phase_deadline=self.deadline,
        )
        self.jobs.append(result)
        proof = result.get("windows_process_tree")
        if (
            not isinstance(proof, dict)
            or proof.get("assigned_before_resume") is not True
            or proof.get("active_owned_processes_after") != 0
            or proof.get("tree_cleanup_verified") is not True
            or result.get("failure_category")
            or result.get("timed_out")
            or result.get("output_overflow")
        ):
            raise StateGateError("CLI_TREE_BOUNDARY_UNPROVEN")
        if result.get("exit_code") != 0 and not allow_failure:
            raise StateGateError("BOUNDED_DOCKER_FAILED")
        output = self.directory / ("docker-" + str(self.call_count) + ".stdout")
        return output.read_text(encoding="utf-8").strip()

    def inspect(self, name: str) -> dict:
        value = json.loads(self.command(["inspect", "--format", VIEW, name]))
        if not isinstance(value, dict):
            raise StateGateError("STRUCTURED_CONTAINER_REQUIRED")
        return value

    def verify(self, name: str) -> dict:
        value = self.inspect(name)
        if (
            value["Name"] != "/" + name
            or value["Labels"].get(LABEL) != SCOPE
            or value["Labels"].get(OWNER) != self.owner
            or value["Image"] != self.owned[name]
            or not re.fullmatch(r"[a-f0-9]{64}", value["Id"])
        ):
            raise StateGateError("OWNED_CONTAINER_IDENTITY_CHANGED")
        host = value["Host"]
        expected = self.expected[name]
        if (
            host.get("Memory") != 134_217_728
            or host.get("NanoCpus") != 250_000_000
            or host.get("PidsLimit") != 64
            or host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or host.get("PortBindings")
            or host.get("PublishAllPorts")
            or host.get("PidMode")
            or host.get("IpcMode") not in ("private", "")
            or host.get("Devices")
            or host.get("DeviceRequests")
            or host.get("VolumesFrom")
            or host.get("UsernsMode")
            or host.get("CapDrop") != ["ALL"]
            or (host.get("CapAdd") or []) != expected["caps"]
            or host.get("NetworkMode") != expected["network"]
            or host.get("SecurityOpt") != ["no-new-privileges:true"]
            or (host.get("Tmpfs") or {}) != expected["tmpfs"]
            or host.get("RestartPolicy", {}).get("Name") != "no"
            or value.get("User") != expected["user"]
            or value.get("Command") != expected["command"]
            or value.get("Entrypoint") != expected["entrypoint"]
        ):
            raise StateGateError("CONTAINER_BOUNDARY_CHANGED")
        networks = value.get("Networks")
        allowed_networks = (
            ({}, {"none": {}}) if expected["network"] == "none" else ({},)
        )
        if not isinstance(networks, dict) or set(networks) not in tuple(
            set(item) for item in allowed_networks
        ):
            raise StateGateError("EXACT_LOOPBACK_NETWORK_ATTACHMENTS_REQUIRED")
        mounts = value.get("Mounts")
        if not isinstance(mounts, list) or len(mounts) != len(expected["mounts"]):
            raise StateGateError("EXACT_FIXTURE_MOUNTS_REQUIRED")
        for wanted in expected["mounts"]:
            matching = [
                mount
                for mount in mounts
                if mount.get("Destination") == wanted["destination"]
            ]
            if len(matching) != 1:
                raise StateGateError("EXACT_FIXTURE_MOUNTS_REQUIRED")
            mount = matching[0]
            if (
                mount.get("Type") != wanted["type"]
                or mount.get("RW") is not wanted["rw"]
            ):
                raise StateGateError("EXACT_FIXTURE_MOUNTS_REQUIRED")
            if wanted["type"] == "volume":
                if mount.get("Name") != self.volume:
                    raise StateGateError("EXACT_STATE_VOLUME_REQUIRED")
            elif (
                str(mount.get("Source", "")).replace("\\", "/").lower()
                not in wanted["sources"]
            ):
                raise StateGateError("EXACT_FIXTURE_BIND_REQUIRED")
        return value

    def register(
        self,
        role: str,
        image: str,
        *,
        user: str,
        network: str,
        entrypoint: str,
        command: list[str],
        mounts: list[dict],
        init: bool = False,
    ) -> str:
        name = "kairos-alert-state-" + self.owner[:12] + "-" + role
        image_id = self.command(["image", "inspect", "--format", "{{.Id}}", image])
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
            raise StateGateError("LOCAL_IMMUTABLE_IMAGE_REQUIRED")
        self.owned[name] = image_id
        self.expected[name] = {
            "user": user,
            "network": network,
            "entrypoint": [entrypoint],
            "command": command,
            "mounts": mounts,
            "caps": ["CHOWN"] if init else [],
            "tmpfs": {} if init else {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},
        }
        save_new(
            self.directory / (role + ".creation-intent.json"),
            {
                "name": name,
                "image": image_id,
                "owner": self.owner,
                "expected": self.expected[name],
            },
        )
        return name

    def create_am(self, role: str, receiver_id: str) -> str:
        # Exact immutable binary, synthetic config, explicit external state only.
        args = [
            "--user",
            "65534:65534",
            "--mount",
            "type=bind,source="
            + str(self.directory / "alertmanager.yml")
            + ",target=/fixture/alertmanager.yml,readonly",
            "--mount",
            "type=volume,source=" + self.volume + ",target=/alertmanager,volume-nocopy",
            "--entrypoint",
            "/bin/alertmanager",
        ]
        command = list(alert_state.DURABLE_COMMAND)
        command[0] = "--config.file=/fixture/alertmanager.yml"
        name = self.register(
            role,
            ALERTMANAGER_IMAGE,
            user="65534:65534",
            network="container:" + receiver_id,
            entrypoint="/bin/alertmanager",
            command=command,
            mounts=[
                bind(self.directory / "alertmanager.yml", "/fixture/alertmanager.yml"),
                volume(),
            ],
        )
        self.command(
            [
                "create",
                "--pull=never",
                "--name",
                name,
                "--label",
                LABEL + "=" + SCOPE,
                "--label",
                OWNER + "=" + self.owner,
                "--network",
                "container:" + receiver_id,
                "--read-only",
                "--memory",
                "128m",
                "--cpus",
                "0.25",
                "--pids-limit",
                "64",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                *args,
                ALERTMANAGER_IMAGE,
                *command,
            ]
        )
        view = self.verify(name)
        if view["Host"].get("NetworkMode") != "container:" + receiver_id:
            raise StateGateError("LOOPBACK_RECEIVER_NAMESPACE_REQUIRED")
        mounts = view["Mounts"]
        if (
            len(mounts) != 2
            or sum(
                m.get("Name") == self.volume
                and m.get("Destination") == "/alertmanager"
                and m.get("RW") is True
                for m in mounts
            )
            != 1
        ):
            raise StateGateError("EXACT_STATE_VOLUME_REQUIRED")
        self.command(["start", view["Id"]])
        return name

    def remove(self, name: str) -> None:
        value = self.verify(name)
        self.command(["rm", "--force", value["Id"]])
        observed = self.command(
            ["ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + value["Id"]]
        )
        if observed:
            raise StateGateError("OWNED_CONTAINER_REMOVAL_UNPROVEN")
        del self.owned[name]
        del self.expected[name]

    def run(self) -> dict:
        policy_hash = hashlib.sha256(CONFIG.encode()).hexdigest()
        if self.command(
            ["volume", "ls", "--quiet", "--filter", "name=^" + self.volume + "$"]
        ):
            raise StateGateError("NEW_STATE_VOLUME_REQUIRED")
        save_new(
            self.directory / "volume.creation-intent.json",
            {"name": self.volume, "owner": self.owner},
        )
        self.volume_intent = True
        self.command(
            [
                "volume",
                "create",
                "--label",
                "com.kairos.scope=" + alert_state.SCOPE,
                "--label",
                "com.kairos.alert-policy-sha256=" + policy_hash,
                self.volume,
            ]
        )
        self.verify_volume()
        # One fixed pre-provisioning operation touches only this new empty volume.
        init_command = [
            "-c",
            'test -z "$(ls -A /alertmanager)" && chmod 0700 /alertmanager && chown 65534:65534 /alertmanager',
        ]
        init_name = self.register(
            "init",
            ALERTMANAGER_IMAGE,
            user="0:0",
            network="none",
            entrypoint="/bin/sh",
            command=init_command,
            mounts=[volume()],
            init=True,
        )
        self.command(
            [
                "create",
                "--pull=never",
                "--name",
                init_name,
                "--label",
                LABEL + "=" + SCOPE,
                "--label",
                OWNER + "=" + self.owner,
                "--network",
                "none",
                "--user",
                "0:0",
                "--read-only",
                "--memory",
                "128m",
                "--cpus",
                "0.25",
                "--pids-limit",
                "64",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--security-opt",
                "no-new-privileges:true",
                "--mount",
                "type=volume,source="
                + self.volume
                + ",target=/alertmanager,volume-nocopy",
                "--entrypoint",
                "/bin/sh",
                ALERTMANAGER_IMAGE,
                *init_command,
            ]
        )
        self.verify(init_name)
        self.command(["start", "--attach", init_name])
        if self.verify(init_name)["State"].get("ExitCode") != 0:
            raise StateGateError("NEW_VOLUME_INIT_FAILED")
        self.remove(init_name)
        receiver_name = self.register(
            "receiver",
            RUNNER,
            user="10001:10001",
            network="none",
            entrypoint="python",
            command=["/fixture.py", "receiver"],
            mounts=[bind(ROOT / "scripts/alert_state_fixture.py", "/fixture.py")],
        )
        self.command(
            [
                "create",
                "--pull=never",
                "--name",
                receiver_name,
                "--label",
                LABEL + "=" + SCOPE,
                "--label",
                OWNER + "=" + self.owner,
                "--network",
                "none",
                "--user",
                "10001:10001",
                "--read-only",
                "--memory",
                "128m",
                "--cpus",
                "0.25",
                "--pids-limit",
                "64",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                "--mount",
                "type=bind,source="
                + str(ROOT / "scripts/alert_state_fixture.py")
                + ",target=/fixture.py,readonly",
                "--entrypoint",
                "python",
                RUNNER,
                "/fixture.py",
                "receiver",
            ]
        )
        receiver_view = self.verify(receiver_name)
        if receiver_view["Host"].get("NetworkMode") != "none":
            raise StateGateError("NETWORK_NONE_RECEIVER_REQUIRED")
        receiver = receiver_view["Id"]
        self.command(["start", receiver])
        results, checkpoints = [], []
        for index, stages in enumerate(
            (
                ("firing",),
                ("restart-no-duplicate", "resolved"),
                ("resolved-no-duplicate",),
            )
        ):
            name = self.create_am("am" + str(index), receiver)
            for stage in stages:
                value = json.loads(
                    self.command(
                        ["exec", receiver, "python", "/fixture.py", "driver", stage]
                    )
                )
                if (
                    value.get("stage") != stage
                    or value.get("synthetic_only") is not True
                ):
                    raise StateGateError("NATIVE_STAGE_NOT_ACCEPTED")
                results.append(value)
            if index < 2:
                time.sleep(
                    6
                )  # bounded checkpoint interval, not an elapsed qualification campaign
                digest = self.command(
                    ["exec", name, "/bin/sh", "-c", "sha256sum /alertmanager/nflog"]
                )
                if not re.fullmatch(r"[a-f0-9]{64}  /alertmanager/nflog", digest):
                    raise StateGateError("NOTIFICATION_LOG_CHECKPOINT_REQUIRED")
                checkpoints.append(digest.split()[0])
                self.command(["kill", "--signal", "KILL", self.verify(name)["Id"]])
                stopped = self.verify(name)
                if (
                    stopped["State"].get("Running") is not False
                    or stopped["State"].get("ExitCode") != 137
                ):
                    raise StateGateError("ACTUAL_ABRUPT_CRASH_NOT_OBSERVED")
            self.remove(name)
        if checkpoints[0] == checkpoints[1]:
            raise StateGateError("RESOLVED_CHECKPOINT_DID_NOT_CHANGE")
        return {
            "result": "PASS_NATIVE_SYNTHETIC_CHECKPOINTED_RESTART_ONLY",
            "stages": results,
            "nflog_checkpoint_sha256": checkpoints,
            "abrupt_checkpointed_crashes": 2,
            "provider_or_telegram_calls": 0,
            "business_services_started": 0,
            "exactly_once_delivery": False,
            "before_checkpoint_crash_qualified": False,
            "host_loss_qualified": False,
            "storage_hard_quota_qualified": False,
        }

    def cleanup(self) -> None:
        self.deadline = min(time.monotonic() + 10, self.cleanup_deadline)
        for name in list(self.owned):
            self.remove(name)
        if self.volume_intent:
            self.verify_volume()
            self.command(["volume", "rm", self.volume])
            if self.command(
                ["volume", "ls", "--quiet", "--filter", "name=^" + self.volume + "$"]
            ):
                raise StateGateError("VOLUME_REMOVAL_UNPROVEN")

    def verify_volume(self) -> None:
        value = json.loads(
            self.command(
                [
                    "volume",
                    "inspect",
                    "--format",
                    '{"Name":{{json .Name}},"Driver":{{json .Driver}},"Scope":{{json .Scope}},"Options":{{json .Options}},"Labels":{{json .Labels}}}',
                    self.volume,
                ]
            )
        )
        if alert_state.validate_state_metadata(
            value,
            volume_name=self.volume,
            policy_sha256=hashlib.sha256(CONFIG.encode()).hexdigest(),
        ):
            raise StateGateError("VOLUME_OWNERSHIP_CHANGED")


def bind(path: Path, destination: str) -> dict:
    if ".." in path.parts:
        raise StateGateError("FIXED_REVIEWED_BIND_REQUIRED")
    source = str(path).replace("\\", "/").lower()
    if not source.startswith("d:/kairos/"):
        raise StateGateError("FIXED_REVIEWED_BIND_REQUIRED")
    canonical = safe_path(path)
    if canonical != path.absolute() or not canonical.is_file():
        raise StateGateError("FIXED_REVIEWED_BIND_REQUIRED")
    if destination == "/fixture.py":
        accepted = canonical == (ROOT / "scripts/alert_state_fixture.py").absolute()
    elif destination == "/fixture/alertmanager.yml":
        accepted = (
            canonical.name == "alertmanager.yml"
            and canonical.parent.parent == PROOF_ROOT
            and re.fullmatch(r"run-[a-f0-9]{32}", canonical.parent.name) is not None
        )
    else:
        accepted = False
    if not accepted:
        raise StateGateError("FIXED_REVIEWED_BIND_REQUIRED")
    return {
        "type": "bind",
        "destination": destination,
        "rw": False,
        "sources": [source, "/run/desktop/mnt/host/d/" + source[3:]],
    }


def volume() -> dict:
    return {"type": "volume", "destination": "/alertmanager", "rw": True}


def execute() -> dict:
    if os.name != "nt":
        raise StateGateError("REVIEWED_WINDOWS_PROCESS_JOB_REQUIRED")
    safe_path(PROOF_ROOT.parent)
    PROOF_ROOT.mkdir(parents=False, exist_ok=True)
    safe_path(PROOF_ROOT)
    owner = uuid.uuid4().hex
    started = time.monotonic()
    result = spec()
    result["created_at_utc"] = datetime.now(UTC).isoformat()
    result["owner"] = owner
    lease = PROOF_ROOT / "execution.lock"
    save_new(lease, {"owner": owner})
    work = PROOF_ROOT / ("run-" + owner)
    native = None
    created_work = False
    failure = None
    cleanup = False
    try:
        work.mkdir(exist_ok=False)
        created_work = True
        (work / "docker-config").mkdir(exist_ok=False)
        save_new(work / "docker-config/config.json", {"auths": {}})
        with (work / "alertmanager.yml").open("xb") as stream:
            stream.write(CONFIG.encode())
            stream.flush()
            os.fsync(stream.fileno())
        native = Native(work, owner, started=started)
        result.update(native.run())
        if sources() != result["source_sha256"]:
            raise StateGateError("SOURCE_CHANGED_DURING_NATIVE_PROOF")
    except BaseException as error:  # noqa: BLE001 - interruptions must enter owned cleanup.
        failure = type(error).__name__
        result["result"] = "FAILED_NATIVE_SYNTHETIC_NO_DELIVERY_AUTHORITY"
    finally:
        if native is not None:
            try:
                native.cleanup()
                cleanup = True
            except BaseException as error:  # noqa: BLE001 - preserve ambiguous cleanup.
                result["cleanup_category"] = type(error).__name__
                result["result"] = "FAILED_NATIVE_SYNTHETIC_NO_DELIVERY_AUTHORITY"
    result.update(
        failure_category=failure,
        owned_cleanup_verified=cleanup,
        cli_tree_proofs=native.jobs if native is not None else [],
        elapsed_seconds=round(time.monotonic() - started, 6),
        lease_retained=not cleanup,
    )
    if created_work:
        save_new(work / "receipt.json", result)
    if cleanup and json.loads(lease.read_text()) == {"owner": owner}:
        lease.unlink()
    return {
        "result": result["result"],
        "owned_cleanup_verified": cleanup,
        "receipt": str(work / "receipt.json") if created_work else None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-synthetic-only", action="store_true")
    parser.add_argument("--confirmation")
    args = parser.parse_args(argv)
    if not args.native_synthetic_only:
        print(json.dumps(spec(), sort_keys=True))
        return 0
    if args.confirmation != CONFIRMATION:
        print(
            json.dumps(
                {"result": "BLOCKED", "category": "EXPLICIT_REVIEWED_PROOF_REQUIRED"}
            )
        )
        return 2
    try:
        result = execute()
    except Exception as error:  # noqa: BLE001 - sanitized fail-closed CLI boundary.
        result = {"result": "BLOCKED", "category": type(error).__name__}
    print(json.dumps(result, sort_keys=True))
    return (
        0
        if result["result"] == "PASS_NATIVE_SYNTHETIC_CHECKPOINTED_RESTART_ONLY"
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
