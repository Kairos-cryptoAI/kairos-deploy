"""Default-deny Compose transport proof using one invocation-owned rootless builder.

Only the generated public synthetic fixture is executable. This is not an
alternative entry point for the release/PAPER image builds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from scripts import buildkit_resource_gate as gate
else:
    import buildkit_resource_gate as gate

OPS = Path("D:/Kairos/runtime/bounded-build-20261003")
GATE_SHA = "e6022d1755a96a79611fe99067c0d3dcf193c3989eededbcd4f8a3c83c040952"
KIND = "kairos-bounded-compose-synthetic-v1"
CONFIRM = "OWNED_SYNTHETIC_COMPOSE_BUILD_ONLY"
TARGET = "fixture"
CASES = ("success", "fault", "cancel")
OWNER_LABEL = "com.kairos.bounded-build.owner"
SCOPE_LABEL = "com.kairos.bounded-build.scope"
PLUGIN_DIR = Path("C:/Program Files/Docker/Docker/resources/cli-plugins")
TOOLS = {
    "docker": gate.DOCKER,
    "buildx": PLUGIN_DIR / "docker-buildx.exe",
    "compose": PLUGIN_DIR / "docker-compose.exe",
}
CAPACITIES = {
    gate.MOUNT_DATA: 512 * 1024**2,
    "/home/user/.local/tmp": 16 * 1024**2,
    "/run/user/1000": 16 * 1024**2,
    "/tmp": 128 * 1024**2,
}
MAX_BINARY = 2 * 1024**2
MAX_IMAGE = 4 * 1024**2
PUBLIC_FILES = {
    "bin/busybox": "f3547b3d78d08a028a4833ddb83b77cf012838c078bfd2b76355f53d1d8bba62",
    "lib/ld-musl-x86_64.so.1": "99eab0629ed5e6bc258bea735a128d1de30c5a8b52f39eed4919452d03c6c4ee",
}
TRANSPORT_PROBE = r"""set -eu
for file in /proc/[0-9]*/comm; do
  [ -r "$file" ] || continue
  IFS= read -r comm < "$file" || continue
  [ "$comm" = buildctl ] || continue
  pid=${file#/proc/}; pid=${pid%/comm}
  args=$(tr '\000' ' ' < /proc/$pid/cmdline) || continue
  case "$args" in 'buildctl dial-stdio ')
    uid=$(awk '$1=="Uid:" {print $2}' /proc/$pid/status)
    [ "$uid" = 1000 ] || exit 91
    ticks=$(sed 's/.*) //' /proc/$pid/stat | awk '{print $20}')
    printf '%s|%s\n' "$pid" "$ticks"
  esac
done
"""
CAPACITY_PROBE = r"""set -eu
export LC_ALL=C
count=0; daemon=0
for file in /proc/[0-9]*/comm; do
  [ -r "$file" ] || continue
  IFS= read -r comm < "$file" || continue
  [ "$comm" = buildkitd ] || continue
  daemon=${file#/proc/}; daemon=${daemon%/comm}; count=$((count+1))
done
[ "$count" = 1 ] || exit 91
ticks=$(sed 's/.*) //' /proc/$daemon/stat | awk '{print $20}')
ns=$(readlink /proc/$daemon/ns/mnt)
printf 'I|before|%s|%s|%s\n' "$daemon" "$ticks" "$ns"
for domain in container daemon; do
  if [ "$domain" = container ]; then prefix=; else prefix=/proc/$daemon/root; fi
  for path in /home/user/.local/share/buildkit /home/user/.local/tmp /run/user/1000 /tmp; do
    meta=$(stat -f -c '%S|%b|%f|%c|%d' "$prefix$path")
    printf 'F|%s|%s|%s\n' "$domain" "$path" "$meta"
  done
done
ticks=$(sed 's/.*) //' /proc/$daemon/stat | awk '{print $20}')
ns=$(readlink /proc/$daemon/ns/mnt)
printf 'I|after|%s|%s|%s\n' "$daemon" "$ticks" "$ns"
"""


def owner(value: str | None) -> str:
    result = uuid.uuid4().hex if value is None else value
    if not isinstance(result, str) or not re.fullmatch(
        r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}", result
    ):
        raise gate.GateError("EXACT_UUID4_INVOCATION_OWNER_REQUIRED")
    return result


def builder_name(value: str) -> str:
    return "kairos-bounded-" + owner(value)


def image_tag(value: str) -> str:
    return "kairos-bounded-synthetic:" + owner(value)


def remote_endpoint(value: str) -> str:
    return "docker-container://" + gate.owner_name(owner(value))


def file_sha(path: Path, limit: int) -> str:
    gate.strict_path(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise gate.GateError("BOUNDED_PUBLIC_FILE_REQUIRED")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        remaining = limit + 1
        while data := stream.read(min(remaining, 1024**2)):
            remaining -= len(data)
            if remaining == 0:
                raise gate.GateError("BOUNDED_PUBLIC_FILE_REQUIRED")
            result.update(data)
    return result.hexdigest()


def source_bindings() -> dict:
    return {
        "adapter": gate.sha(Path(__file__)),
        "resource_gate": gate.sha(Path(gate.__file__)),
        "windows_job": gate.sha(gate.JOB_SOURCE),
    }


def tool_bindings() -> dict:
    return {name: file_sha(path, 128 * 1024**2) for name, path in TOOLS.items()}


def config() -> dict:
    return {"auths": {}, "cliPluginsExtraDirs": [str(PLUGIN_DIR)]}


def public_environment() -> dict[str, str]:
    # Never enumerate values before filtering: only these public OS paths are read.
    return {
        key: value
        for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
        if (value := os.environ.get(key)) is not None
    }


def environment(work: Path) -> dict:
    gate.strict_path(work)
    result = public_environment()
    system = Path(result.get("SystemRoot", result.get("SYSTEMROOT", "C:/Windows")))
    if str(system).replace("\\", "/").lower() != "c:/windows":
        raise gate.GateError("TRUSTED_WINDOWS_SYSTEM_ROOT_REQUIRED")
    result.update(
        {
            "PATH": str(gate.DOCKER.parent) + os.pathsep + str(system / "System32"),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            "DOCKER_HOST": gate.ENDPOINT,
            "DOCKER_CONFIG": str(work / "docker-config"),
            "BUILDX_CONFIG": str(work / "buildx-config"),
            "COMPOSE_BAKE": "false",
            "COMPOSE_PARALLEL_LIMIT": "1",
            "COMPOSE_DISABLE_ENV_FILE": "true",
            "BUILDX_METADATA_WARNINGS": "0",
        }
    )
    return result


def registration_arguments(value: str) -> list[str]:
    name = builder_name(value)
    return [
        "buildx",
        "create",
        "--name",
        name,
        "--node",
        name + "0",
        "--driver",
        "remote",
        "--driver-opt",
        "default-load=false",
        "--platform",
        "linux/amd64",
        remote_endpoint(value),
    ]


def verify_registration(value: dict, invocation: str) -> None:
    name = builder_name(invocation)
    if (
        not isinstance(value, dict)
        or set(value) != {"Name", "Driver", "Nodes", "Dynamic"}
        or value.get("Name") != name
        or value.get("Driver") != "remote"
        or value.get("Dynamic") is not False
        or not isinstance(value.get("Nodes"), list)
        or len(value["Nodes"]) != 1
    ):
        raise gate.GateError("PRIVATE_REMOTE_REGISTRATION_CHANGED")
    node = value["Nodes"][0]
    if (
        not isinstance(node, dict)
        or set(node)
        != {"Name", "Endpoint", "Platforms", "DriverOpts", "Flags", "Files"}
        or node.get("Name") != name + "0"
        or node.get("Endpoint") != remote_endpoint(invocation)
        or node.get("Platforms") != [{"architecture": "amd64", "os": "linux"}]
        or node.get("DriverOpts") != {"default-load": "false"}
        or node.get("Flags") not in (None, [])
        or node.get("Files") not in (None, {})
    ):
        raise gate.GateError("PRIVATE_REMOTE_NODE_CHANGED")


def fixture_documents(work: Path, invocation: str, case: str) -> tuple[str, dict]:
    if case not in CASES:
        raise gate.GateError("FIXED_SYNTHETIC_CASE_REQUIRED")
    name = builder_name(invocation)
    labels = {OWNER_LABEL: invocation, SCOPE_LABEL: KIND}
    dockerfile = (
        "FROM scratch\n"
        "COPY --chmod=0755 skeleton/ /\n"
        "COPY --chmod=0555 bin/busybox /bin/busybox\n"
        "COPY --chmod=0555 lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1\n"
        "COPY --chmod=0444 payload /result\n"
    )
    commands = {
        "success": 'test "$(/bin/busybox sha256sum /result | /bin/busybox cut -d " " -f 1)" = '
        + hashlib.sha256(gate.PAYLOAD).hexdigest(),
        "fault": "echo KAIROS_SYNTHETIC_FAULT37; exit 37",
        "cancel": gate.TOKEN_PREFIX + invocation + "=1; (while :; do :; done) & wait",
    }
    dockerfile += (
        "RUN " + json.dumps(["/bin/busybox", "sh", "-c", commands[case]]) + "\n"
    )
    document = {
        "name": name,
        "services": {
            TARGET: {
                "image": image_tag(invocation),
                "platform": "linux/amd64",
                "pull_policy": "never",
                "build": {
                    "context": str(work / "context"),
                    "dockerfile": "Dockerfile." + case,
                    "network": "none",
                    "pull": False,
                    "no_cache": True,
                    "provenance": False,
                    "sbom": False,
                    "labels": labels,
                },
            }
        },
    }
    return dockerfile, document


def compose_arguments(work: Path, invocation: str, case: str) -> list[str]:
    if case not in CASES:
        raise gate.GateError("FIXED_SYNTHETIC_CASE_REQUIRED")
    return [
        "compose",
        "--ansi",
        "never",
        "--progress",
        "plain",
        "--env-file",
        str(work / "empty.env"),
        "--project-directory",
        str(work),
        "--project-name",
        builder_name(invocation),
        "--file",
        str(work / (case + ".compose.json")),
        "build",
        "--builder",
        builder_name(invocation),
        "--no-cache",
        TARGET,
    ]


def parse_capacity(text: str, expected_daemon: dict) -> dict:
    if len(text.encode()) > 8192:
        raise gate.GateError("CAPACITY_PROJECTION_BOUNDARY")
    identities, rows = {}, {}
    for line in text.splitlines():
        fields = line.split("|")
        if len(fields) == 5 and fields[0] == "I" and fields[1] in {"before", "after"}:
            if fields[1] in identities:
                raise gate.GateError("CAPACITY_IDENTITY_DUPLICATED")
            identities[fields[1]] = {
                "pid": gate.mount_unsigned(fields[2], positive=True),
                "start_ticks": gate.mount_unsigned(fields[3], 2**64 - 1, positive=True),
                "mount_namespace_inode": gate.mount_namespace(fields[4]),
            }
        elif len(fields) == 8 and fields[0] == "F":
            key = (fields[1], fields[2])
            if (
                fields[1] not in {"container", "daemon"}
                or fields[2] not in CAPACITIES
                or key in rows
            ):
                raise gate.GateError("FIXED_CAPACITY_ROWS_REQUIRED")
            block_size, blocks, free, inodes, free_inodes = (
                gate.mount_unsigned(v, 2**64 - 1, positive=i in {0, 1, 3})
                for i, v in enumerate(fields[3:])
            )
            if (
                block_size not in {4096, 65536}
                or block_size * blocks != CAPACITIES[fields[2]]
                or free > blocks
                or free_inodes > inodes
            ):
                raise gate.GateError("HARD_TMPFS_CAPACITY_CHANGED")
            rows[key] = {
                "capacity_bytes": block_size * blocks,
                "free_bytes": block_size * free,
                "inodes": inodes,
                "free_inodes": free_inodes,
            }
        else:
            raise gate.GateError("FIXED_CAPACITY_PROJECTION_REQUIRED")
    if identities != {"before": expected_daemon, "after": expected_daemon} or set(
        rows
    ) != {(domain, path) for domain in ("container", "daemon") for path in CAPACITIES}:
        raise gate.GateError("STABLE_EXACT_CAPACITY_PROOF_REQUIRED")
    return {
        domain: {path: rows[domain, path] for path in CAPACITIES}
        for domain in ("container", "daemon")
    }


def parse_transports(text: str) -> list[dict]:
    lines = text.splitlines() if text else []
    if not 1 <= len(lines) <= 4:
        raise gate.GateError("OWNED_TRANSPORT_COUNT_UNPROVEN")
    result = []
    for line in lines:
        fields = line.split("|")
        if len(fields) != 2:
            raise gate.GateError("FIXED_TRANSPORT_PROJECTION_REQUIRED")
        row = {
            "pid": gate.mount_unsigned(fields[0], positive=True),
            "start_ticks": gate.mount_unsigned(fields[1], 2**64 - 1, positive=True),
        }
        if row["pid"] <= 1 or any(v["pid"] == row["pid"] for v in result):
            raise gate.GateError("UNIQUE_TRANSPORT_IDENTITY_REQUIRED")
        result.append(row)
    return result


def cancel_transport_script(rows: list[dict]) -> str:
    # Revalidate the complete set before sending the first signal. Never signal
    # buildkitd/ExecOp/host processes, or accept PID alone as identity.
    validated = parse_transports(
        "\n".join(f"{r['pid']}|{r['start_ticks']}" for r in rows)
    )
    parts = ["set -eu"]
    for row in validated:
        pid, ticks = row["pid"], row["start_ticks"]
        parts += [
            f'[ "$(cat /proc/{pid}/comm)" = buildctl ] || exit 91',
            f"[ \"$(sed 's/.*) //' /proc/{pid}/stat | awk '{{print $20}}')\" = {ticks} ] || exit 91",
            f"[ \"$(tr '\\000' ' ' < /proc/{pid}/cmdline)\" = 'buildctl dial-stdio ' ] || exit 91",
            f'[ "$(awk \'$1=="Uid:" {{print $2}}\' /proc/{pid}/status)" = 1000 ] || exit 91',
        ]
    parts += [f"kill -TERM {r['pid']}" for r in validated]
    return "; ".join(parts)


def verify_image(value: dict, invocation: str, compose_version: str) -> str:
    iid = gate.digest(value.get("Id"), image=True)
    expected_labels = {
        OWNER_LABEL: invocation,
        SCOPE_LABEL: KIND,
        "com.docker.compose.project": builder_name(invocation),
        "com.docker.compose.service": TARGET,
        "com.docker.compose.version": compose_version,
    }
    if (
        value.get("Os") != "linux"
        or value.get("Architecture") != "amd64"
        or type(value.get("Size")) is not int
        or not 0 < value["Size"] <= MAX_IMAGE
        or value.get("Config", {}).get("Labels") != expected_labels
        or value.get("Config", {}).get("Volumes") not in (None, {})
        # Docker's containerd image store can use the OCI manifest digest as Id
        # and attach that SAME digest to the fixed self-owned repository. No
        # foreign repository, different digest, second entry, or tuple is allowed.
        or value.get("RepoDigests")
        not in (None, [], [image_tag(invocation).split(":", 1)[0] + "@" + iid])
        or value.get("RepoTags") not in (None, [], [image_tag(invocation)])
    ):
        raise gate.GateError("OWNED_SYNTHETIC_IMAGE_BOUNDARY_CHANGED")
    return iid


class Process:
    """A whole Docker/plugin/connhelper tree assigned before any child runs."""

    def __init__(
        self, native, arguments: list[str], deadline: float, seconds: float
    ) -> None:
        now = time.monotonic()
        if (
            not math.isfinite(deadline)
            or not math.isfinite(seconds)
            or seconds <= 0
            or deadline - now <= gate.TREE_SECONDS
        ):
            raise gate.GateError("INSUFFICIENT_CLI_TREE_PROOF_BUDGET")
        self.native, self.started, self.deadline = native, now, deadline
        self.end = min(now + seconds, deadline - gate.TREE_SECONDS)
        self.output_limit = (
            8192
            if arguments
            and arguments[-1] in {gate.MOUNT_PROBE, CAPACITY_PROBE, TRANSPORT_PROBE}
            else gate.MAX_OUTPUT
        )
        native.sequence += 1
        self.sequence = native.sequence
        self.outpath = native.work / f"cli-{self.sequence:03d}.stdout"
        self.errpath = native.work / f"cli-{self.sequence:03d}.stderr"
        self.job = self.process = None
        self.out = self.err = None
        self.done = False
        self.record = None
        native.processes.append(self)
        try:
            self.out, self.err = self.outpath.open("xb"), self.errpath.open("xb")
            self.job = native.module.WindowsProcessJob()
            self.process = subprocess.Popen(
                [
                    str(gate.DOCKER),
                    "--config",
                    str(native.work / "docker-config"),
                    "--host",
                    gate.ENDPOINT,
                    *arguments,
                ],
                cwd=native.work,
                env=environment(native.work),
                stdin=subprocess.DEVNULL,
                stdout=self.out,
                stderr=self.err,
                shell=False,
                creationflags=self.job.creation_flags,
            )
            self.job.attach_and_resume(self.process)
        except BaseException:  # noqa: BLE001 -- a suspended/partial native tree still requires cleanup
            self.finish(cancel=True)
            raise gate.GateError("NATIVE_PROCESS_START_FAILED_CLOSED") from None

    def poll(self) -> int | None:
        if self.done:
            return self.record["exit_code"]
        if any(
            p.stat().st_size > self.output_limit for p in (self.outpath, self.errpath)
        ):
            raise gate.GateError("NATIVE_OUTPUT_BOUNDARY")
        if time.monotonic() >= self.end:
            raise gate.GateError("NATIVE_OPERATION_DEADLINE")
        return self.process.poll()

    def finish(self, *, cancel: bool = False, deadline: float | None = None) -> dict:
        if self.done:
            if (
                not self.record
                or not self.record.get("cli_tree")
                or self.record.get("overflow")
            ):
                raise gate.GateError("NATIVE_CLI_TREE_CLEANUP_UNKNOWN")
            return self.record
        proof = None
        failed = False
        try:
            if self.job is not None:
                proof = gate.bounded_finish(
                    self.job,
                    self.process,
                    min(
                        self.deadline,
                        deadline if deadline is not None else self.deadline,
                        time.monotonic() + gate.TREE_SECONDS,
                    ),
                    cancel=cancel,
                )
        except BaseException:  # noqa: BLE001 -- interrupts cannot bypass owned tree proof
            failed = True
        finally:
            if self.job is not None:
                try:
                    self.job.close()
                except BaseException:  # noqa: BLE001 -- uncertain Job close is never accepted
                    failed = True
            for stream in (self.out, self.err):
                if stream is not None:
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.close()
            self.done = True
        overflow = any(
            p.exists() and p.stat().st_size > self.output_limit
            for p in (self.outpath, self.errpath)
        )
        self.record = {
            "sequence": self.sequence,
            "exit_code": self.process.returncode if self.process else None,
            "cli_tree": proof,
            "cancel_requested": cancel,
            "overflow": overflow,
            "elapsed_seconds": round(time.monotonic() - self.started, 6),
        }
        self.native.operations.append(self.record)
        if failed or not proof or overflow:
            raise gate.GateError("NATIVE_CLI_TREE_CLEANUP_UNKNOWN")
        return self.record


class Native(gate.Native):
    def __init__(self, work: Path) -> None:
        super().__init__(work)
        self.processes = []

    def call(
        self,
        arguments: list[str],
        deadline: float,
        *,
        seconds: float = 10,
        allow_failure: bool = False,
    ) -> tuple[int, str]:
        process = Process(self, arguments, deadline, seconds)
        success = False
        try:
            while process.poll() is None:
                time.sleep(0.025)
            success = True
        finally:
            record = process.finish(cancel=not success)
        if record["exit_code"] != 0 and not allow_failure:
            raise gate.GateError("NATIVE_DOCKER_OPERATION_FAILED")
        return record["exit_code"], gate.bounded(process.outpath).decode(
            "utf-8", errors="strict"
        ).strip()


class Controller(gate.Controller):
    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.client = None
        self.builder_intended = False
        self.image_intended = False
        self.image_acknowledged = False
        self.compose_version = ""

    def registration(self) -> None:
        path = self.work / "buildx-config/instances" / builder_name(self.owner)
        verify_registration(json.loads(gate.bounded(path)), self.owner)
        defaults = self.work / "buildx-config/defaults"
        gate.strict_path(defaults)
        if any(defaults.iterdir()):
            raise gate.GateError("DEFAULT_BUILDER_SELECTION_FORBIDDEN")
        current = self.work / "buildx-config/current"
        if current.exists():
            value = json.loads(gate.bounded(current))
            if (
                not isinstance(value, dict)
                or set(value) != {"Key", "Name", "Global"}
                or value.get("Key") not in {"default", gate.ENDPOINT}
                or value.get("Name") != ""
                or value.get("Global") is not False
            ):
                raise gate.GateError("DEFAULT_BUILDER_SELECTION_FORBIDDEN")
        if (
            json.loads(gate.bounded(self.work / "docker-config/config.json"))
            != config()
        ):
            raise gate.GateError("EMPTY_PRIVATE_DOCKER_CONFIGURATION_CHANGED")

    def fixture(self) -> None:
        context = self.work / "context"
        context.mkdir(exist_ok=False)
        for name in ("bin", "lib", "skeleton", "skeleton/bin", "skeleton/lib"):
            (context / name).mkdir(exist_ok=False)
        for relative, expected in PUBLIC_FILES.items():
            path = context / relative
            self.call(["cp", self.cid + ":/" + relative, str(path)])
            if file_sha(path, MAX_BINARY) != expected:
                raise gate.GateError("PINNED_PUBLIC_SYNTHETIC_BINARY_CHANGED")
        with (context / "payload").open("xb") as stream:
            stream.write(gate.PAYLOAD)
        for case in CASES:
            dockerfile, document = fixture_documents(self.work, self.owner, case)
            with (context / ("Dockerfile." + case)).open(
                "x", encoding="utf-8", newline="\n"
            ) as stream:
                stream.write(dockerfile)
            gate.save_new(self.work / (case + ".compose.json"), document)
        with (self.work / "empty.env").open("xb"):
            pass
        # Only a token file is placed inside the server; no host context mount.
        self.shell(
            "umask 077; mkdir "
            + gate.ROOT
            + "; mkdir "
            + gate.ROOT
            + "/empty-config; printf '%s' '"
            + gate.TOKEN_PREFIX
            + self.owner
            + "' > "
            + gate.ROOT
            + "/token"
        )
        self.proofs["fixture_hashes"] = self.fixture_hashes()

    def fixture_hashes(self) -> dict:
        context = self.work / "context"
        expected_directories = {
            "bin",
            "lib",
            "skeleton",
            "skeleton/bin",
            "skeleton/lib",
        }
        expected_files = {"payload", *PUBLIC_FILES, *["Dockerfile." + c for c in CASES]}
        observed_directories, observed_files = set(), set()
        pending = [context]
        while pending:
            directory = pending.pop()
            gate.strict_path(directory)
            for item in directory.iterdir():
                gate.strict_path(item)
                relative = str(item.relative_to(context)).replace("\\", "/")
                if item.is_dir() and relative in expected_directories:
                    observed_directories.add(relative)
                    pending.append(item)
                elif item.is_file() and relative in expected_files:
                    observed_files.add(relative)
                else:
                    raise gate.GateError("EXACT_SYNTHETIC_CONTEXT_ALLOWLIST_REQUIRED")
        if (
            observed_directories != expected_directories
            or observed_files != expected_files
        ):
            raise gate.GateError("EXACT_SYNTHETIC_CONTEXT_ALLOWLIST_REQUIRED")
        paths = [
            self.work / "empty.env",
            *[self.work / (c + ".compose.json") for c in CASES],
            *[self.work / "context" / ("Dockerfile." + c) for c in CASES],
            self.work / "context/payload",
            *[self.work / "context" / r for r in PUBLIC_FILES],
        ]
        return {
            str(p.relative_to(self.work)).replace("\\", "/"): file_sha(p, MAX_BINARY)
            for p in paths
        }

    def capacity(self) -> dict:
        end = min(self.deadline, time.monotonic() + 9)
        _, text = self.shell(CAPACITY_PROBE, seconds=5, phase_deadline=end)
        if time.monotonic() >= end:
            raise gate.GateError("CAPACITY_PROBE_DEADLINE")
        return parse_capacity(text, self.proofs["effective_mounts_before"]["daemon"])

    def owned_images(self) -> list[str]:
        _, text = self.call(
            [
                "image",
                "ls",
                "-q",
                "--no-trunc",
                "--filter",
                "label=" + OWNER_LABEL + "=" + self.owner,
                "--filter",
                "label=" + SCOPE_LABEL + "=" + KIND,
            ]
        )
        ids = sorted(set(text.splitlines())) if text else []
        if len(ids) > 2:
            raise gate.GateError("OWNED_IMAGE_COUNT_BOUNDARY")
        for iid in ids:
            gate.digest(iid, image=True)
            _, raw = self.call(["image", "inspect", "--format", gate.VIEW, iid])
            value = json.loads(raw)
            if verify_image(value, self.owner, self.compose_version) != iid:
                raise gate.GateError("OWNED_IMAGE_IDENTITY_CHANGED")
            self.proofs.setdefault("owned_image_identity", {})[iid] = {
                "inspector_form": "OCI_SELF_REPOSITORY_DIGEST"
                if value.get("RepoDigests")
                else "NO_REPOSITORY_DIGEST",
                "repo_digests": value.get("RepoDigests") or [],
                "repo_tags": value.get("RepoTags") or [],
            }
        return ids

    def build(self, case: str, seconds: float) -> None:
        self.registration()
        if self.fixture_hashes() != self.proofs["fixture_hashes"]:
            raise gate.GateError("SYNTHETIC_CONTEXT_CHANGED")
        code, text = self.call(
            compose_arguments(self.work, self.owner, case),
            seconds=seconds,
            allow_failure=case == "fault",
        )
        if case == "fault":
            capture = text + self.native.last_errors()
            if (
                code == 0
                or "KAIROS_SYNTHETIC_FAULT37" not in capture
                or "exit code: 37" not in capture
            ):
                raise gate.GateError("COMPOSE_FAULT_NOT_REJECTED")
            self.proofs["fault_exit_code"] = code
        else:
            if not self.owned_images():
                raise gate.GateError("COMPOSE_OUTPUT_IMAGE_UNPROVEN")
            self.image_acknowledged = True

    def start_cancel(self, worker_end: float) -> None:
        self.registration()
        if self.fixture_hashes() != self.proofs["fixture_hashes"]:
            raise gate.GateError("SYNTHETIC_CONTEXT_CHANGED")
        self.client = Process(
            self.native,
            compose_arguments(self.work, self.owner, "cancel"),
            worker_end,
            19,
        )

    def run(self) -> None:
        self.baseline = self.inventory()
        gate.save_new(self.work / "baseline.json", self.baseline)
        _, existing = self.call(
            [
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                "label=" + gate.SCOPE_LABEL + "=" + gate.SCOPE,
            ]
        )
        if existing:
            raise gate.GateError("EXISTING_SCOPE_NO_DUPLICATE_OR_ADOPTION")
        _, raw = self.call(["image", "inspect", "--format", gate.VIEW, self.image])
        image = json.loads(raw)
        if (
            image.get("Id") != self.image_id
            or self.image not in image.get("RepoDigests", [])
            or image.get("Os") != "linux"
            or image.get("Architecture") != "amd64"
            or image.get("Config", {}).get("User") != "1000:1000"
        ):
            raise gate.GateError("LOCAL_IMAGE_IDENTITY_CHANGED_NO_PULL")
        self.labels = image.get("Config", {}).get("Labels") or {}
        _, self.compose_version = self.call(["compose", "version", "--short"])
        if not re.fullmatch(
            r"v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", self.compose_version
        ):
            raise gate.GateError("BOUNDED_COMPOSE_VERSION_REQUIRED")
        self.proofs["compose_version"] = self.compose_version
        gate.save_new(
            self.work / "public-tools.json",
            {
                "compose_version": self.compose_version,
                "image": self.image,
                "image_id": self.image_id,
                "image_labels": self.labels,
            },
        )
        gate.save_new(
            self.work / "create.intent.json",
            {
                "name": gate.owner_name(self.owner),
                "owner": self.owner,
                "image_id": self.image_id,
                "no_retry": True,
            },
        )
        self.intended = True
        _, self.cid = self.call(gate.create_arguments(self.owner, self.image_id))
        gate.digest(self.cid)
        gate.save_new(self.work / "create.ack.json", {"id": self.cid})
        self.inspect()
        self.call(["start", self.cid])
        ready_end = min(self.deadline, time.monotonic() + 25)
        while time.monotonic() < ready_end:
            code, raw = self.call(
                [
                    "exec",
                    self.cid,
                    "buildctl",
                    "--addr",
                    gate.SOCKET,
                    "debug",
                    "workers",
                    "--format",
                    "{{json .}}",
                ],
                seconds=3,
                allow_failure=True,
                phase_deadline=ready_end,
            )
            if code == 0 and raw:
                self.proofs["worker_configuration"] = gate.worker_info(raw)
                if time.monotonic() >= ready_end:
                    raise gate.GateError("OWNED_BUILDKIT_READY_TIMEOUT")
                break
            time.sleep(0.2)
        else:
            raise gate.GateError("OWNED_BUILDKIT_READY_TIMEOUT")
        _, cg = self.shell(gate.CGROUP_PROBE)
        self.proofs["kernel_before"] = gate.parse_cgroup(cg)
        _, server_path = self.shell("cat /proc/1/cgroup")
        gate.cgroup_path(server_path)
        self.proofs["effective_mounts_before"] = self.observe_mounts()
        self.proofs["effective_capacity_before"] = self.capacity()
        self.fixture()
        gate.save_new(
            self.work / "builder.intent.json",
            {
                "name": builder_name(self.owner),
                "driver": "remote",
                "endpoint": remote_endpoint(self.owner),
            },
        )
        self.builder_intended = True
        _, result = self.call(registration_arguments(self.owner))
        if result != builder_name(self.owner):
            raise gate.GateError("EXACT_PRIVATE_BUILDER_ACK_REQUIRED")
        self.registration()
        gate.save_new(self.work / "builder.ack.json", {"name": result})
        _, existing_tag = self.call(
            [
                "image",
                "ls",
                "-q",
                "--no-trunc",
                "--filter",
                "reference=" + image_tag(self.owner),
            ]
        )
        if existing_tag or self.owned_images():
            raise gate.GateError("PREEXISTING_SYNTHETIC_IMAGE_NO_ADOPTION")
        gate.save_new(
            self.work / "image.intent.json",
            {"tag": image_tag(self.owner), "owner": self.owner},
        )
        self.image_intended = True
        self.build("success", 30)
        gate.save_new(self.work / "image.ack.json", {"ids": self.owned_images()})
        self.proofs["tiny_build_payload_sha256"] = hashlib.sha256(
            gate.PAYLOAD
        ).hexdigest()
        self.build("fault", 20)
        worker_end = min(self.deadline, time.monotonic() + 20)
        self.start_cancel(worker_end)
        while time.monotonic() < worker_end - gate.TREE_SECONDS:
            if self.client.poll() is not None:
                raise gate.GateError("CANCEL_CASE_DID_NOT_START")
            _, raw = self.shell(gate.WORKER_PROBE, phase_deadline=worker_end)
            workers = gate.parse_workers(
                raw, server_path, self.proofs["kernel_before"]["namespace"]
            )
            if len(workers) >= 2:
                break
            time.sleep(0.2)
        else:
            raise gate.GateError("REAL_COMPOSE_WORKERS_NOT_OBSERVED")
        self.proofs["workers_before_cancel"] = workers
        time.sleep(1)
        _, cg = self.shell(gate.CGROUP_PROBE, phase_deadline=worker_end)
        busy = gate.parse_cgroup(cg)
        if (
            busy["nr_throttled"] <= self.proofs["kernel_before"]["nr_throttled"]
            or busy["usage_usec"] <= self.proofs["kernel_before"]["usage_usec"]
        ):
            raise gate.GateError("ACTUAL_COMPOSE_CPU_BOUND_UNPROVEN")
        self.proofs["kernel_under_load"] = busy
        _, raw = self.shell(TRANSPORT_PROBE, phase_deadline=worker_end)
        transports = parse_transports(raw)
        self.proofs["transports_before_cancel"] = transports
        self.shell(cancel_transport_script(transports), phase_deadline=worker_end)
        cancel_end = min(self.deadline, worker_end, time.monotonic() + 15)
        while time.monotonic() < cancel_end - gate.TREE_SECONDS:
            code = self.client.poll()
            _, raw = self.shell(gate.WORKER_PROBE, phase_deadline=cancel_end)
            remaining = gate.parse_workers(raw, server_path, busy["namespace"])
            if code is not None and code != 0 and not remaining:
                gone, _ = self.shell(
                    gate.exited_worker_script(workers),
                    allow_failure=True,
                    phase_deadline=cancel_end,
                )
                transports_gone, _ = self.shell(
                    gate.exited_worker_script(transports),
                    allow_failure=True,
                    phase_deadline=cancel_end,
                )
                if gone == 0 and transports_gone == 0:
                    self.client.finish(deadline=cancel_end)
                    if time.monotonic() >= cancel_end:
                        raise gate.GateError("COMPOSE_CANCELLATION_DEADLINE")
                    break
            time.sleep(0.2)
        else:
            raise gate.GateError("LINUX_COMPOSE_CANCELLATION_UNPROVEN")
        self.proofs["cancelled_compose_exit_code"] = code
        self.proofs["workers_after_cancel"] = []
        self.proofs["observed_transports_after_cancel"] = []
        if self.inspect().get("State", {}).get("Running") is not True:
            raise gate.GateError("DAEMON_DIED_INSTEAD_OF_CANCELLING_BUILD")
        self.build("success", 30)
        self.proofs["fresh_compose_build_after_cancel"] = True
        self.proofs["effective_mounts_after"] = self.observe_mounts()
        if (
            self.proofs["effective_mounts_after"]
            != self.proofs["effective_mounts_before"]
        ):
            raise gate.GateError("EFFECTIVE_MOUNTS_CHANGED")
        self.proofs["effective_capacity_after"] = self.capacity()
        if self.fixture_hashes() != self.proofs["fixture_hashes"]:
            raise gate.GateError("SYNTHETIC_CONTEXT_CHANGED")

    def cleanup(self) -> bool:
        cli_unknown = False
        for process in self.native.processes:
            try:
                process.finish(cancel=True, deadline=self.deadline)
            except BaseException:  # noqa: BLE001 -- still attempt verified owned-daemon cleanup
                cli_unknown = True
        # Stop/inspect/remove only the exact fully-verified owned server. Then
        # no retained build session can keep exporting a late image.
        if self.cid is None and self.intended:
            _, raw = self.call(
                [
                    "ps",
                    "-aq",
                    "--no-trunc",
                    "--filter",
                    "label=" + gate.OWNER_LABEL + "=" + self.owner,
                    "--filter",
                    "label=" + gate.SCOPE_LABEL + "=" + gate.SCOPE,
                ]
            )
            rows = raw.splitlines() if raw else []
            if len(rows) != 1:
                raise gate.GateError("CREATION_OUTCOME_UNKNOWN_PRESERVE_LEASE")
            self.cid = gate.digest(rows[0])
        if self.cid:
            self.inspect()
            self.call(["stop", "--time", "3", self.cid], seconds=6)
            stopped = self.inspect().get("State", {})
            if stopped.get("Running") is not False or stopped.get("Pid") != 0:
                raise gate.GateError("LINUX_SERVER_TREE_CLEANUP_UNPROVEN")
            self.call(["rm", self.cid])
        if self.builder_intended:
            self.registration()
            self.call(["buildx", "rm", builder_name(self.owner)])
            if (
                self.work / "buildx-config/instances" / builder_name(self.owner)
            ).exists():
                raise gate.GateError("PRIVATE_BUILDER_REMOVAL_UNPROVEN")
        if self.image_intended:
            ids = self.owned_images()
            if not self.image_acknowledged and not ids:
                raise gate.GateError("IMAGE_CREATION_OUTCOME_UNKNOWN_PRESERVE_LEASE")
            for iid in ids:
                _, users = self.call(
                    ["ps", "-aq", "--no-trunc", "--filter", "ancestor=" + iid]
                )
                if users:
                    raise gate.GateError("SYNTHETIC_IMAGE_HAS_UNEXPECTED_CONSUMER")
                self.call(["image", "rm", iid])
            if self.owned_images():
                raise gate.GateError("OWNED_IMAGE_REMOVAL_UNPROVEN")
        if self.inventory() != self.baseline:
            raise gate.GateError("UNRELATED_RESOURCE_INVENTORY_CHANGED")
        if cli_unknown or any(
            not operation.get("cli_tree") or operation.get("overflow")
            for operation in self.native.operations
        ):
            raise gate.GateError("NATIVE_CLI_TREE_CLEANUP_UNKNOWN")
        return True


def plan() -> dict:
    return {
        "mode": "PLAN_ONLY_DEFAULT_DENY",
        "kind": KIND,
        "target": TARGET,
        "execute_scope": "GENERATED_SYNTHETIC_COMPOSE_ONLY",
        "real_release_builds": "DENIED",
        "driver": "remote",
        "transport": "docker-container://EXACT_OWNED_SERVER",
        "buildkit_image": gate.BUILDKIT_IMAGE,
        "resource_gate_sha256": GATE_SHA,
        "resources": {
            "cpu": 1,
            "memory_bytes": gate.MEMORY,
            "swap_bytes": 0,
            "pids": gate.PIDS,
            "tmpfs_capacities_bytes": CAPACITIES,
            "max_parallel_execops": 1,
        },
        "work_seconds": gate.WORK_SECONDS,
        "cleanup_seconds": gate.CLEANUP_SECONDS,
        "total_seconds": gate.TOTAL_SECONDS,
        "default_builder_mutations": 0,
        "downloads": 0,
        "production_build_qualified": False,
    }


def execute(
    expected_source_sha: str,
    expected_deploy_sha: str,
    expected_tools: dict,
    image_id: str,
    *,
    invocation_owner: str | None = None,
) -> Path:
    invocation = owner(invocation_owner)
    gate.digest(expected_source_sha)
    gate.digest(image_id, image=True)
    if not re.fullmatch(r"[0-9a-f]{40}", expected_deploy_sha) or set(
        expected_tools
    ) != set(TOOLS):
        raise gate.GateError("REVIEWED_SOURCE_AND_TOOLS_REQUIRED")
    for value in expected_tools.values():
        gate.digest(value)
    before = source_bindings()
    if (
        before
        != {
            "adapter": expected_source_sha,
            "resource_gate": GATE_SHA,
            "windows_job": gate.JOB_SHA,
        }
        or tool_bindings() != expected_tools
    ):
        raise gate.GateError("REVIEWED_SOURCE_AND_TOOLS_CHANGED")
    if os.name != "nt":
        raise gate.GateError("REVIEWED_WINDOWS_JOB_PLATFORM_REQUIRED")
    gate.strict_path(OPS)
    gate.strict_path(gate.OPS)
    # One shared lease also excludes the direct resource qualifier. No adoption
    # or deletion of an existing/stale/foreign lease is permitted.
    lease = gate.OPS / "execution.lease"
    with lease.open("xb") as stream:
        stream.write(invocation.encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    started = time.monotonic()
    work = controller = None
    cleanup, failure = False, None
    try:
        prospective = OPS / ("run-" + invocation)
        prospective.mkdir(exist_ok=False)
        work = prospective
        for name in ("docker-config", "buildx-config"):
            (work / name).mkdir(exist_ok=False)
        gate.save_new(work / "docker-config/config.json", config())
        gate.save_new(
            work / "control.json",
            {
                "owner": invocation,
                "source_sha256": before,
                "tools_sha256": expected_tools,
                "deploy_sha": expected_deploy_sha,
                "image_id": image_id,
                "fixture_only": True,
                "total_seconds": gate.TOTAL_SECONDS,
            },
        )
        if (
            gate.bounded(gate.REPO / ".git/HEAD", 256).decode().strip()
            != "ref: refs/heads/main"
            or gate.bounded(gate.REPO / ".git/refs/heads/main", 256).decode().strip()
            != expected_deploy_sha
        ):
            raise gate.GateError("DEPLOY_MAIN_SOURCE_CHANGED")
        controller = Controller(
            work,
            invocation,
            gate.BUILDKIT_IMAGE,
            image_id,
            Native(work),
            started + gate.WORK_SECONDS,
        )
        controller.run()
        if (
            source_bindings() != before
            or tool_bindings() != expected_tools
            or gate.bounded(gate.REPO / ".git/refs/heads/main", 256).decode().strip()
            != expected_deploy_sha
        ):
            raise gate.GateError("SOURCE_OR_TOOL_CHANGED_DURING_NATIVE")
    except BaseException as exc:  # noqa: BLE001 -- preserve interruption and fail closed
        failure = (
            str(exc)
            if isinstance(exc, gate.GateError)
            else "BOUNDED_BUILD_FAILED_CLOSED"
        )
    finally:
        if controller is not None:
            controller.deadline = min(
                time.monotonic() + gate.CLEANUP_SECONDS, started + gate.TOTAL_SECONDS
            )
            try:
                cleanup = controller.cleanup()
            except BaseException:  # noqa: BLE001 -- do not claim unknown cleanup
                cleanup = False
        if work is not None:
            gate.save_new(
                work / "receipt.json",
                {
                    "kind": KIND,
                    "result": "PASS_SYNTHETIC_COMPOSE_ONLY"
                    if failure is None and cleanup
                    else "FAILED_OR_UNKNOWN",
                    "failure_category": failure,
                    "invocation_owner": invocation,
                    "owned_cleanup_verified": cleanup,
                    "lease_retained": not cleanup,
                    "source_sha256": before,
                    "tools_sha256": expected_tools,
                    "deploy_sha": expected_deploy_sha,
                    "image": gate.BUILDKIT_IMAGE,
                    "image_id": image_id,
                    "proofs": controller.proofs if controller else {},
                    "native_operations": controller.native.operations
                    if controller
                    else [],
                    "elapsed_seconds": round(time.monotonic() - started, 6),
                    "completed_at_utc": datetime.now(UTC).isoformat(),
                    "default_builder_mutations": 0,
                    "image_pulls": 0,
                    "primary_mutations": 0,
                    "provider_or_trading_calls": 0,
                    "production_build_qualified": False,
                    "readiness": {
                        "PAPER_QUALIFIED": False,
                        "ALPHA_READY": False,
                        "LIVE_READY": False,
                        "STRATEGY_POLICY": "REJECT_ALL",
                    },
                },
            )
        if cleanup:
            if gate.bounded(lease, 32) != invocation.encode("ascii"):
                raise gate.GateError("LEASE_OWNERSHIP_CHANGED")
            lease.unlink()
    if failure is not None or not cleanup or work is None:
        raise gate.GateError("BOUNDED_BUILD_FAILED_OR_UNKNOWN_PRESERVE_EVIDENCE")
    return work / "receipt.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-deploy-sha")
    parser.add_argument("--docker-sha")
    parser.add_argument("--buildx-sha")
    parser.add_argument("--compose-sha")
    parser.add_argument("--image-id")
    parser.add_argument("--invocation-owner")
    args = parser.parse_args(argv)
    try:
        if not args.execute:
            print(json.dumps(plan(), sort_keys=True))
            return 0
        if args.confirm != CONFIRM:
            raise gate.GateError("EXPLICIT_SYNTHETIC_SCOPE_CONFIRMATION_REQUIRED")
        receipt = execute(
            args.expected_source_sha,
            args.expected_deploy_sha,
            {
                "docker": args.docker_sha,
                "buildx": args.buildx_sha,
                "compose": args.compose_sha,
            },
            args.image_id,
            invocation_owner=args.invocation_owner,
        )
        print(
            json.dumps(
                {"result": "PASS_SYNTHETIC_COMPOSE_ONLY", "receipt": str(receipt)},
                sort_keys=True,
            )
        )
        return 0
    except (gate.GateError, TypeError, ValueError, OSError):
        print(json.dumps({"result": "DENIED_OR_FAILED", "qualification": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
