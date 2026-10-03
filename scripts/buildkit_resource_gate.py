"""Opt-in, synthetic-only qualification of an invocation-owned rootless BuildKit.

The default prints a plan and makes no native calls. Native execution is a
separately reviewed operation, not permission to use a default/shared builder.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

REPO = Path("D:/Kairos/kairos-deploy")
OPS = Path("D:/Kairos/runtime/buildkit-resource-20261003")
DOCKER = Path("C:/Program Files/Docker/Docker/resources/bin/docker.exe")
ENDPOINT = "npipe:////./pipe/dockerDesktopLinuxEngine"
JOB_SOURCE = Path(
    "D:/Kairos/runtime/operator-control-20261002/run-current-source-docker-gates.py"
)
JOB_SHA = "601d8c07d52e101c8e16d73a752b5ab85560dc6b745590f0885a11a3399fb95a"
BUILDKIT_IMAGE = "moby/buildkit@sha256:60d1f642e29dc938bd6c109ba5500849fccf41921927c5339788b8227f57feb9"
SCOPE = "kairos-buildkit-synthetic-resource-v1"
OWNER_LABEL = "com.kairos.buildkit.owner"
SCOPE_LABEL = "com.kairos.buildkit.scope"
CONFIRM = "OWNED_SYNTHETIC_BUILDKIT_ONLY"
MEMORY = 1024**3
PIDS = 128
CPU_QUOTA = CPU_PERIOD = 100_000
WORK_SECONDS = 160
CLEANUP_SECONDS = 20
TOTAL_SECONDS = WORK_SECONDS + CLEANUP_SECONDS
TREE_SECONDS = 4
MAX_OUTPUT = 256 * 1024
SOCKET = "unix:///run/user/1000/buildkit/buildkitd.sock"
ROOT = "/tmp/kairos-buildkit-gate"
TOKEN_PREFIX = "KAIROS_SYNTHETIC_BUILDKIT_SPIN_"
PAYLOAD = b"kairos-buildkit-synthetic-only\n"
SECURITY = ["seccomp=unconfined", "apparmor=unconfined", "systempaths=unconfined"]
TMPFS = {
    "/home/user/.local/share/buildkit": "rw,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700",
    "/run/user/1000": "rw,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=0700",
    "/tmp": "rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=0700",
    "/home/user/.local/tmp": "rw,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=0700",
}
CONFIG = """root = "/home/user/.local/share/buildkit"
insecure-entitlements = []
[grpc]
address = ["unix:///run/user/1000/buildkit/buildkitd.sock"]
[worker.oci]
enabled = true
rootless = true
snapshotter = "native"
networkMode = "host"
noProcessSandbox = false
max-parallelism = 1
gc = false
[worker.containerd]
enabled = false
[cdi]
disabled = true
"""
BOOT = (
    "umask 077; printf '%s' "
    + shlex.quote(CONFIG)
    + " > /tmp/kairos-buildkitd.toml; exec rootlesskit buildkitd --config /tmp/kairos-buildkitd.toml"
)
VIEW = "{{json .}}"


class GateError(RuntimeError):
    """Fixed non-sensitive categories only."""


def digest(value: str, *, image: bool = False) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}" if image else r"[0-9a-f]{64}", value
    ):
        raise GateError("IMMUTABLE_DIGEST_REQUIRED")
    return value


def image_reference(value: str) -> str:
    if value != BUILDKIT_IMAGE:
        raise GateError("PINNED_OFFICIAL_ROOTLESS_IMAGE_REQUIRED")
    return value


def owner_name(owner: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", owner):
        raise GateError("EXACT_OWNER_REQUIRED")
    return "kairos-buildkit-gate-" + owner


def strict_path(path: Path, *, existing: bool = True) -> Path:
    for item in (path, *path.parents):
        if (item.exists() or item.is_symlink()) and (
            item.is_symlink() or getattr(item.lstat(), "st_file_attributes", 0) & 0x400
        ):
            raise GateError("REPARSE_PATH_REJECTED")
    return path.resolve(strict=existing)


def bounded(path: Path, limit: int = MAX_OUTPUT) -> bytes:
    strict_path(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise GateError("BOUNDED_REGULAR_FILE_REQUIRED")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise GateError("BOUNDED_REGULAR_FILE_REQUIRED")
    return data


def sha(path: Path) -> str:
    return hashlib.sha256(bounded(path)).hexdigest()


def save_new(path: Path, value: object) -> None:
    strict_path(path.parent)
    data = (
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    if len(data) > MAX_OUTPUT:
        raise GateError("RECEIPT_SIZE_BOUNDARY")
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def create_arguments(owner: str, image_id: str) -> list[str]:
    args = [
        "create",
        "--pull=never",
        "--name",
        owner_name(owner),
        "--label",
        OWNER_LABEL + "=" + owner,
        "--label",
        SCOPE_LABEL + "=" + SCOPE,
        "--network=none",
        "--restart=no",
        "--read-only",
        "--user=1000:1000",
        "--memory=1g",
        "--memory-swap=1g",
        "--cpus=1",
        "--pids-limit=128",
    ]
    for option in SECURITY:
        args += ["--security-opt", option]
    for target, options in TMPFS.items():
        args += ["--tmpfs", target + ":" + options]
    return args + ["--entrypoint=/bin/sh", digest(image_id, image=True), "-c", BOOT]


def verify_container(view: dict, owner: str, image_id: str, image_labels: dict) -> str:
    cid = digest(view.get("Id"))
    host, config = view.get("HostConfig") or {}, view.get("Config") or {}
    expected_labels = image_labels | {OWNER_LABEL: owner, SCOPE_LABEL: SCOPE}
    if (
        view.get("Name") != "/" + owner_name(owner)
        or view.get("Image") != image_id
        or config.get("Labels") != expected_labels
    ):
        raise GateError("OWNED_CONTAINER_IDENTITY_CHANGED")
    exact = {
        "Memory": MEMORY,
        "MemorySwap": MEMORY,
        "NanoCpus": 1_000_000_000,
        "PidsLimit": PIDS,
        "ReadonlyRootfs": True,
        "Privileged": False,
        "NetworkMode": "none",
    }
    if any(
        type(host.get(key)) is not type(value) or host[key] != value
        for key, value in exact.items()
    ):
        raise GateError("SERVER_RESOURCE_OR_ISOLATION_CHANGED")
    if (
        host.get("Binds")
        or host.get("PortBindings")
        or host.get("Devices")
        or host.get("VolumesFrom")
        or host.get("CapAdd")
        or host.get("PidMode")
        or host.get("IpcMode") not in ("private", "")
        or host.get("RestartPolicy", {}).get("Name") != "no"
        or host.get("Tmpfs") != TMPFS
        # Docker consumes systempaths=unconfined into these two exact empty
        # path lists; it does not retain that operand in SecurityOpt.
        or sorted(host.get("SecurityOpt") or []) != sorted(SECURITY[:2])
        or host.get("MaskedPaths") != []
        or host.get("ReadonlyPaths") != []
        or config.get("User") != "1000:1000"
        or config.get("Entrypoint") != ["/bin/sh"]
        or config.get("Cmd") != ["-c", BOOT]
        or any(item.get("Type") != "tmpfs" for item in view.get("Mounts", []))
    ):
        raise GateError("SERVER_CAPABILITY_OR_MOUNT_CHANGED")
    networks = view.get("NetworkSettings", {}).get("Networks") or {}
    if set(networks) not in (set(), {"none"}):
        raise GateError("SERVER_NETWORK_CHANGED")
    return cid


def parse_cgroup(text: str) -> dict:
    lines = text.strip().splitlines()
    if (
        len(lines) != 7
        or not re.fullmatch(r"[0-9]+ [0-9]+", lines[0])
        or any(not line.isdecimal() for line in lines[1:6])
    ):
        raise GateError("KERNEL_CGROUP_PROOF_UNAVAILABLE")
    quota, period = map(int, lines[0].split())
    memory, swap, pids, throttled, usage = map(int, lines[1:6])
    namespace = lines[6]
    if (quota, period, memory, swap, pids) != (
        CPU_QUOTA,
        CPU_PERIOD,
        MEMORY,
        0,
        PIDS,
    ) or not re.fullmatch(r"cgroup:\[[0-9]+\]", namespace):
        raise GateError("KERNEL_CGROUP_LIMIT_MISMATCH")
    return {
        "cpu_quota": quota,
        "cpu_period": period,
        "memory_max": memory,
        "swap_max": swap,
        "pids_max": pids,
        "nr_throttled": throttled,
        "usage_usec": usage,
        "namespace": namespace,
    }


def cgroup_path(value: str) -> str:
    if not value.startswith("0::/") or "\n" in value or "\r" in value:
        raise GateError("WORKER_CGROUP_BOUNDARY")
    path = value[3:]
    if ".." in PurePosixPath(path).parts or not re.fullmatch(
        r"/[A-Za-z0-9_./:-]*", path
    ):
        raise GateError("WORKER_CGROUP_BOUNDARY")
    return path.rstrip("/") or "/"


def parse_workers(text: str, server_cgroup: str, namespace: str) -> list[dict]:
    parent = cgroup_path(server_cgroup)
    if not re.fullmatch(r"cgroup:\[[0-9]+\]", namespace):
        raise GateError("SERVER_CGROUP_NAMESPACE_UNPROVEN")
    found = []
    for line in text.strip().splitlines():
        fields = line.split("|")
        if (
            len(fields) != 4
            or not fields[0].isdecimal()
            or not fields[1].isdecimal()
            or int(fields[0]) <= 1
            or int(fields[1]) <= 0
        ):
            raise GateError("WORKER_IDENTITY_UNPROVEN")
        path = cgroup_path(fields[2])
        # OCI creates a child cgroup namespace. /proc/<pid>/cgroup is read by
        # this observer in the server namespace, so its ancestry must remain
        # below the bounded server root; the child's inode need not equal ours.
        if not re.fullmatch(r"cgroup:\[[0-9]+\]", fields[3]) or not (
            parent == "/" or path == parent or path.startswith(parent + "/")
        ):
            raise GateError("WORKER_ESCAPED_BOUNDED_CGROUP")
        found.append(
            {
                "pid": int(fields[0]),
                "start_ticks": int(fields[1]),
                "cgroup": path,
                "namespace": fields[3],
            }
        )
    if len(found) > 4 or len({row["pid"] for row in found}) != len(found):
        raise GateError("WORKER_COUNT_BOUNDARY")
    return found


def worker_info(text: str) -> dict:
    rows = json.loads(text)
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise GateError("EXACT_ONE_OCI_WORKER_REQUIRED")
    worker = rows[0]
    version = worker.get("buildkitVersion") or {}
    labels = worker.get("labels") or {}
    expected = {
        "executor": "oci",
        "snapshotter": "native",
        "network": "host",
        "oci.process-mode": "sandbox",
    }
    if any(
        labels.get("org.mobyproject.buildkit.worker." + key) != value
        for key, value in expected.items()
    ):
        raise GateError("ACTUAL_WORKER_MODE_CHANGED")
    if (
        version.get("package") != "github.com/moby/buildkit"
        or version.get("version") != "v0.32.2"
        or not re.fullmatch(r"[0-9a-f]{40}", str(version.get("revision", "")))
        or worker.get("cdiDevices")
    ):
        raise GateError("ACTUAL_BUILDKIT_VERSION_OR_DEVICE_CHANGED")
    if not any(
        row.get("os") == "linux" and row.get("architecture") == "amd64"
        for row in worker.get("platforms", [])
    ):
        raise GateError("NATIVE_AMD64_WORKER_REQUIRED")
    return {"version": version, "modes": expected}


def exited_worker_script(workers: list[dict]) -> str:
    if not workers or len(workers) > 4:
        raise GateError("OBSERVED_WORKERS_REQUIRED")
    pieces = ["set -eu"]
    for row in workers:
        pid, ticks = row["pid"], row["start_ticks"]
        if type(pid) is not int or pid <= 1 or type(ticks) is not int or ticks <= 0:
            raise GateError("OBSERVED_WORKER_NUMERIC_IDENTITY")
        pieces.append(
            f"if [ -r /proc/{pid}/stat ]; then ticks=$(sed 's/.*) //' /proc/{pid}/stat | awk '{{print $20}}'); [ \"$ticks\" != \"{ticks}\" ] || exit 92; fi"
        )
    return "; ".join(pieces)


CGROUP_PROBE = """set -eu
cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/pids.max
awk '$1=="nr_throttled" {print $2}' /sys/fs/cgroup/cpu.stat
awk '$1=="usage_usec" {print $2}' /sys/fs/cgroup/cpu.stat
readlink /proc/1/ns/cgroup
"""
WORKER_PROBE = """set -eu
token=$(cat /tmp/kairos-buildkit-gate/token)
for file in /proc/[0-9]*/cmdline; do
  [ -r "$file" ] || continue
  args=$(tr '\\000' ' ' < "$file") || continue
  case "$args" in *"$token"*)
    pid=${file#/proc/}; pid=${pid%/cmdline}
    ticks=$(sed 's/.*) //' /proc/$pid/stat | awk '{print $20}') || continue
    cg=$(cat /proc/$pid/cgroup) || continue
    ns=$(readlink /proc/$pid/ns/cgroup) || continue
    printf '%s|%s|%s|%s\\n' "$pid" "$ticks" "$cg" "$ns"
  esac
done
"""


def fixture_script(owner: str) -> str:
    owner_name(owner)
    rootfs = "FROM scratch\nCOPY bin/busybox /bin/busybox\nCOPY lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1\nCOPY payload /result\n"
    cases = {
        "success": rootfs + 'RUN ["/bin/busybox", "sh", "-c", "test -s /result"]\n',
        "fault": rootfs
        + 'RUN ["/bin/busybox", "sh", "-c", "echo KAIROS_SYNTHETIC_FAULT37; exit 37"]\n',
        "cancel": rootfs
        + "RUN "
        + json.dumps(
            [
                "/bin/busybox",
                "sh",
                "-c",
                TOKEN_PREFIX + owner + "=1; (while :; do :; done) & wait",
            ]
        )
        + "\n",
    }
    # Fixed literals only; neither an operator file nor caller shell fragment is accepted.
    shell = (
        "set -eu; umask 077; mkdir "
        + ROOT
        + "; mkdir "
        + ROOT
        + "/context "
        + ROOT
        + "/context/bin "
        + ROOT
        + "/context/lib "
        + ROOT
        + "/empty-config; "
    )
    shell += (
        "test -f /bin/busybox; test -f /lib/ld-musl-x86_64.so.1; cp /bin/busybox "
        + ROOT
        + "/context/bin/busybox; cp /lib/ld-musl-x86_64.so.1 "
        + ROOT
        + "/context/lib/ld-musl-x86_64.so.1; "
    )
    shell += (
        "printf '%s' '"
        + PAYLOAD.decode()
        + "' > "
        + ROOT
        + "/context/payload; printf '%s' '"
        + TOKEN_PREFIX
        + owner
        + "' > "
        + ROOT
        + "/token; "
    )
    for name, value in cases.items():
        shell += (
            "printf '%s' '"
            + value
            + "' > "
            + ROOT
            + "/context/Dockerfile."
            + name
            + "; "
        )
    return (
        shell
        + "sha256sum "
        + ROOT
        + "/context/bin/busybox "
        + ROOT
        + "/context/lib/ld-musl-x86_64.so.1"
    )


def build_arguments(case: str) -> list[str]:
    if case not in {"success", "fault", "cancel"}:
        raise GateError("FIXED_SYNTHETIC_CASE_REQUIRED")
    return [
        "buildctl",
        "--addr",
        SOCKET,
        "build",
        "--progress=plain",
        "--frontend",
        "dockerfile.v0",
        "--local",
        "context=" + ROOT + "/context",
        "--local",
        "dockerfile=" + ROOT + "/context",
        "--opt",
        "filename=Dockerfile." + case,
        "--opt",
        "platform=linux/amd64",
        "--no-cache",
        "--output",
        "type=local,dest=" + ROOT + "/result-" + case,
    ]


def plan(image: str | None = None) -> dict:
    if image is not None:
        image_reference(image)
    return {
        "kind": "OWNED_BUILDKIT_RESOURCE_AND_CANCELLATION_V1",
        "result": "PLAN_ONLY_NO_NATIVE_CALLS",
        "image": image,
        "native_state": "REVIEWED_LAUNCHER_REQUIRED"
        if image
        else "BLOCKED_IMAGE_UNCONFIGURED",
        "server": {
            "memory": MEMORY,
            "cpus": 1,
            "pids": PIDS,
            "swap": 0,
            "network": "none",
            "rootless": True,
            "process_sandbox": True,
            "privileged": False,
            "security_exceptions": SECURITY,
            "tmpfs": TMPFS,
        },
        "scope": SCOPE,
        "seconds": TOTAL_SECONDS,
        "mutates_default_builder": False,
        "pulls": 0,
        "host_data_mounts": 0,
        "provider_or_trading_calls": 0,
        "qualification": "UNPROVEN",
    }


def _job_module():
    if sha(JOB_SOURCE) != JOB_SHA:
        raise GateError("REVIEWED_WINDOWS_JOB_SOURCE_CHANGED")
    spec = importlib.util.spec_from_file_location(
        "kairos_buildkit_reviewed_job", JOB_SOURCE
    )
    if spec is None or spec.loader is None:
        raise GateError("REVIEWED_WINDOWS_JOB_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if sha(JOB_SOURCE) != JOB_SHA:
        raise GateError("REVIEWED_WINDOWS_JOB_SOURCE_CHANGED")
    return module


def bounded_finish(job, process, deadline: float, *, cancel: bool) -> dict:
    if not job.assigned:
        if process is not None and process.poll() is None:
            process.kill()
    else:
        if (
            cancel or job.accounting().active_processes
        ) and not job.kernel.TerminateJobObject(job.handle, 125):
            raise GateError("WINDOWS_TREE_TERMINATION_FAILED")
        while job.accounting().active_processes:
            if time.monotonic() >= deadline:
                raise GateError("WINDOWS_TREE_CLEANUP_UNKNOWN")
            time.sleep(0.025)
    if process is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GateError("WINDOWS_TREE_CLEANUP_UNKNOWN")
        process.wait(timeout=remaining)
    if job.accounting().active_processes or time.monotonic() > deadline:
        raise GateError("WINDOWS_TREE_CLEANUP_UNKNOWN")
    return {
        "assigned_before_resume": job.assigned and job.resumed,
        "active_processes_after": 0,
    }


class Native:
    """Bound Windows CLI descendants; this is explicitly NOT Linux proof."""

    def __init__(self, work: Path) -> None:
        self.work, self.sequence, self.operations = work, 0, []
        self.module = _job_module()

    def last_errors(self) -> str:
        return bounded(self.work / f"cli-{self.sequence:03d}.stderr").decode(
            "utf-8", errors="strict"
        )

    def call(
        self,
        arguments: list[str],
        deadline: float,
        *,
        seconds: float = 10,
        allow_failure: bool = False,
    ) -> tuple[int, str]:
        now = time.monotonic()
        if (
            not math.isfinite(deadline)
            or not math.isfinite(seconds)
            or seconds <= 0
            or deadline - now <= TREE_SECONDS
        ):
            raise GateError("INSUFFICIENT_CLI_TREE_PROOF_BUDGET")
        end = min(now + seconds, deadline - TREE_SECONDS)
        self.sequence += 1
        outpath, errpath = (
            self.work / f"cli-{self.sequence:03d}.stdout",
            self.work / f"cli-{self.sequence:03d}.stderr",
        )
        process = job = proof = None
        failed = timed_out = overflow = False
        with outpath.open("xb") as out, errpath.open("xb") as err:
            try:
                job = self.module.WindowsProcessJob()
                process = subprocess.Popen(
                    [
                        str(DOCKER),
                        "--config",
                        str(self.work / "docker-config"),
                        "--host",
                        ENDPOINT,
                        *arguments,
                    ],
                    cwd=self.work,
                    env={
                        key: value
                        for key, value in os.environ.items()
                        if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
                    },
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    shell=False,
                    creationflags=job.creation_flags,
                )
                job.attach_and_resume(process)
                while process.poll() is None:
                    timed_out = time.monotonic() >= end
                    overflow = (
                        outpath.stat().st_size > MAX_OUTPUT
                        or errpath.stat().st_size > MAX_OUTPUT
                    )
                    if timed_out or overflow:
                        break
                    time.sleep(0.025)
            except BaseException:  # noqa: BLE001 -- interruptions must still cancel the owned CLI tree
                failed = True
            finally:
                if job is not None:
                    try:
                        proof = bounded_finish(
                            job,
                            process,
                            min(deadline, time.monotonic() + TREE_SECONDS),
                            cancel=failed or timed_out or overflow,
                        )
                    except BaseException:  # noqa: BLE001 -- any cleanup uncertainty is fail-closed
                        failed = True
                    finally:
                        job.close()
                out.flush()
                err.flush()
                os.fsync(out.fileno())
                os.fsync(err.fileno())
        overflow = (
            overflow
            or outpath.stat().st_size > MAX_OUTPUT
            or errpath.stat().st_size > MAX_OUTPUT
        )
        result = {
            "sequence": self.sequence,
            "exit_code": process.returncode if process else None,
            "timed_out": timed_out,
            "overflow": overflow,
            "cli_tree": proof,
            "elapsed_seconds": round(time.monotonic() - now, 6),
        }
        self.operations.append(result)
        if failed or timed_out or overflow or not proof:
            raise GateError("NATIVE_OPERATION_OR_CLI_CLEANUP_UNKNOWN")
        if process is None or (process.returncode != 0 and not allow_failure):
            raise GateError("NATIVE_DOCKER_OPERATION_FAILED")
        return process.returncode, bounded(outpath).decode(
            "utf-8", errors="strict"
        ).strip()


class Controller:
    def __init__(
        self, work: Path, owner: str, image: str, image_id: str, native, deadline: float
    ) -> None:
        self.work, self.owner, self.image, self.image_id, self.native = (
            work,
            owner,
            image_reference(image),
            digest(image_id, image=True),
            native,
        )
        self.deadline = deadline
        self.cid = None
        self.intended = False
        self.labels = {}
        self.proofs = {}
        self.baseline = {}

    def call(
        self,
        args: list[str],
        *,
        seconds: float = 10,
        allow_failure: bool = False,
        phase_deadline: float | None = None,
    ) -> tuple[int, str]:
        return self.native.call(
            args,
            min(self.deadline, phase_deadline)
            if phase_deadline is not None
            else self.deadline,
            seconds=seconds,
            allow_failure=allow_failure,
        )

    def shell(
        self,
        script: str,
        *,
        seconds: float = 10,
        allow_failure: bool = False,
        phase_deadline: float | None = None,
    ) -> tuple[int, str]:
        if self.cid is None:
            raise GateError("OWNED_SERVER_REQUIRED")
        return self.call(
            [
                "exec",
                "--env",
                "DOCKER_CONFIG=" + ROOT + "/empty-config",
                self.cid,
                "/bin/sh",
                "-c",
                script,
            ],
            seconds=seconds,
            allow_failure=allow_failure,
            phase_deadline=phase_deadline,
        )

    def inspect(self) -> dict:
        _, text = self.call(["inspect", "--format", VIEW, self.cid or ""])
        value = json.loads(text)
        if verify_container(value, self.owner, self.image_id, self.labels) != self.cid:
            raise GateError("EXACT_SERVER_ID_CHANGED")
        return value

    def inventory(self) -> dict:
        result = {}
        for key, args in {
            "containers": ["ps", "-aq", "--no-trunc"],
            "networks": ["network", "ls", "-q", "--no-trunc"],
            "volumes": ["volume", "ls", "-q"],
            "images": ["image", "ls", "-aq", "--no-trunc"],
        }.items():
            _, text = self.call(args)
            values = text.splitlines() if text else []
            if (
                len(values) > 4096
                or (key != "images" and len(set(values)) != len(values))
                or any(
                    not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value)
                    for value in values
                )
            ):
                raise GateError("LOCAL_RESOURCE_INVENTORY_BOUNDARY")
            result[key] = sorted(set(values))
        return result

    def run(self) -> None:
        self.baseline = self.inventory()
        _, existing_scope = self.call(
            [
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                "label=" + SCOPE_LABEL + "=" + SCOPE,
            ]
        )
        if existing_scope:
            raise GateError("EXISTING_SCOPE_NO_DUPLICATE_OR_ADOPTION")
        _, text = self.call(["image", "inspect", "--format", VIEW, self.image])
        image = json.loads(text)
        official_digest = "moby/buildkit@" + self.image.split("@", 1)[1]
        if (
            image.get("Id") != self.image_id
            or official_digest not in image.get("RepoDigests", [])
            or image.get("Architecture") != "amd64"
            or image.get("Os") != "linux"
        ):
            raise GateError("LOCAL_IMAGE_IDENTITY_CHANGED_NO_PULL")
        self.labels = image.get("Config", {}).get("Labels") or {}
        if image.get("Config", {}).get("User") != "1000:1000":
            raise GateError("OFFICIAL_ROOTLESS_IMAGE_USER_CHANGED")
        save_new(
            self.work / "create.intent.json",
            {
                "name": owner_name(self.owner),
                "owner": self.owner,
                "image_id": self.image_id,
                "no_retry": True,
            },
        )
        self.intended = True
        _, self.cid = self.call(create_arguments(self.owner, self.image_id))
        digest(self.cid)
        save_new(self.work / "create.ack.json", {"id": self.cid})
        self.inspect()
        self.call(["start", self.cid])
        ready_end = min(self.deadline, time.monotonic() + 25)
        while time.monotonic() < ready_end:
            code, workers = self.call(
                [
                    "exec",
                    self.cid,
                    "buildctl",
                    "--addr",
                    SOCKET,
                    "debug",
                    "workers",
                    "--format",
                    "{{json .}}",
                ],
                seconds=3,
                allow_failure=True,
                phase_deadline=ready_end,
            )
            if code == 0 and workers:
                actual_worker = worker_info(workers)
                if time.monotonic() >= ready_end:
                    raise GateError("OWNED_BUILDKIT_READY_TIMEOUT")
                self.proofs["worker_configuration"] = actual_worker
                break
            time.sleep(0.2)
        else:
            raise GateError("OWNED_BUILDKIT_READY_TIMEOUT")
        _, cg = self.shell(CGROUP_PROBE)
        self.proofs["kernel_before"] = parse_cgroup(cg)
        _, server_path = self.shell("cat /proc/1/cgroup")
        cgroup_path(server_path)
        _, binaries = self.shell(fixture_script(self.owner))
        binary_lines = binaries.splitlines()
        if len(binary_lines) != 2 or any(
            not re.fullmatch(
                r"[0-9a-f]{64}  /tmp/kairos-buildkit-gate/context/(bin/busybox|lib/ld-musl-x86_64.so.1)",
                line,
            )
            for line in binary_lines
        ):
            raise GateError("IMAGE_OWNED_SYNTHETIC_BINARY_IDENTITY")
        self.proofs["synthetic_binary_hashes"] = [
            line.split()[0] for line in binary_lines
        ]
        self.call(
            [
                "exec",
                "--env",
                "DOCKER_CONFIG=" + ROOT + "/empty-config",
                self.cid,
                *build_arguments("success"),
            ],
            seconds=30,
        )
        _, payload = self.shell("sha256sum " + ROOT + "/result-success/result")
        if payload.split()[0] != hashlib.sha256(PAYLOAD).hexdigest():
            raise GateError("DETERMINISTIC_SYNTHETIC_BUILD_MISMATCH")
        self.proofs["tiny_build_sha256"] = payload.split()[0]
        fault, output = self.call(
            [
                "exec",
                "--env",
                "DOCKER_CONFIG=" + ROOT + "/empty-config",
                self.cid,
                *build_arguments("fault"),
            ],
            seconds=20,
            allow_failure=True,
        )
        fault_capture = output + self.native.last_errors()
        if (
            fault == 0
            or "KAIROS_SYNTHETIC_FAULT37" not in fault_capture
            or "exit code: 37" not in fault_capture
        ):
            raise GateError("SYNTHETIC_FAULT_NOT_REJECTED")
        self.proofs["fault_exit_code"] = fault
        # The client is controlled INSIDE the server. Windows CLI cancellation
        # alone is neither the cancellation stimulus nor accepted Linux proof.
        command = " ".join(build_arguments("cancel"))
        launch = (
            "umask 077; ("
            + command
            + " > "
            + ROOT
            + "/cancel.stdout 2> "
            + ROOT
            + "/cancel.stderr & client=$!; printf '%s' \"$client\" > "
            + ROOT
            + "/client.pid; sed 's/.*) //' /proc/$client/stat | awk '{print $20}' > "
            + ROOT
            + '/client.start; wait "$client"; printf \'%s\' "$?" > '
            + ROOT
            + "/client.exit)"
        )
        self.call(
            [
                "exec",
                "-d",
                "--env",
                "DOCKER_CONFIG=" + ROOT + "/empty-config",
                self.cid,
                "/bin/sh",
                "-c",
                launch,
            ]
        )
        worker_end = min(self.deadline, time.monotonic() + 20)
        while time.monotonic() < worker_end:
            _, text = self.shell(WORKER_PROBE, phase_deadline=worker_end)
            active = parse_workers(
                text, server_path, self.proofs["kernel_before"]["namespace"]
            )
            if len(active) >= 2:
                if time.monotonic() >= worker_end:
                    raise GateError("REAL_SYNTHETIC_WORKERS_NOT_OBSERVED")
                break
            time.sleep(0.2)
        else:
            raise GateError("REAL_SYNTHETIC_WORKERS_NOT_OBSERVED")
        self.proofs["workers_before_cancel"] = active
        time.sleep(1)
        _, cg = self.shell(CGROUP_PROBE)
        busy = parse_cgroup(cg)
        if (
            busy["nr_throttled"] <= self.proofs["kernel_before"]["nr_throttled"]
            or busy["usage_usec"] <= self.proofs["kernel_before"]["usage_usec"]
        ):
            raise GateError("ACTUAL_SERVER_CPU_ENFORCEMENT_UNPROVEN")
        self.proofs["kernel_under_load"] = busy
        self.shell(
            "set -eu; pid=$(cat "
            + ROOT
            + '/client.pid); case "$pid" in *[!0-9]*|"") exit 90;; esac; '
            "expected=$(cat "
            + ROOT
            + '/client.start); case "$expected" in *[!0-9]*|"") exit 90;; esac; '
            "actual=$(sed 's/.*) //' /proc/$pid/stat | awk '{print $20}'); [ \"$actual\" = \"$expected\" ] || exit 91; "
            'args=$(tr "\\000" " " < /proc/$pid/cmdline); case "$args" in "buildctl --addr '
            + SOCKET
            + ' build --progress=plain --frontend dockerfile.v0 "*"filename=Dockerfile.cancel "*) ;; *) exit 91;; esac; kill -TERM "$pid"'
        )
        cancel_end = min(self.deadline, time.monotonic() + 15)
        while time.monotonic() < cancel_end:
            _, text = self.shell(WORKER_PROBE, phase_deadline=cancel_end)
            remaining = parse_workers(text, server_path, busy["namespace"])
            code, status = self.shell(
                "test -f " + ROOT + "/client.exit && cat " + ROOT + "/client.exit",
                allow_failure=True,
                phase_deadline=cancel_end,
            )
            if not remaining and code == 0 and status.isdecimal() and int(status) != 0:
                gone, _ = self.shell(
                    exited_worker_script(active),
                    allow_failure=True,
                    phase_deadline=cancel_end,
                )
                if gone == 0:
                    if time.monotonic() >= cancel_end:
                        raise GateError("LINUX_SERVER_CANCELLATION_UNPROVEN")
                    break
            time.sleep(0.2)
        else:
            raise GateError("LINUX_SERVER_CANCELLATION_UNPROVEN")
        self.proofs["workers_after_cancel"] = []
        self.proofs["cancelled_client_exit_code"] = int(status)
        view = self.inspect()
        if view.get("State", {}).get("Running") is not True:
            raise GateError("SERVER_DIED_INSTEAD_OF_CANCELLING_WORKERS")
        self.call(
            [
                "exec",
                "--env",
                "DOCKER_CONFIG=" + ROOT + "/empty-config",
                self.cid,
                *build_arguments("success"),
            ],
            seconds=30,
        )
        self.proofs["fresh_build_after_cancel"] = True

    def cleanup(self) -> bool:
        if self.cid is None and self.intended:
            _, text = self.call(
                [
                    "ps",
                    "-aq",
                    "--no-trunc",
                    "--filter",
                    "label=" + OWNER_LABEL + "=" + self.owner,
                    "--filter",
                    "label=" + SCOPE_LABEL + "=" + SCOPE,
                ]
            )
            values = text.splitlines() if text else []
            if len(values) != 1:
                raise GateError("CREATION_OUTCOME_UNKNOWN_PRESERVE_LEASE")
            self.cid = digest(values[0])
        if self.cid:
            self.inspect()
            self.call(["stop", "--time", "3", self.cid], seconds=6)
            view = self.inspect()
            if (
                view.get("State", {}).get("Running") is not False
                or view.get("State", {}).get("Pid") != 0
            ):
                raise GateError("LINUX_SERVER_TREE_CLEANUP_UNPROVEN")
            self.call(["rm", self.cid])
        after = self.inventory()
        if after != self.baseline:
            raise GateError("UNRELATED_RESOURCE_INVENTORY_CHANGED")
        return True


def execute(
    image: str,
    image_id: str,
    expected_source_sha: str,
    expected_deploy_sha: str,
    *,
    invocation_owner: str | None = None,
) -> Path:
    owner = uuid.uuid4().hex if invocation_owner is None else invocation_owner
    if (
        not isinstance(owner, str)
        or re.fullmatch(r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}", owner) is None
    ):
        raise GateError("EXACT_UUID4_INVOCATION_OWNER_REQUIRED")
    digest(expected_source_sha)
    if (
        not re.fullmatch(r"[0-9a-f]{40}", expected_deploy_sha)
        or sha(Path(__file__)) != expected_source_sha
    ):
        raise GateError("REVIEWED_SOURCE_IDENTITY_REQUIRED")
    image_reference(image)
    digest(image_id, image=True)
    strict_path(OPS)
    lease = OPS / "execution.lease"
    # An existing/stale lease is never deleted, adopted, or automatically retried.
    with lease.open("xb") as stream:
        stream.write(owner.encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    prospective_work = OPS / ("run-" + owner)
    work = None
    controller = None
    cleanup = False
    failed = None
    started = time.monotonic()
    try:
        prospective_work.mkdir(exist_ok=False)
        # A collision must never make the exception path append to an old run.
        work = prospective_work
        (work / "docker-config").mkdir(exist_ok=False)
        save_new(work / "docker-config/config.json", {"auths": {}})
        save_new(
            work / "control.json",
            {
                "owner": owner,
                "source_sha256": expected_source_sha,
                "deploy_sha": expected_deploy_sha,
                "image": image,
                "image_id": image_id,
                "job_sha256": JOB_SHA,
                "seconds": TOTAL_SECONDS,
            },
        )
        # This is a source ref check, not a substitute for root's trusted signed
        # clean-main launcher preflight. No Git/signing process is started here.
        if (
            bounded(REPO / ".git/HEAD", 256).decode().strip() != "ref: refs/heads/main"
            or bounded(REPO / ".git/refs/heads/main", 256).decode().strip()
            != expected_deploy_sha
        ):
            raise GateError("DEPLOY_MAIN_SOURCE_CHANGED")
        native = Native(work)
        controller = Controller(
            work, owner, image, image_id, native, started + WORK_SECONDS
        )
        controller.run()
        if (
            sha(Path(__file__)) != expected_source_sha
            or sha(JOB_SOURCE) != JOB_SHA
            or bounded(REPO / ".git/refs/heads/main", 256).decode().strip()
            != expected_deploy_sha
        ):
            raise GateError("REVIEWED_SOURCE_CHANGED_DURING_NATIVE")
    except BaseException as exc:  # noqa: BLE001 -- retain sanitized evidence and owned cleanup on interruption
        failed = str(exc) if isinstance(exc, GateError) else "NATIVE_GATE_FAILED_CLOSED"
    finally:
        if controller is not None:
            controller.deadline = min(
                time.monotonic() + CLEANUP_SECONDS, started + TOTAL_SECONDS
            )
            try:
                cleanup = controller.cleanup()
            except BaseException:  # noqa: BLE001 -- never accept interrupted or uncertain Docker cleanup
                cleanup = False
        if work is not None and work.is_dir():
            save_new(
                work / "receipt.json",
                {
                    "kind": SCOPE,
                    "result": "PASS_SYNTHETIC_ONLY"
                    if failed is None and cleanup
                    else "FAILED_OR_UNKNOWN",
                    "failure_category": failed,
                    "owned_cleanup_verified": cleanup,
                    "lease_retained": not cleanup,
                    "source_sha256": expected_source_sha,
                    "deploy_sha": expected_deploy_sha,
                    "invocation_owner": owner,
                    "image": image,
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
                    "scope_qualification_only": True,
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
            if bounded(lease, 32) != owner.encode("ascii"):
                raise GateError("LEASE_OWNERSHIP_CHANGED")
            lease.unlink()
    if failed is not None or not cleanup:
        raise GateError("BUILDKIT_GATE_FAILED_OR_UNKNOWN_PRESERVE_EVIDENCE")
    if work is None:
        raise GateError("EXCLUSIVE_WORKSPACE_REQUIRED")
    return work / "receipt.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--buildkit-image")
    parser.add_argument("--image-id")
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-deploy-sha")
    parser.add_argument("--confirm")
    parser.add_argument("--invocation-owner")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.execute:
            print(json.dumps(plan(args.buildkit_image), sort_keys=True))
            return 0
        if args.confirm != CONFIRM or not all(
            (
                args.buildkit_image,
                args.image_id,
                args.expected_source_sha,
                args.expected_deploy_sha,
            )
        ):
            raise GateError("REVIEWED_EXPLICIT_NATIVE_CONFIRMATION_REQUIRED")
        result = execute(
            args.buildkit_image,
            args.image_id,
            args.expected_source_sha,
            args.expected_deploy_sha,
            invocation_owner=args.invocation_owner,
        )
        print(json.dumps({"receipt": str(result), "result": "PASS_SYNTHETIC_ONLY"}))
        return 0
    except (GateError, OSError, ValueError):
        print("BUILDKIT_GATE_REJECTED_SEE_RETAINED_SANITIZED_RECEIPT")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
