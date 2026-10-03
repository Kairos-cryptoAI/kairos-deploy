from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import buildkit_resource_gate as gate

OWNER = "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
IMAGE_ID = "sha256:" + "b" * 64
CID = "c" * 64


def view() -> dict:
    return {
        "Id": CID,
        "Name": "/" + gate.owner_name(OWNER),
        "Image": IMAGE_ID,
        "Config": {
            "Labels": {gate.OWNER_LABEL: OWNER, gate.SCOPE_LABEL: gate.SCOPE},
            "User": "1000:1000",
            "Entrypoint": ["/bin/sh"],
            "Cmd": ["-c", gate.BOOT],
        },
        "HostConfig": {
            "Memory": gate.MEMORY,
            "MemorySwap": gate.MEMORY,
            "NanoCpus": 1_000_000_000,
            "PidsLimit": gate.PIDS,
            "ReadonlyRootfs": True,
            "Privileged": False,
            "NetworkMode": "none",
            "IpcMode": "private",
            "Tmpfs": gate.TMPFS,
            "SecurityOpt": gate.SECURITY[:2],
            "MaskedPaths": [],
            "ReadonlyPaths": [],
            "RestartPolicy": {"Name": "no"},
        },
        "Mounts": [],
        "NetworkSettings": {"Networks": {}},
        "State": {"Running": True, "Pid": 1234},
    }


class ContractTests(unittest.TestCase):
    def test_default_is_plan_only_without_calls_or_files(self):
        with (
            patch.object(gate, "Native") as native,
            patch.object(gate, "execute") as execute,
            patch.object(gate, "save_new") as save,
            patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            self.assertEqual(gate.main([]), 0)
        native.assert_not_called()
        execute.assert_not_called()
        save.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertEqual(result["result"], "PLAN_ONLY_NO_NATIVE_CALLS")
        self.assertEqual(result["native_state"], "BLOCKED_IMAGE_UNCONFIGURED")
        self.assertFalse(result["mutates_default_builder"])

    def test_execute_needs_all_explicit_reviewed_inputs(self):
        with (
            patch.object(gate, "execute") as execute,
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            self.assertEqual(gate.main(["--execute"]), 1)
        execute.assert_not_called()

    def test_only_matching_official_release_digest_is_admitted(self):
        self.assertEqual(gate.image_reference(gate.BUILDKIT_IMAGE), gate.BUILDKIT_IMAGE)
        for value in (
            "moby/buildkit:latest",
            "moby/buildkit:rootless",
            "moby/buildkit@sha256:" + "a" * 64,
            "moby/buildkit:v0.32.1-rootless@" + gate.BUILDKIT_IMAGE.split("@")[1],
            gate.BUILDKIT_IMAGE.replace("moby/", "evil/"),
        ):
            with self.subTest(value=value), self.assertRaises(gate.GateError):
                gate.image_reference(value)

    def test_owner_and_digest_are_not_shell_fragments(self):
        for value in (OWNER + " ", "a;id", "A" * 32, "../old", ""):
            with self.subTest(value=value), self.assertRaises(gate.GateError):
                gate.owner_name(value)
        for value in ("b" * 64, "sha256:" + "B" * 64, IMAGE_ID + " "):
            with self.subTest(value=value), self.assertRaises(gate.GateError):
                gate.digest(value, image=True)

    def test_create_has_no_pull_port_hostbind_device_or_privileged(self):
        args = gate.create_arguments(OWNER, IMAGE_ID)
        self.assertIn("--pull=never", args)
        for required in (
            "--network=none",
            "--read-only",
            "--memory=1g",
            "--memory-swap=1g",
            "--cpus=1",
            "--pids-limit=128",
            "--user=1000:1000",
        ):
            self.assertIn(required, args)
        for forbidden in (
            "--privileged",
            "--publish",
            "--device",
            "--mount",
            "--volume",
            "--cap-add",
            "--network=host",
        ):
            self.assertNotIn(forbidden, args)
        self.assertEqual(
            [
                args[index + 1]
                for index, value in enumerate(args)
                if value == "--security-opt"
            ],
            gate.SECURITY,
        )
        self.assertEqual(args[-3:], [IMAGE_ID, "-c", gate.BOOT])

    def test_config_preserves_process_sandbox_and_no_extra_entitlements(self):
        import tomllib

        cfg = tomllib.loads(gate.CONFIG)
        self.assertIs(cfg["worker"]["oci"]["noProcessSandbox"], False)
        self.assertEqual(cfg["worker"]["oci"]["max-parallelism"], 1)
        self.assertEqual(cfg["insecure-entitlements"], [])
        self.assertEqual(cfg["grpc"]["address"], [gate.SOCKET])
        self.assertFalse(cfg["worker"]["containerd"]["enabled"])
        self.assertNotIn("\\n", gate.BOOT)

    def test_verify_exact_container(self):
        self.assertEqual(gate.verify_container(view(), OWNER, IMAGE_ID, {}), CID)

    def test_systempaths_requires_exact_docker_inspector_representation(self):
        for key, bad in (
            ("SecurityOpt", gate.SECURITY),
            ("SecurityOpt", gate.SECURITY[:2] + ["no-new-privileges:true"]),
            ("MaskedPaths", ["/proc/kcore"]),
            ("ReadonlyPaths", ["/proc/sys"]),
            ("MaskedPaths", None),
            ("ReadonlyPaths", None),
        ):
            invalid = view()
            invalid["HostConfig"][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(gate.GateError):
                gate.verify_container(invalid, OWNER, IMAGE_ID, {})

    def test_host_limits_require_strict_types(self):
        for key, bad in {
            "Memory": True,
            "NanoCpus": 1.0,
            "PidsLimit": True,
            "ReadonlyRootfs": 1,
            "Privileged": 0,
            "MemorySwap": "1073741824",
        }.items():
            invalid = view()
            invalid["HostConfig"][key] = bad
            with self.subTest(key=key), self.assertRaises(gate.GateError):
                gate.verify_container(invalid, OWNER, IMAGE_ID, {})

    def test_verify_rejects_host_capability_mount_network_and_shared_names(self):
        negatives = [
            ("HostConfig", "Binds", ["/secret:/secret:ro"]),
            ("HostConfig", "Devices", [{"PathOnHost": "/dev/fuse"}]),
            ("HostConfig", "PortBindings", {"1234/tcp": []}),
            ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
            ("HostConfig", "Privileged", True),
            ("HostConfig", "SecurityOpt", ["seccomp=unconfined"]),
            ("HostConfig", "NetworkMode", "host"),
            ("Config", "User", "0:0"),
        ]
        for parent, key, bad in negatives:
            invalid = view()
            invalid[parent][key] = bad
            with self.subTest(key=key), self.assertRaises(gate.GateError):
                gate.verify_container(invalid, OWNER, IMAGE_ID, {})
        for key, bad in (
            ("Name", "/default-builder"),
            ("Image", "sha256:" + "d" * 64),
            ("Mounts", [{"Type": "volume", "Name": "old-build-cache"}]),
        ):
            invalid = view()
            invalid[key] = bad
            with self.subTest(key=key), self.assertRaises(gate.GateError):
                gate.verify_container(invalid, OWNER, IMAGE_ID, {})

    def test_kernel_cgroup_not_docker_metadata_is_required(self):
        sample = f"100000 100000\n{gate.MEMORY}\n0\n128\n5\n123\ncgroup:[1234]\n"
        self.assertEqual(gate.parse_cgroup(sample)["nr_throttled"], 5)
        for bad in (
            sample.replace("100000 100000", "max 100000"),
            sample.replace("\n0\n", "\n1073741824\n"),
            sample.replace("\n128\n", "\nmax\n"),
            sample + "extra\n",
            "",
        ):
            with self.subTest(bad=bad), self.assertRaises(gate.GateError):
                gate.parse_cgroup(bad)

    def test_workers_bound_pid_start_namespace_and_cgroup_ancestor(self):
        rows = gate.parse_workers(
            "40|200|0::/bounded/worker|cgroup:[1]\n41|201|0::/bounded|cgroup:[1]",
            "0::/bounded",
            "cgroup:[1]",
        )
        self.assertEqual([row["pid"] for row in rows], [40, 41])
        for bad in (
            "40|200|0::/bounded-sibling|cgroup:[1]",
            "40|200|0::/bounded/../escape|cgroup:[1]",
            "40|200|0::/bounded|invalid",
            "1|200|0::/bounded|cgroup:[1]",
            "40|0|0::/bounded|cgroup:[1]",
            "40|200|0::/bounded|cgroup:[1]\n40|201|0::/bounded|cgroup:[1]",
        ):
            with self.subTest(bad=bad), self.assertRaises(gate.GateError):
                gate.parse_workers(bad, "0::/bounded", "cgroup:[1]")

    def test_fixture_never_reads_operator_inputs_or_registry(self):
        script = gate.fixture_script(OWNER)
        self.assertIn("/bin/busybox", script)
        self.assertIn("/lib/ld-musl-x86_64.so.1", script)
        self.assertIn("FROM scratch", script)
        self.assertIn("exit 37", script)
        self.assertIn(gate.TOKEN_PREFIX + OWNER, script)
        self.assertNotIn("FROM alpine", script)
        self.assertNotIn("curl", script)
        self.assertNotIn("docker.sock", script)
        self.assertNotIn("keys.txt", script)

    def test_build_inputs_are_fixed_builtin_frontend_and_local_output(self):
        for case in ("success", "fault", "cancel"):
            args = gate.build_arguments(case)
            self.assertIn("dockerfile.v0", args)
            self.assertIn("--no-cache", args)
            self.assertIn("type=local,dest=" + gate.ROOT + "/result-" + case, args)
            for bad in (
                "--secret",
                "--ssh",
                "--allow",
                "--import-cache",
                "--export-cache",
                "--push",
                "--load",
            ):
                self.assertNotIn(bad, args)
        with self.assertRaises(gate.GateError):
            gate.build_arguments("../../production")

    def test_worker_observer_does_not_embed_marker_in_its_argv(self):
        self.assertNotIn(gate.TOKEN_PREFIX, gate.WORKER_PROBE)
        self.assertIn("/proc/$pid/stat", gate.WORKER_PROBE)
        self.assertIn("/proc/$pid/cgroup", gate.WORKER_PROBE)
        self.assertIn("/proc/$pid/ns/cgroup", gate.WORKER_PROBE)

    def test_receipt_is_create_only_and_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipt.json"
            gate.save_new(path, {"result": "OFFLINE_FIXTURE_ONLY"})
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                gate.save_new(path, {"result": "overwrite"})
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaises(gate.GateError):
                gate.save_new(
                    Path(folder) / "large.json", {"value": "a" * gate.MAX_OUTPUT}
                )

    def test_source_guard_rejects_before_lease_or_native(self):
        with (
            patch.object(gate, "sha", return_value="f" * 64),
            patch.object(gate, "Native") as native,
            self.assertRaises(gate.GateError),
        ):
            gate.execute(gate.BUILDKIT_IMAGE, IMAGE_ID, "e" * 64, "a" * 40)
        native.assert_not_called()

    def test_invalid_invocation_owner_is_rejected_before_path_lease_or_native(self):
        for owner in ("a" * 32, OWNER.upper(), OWNER + " ", "../old", "", 1, True):
            with (
                self.subTest(owner=owner),
                patch.object(gate, "strict_path") as path,
                patch.object(gate, "Native") as native,
                patch.object(gate.uuid, "uuid4") as fresh,
                self.assertRaisesRegex(
                    gate.GateError, "EXACT_UUID4_INVOCATION_OWNER_REQUIRED"
                ),
            ):
                gate.execute(
                    gate.BUILDKIT_IMAGE,
                    IMAGE_ID,
                    "e" * 64,
                    "a" * 40,
                    invocation_owner=owner,
                )
            path.assert_not_called()
            native.assert_not_called()
            fresh.assert_not_called()

    def test_explicit_watchdog_owner_binds_only_fresh_exclusive_lease(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(gate, "OPS", Path(folder)),
            patch.object(gate, "sha", return_value="e" * 64),
            patch.object(gate.uuid, "uuid4") as fresh,
            patch.object(gate, "Native") as native,
        ):
            old = Path(folder) / ("run-" + OWNER)
            old.mkdir()
            marker = old / "old-evidence"
            marker.write_bytes(b"immutable")
            with self.assertRaises(gate.GateError):
                gate.execute(
                    gate.BUILDKIT_IMAGE,
                    IMAGE_ID,
                    "e" * 64,
                    "a" * 40,
                    invocation_owner=OWNER,
                )
            self.assertEqual(
                (Path(folder) / "execution.lease").read_bytes(), OWNER.encode()
            )
            self.assertEqual(list(old.iterdir()), [marker])
            self.assertEqual(marker.read_bytes(), b"immutable")
            native.assert_not_called()
            fresh.assert_not_called()

    def test_cli_forwards_explicit_invocation_owner_without_adoption(self):
        with (
            patch.object(gate, "execute", return_value=Path("receipt.json")) as execute,
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            self.assertEqual(
                gate.main(
                    [
                        "--execute",
                        "--confirm",
                        gate.CONFIRM,
                        "--buildkit-image",
                        gate.BUILDKIT_IMAGE,
                        "--image-id",
                        IMAGE_ID,
                        "--expected-source-sha",
                        "e" * 64,
                        "--expected-deploy-sha",
                        "a" * 40,
                        "--invocation-owner",
                        OWNER,
                    ]
                ),
                0,
            )
        self.assertEqual(execute.call_args.kwargs, {"invocation_owner": OWNER})

    def test_existing_lease_cannot_be_adopted_or_removed(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(gate, "OPS", Path(folder)),
            patch.object(gate, "sha", return_value="e" * 64),
        ):
            lease = Path(folder) / "execution.lease"
            lease.write_bytes(b"old-owner")
            with self.assertRaises(FileExistsError):
                gate.execute(gate.BUILDKIT_IMAGE, IMAGE_ID, "e" * 64, "a" * 40)
            self.assertEqual(lease.read_bytes(), b"old-owner")
            self.assertEqual(list(Path(folder).iterdir()), [lease])

    def test_workspace_collision_never_appends_receipt_to_old_run(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(gate, "OPS", Path(folder)),
            patch.object(gate, "sha", return_value="e" * 64),
            patch.object(gate.uuid, "uuid4", return_value=SimpleNamespace(hex=OWNER)),
            patch.object(gate, "Native") as native,
        ):
            old = Path(folder) / ("run-" + OWNER)
            old.mkdir()
            marker = old / "old-evidence"
            marker.write_bytes(b"immutable")
            with self.assertRaises(gate.GateError):
                gate.execute(gate.BUILDKIT_IMAGE, IMAGE_ID, "e" * 64, "a" * 40)
            self.assertEqual(marker.read_bytes(), b"immutable")
            self.assertEqual(list(old.iterdir()), [marker])
            self.assertEqual(
                (Path(folder) / "execution.lease").read_bytes(), OWNER.encode()
            )
            native.assert_not_called()

    def test_early_and_late_failure_share_maximum_twenty_second_cleanup(self):
        for failed_at, expected_end in ((10.0, 30.0), (189.0, 190.0)):
            clock = [10.0]
            observed = []
            with (
                self.subTest(failed_at=failed_at),
                tempfile.TemporaryDirectory() as folder,
                patch.object(gate, "OPS", Path(folder)),
                patch.object(gate, "sha", return_value="e" * 64),
                patch.object(
                    gate.time, "monotonic", side_effect=lambda clock=clock: clock[0]
                ),
                patch.object(gate, "Native") as native,
                patch.object(gate, "Controller") as create_controller,
            ):

                def public_bytes(path, limit=gate.MAX_OUTPUT):
                    if path.name == "HEAD":
                        return b"ref: refs/heads/main"
                    if path.name == "main":
                        return b"a" * 40
                    return path.read_bytes()

                native.return_value.operations = []
                controller = create_controller.return_value
                controller.native = native.return_value
                controller.proofs = {}

                def failure(clock=clock, failed_at=failed_at):
                    clock[0] = failed_at
                    raise gate.GateError("SYNTHETIC_OFFLINE_FAILURE")

                def cleanup(observed=observed, controller=controller):
                    observed.append(controller.deadline)
                    return True

                controller.run.side_effect = failure
                controller.cleanup.side_effect = cleanup
                with (
                    patch.object(gate, "bounded", side_effect=public_bytes),
                    self.assertRaises(gate.GateError),
                ):
                    gate.execute(gate.BUILDKIT_IMAGE, IMAGE_ID, "e" * 64, "a" * 40)
                self.assertEqual(observed, [expected_end])
                receipt = json.loads(
                    next(Path(folder).glob("run-*/receipt.json")).read_text()
                )
                self.assertEqual(receipt["result"], "FAILED_OR_UNKNOWN")

    def test_unknown_create_discovery_empty_preserves_failure(self):
        native = Mock()
        native.call.return_value = (0, "")
        controller = gate.Controller(
            Path("unused"), OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, native, 1000
        )
        controller.intended = True
        with self.assertRaisesRegex(gate.GateError, "CREATION_OUTCOME_UNKNOWN"):
            controller.cleanup()
        self.assertFalse(
            any("rm" in call.args[0] for call in native.call.call_args_list)
        )

    def test_foreign_cleanup_resource_is_never_stopped(self):
        native = Mock()
        wrong = view()
        wrong["Config"]["Labels"][gate.OWNER_LABEL] = "d" * 32
        native.call.return_value = (0, json.dumps(wrong))
        controller = gate.Controller(
            Path("unused"), OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, native, 1000
        )
        controller.cid = CID
        with self.assertRaises(gate.GateError):
            controller.cleanup()
        self.assertEqual(len(native.call.call_args_list), 1)

    def test_one_absolute_cli_cleanup_deadline(self):
        job = Mock()
        job.assigned = True
        job.resumed = True
        job.accounting.return_value = SimpleNamespace(active_processes=0)
        job.kernel.TerminateJobObject.return_value = True
        process = Mock()
        with patch.object(gate.time, "monotonic", side_effect=[10.0, 10.0]):
            self.assertEqual(
                gate.bounded_finish(job, process, 12.0, cancel=True)[
                    "active_processes_after"
                ],
                0,
            )
        process.wait.assert_called_once_with(timeout=2.0)
        job.kernel.TerminateJobObject.assert_called_once()

    def test_insufficient_deadline_refuses_before_cli_launch(self):
        native = object.__new__(gate.Native)
        native.work = Path("unused")
        native.sequence = 0
        native.operations = []
        with (
            patch.object(gate.time, "monotonic", return_value=10),
            patch.object(gate.subprocess, "Popen") as process,
            self.assertRaises(gate.GateError),
        ):
            native.call(["version"], 13.9)
        process.assert_not_called()

    def test_hanging_cli_tree_is_never_accepted(self):
        job = Mock()
        job.assigned = True
        job.resumed = True
        job.accounting.return_value = SimpleNamespace(active_processes=1)
        job.kernel.TerminateJobObject.return_value = True
        with (
            patch.object(gate.time, "monotonic", return_value=12.0),
            self.assertRaisesRegex(gate.GateError, "WINDOWS_TREE_CLEANUP_UNKNOWN"),
        ):
            gate.bounded_finish(job, Mock(), 12.0, cancel=True)

    def test_worker_child_cgroup_namespace_is_not_incorrectly_equalized(self):
        rows = gate.parse_workers(
            "40|200|0::/bounded/worker|cgroup:[2]", "0::/bounded", "cgroup:[1]"
        )
        self.assertEqual(rows[0]["namespace"], "cgroup:[2]")
        with self.assertRaises(gate.GateError):
            gate.parse_workers(
                "40|200|0::/escaped|cgroup:[2]", "0::/bounded", "cgroup:[1]"
            )

    def test_old_worker_start_identity_must_disappear_not_just_argv_marker(self):
        script = gate.exited_worker_script([{"pid": 40, "start_ticks": 200}])
        self.assertIn("/proc/40/stat", script)
        self.assertIn('"200"', script)
        self.assertIn("exit 92", script)
        self.assertIn("awk '{print $20}'", script)
        with self.assertRaises(gate.GateError):
            gate.exited_worker_script([{"pid": True, "start_ticks": 200}])


def worker_metadata() -> list[dict]:
    return [
        {
            "id": "synthetic-mock-only",
            "labels": {
                "org.mobyproject.buildkit.worker.executor": "oci",
                "org.mobyproject.buildkit.worker.snapshotter": "native",
                "org.mobyproject.buildkit.worker.network": "host",
                "org.mobyproject.buildkit.worker.oci.process-mode": "sandbox",
            },
            "buildkitVersion": {
                "package": "github.com/moby/buildkit",
                "version": "v0.32.2",
                "revision": "d" * 40,
            },
            "platforms": [{"os": "linux", "architecture": "amd64"}],
            "cdiDevices": [],
        }
    ]


class FakeNative:
    """Offline protocol fixture only. Never emits a real qualification receipt."""

    def __init__(self, bad: str | None = None):
        self.bad, self.calls, self.operations = bad, [], []
        self.deadlines = []
        self.created = self.removed = self.cancelled = self.stopped = False
        self.kernel_reads = 0
        self.errors = ""

    def last_errors(self):
        return self.errors

    def call(self, args, deadline, *, seconds=10, allow_failure=False):
        self.calls.append(args)
        self.deadlines.append(deadline)
        if args[:3] == ["ps", "-aq", "--no-trunc"]:
            if "--filter" in args:
                return 0, "e" * 64 if self.bad == "existing" else ""
            return 0, CID if self.created and not self.removed else ""
        if args[:3] == ["network", "ls", "-q"] or args[:3] == ["volume", "ls", "-q"]:
            return (
                0,
                "unexpected-volume" if self.removed and self.bad == "inventory" else "",
            )
        if args[:3] == ["image", "ls", "-aq"]:
            return 0, IMAGE_ID
        if args[:2] == ["image", "inspect"]:
            return 0, json.dumps(
                {
                    "Id": IMAGE_ID,
                    "RepoDigests": [
                        "moby/buildkit@" + gate.BUILDKIT_IMAGE.split("@")[1]
                    ],
                    "Architecture": "amd64",
                    "Os": "linux",
                    "Config": {"User": "1000:1000", "Labels": {}},
                }
            )
        if args[0] == "create":
            self.created = True
            return 0, CID
        if args[0] == "start":
            return 0, CID
        if args[0] == "inspect":
            result = view()
            result["State"] = {
                "Running": not self.stopped and self.bad != "dead",
                "Pid": 0 if self.stopped else 1234,
            }
            return 0, json.dumps(result)
        if args[0] == "stop":
            self.stopped = True
            return 0, CID
        if args[0] == "rm":
            self.removed = True
            return 0, CID
        if "debug" in args and "workers" in args:
            meta = worker_metadata()
            if self.bad == "sandbox":
                meta[0]["labels"][
                    "org.mobyproject.buildkit.worker.oci.process-mode"
                ] = "no-sandbox"
            return 0, json.dumps(meta)
        if args[0] == "exec" and "-d" in args:
            return 0, ""
        if "buildctl" in args:
            if "filename=Dockerfile.fault" in args:
                self.errors = (
                    "KAIROS_SYNTHETIC_FAULT37; process failed: exit code: 37"
                    if self.bad != "fault"
                    else "unrelated Docker connection failed"
                )
                return 1, ""
            return 0, ""
        script = args[-1]
        if script == gate.CGROUP_PROBE:
            self.kernel_reads += 1
            throttled = 5 if self.kernel_reads == 1 or self.bad == "cpu" else 8
            return (
                0,
                f"100000 100000\n{gate.MEMORY}\n0\n128\n{throttled}\n{123 + self.kernel_reads}\ncgroup:[1234]",
            )
        if script == "cat /proc/1/cgroup":
            return 0, "0::/bounded"
        if script.startswith("set -eu; umask 077; mkdir "):
            return (
                0,
                "a" * 64
                + "  "
                + gate.ROOT
                + "/context/bin/busybox\n"
                + "b" * 64
                + "  "
                + gate.ROOT
                + "/context/lib/ld-musl-x86_64.so.1",
            )
        if script.startswith("sha256sum "):
            return 0, hashlib.sha256(
                gate.PAYLOAD
            ).hexdigest() + "  " + gate.ROOT + "/result-success/result"
        if script == gate.WORKER_PROBE:
            return (
                0,
                ""
                if self.cancelled and self.bad != "orphan"
                else "40|200|0::/bounded/worker|cgroup:[2]\n41|201|0::/bounded/worker|cgroup:[2]",
            )
        if "kill -TERM" in script:
            self.cancelled = True
            return 0, ""
        if "client.exit" in script:
            return 0, "0" if self.bad == "status" else "143"
        if "exit 92" in script:
            return (92, "") if self.bad == "oldpid" else (0, "")
        raise AssertionError("Unexpected offline protocol operation")


class LifecycleTests(unittest.TestCase):
    def setup_controller(self, folder, bad=None):
        return gate.Controller(
            Path(folder), OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, FakeNative(bad), 160
        )

    def fake_clock(self):
        state = [0.0]

        def monotonic():
            state[0] += 0.2
            return state[0]

        return monotonic

    def test_complete_offline_protocol_contains_actual_linux_cancel_stimulus(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(gate.time, "monotonic", side_effect=self.fake_clock()),
            patch.object(gate.time, "sleep"),
        ):
            controller = self.setup_controller(folder)
            controller.run()
            self.assertTrue(controller.proofs["fresh_build_after_cancel"])
            self.assertEqual(controller.proofs["workers_after_cancel"], [])
            self.assertEqual(len(controller.proofs["workers_before_cancel"]), 2)
            self.assertTrue(
                any("kill -TERM" in args[-1] for args in controller.native.calls)
            )
            cancel = next(
                args[-1] for args in controller.native.calls if "kill -TERM" in args[-1]
            )
            self.assertIn("/client.start", cancel)
            self.assertIn('[ "$actual" = "$expected" ] || exit 91', cancel)
            self.assertEqual(controller.proofs["kernel_under_load"]["pids_max"], 128)
            local_calls = [
                deadline
                for args, deadline in zip(
                    controller.native.calls, controller.native.deadlines, strict=True
                )
                if "debug" in args
                or args[-1] == gate.WORKER_PROBE
                or args[-1].startswith("test -f " + gate.ROOT + "/client.exit")
                or "exit 92" in args[-1]
            ]
            self.assertTrue(local_calls)
            self.assertTrue(
                all(deadline < controller.deadline for deadline in local_calls)
            )
            self.assertTrue(controller.cleanup())
            self.assertTrue(controller.native.removed)
            self.assertFalse(
                any(
                    args[0] in {"buildx", "pull", "prune"}
                    for args in controller.native.calls
                )
            )

    def test_late_ready_worker_or_cancel_result_cannot_be_accepted(self):
        for phase, category in (
            ("ready", "OWNED_BUILDKIT_READY_TIMEOUT"),
            ("worker", "REAL_SYNTHETIC_WORKERS_NOT_OBSERVED"),
            ("cancel", "LINUX_SERVER_CANCELLATION_UNPROVEN"),
        ):
            clock = [0.0]
            with (
                self.subTest(phase=phase),
                tempfile.TemporaryDirectory() as folder,
                patch.object(
                    gate.time, "monotonic", side_effect=lambda clock=clock: clock[0]
                ),
                patch.object(gate.time, "sleep"),
            ):
                controller = self.setup_controller(folder)
                original = controller.native.call

                def late(
                    args,
                    deadline,
                    *,
                    seconds=10,
                    allow_failure=False,
                    original=original,
                    controller=controller,
                    phase=phase,
                    clock=clock,
                ):
                    result = original(
                        args, deadline, seconds=seconds, allow_failure=allow_failure
                    )
                    ready = "debug" in args
                    worker = (
                        args[-1] == gate.WORKER_PROBE
                        and not controller.native.cancelled
                    )
                    cancel = "exit 92" in args[-1]
                    if (
                        (phase == "ready" and ready)
                        or (phase == "worker" and worker)
                        or (phase == "cancel" and cancel)
                    ):
                        self.assertLess(deadline, controller.deadline)
                        clock[0] = deadline + 0.01
                    return result

                controller.native.call = late
                with self.assertRaisesRegex(gate.GateError, category):
                    controller.run()
                self.assertNotIn("fresh_build_after_cancel", controller.proofs)

    def test_cpu_counter_metadata_alone_does_not_qualify(self):
        self.assert_stage_rejected("cpu", "ACTUAL_SERVER_CPU_ENFORCEMENT_UNPROVEN")

    def test_unrelated_cli_error_is_not_synthetic_fault(self):
        self.assert_stage_rejected("fault", "SYNTHETIC_FAULT_NOT_REJECTED")

    def test_disabled_actual_sandbox_is_rejected(self):
        self.assert_stage_rejected("sandbox", "ACTUAL_WORKER_MODE_CHANGED")

    def test_surviving_marker_worker_blocks_cancellation(self):
        self.assert_stage_rejected("orphan", "LINUX_SERVER_CANCELLATION_UNPROVEN")

    def test_surviving_old_pid_start_blocks_cancellation_even_marker_disappears(self):
        self.assert_stage_rejected("oldpid", "LINUX_SERVER_CANCELLATION_UNPROVEN")

    def test_zero_client_exit_blocks_false_cancellation_claim(self):
        self.assert_stage_rejected("status", "LINUX_SERVER_CANCELLATION_UNPROVEN")

    def test_dead_server_is_not_successful_worker_cancellation(self):
        self.assert_stage_rejected("dead", "SERVER_DIED_INSTEAD_OF_CANCELLING_WORKERS")

    def test_existing_scope_blocks_duplicate_before_create(self):
        self.assert_stage_rejected(
            "existing", "EXISTING_SCOPE_NO_DUPLICATE_OR_ADOPTION"
        )

    def test_unrelated_resource_drift_is_not_silently_cleaned_up(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(gate.time, "monotonic", side_effect=self.fake_clock()),
            patch.object(gate.time, "sleep"),
        ):
            controller = self.setup_controller(folder, "inventory")
            controller.run()
            with self.assertRaisesRegex(
                gate.GateError, "UNRELATED_RESOURCE_INVENTORY_CHANGED"
            ):
                controller.cleanup()
            self.assertTrue(controller.native.removed)
            self.assertFalse(
                any(
                    args[0] == "volume" and "rm" in args
                    for args in controller.native.calls
                )
            )

    def assert_stage_rejected(self, bad, category):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.object(gate.time, "monotonic", side_effect=self.fake_clock()),
            patch.object(gate.time, "sleep"),
        ):
            controller = self.setup_controller(folder, bad)
            with self.assertRaisesRegex(gate.GateError, category):
                controller.run()
            self.assertNotIn("fresh_build_after_cancel", controller.proofs)
            if bad == "existing":
                self.assertFalse(controller.native.created)
            self.assertTrue(controller.cleanup())

    def test_multiple_workers_and_wrong_actual_release_are_rejected(self):
        for mutate in (
            lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows[0]["buildkitVersion"].update(version="v0.32.1"),
            lambda rows: rows[0].update(cdiDevices=[{"name": "gpu"}]),
        ):
            rows = worker_metadata()
            mutate(rows)
            with self.assertRaises(gate.GateError):
                gate.worker_info(json.dumps(rows))


if __name__ == "__main__":
    unittest.main()
