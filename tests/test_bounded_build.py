from __future__ import annotations

import copy
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import bounded_build as bounded

gate = bounded.gate
OWNER = "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
IMAGE_ID = "sha256:" + "b" * 64
TOOLS = {name: "f" * 64 for name in bounded.TOOLS}
DAEMON = {"pid": 29, "start_ticks": 100, "mount_namespace_inode": 600}


def registration() -> dict:
    name = bounded.builder_name(OWNER)
    return {
        "Name": name,
        "Driver": "remote",
        "Dynamic": False,
        "Nodes": [
            {
                "Name": name + "0",
                "Endpoint": bounded.remote_endpoint(OWNER),
                "Platforms": [{"os": "linux", "architecture": "amd64"}],
                "DriverOpts": {"default-load": "false"},
                "Flags": None,
                "Files": None,
            }
        ],
    }


def capacity() -> str:
    rows = ["I|before|29|100|mnt:[600]"]
    for domain in ("container", "daemon"):
        for path, size in bounded.CAPACITIES.items():
            blocks = size // 4096
            rows.append(f"F|{domain}|{path}|4096|{blocks}|{blocks - 1}|100000|99999")
    rows.append("I|after|29|100|mnt:[600]")
    return "\n".join(rows)


def image_view() -> dict:
    return {
        "Id": IMAGE_ID,
        "Os": "linux",
        "Architecture": "amd64",
        "Size": 1_000_000,
        "Config": {
            "Labels": {
                bounded.OWNER_LABEL: OWNER,
                bounded.SCOPE_LABEL: bounded.KIND,
                "com.docker.compose.project": bounded.builder_name(OWNER),
                "com.docker.compose.service": bounded.TARGET,
                "com.docker.compose.version": "2.40.1",
            }
        },
        "RepoTags": [bounded.image_tag(OWNER)],
        "RepoDigests": [],
    }


def write_registration(work: Path) -> None:
    (work / "buildx-config/instances").mkdir(parents=True)
    (work / "buildx-config/defaults").mkdir()
    (work / "buildx-config/instances" / bounded.builder_name(OWNER)).write_text(
        json.dumps(registration())
    )
    (work / "docker-config").mkdir()
    (work / "docker-config/config.json").write_text(json.dumps(bounded.config()))


class ContractTests(unittest.TestCase):
    def test_environment_never_enumerates_or_reads_other_values(self):
        requested = []

        class PublicPathsOnly:
            def get(self, key):
                requested.append(key)
                if key not in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}:
                    raise AssertionError("UNSCOPED_VALUE_READ")
                return "C:/Windows" if key in {"SYSTEMROOT", "WINDIR"} else "C:/Temp"

            def items(self):
                raise AssertionError("ENVIRONMENT_VALUE_ENUMERATION")

        with patch.object(bounded.os, "environ", PublicPathsOnly()):
            result = bounded.environment(Path("."))
        self.assertEqual(requested, ["SYSTEMROOT", "WINDIR", "TEMP", "TMP"])
        self.assertNotIn("OPENAI_API_KEY", result)
        self.assertEqual(result["DOCKER_HOST"], gate.ENDPOINT)

    def test_default_plan_has_no_native_or_filesystem_effects(self):
        with (
            patch.object(bounded, "execute") as execute,
            patch.object(gate, "strict_path") as paths,
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(bounded.main([]), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value["mode"], "PLAN_ONLY_DEFAULT_DENY")
        self.assertFalse(value["production_build_qualified"])
        execute.assert_not_called()
        paths.assert_not_called()

    def test_execute_requires_distinct_explicit_confirmation(self):
        with (
            patch.object(bounded, "execute") as execute,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(bounded.main(["--execute", "--confirm", gate.CONFIRM]), 1)
        execute.assert_not_called()

    def test_owner_rejects_non_uuid4_before_io(self):
        for value in (
            "a" * 32,
            OWNER.upper(),
            "../escape",
            "aaaaaaaaaaaa4aaa7aaaaaaaaaaaaaaa",
            5,
        ):
            with (
                self.subTest(value=value),
                patch.object(gate, "strict_path") as paths,
                self.assertRaises(gate.GateError),
            ):
                bounded.execute(
                    "a" * 64, "b" * 40, TOOLS, IMAGE_ID, invocation_owner=value
                )
            paths.assert_not_called()

    def test_private_remote_does_not_select_default_or_create_builder_container(self):
        args = bounded.registration_arguments(OWNER)
        self.assertEqual(args[args.index("--driver") + 1], "remote")
        self.assertEqual(args[-1], "docker-container://" + gate.owner_name(OWNER))
        for denied in (
            "--use",
            "--append",
            "--bootstrap",
            "--buildkitd-flags",
            "--buildkitd-config",
            "--allow",
        ):
            self.assertNotIn(denied, args)
        self.assertEqual(args[args.index("--driver-opt") + 1], "default-load=false")

    def test_resource_arguments_are_identical_to_reviewed_rootless_contract(self):
        args = gate.create_arguments(OWNER, IMAGE_ID)
        for value in (
            "--network=none",
            "--read-only",
            "--user=1000:1000",
            "--memory=1g",
            "--memory-swap=1g",
            "--cpus=1",
            "--pids-limit=128",
            "--pull=never",
        ):
            self.assertIn(value, args)
        for value in ("--privileged", "--volume", "--mount", "--publish"):
            self.assertNotIn(value, args)
        self.assertIn("noProcessSandbox = false", gate.CONFIG)
        self.assertIn("max-parallelism = 1", gate.CONFIG)

    def test_private_environment_excludes_secrets_home_proxy_and_caller_builder(self):
        with (
            tempfile.TemporaryDirectory() as folder,
            patch.dict(
                os.environ,
                {
                    "SystemRoot": "C:/Windows",
                    "OPENAI_API_KEY": "not-a-real-key",
                    "USERPROFILE": "private-home",
                    "HTTP_PROXY": "private-proxy",
                    "BUILDX_BUILDER": "default",
                    "DOCKER_CONTEXT": "foreign",
                },
                clear=True,
            ),
        ):
            result = bounded.environment(Path(folder))
        for value in (
            "OPENAI_API_KEY",
            "USERPROFILE",
            "HTTP_PROXY",
            "BUILDX_BUILDER",
            "DOCKER_CONTEXT",
        ):
            self.assertNotIn(value, result)
        self.assertEqual(result["DOCKER_HOST"], gate.ENDPOINT)
        self.assertTrue(result["DOCKER_CONFIG"].endswith("docker-config"))
        self.assertTrue(result["BUILDX_CONFIG"].endswith("buildx-config"))
        self.assertEqual(result["COMPOSE_BAKE"], "false")
        self.assertEqual(result["COMPOSE_PARALLEL_LIMIT"], "1")
        self.assertEqual(result["PATHEXT"], ".COM;.EXE;.BAT;.CMD")

    def test_registration_refuses_extra_nodes_flags_endpoint_defaults_or_wrong_types(
        self,
    ):
        bounded.verify_registration(registration(), OWNER)
        mutations = [
            lambda v: v.update(Driver="docker-container"),
            lambda v: v.update(Dynamic=0),
            lambda v: v.update(unknown=True),
            lambda v: v["Nodes"].append(copy.deepcopy(v["Nodes"][0])),
            lambda v: v["Nodes"][0].update(Endpoint="tcp://unapproved:1234"),
            lambda v: v["Nodes"][0].update(DriverOpts={"default-load": "true"}),
            lambda v: v["Nodes"][0].update(Flags=["--oci-worker-no-process-sandbox"]),
            lambda v: v["Nodes"][0].update(Files={"secret": "unapproved"}),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = registration()
                mutate(value)
                with self.assertRaises(gate.GateError):
                    bounded.verify_registration(value, OWNER)

    def test_empty_buildx_defaults_directory_is_legitimate_but_selection_is_denied(
        self,
    ):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            write_registration(work)
            controller = bounded.Controller(
                work, OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, Mock(), 1000
            )
            controller.registration()
            (work / "buildx-config/current").write_text(
                json.dumps({"Key": gate.ENDPOINT, "Name": "", "Global": False})
            )
            controller.registration()
            (work / "buildx-config/defaults/selection").write_text("default")
            with self.assertRaisesRegex(gate.GateError, "DEFAULT_BUILDER"):
                controller.registration()

    def test_selected_current_builder_is_denied_even_in_private_store(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            write_registration(work)
            (work / "buildx-config/current").write_text(
                json.dumps({"Key": gate.ENDPOINT, "Name": "default", "Global": False})
            )
            controller = bounded.Controller(
                work, OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, Mock(), 1000
            )
            with self.assertRaisesRegex(gate.GateError, "DEFAULT_BUILDER"):
                controller.registration()

    def test_fixture_has_one_explicit_build_target_no_runtime_or_remote_inputs(self):
        for case in bounded.CASES:
            with self.subTest(case=case):
                dockerfile, value = bounded.fixture_documents(
                    Path("public-fixture"), OWNER, case
                )
                self.assertTrue(dockerfile.startswith("FROM scratch\n"))
                for denied in (
                    "#syntax",
                    "ADD ",
                    "http://",
                    "https://",
                    "--mount=",
                    "USER root",
                ):
                    self.assertNotIn(denied, dockerfile)
                self.assertIn("COPY --chmod=0755 skeleton/ /", dockerfile)
                self.assertIn("COPY --chmod=0555 bin/busybox", dockerfile)
                self.assertIn("COPY --chmod=0444 payload", dockerfile)
                self.assertEqual(set(value["services"]), {bounded.TARGET})
                service = value["services"][bounded.TARGET]
                self.assertEqual(
                    set(service), {"image", "platform", "pull_policy", "build"}
                )
                self.assertEqual(service["pull_policy"], "never")
                self.assertEqual(service["build"]["network"], "none")
                self.assertFalse(service["build"]["pull"])
                self.assertFalse(service["build"]["provenance"])
                self.assertFalse(service["build"]["sbom"])
                args = bounded.compose_arguments(Path("fixture"), OWNER, case)
                self.assertEqual(args[-1], bounded.TARGET)
                self.assertEqual(
                    args[args.index("--builder") + 1], bounded.builder_name(OWNER)
                )
                for denied in (
                    "up",
                    "run",
                    "push",
                    "--pull",
                    "--with-dependencies",
                    "--build-arg",
                    "--ssh",
                ):
                    self.assertNotIn(denied, args)

    def test_arbitrary_case_or_compose_file_not_exposed(self):
        for case in ("PAPER", "../../Dockerfile", "success --pull", "LIVE", "build"):
            with self.subTest(case=case), self.assertRaises(gate.GateError):
                bounded.compose_arguments(Path("fixture"), OWNER, case)

    def test_actual_statfs_capacity_and_stable_daemon_are_required(self):
        value = bounded.parse_capacity(capacity(), DAEMON)
        self.assertEqual(
            value["daemon"][gate.MOUNT_DATA]["capacity_bytes"], 512 * 1024**2
        )
        mutations = [
            capacity().replace("|131072|", "|131073|", 1),
            capacity().replace("I|after|29|100", "I|after|29|101"),
            capacity().replace("F|daemon|/tmp", "F|daemon|/unknown"),
            capacity().replace("|100000|99999", "|100000|100001", 1),
            capacity() + "\n" + capacity().splitlines()[1],
            capacity().replace("|4096|", "|4096.0|", 1),
            capacity().replace("|4096|", "|8192|", 1),
        ]
        for text in mutations:
            with self.subTest(text=text[:80]), self.assertRaises(gate.GateError):
                bounded.parse_capacity(text, DAEMON)

    def test_transport_probe_and_signal_use_exact_pid_start_command_and_uid(self):
        rows = bounded.parse_transports("72|900\n73|901")
        script = bounded.cancel_transport_script(rows)
        self.assertIn("/proc/72/comm", script)
        self.assertIn("/proc/72/stat", script)
        self.assertIn("buildctl dial-stdio ", script)
        self.assertIn("= 1000", script)
        self.assertLess(script.index("/proc/73/status"), script.index("kill -TERM 72"))
        self.assertIn("kill -TERM 73", script)
        self.assertNotIn("kill -KILL", script)
        self.assertNotIn("buildkitd", script)
        self.assertIn('[ "$comm" = buildctl ]', bounded.TRANSPORT_PROBE)

    def test_transport_identity_rejects_empty_duplicate_and_injected_pid(self):
        for value in (
            "",
            "1|9",
            "72|9\n72|10",
            "72;kill|9",
            "72|0",
            "\n".join(f"{i}|9" for i in range(10, 15)),
        ):
            with self.subTest(value=value), self.assertRaises(gate.GateError):
                bounded.parse_transports(value)

    def test_image_cleanup_identity_has_no_foreign_tags_labels_volumes_or_oversize(
        self,
    ):
        self.assertEqual(bounded.verify_image(image_view(), OWNER, "2.40.1"), IMAGE_ID)
        for mutate in (
            lambda v: v.update(Size=True),
            lambda v: v.update(Size=bounded.MAX_IMAGE + 1),
            lambda v: v.update(RepoTags=[bounded.image_tag(OWNER), "unrelated:latest"]),
            lambda v: v.update(RepoDigests=["unrelated@sha256:" + "a" * 64]),
            lambda v: v["Config"].update(Volumes={"/data": {}}),
            lambda v: v["Config"]["Labels"].update(extra="foreign"),
            lambda v: v["Config"]["Labels"].update(
                {"com.docker.compose.project": "other"}
            ),
        ):
            with self.subTest(mutate=mutate):
                value = image_view()
                mutate(value)
                with self.assertRaises(gate.GateError):
                    bounded.verify_image(value, OWNER, "2.40.1")

    def test_containerd_single_self_repository_digest_must_equal_image_id(self):
        own = bounded.image_tag(OWNER).split(":", 1)[0] + "@" + IMAGE_ID
        value = image_view()
        value["RepoDigests"] = [own]
        self.assertEqual(bounded.verify_image(value, OWNER, "2.40.1"), IMAGE_ID)
        for digests in (
            [own, own],
            [own, "foreign@" + IMAGE_ID],
            ["foreign@" + IMAGE_ID],
            [bounded.image_tag(OWNER).split(":", 1)[0] + "@sha256:" + "c" * 64],
            [bounded.image_tag(OWNER) + "@" + IMAGE_ID],
            (own,),
            own,
        ):
            with self.subTest(digests=digests), self.assertRaises(gate.GateError):
                bounded.verify_image(value | {"RepoDigests": digests}, OWNER, "2.40.1")

    def test_owned_image_inspector_branch_is_recorded_only_after_full_verification(
        self,
    ):
        controller = bounded.Controller(
            Path("D:/public"), OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, Mock(), 100
        )
        controller.compose_version = "2.40.1"
        value = image_view()
        own = bounded.image_tag(OWNER).split(":", 1)[0] + "@" + IMAGE_ID
        value["RepoDigests"] = [own]
        with patch.object(
            controller, "call", side_effect=[(0, IMAGE_ID), (0, json.dumps(value))]
        ):
            self.assertEqual(controller.owned_images(), [IMAGE_ID])
        self.assertEqual(
            controller.proofs["owned_image_identity"][IMAGE_ID],
            {
                "inspector_form": "OCI_SELF_REPOSITORY_DIGEST",
                "repo_digests": [own],
                "repo_tags": [bounded.image_tag(OWNER)],
            },
        )
        prior = copy.deepcopy(controller.proofs)
        value["RepoDigests"] = ["foreign@" + IMAGE_ID]
        with (
            patch.object(
                controller, "call", side_effect=[(0, IMAGE_ID), (0, json.dumps(value))]
            ),
            self.assertRaises(gate.GateError),
        ):
            controller.owned_images()
        self.assertEqual(controller.proofs, prior)

    def test_context_rejects_extra_dotenv_before_build(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            context = work / "context"
            context.mkdir()
            (context / ".env").write_text("not-a-secret")
            controller = bounded.Controller(
                work, OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, Mock(), 1000
            )
            with self.assertRaisesRegex(gate.GateError, "CONTEXT_ALLOWLIST"):
                controller.fixture_hashes()


class ExecutionBoundaryTests(unittest.TestCase):
    def test_shared_existing_lease_is_never_adopted_or_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ops, shared = root / "new-ops", root / "shared"
            ops.mkdir()
            shared.mkdir()
            lease = shared / "execution.lease"
            lease.write_bytes(b"foreign-owner")
            with (
                patch.object(bounded, "OPS", ops),
                patch.object(gate, "OPS", shared),
                patch.object(
                    bounded,
                    "source_bindings",
                    return_value={
                        "adapter": "e" * 64,
                        "resource_gate": bounded.GATE_SHA,
                        "windows_job": gate.JOB_SHA,
                    },
                ),
                patch.object(bounded, "tool_bindings", return_value=TOOLS),
                self.assertRaises(FileExistsError),
            ):
                bounded.execute(
                    "e" * 64, "a" * 40, TOOLS, IMAGE_ID, invocation_owner=OWNER
                )
            self.assertEqual(lease.read_bytes(), b"foreign-owner")
            self.assertEqual(list(ops.iterdir()), [])

    def test_changed_cancel_context_never_dispatches_process(self):
        controller = bounded.Controller(
            Path("unused"), OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, Mock(), 1000
        )
        controller.proofs["fixture_hashes"] = {"payload": "a" * 64}
        with (
            patch.object(controller, "registration"),
            patch.object(
                controller, "fixture_hashes", return_value={"payload": "b" * 64}
            ),
            patch.object(bounded, "Process") as process,
            self.assertRaises(gate.GateError),
        ):
            controller.start_cancel(500)
        process.assert_not_called()

    def test_workspace_collision_never_appends_to_old_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ops, shared = root / "new-ops", root / "shared"
            ops.mkdir()
            shared.mkdir()
            previous = ops / ("run-" + OWNER)
            previous.mkdir()
            marker = previous / "immutable"
            marker.write_bytes(b"old")
            with (
                patch.object(bounded, "OPS", ops),
                patch.object(gate, "OPS", shared),
                patch.object(
                    bounded,
                    "source_bindings",
                    return_value={
                        "adapter": "e" * 64,
                        "resource_gate": bounded.GATE_SHA,
                        "windows_job": gate.JOB_SHA,
                    },
                ),
                patch.object(bounded, "tool_bindings", return_value=TOOLS),
                patch.object(bounded, "Native") as native,
                self.assertRaises(gate.GateError),
            ):
                bounded.execute(
                    "e" * 64, "a" * 40, TOOLS, IMAGE_ID, invocation_owner=OWNER
                )
            native.assert_not_called()
            self.assertEqual(list(previous.iterdir()), [marker])
            self.assertEqual(marker.read_bytes(), b"old")
            self.assertEqual((shared / "execution.lease").read_bytes(), OWNER.encode())

    def test_early_and_late_failures_do_not_extend_twenty_second_cleanup(self):
        for failed_at, expected in ((10.0, 30.0), (189.0, 190.0)):
            with (
                self.subTest(failed_at=failed_at),
                tempfile.TemporaryDirectory() as folder,
            ):
                root = Path(folder)
                ops, shared = root / "new-ops", root / "shared"
                ops.mkdir()
                shared.mkdir()
                clock = [10.0]
                ends = []

                def read(path, limit=gate.MAX_OUTPUT):
                    if path.name == "HEAD":
                        return b"ref: refs/heads/main"
                    if path.name == "main":
                        return b"a" * 40
                    return path.read_bytes()

                def fail(clock=clock, failed_at=failed_at):
                    clock[0] = failed_at
                    raise gate.GateError("OFFLINE_SYNTHETIC_FAILURE")

                with (
                    patch.object(bounded, "OPS", ops),
                    patch.object(gate, "OPS", shared),
                    patch.object(
                        bounded,
                        "source_bindings",
                        return_value={
                            "adapter": "e" * 64,
                            "resource_gate": bounded.GATE_SHA,
                            "windows_job": gate.JOB_SHA,
                        },
                    ),
                    patch.object(bounded, "tool_bindings", return_value=TOOLS),
                    patch.object(gate, "bounded", side_effect=read),
                    patch.object(
                        bounded.time,
                        "monotonic",
                        side_effect=lambda clock=clock: clock[0],
                    ),
                    patch.object(bounded, "Native") as native,
                    patch.object(bounded, "Controller") as create,
                ):
                    controller = create.return_value
                    controller.native = native.return_value
                    native.return_value.operations = []
                    controller.proofs = {}
                    controller.run.side_effect = fail
                    controller.cleanup.side_effect = (
                        lambda ends=ends, controller=controller: (
                            ends.append(controller.deadline) or True
                        )
                    )
                    with self.assertRaises(gate.GateError):
                        bounded.execute(
                            "e" * 64, "a" * 40, TOOLS, IMAGE_ID, invocation_owner=OWNER
                        )
                self.assertEqual(ends, [expected])
                receipt = json.loads(next(ops.glob("run-*/receipt.json")).read_text())
                self.assertEqual(receipt["result"], "FAILED_OR_UNKNOWN")
                self.assertTrue(receipt["owned_cleanup_verified"])
                self.assertFalse(receipt["production_build_qualified"])
                self.assertFalse((shared / "execution.lease").exists())

    def test_unacknowledged_create_missing_from_discovery_is_unknown_not_clean(self):
        native = Mock()
        native.operations = []
        native.processes = []
        native.call.return_value = (0, "")
        controller = bounded.Controller(
            Path("unused"), OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, native, 1000
        )
        controller.intended = True
        with self.assertRaisesRegex(gate.GateError, "CREATION_OUTCOME_UNKNOWN"):
            controller.cleanup()
        self.assertFalse(
            any("rm" in call.args[0] for call in native.call.call_args_list)
        )

    def test_public_baseline_and_compose_identity_are_saved_before_create(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            native = Mock()
            native.operations = native.processes = []
            baseline = {
                key: [] for key in ("containers", "networks", "volumes", "images")
            }
            image = {
                "Id": IMAGE_ID,
                "RepoDigests": [gate.BUILDKIT_IMAGE],
                "Os": "linux",
                "Architecture": "amd64",
                "Config": {"User": "1000:1000", "Labels": {}},
            }

            def call(args, deadline, **kwargs):
                if args[:2] == ["image", "inspect"]:
                    return 0, json.dumps(image)
                if args[:2] == ["compose", "version"]:
                    return 0, "2.40.1"
                if args[0] == "create":
                    self.assertEqual(
                        json.loads((work / "baseline.json").read_text()), baseline
                    )
                    self.assertEqual(
                        json.loads((work / "public-tools.json").read_text())[
                            "compose_version"
                        ],
                        "2.40.1",
                    )
                    raise gate.GateError("OFFLINE_STOP_BEFORE_NATIVE_CREATE")
                return 0, ""

            native.call.side_effect = call
            controller = bounded.Controller(
                work, OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, native, 1000
            )
            controller.inventory = Mock(return_value=baseline)
            with self.assertRaisesRegex(gate.GateError, "OFFLINE_STOP"):
                controller.run()
            self.assertEqual(controller.proofs["compose_version"], "2.40.1")
            self.assertTrue((work / "create.intent.json").is_file())

    def test_unacknowledged_image_absence_is_unknown_not_success(self):
        native = Mock()
        native.operations = []
        native.processes = []
        controller = bounded.Controller(
            Path("unused"), OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, native, 1000
        )
        controller.image_intended = True
        controller.owned_images = Mock(return_value=[])
        with self.assertRaisesRegex(gate.GateError, "IMAGE_CREATION_OUTCOME_UNKNOWN"):
            controller.cleanup()

    def test_foreign_image_consumer_prevents_image_removal(self):
        native = Mock()
        native.operations = []
        native.processes = []
        native.call.return_value = (0, "foreign-container")
        controller = bounded.Controller(
            Path("unused"), OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, native, 1000
        )
        controller.image_intended = controller.image_acknowledged = True
        controller.owned_images = Mock(return_value=[IMAGE_ID])
        with self.assertRaisesRegex(gate.GateError, "UNEXPECTED_CONSUMER"):
            controller.cleanup()
        self.assertFalse(
            any(
                call.args[0][:2] == ["image", "rm"]
                for call in native.call.call_args_list
            )
        )

    def test_unknown_windows_tree_cannot_be_reclassified_by_repeated_finish(self):
        process = bounded.Process.__new__(bounded.Process)
        process.done = True
        process.record = {"cli_tree": None, "overflow": False, "exit_code": 125}
        with self.assertRaisesRegex(gate.GateError, "CLI_TREE_CLEANUP_UNKNOWN"):
            process.finish(cancel=True)

    def test_process_admission_reserves_tree_budget_before_creating_files(self):
        with (
            patch.object(bounded.time, "monotonic", return_value=10),
            patch.object(subprocess_stub := bounded.subprocess, "Popen") as popen,
        ):
            for deadline, seconds in (
                (14, 10),
                (15, 0),
                (float("inf"), 1),
                (20, float("nan")),
            ):
                with (
                    self.subTest(deadline=deadline, seconds=seconds),
                    self.assertRaises(gate.GateError),
                ):
                    bounded.Process(Mock(), ["version"], deadline, seconds)
            popen.assert_not_called()
        self.assertIs(subprocess_stub, bounded.subprocess)

    def test_native_plugin_tree_is_suspended_assigned_then_proved_empty(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            job = Mock()
            job.creation_flags = 0x08000004
            process = Mock()
            process.returncode = 0
            process.poll.return_value = 0
            native = SimpleNamespace(
                work=work,
                sequence=0,
                operations=[],
                processes=[],
                module=SimpleNamespace(WindowsProcessJob=Mock(return_value=job)),
            )
            with (
                patch.object(bounded.time, "monotonic", return_value=10),
                patch.object(
                    bounded.subprocess, "Popen", return_value=process
                ) as popen,
                patch.object(
                    bounded, "environment", return_value={"DOCKER_HOST": gate.ENDPOINT}
                ),
                patch.object(
                    gate,
                    "bounded_finish",
                    return_value={
                        "assigned_before_resume": True,
                        "active_processes_after": 0,
                    },
                ) as finish,
            ):
                owned = bounded.Process(
                    native, ["compose", "version", "--short"], 20, 6
                )
                self.assertEqual(owned.poll(), 0)
                value = owned.finish()
            job.attach_and_resume.assert_called_once_with(process)
            self.assertEqual(popen.call_args.kwargs["creationflags"], 0x08000004)
            self.assertFalse(popen.call_args.kwargs["shell"])
            self.assertEqual(
                popen.call_args.args[0][:5],
                [
                    str(gate.DOCKER),
                    "--config",
                    str(work / "docker-config"),
                    "--host",
                    gate.ENDPOINT,
                ],
            )
            self.assertEqual(finish.call_args.args, (job, process, 14))
            self.assertEqual(value["cli_tree"]["active_processes_after"], 0)
            self.assertEqual(native.operations, [value])
            job.close.assert_called_once()

    def test_process_overflow_is_failed_even_if_job_cleanup_succeeds(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            job = Mock()
            job.creation_flags = 0x08000004
            process = Mock(returncode=125)
            process.poll.return_value = None
            native = SimpleNamespace(
                work=work,
                sequence=0,
                operations=[],
                processes=[],
                module=SimpleNamespace(WindowsProcessJob=Mock(return_value=job)),
            )
            with (
                patch.object(bounded.time, "monotonic", return_value=10),
                patch.object(bounded.subprocess, "Popen", return_value=process),
                patch.object(bounded, "environment", return_value={}),
                patch.object(
                    gate,
                    "bounded_finish",
                    return_value={
                        "assigned_before_resume": True,
                        "active_processes_after": 0,
                    },
                ),
            ):
                owned = bounded.Process(
                    native, ["exec", "id", "sh", "-c", bounded.CAPACITY_PROBE], 20, 6
                )
                self.assertEqual(owned.output_limit, 8192)
                owned.out.write(b"x" * 8193)
                owned.out.flush()
                with self.assertRaisesRegex(gate.GateError, "OUTPUT_BOUNDARY"):
                    owned.poll()
                with self.assertRaisesRegex(gate.GateError, "CLI_TREE_CLEANUP_UNKNOWN"):
                    owned.finish(cancel=True)
            self.assertTrue(native.operations[0]["overflow"])

    def test_uncertain_cli_history_prevents_positive_cleanup_classification(self):
        native = Mock()
        native.operations = [{"cli_tree": None, "overflow": False}]
        native.processes = []
        controller = bounded.Controller(
            Path("unused"), OWNER, gate.BUILDKIT_IMAGE, IMAGE_ID, native, 1000
        )
        controller.baseline = {"images": []}
        controller.inventory = Mock(return_value=controller.baseline)
        with self.assertRaisesRegex(gate.GateError, "CLI_TREE_CLEANUP_UNKNOWN"):
            controller.cleanup()

    def test_cli_routed_hashes_owner_and_image_explicitly(self):
        with (
            patch.object(
                bounded, "execute", return_value=Path("receipt.json")
            ) as execute,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                bounded.main(
                    [
                        "--execute",
                        "--confirm",
                        bounded.CONFIRM,
                        "--expected-source-sha",
                        "e" * 64,
                        "--expected-deploy-sha",
                        "a" * 40,
                        "--docker-sha",
                        TOOLS["docker"],
                        "--buildx-sha",
                        TOOLS["buildx"],
                        "--compose-sha",
                        TOOLS["compose"],
                        "--image-id",
                        IMAGE_ID,
                        "--invocation-owner",
                        OWNER,
                    ]
                ),
                0,
            )
        self.assertEqual(execute.call_args.args, ("e" * 64, "a" * 40, TOOLS, IMAGE_ID))
        self.assertEqual(execute.call_args.kwargs, {"invocation_owner": OWNER})


if __name__ == "__main__":
    unittest.main()
