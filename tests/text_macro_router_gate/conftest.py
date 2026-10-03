"""Hermetic opt-in composition proof; missing installed consumers are failures."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import re
import socket
from pathlib import Path

import pytest
import pytest_asyncio

from native_policy import CLASSIFICATION, DATABASE_ENV, REDIS_ENV, TARGET, allowed_address, require_targets

ROOT = Path(__file__).resolve().parent
MODULES = {
    "kairos-core": "kairos_core",
    "kairos-persistence": "kairos_persistence",
    "kairos-llm": "kairos_llm",
    "kairos-text-scouts": "kairos_text",
    "kairos-macro-strategist": "kairos_macro",
    "kairos-router": "kairos_router",
    "kairos-aggregator": "kairos_aggregator",
    "kairos-risk-manager": "kairos_risk",
    "kairos-strategy-engine": "kairos_strategy",
}


def pytest_addoption(parser):
    parser.addoption(
        "--native-composition",
        action="store_true",
        help="Only the fixed target may contact explicitly named disposable PG/Redis",
    )
    parser.addoption(
        "--source-checkout-preliminary",
        action="store_true",
        help="Explicit preliminary source-only check; NOT installed-wheel qualification",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "asyncio: local asynchronous contract composition")
    config.addinivalue_line("markers", "native_composition: explicit disposable PG/Redis engineering gate")
    if config.getoption("--source-checkout-preliminary"):
        if config.getoption("--native-composition"):
            raise pytest.UsageError("Native composition requires verified non-editable installed packages")
        return
    lock = json.loads((ROOT / "source-lock.json").read_text(encoding="utf-8"))
    readiness = lock.get("readiness", {})
    if (
        lock.get("schema_version") != 1
        or lock.get("classification") != "OFFLINE_ENGINEERING_FIXTURE"
        or set(readiness) != {"paper_qualified", "alpha_ready", "live_ready", "strategy_policy"}
        or any(readiness.get(flag) is not False for flag in ("paper_qualified", "alpha_ready", "live_ready"))
        or readiness.get("strategy_policy") != "REJECT_ALL"
        or set(lock.get("dependencies", {})) != set(MODULES)
    ):
        raise pytest.UsageError("Composition proof cannot confer trading readiness")
    for distribution, module in MODULES.items():
        try:
            spec = importlib.util.find_spec(module)
            dist = importlib.metadata.distribution(distribution)
            direct = json.loads(dist.read_text("direct_url.json") or "{}")
        except (
            ImportError,
            importlib.metadata.PackageNotFoundError,
            ValueError,
        ) as error:
            raise pytest.UsageError("Required installed pinned consumer unavailable") from error
        expected = lock["dependencies"][distribution]
        if (
            set(expected) != {"repository", "revision"}
            or expected["repository"] != "https://github.com/Kairos-cryptoAI/" + distribution
            or re.fullmatch(r"[a-f0-9]{40}", expected["revision"]) is None
            or spec is None
            or not spec.origin
            or "site-packages" not in Path(spec.origin).resolve(strict=True).parts
            or direct.get("dir_info", {}).get("editable", False)
            or direct.get("url", "").removesuffix(".git") != expected["repository"]
            or direct.get("vcs_info", {}).get("commit_id") != expected["revision"]
        ):
            raise pytest.UsageError("Imported consumer differs from locked non-editable wheel")


def pytest_report_header(config):
    if config.getoption("--source-checkout-preliminary"):
        return "PRELIMINARY_SOURCE_ONLY; installed-wheel-qualified=false; trading-authority=false"
    if config.getoption("--native-composition"):
        return f"{CLASSIFICATION}; pinned-installed=true; trading-authority=false; REJECT_ALL"
    return "PINNED_INSTALLED_CONTRACT_FIXTURE_ONLY; trading-authority=false; REJECT_ALL"


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    # Keep the proof classification visible even with -q or on a failed run.
    terminalreporter.write_line(pytest_report_header(config))


@pytest_asyncio.fixture(autouse=True)
async def no_external_io_or_operator_configuration(monkeypatch, request):
    # The Windows event loop creates its own local self-pipe before this async
    # fixture starts. No general loopback exception is granted to test code.
    # Names only: never read operator values or load .env files.
    native = request.config.getoption("--native-composition") and request.node.name == TARGET
    targets = None
    if native:
        targets = (os.environ.get(DATABASE_ENV), os.environ.get(REDIS_ENV))
        require_targets(*targets)
    for name in list(os.environ):
        if name.upper().startswith(("KAIROS_", "OPENAI_", "DEEPSEEK_", "TELEGRAM_")):
            monkeypatch.delenv(name, raising=False)

    def denied(*_args, **_kwargs):
        raise AssertionError("External transport/provider construction forbidden in contract fixture")

    if native:
        connect, connect_ex, resolve = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

        def fixture_connect(sock, address):
            if not allowed_address(address):
                denied()
            return connect(sock, address)

        def fixture_connect_ex(sock, address):
            if not allowed_address(address):
                denied()
            return connect_ex(sock, address)

        def fixture_resolve(host, port, *args, **kwargs):
            if not allowed_address((host, port)):
                denied()
            return resolve(host, port, *args, **kwargs)

        monkeypatch.setattr(socket.socket, "connect", fixture_connect)
        monkeypatch.setattr(socket.socket, "connect_ex", fixture_connect_ex)
        monkeypatch.setattr(socket, "getaddrinfo", fixture_resolve)
        monkeypatch.setenv(DATABASE_ENV, targets[0])
        monkeypatch.setenv(REDIS_ENV, targets[1])
    else:
        monkeypatch.setattr(socket.socket, "connect", denied)
        monkeypatch.setattr(socket.socket, "connect_ex", denied)
        monkeypatch.setattr(socket, "getaddrinfo", denied)
    import kairos_llm.gateway

    monkeypatch.setattr(kairos_llm.gateway.LLMGateway, "__init__", denied)
    try:
        yield
    finally:
        monkeypatch.undo()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    if item.name != TARGET:
        return
    report = outcome.get_result()
    # Credentials are generated in memory in this one target. Never retain a
    # traceback, exception message, locals or captured service/driver output.
    report.sections.clear()
    if report.failed:
        safe_classes = {
            "AssertionError",
            "TimeoutError",
            "ValueError",
            "TypeError",
            "AttributeError",
            "KeyError",
            "NameError",
            "RuntimeError",
            "ValidationError",
            "ConnectionRefusedError",
            "InterfaceError",
            "DataError",
            "UndefinedTableError",
            "UndefinedColumnError",
            "UniqueViolationError",
            "NotNullViolationError",
            "CheckViolationError",
            "ForeignKeyViolationError",
            "InvalidTextRepresentationError",
            "ConnectionDoesNotExistError",
            "InsufficientPrivilegeError",
            "InvalidPasswordError",
            "InvalidCatalogNameError",
            "InvalidAuthorizationSpecificationError",
            "MessageIdentityConflict",
            "DatabaseTargetError",
            "OperatorControlRefused",
            "OperatorControlUnavailable",
            "PaperInputDeadlineExceeded",
            "PaperInputUnavailable",
            "CommittedAckLoss",
        }
        exception = call.excinfo.type.__name__ if call.excinfo else "UnknownFailure"
        exception = exception if exception in safe_classes else "OtherFailure"
        phase = getattr(item, "_composition_phase", "admission")
        phases = {
            "admission",
            "clock",
            "producer",
            "news",
            "macro",
            "risk-inputs",
            "route",
            "review",
            "risk",
            "replay",
            "quiet",
            "drain",
            "cleanup",
        }
        phase = phase if phase in phases else "admission"
        locations = []
        trace = call.excinfo.value.__traceback__ if call.excinfo else None
        # Only public engineering source basenames and line numbers; never
        # exception text, locals, source lines, paths or provider payloads.
        while trace is not None:
            filename = Path(trace.tb_frame.f_code.co_filename).name
            if filename in {"test_native_composition.py", "native_policy.py", "conftest.py"}:
                locations.append(f"{filename}:{trace.tb_lineno}")
            trace = trace.tb_next
        location = ",".join(locations[-4:]) or "public-location-unavailable"
        report.longrepr = f"NATIVE_COMPOSITION_FAILED phase={phase} class={exception} location={location}"
