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
}


def pytest_addoption(parser):
    parser.addoption(
        "--source-checkout-preliminary",
        action="store_true",
        help="Explicit preliminary source-only check; NOT installed-wheel qualification",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "asyncio: local asynchronous contract composition")
    if config.getoption("--source-checkout-preliminary"):
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
    return "PINNED_INSTALLED_CONTRACT_FIXTURE_ONLY; trading-authority=false; REJECT_ALL"


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    # Keep the proof classification visible even with -q or on a failed run.
    terminalreporter.write_line(pytest_report_header(config))


@pytest_asyncio.fixture(autouse=True)
async def no_external_io_or_operator_configuration(monkeypatch):
    # The Windows event loop creates its own local self-pipe before this async
    # fixture starts. No general loopback exception is granted to test code.
    # Names only: never read operator values or load .env files.
    for name in list(os.environ):
        if name.upper().startswith(("KAIROS_", "OPENAI_", "DEEPSEEK_", "TELEGRAM_")):
            monkeypatch.delenv(name, raising=False)

    def denied(*_args, **_kwargs):
        raise AssertionError("External transport/provider construction forbidden in contract fixture")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    import kairos_llm.gateway

    monkeypatch.setattr(kairos_llm.gateway.LLMGateway, "__init__", denied)
    try:
        yield
    finally:
        monkeypatch.undo()
