"""Hermetic guard tests: no Docker, network, credentials or database required."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import policy


@pytest.fixture(autouse=True)
def isolated_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def environment():
    return {
        "KAIROS_RELEASE_GATE_CONFIRM": policy.CONFIRMATION,
        "KAIROS_RELEASE_GATE_PROJECT": policy.PROJECT,
        "KAIROS_EXECUTION_TEST_DATABASE": policy.DATABASE,
        "KAIROS_PERSISTENCE_DATABASE_URL": policy.DATABASE_URL,
        "KAIROS_REDIS_URL": policy.REDIS_URL,
    }


def test_exact_explicit_targets_are_accepted(environment):
    policy.validate_environment(environment)


@pytest.mark.parametrize(
    "key",
    [
        "KAIROS_RELEASE_GATE_CONFIRM",
        "KAIROS_RELEASE_GATE_PROJECT",
        "KAIROS_EXECUTION_TEST_DATABASE",
        "KAIROS_PERSISTENCE_DATABASE_URL",
        "KAIROS_REDIS_URL",
    ],
)
def test_each_confirmation_and_target_is_mandatory(environment, key):
    environment.pop(key)
    with pytest.raises(ValueError, match="exact isolated"):
        policy.validate_environment(environment)


@pytest.mark.parametrize(
    "dsn",
    [
        policy.DATABASE_URL.replace(policy.DATABASE, "kairos"),
        policy.DATABASE_URL.replace("timescaledb:5432", "localhost:5432"),
        policy.DATABASE_URL.replace("timescaledb:5432", "host.docker.internal:5432"),
        policy.DATABASE_URL.replace("timescaledb", "production.example"),
        policy.DATABASE_URL + "?options=-csearch_path%3Dother",
        policy.DATABASE_URL.replace("kairos_execution", "%6bairos_execution"),
        policy.DATABASE_URL.replace(":5432", ":5433"),
    ],
)
def test_alternative_database_targets_are_rejected(environment, dsn):
    environment["KAIROS_PERSISTENCE_DATABASE_URL"] = dsn
    with pytest.raises(ValueError, match="exact isolated"):
        policy.validate_environment(environment)


@pytest.mark.parametrize("url", ["redis://localhost:6379/0", "redis://redis:6379/1", "rediss://redis:6379/0"])
def test_alternative_redis_targets_are_rejected(environment, url):
    environment["KAIROS_REDIS_URL"] = url
    with pytest.raises(ValueError, match="exact isolated"):
        policy.validate_environment(environment)


@pytest.mark.parametrize(
    "key",
    [
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "X_BEARER_TOKEN",
        "EVEDEX_PRIVATE_KEY",
        "EVEDEX_SIGNING_KEY",
        "EVEDEX_JWT",
    ],
)
def test_credential_environment_is_rejected(environment, key):
    environment[key] = "synthetic-forbidden-value"
    with pytest.raises(ValueError, match="credential environment"):
        policy.validate_environment(environment)


def test_workspace_dotenv_is_rejected(environment, tmp_path):
    (tmp_path / ".env").touch()
    with pytest.raises(ValueError, match="workspace .env"):
        policy.validate_environment(environment)


class FakeDatabase:
    def __init__(self, *, target=policy.DATABASE_URL, identity=policy.DATABASE, tables=0):
        self.settings = SimpleNamespace(database_url=target)
        self.identity, self.tables = identity, tables
        self.pool = self
        self.connected, self.closed = False, False
        self.queries = []

    async def connect(self):
        self.connected = True

    async def close(self):
        self.closed = True

    async def fetchval(self, query):
        self.queries.append(query)
        if query == "SELECT current_database()":
            return self.identity
        assert query == "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
        return self.tables

    async def migrate(self):
        pytest.fail("a guard must never migrate")


@pytest.fixture
def configured_environment(environment, monkeypatch):
    monkeypatch.setattr(policy.os, "environ", environment)


@pytest.mark.asyncio
async def test_wrong_service_dsn_is_rejected_before_connect(configured_environment):
    database = FakeDatabase(target=policy.DATABASE_URL.replace(policy.DATABASE, "kairos"))
    with pytest.raises(ValueError, match="service persistence target"):
        await policy.connect_verified(database)
    assert not database.connected and not database.queries


@pytest.mark.asyncio
async def test_actual_server_identity_checked_before_migration(configured_environment):
    database = FakeDatabase(identity="kairos")
    with pytest.raises(ValueError, match="connected server"):
        await policy.require_fresh_database(database)
    assert database.connected and database.closed
    assert database.queries == ["SELECT current_database()"]


@pytest.mark.asyncio
async def test_previous_schema_is_never_cleaned_or_reused(configured_environment):
    database = FakeDatabase(tables=1)
    with pytest.raises(ValueError, match="preserve previous evidence"):
        await policy.require_fresh_database(database)
    assert len(database.queries) == 2 and all(query.startswith("SELECT ") for query in database.queries)


@pytest.mark.asyncio
async def test_fresh_target_verified_without_any_write(configured_environment):
    database = FakeDatabase()
    await policy.require_fresh_database(database)
    assert database.connected and len(database.queries) == 2
    assert all(query.startswith("SELECT ") for query in database.queries)


@pytest.fixture
def installed(monkeypatch, tmp_path):
    root = tmp_path / "venv" / "lib" / "site-packages"
    documents = {
        name: {"url": f"https://github.com/Kairos-cryptoAI/{name}.git", "vcs_info": {"commit_id": revision}}
        for name, revision in policy.PINS.items()
    }
    modules = {
        package: SimpleNamespace(__file__=str(root / package / "__init__.py"))
        for package in policy.MODULES.values()
    }
    monkeypatch.setattr(
        policy.importlib.metadata,
        "distribution",
        lambda name: SimpleNamespace(
            read_text=lambda filename: json.dumps(documents[name]), locate_file=lambda path: root / path
        ),
    )
    monkeypatch.setattr(policy.importlib, "import_module", modules.__getitem__)
    return documents, modules


def test_installed_git_metadata_and_actual_module_paths_checked(installed):
    policy.validate_installed_sources()


@pytest.mark.parametrize(
    "change", ["wrong_revision", "wrong_repository", "editable", "source_override", "no_file"]
)
def test_install_metadata_alone_cannot_hide_source_override(installed, change, tmp_path):
    documents, modules = installed
    name = "kairos-risk-manager"
    if change == "wrong_revision":
        documents[name]["vcs_info"]["commit_id"] = "0" * 40
    elif change == "wrong_repository":
        documents[name]["url"] = "https://github.com/untrusted/replacement.git"
    elif change == "editable":
        documents[name]["dir_info"] = {"editable": True}
    elif change == "source_override":
        modules["kairos_risk"].__file__ = str(tmp_path / "checkout" / "kairos_risk" / "__init__.py")
    else:
        modules["kairos_risk"].__file__ = None
    with pytest.raises(ValueError):
        policy.validate_installed_sources()


@pytest.fixture
def compose():
    return yaml.safe_load(Path(__file__).with_name("compose.yml").read_text(encoding="utf-8"))


def test_committed_compose_is_isolated(compose):
    policy.validate_compose(compose)


@pytest.mark.parametrize("service", ["timescaledb", "redis"])
@pytest.mark.parametrize("change", ["wrong_digest", "wrong_repository"])
def test_alternative_digest_pinned_images_are_rejected(compose, service, change):
    image = compose["services"][service]["image"]
    if change == "wrong_digest":
        image = image.split("@sha256:")[0] + "@sha256:" + "0" * 64
    else:
        image = "untrusted/replacement@sha256:" + image.split("@sha256:")[1]
    compose["services"][service]["image"] = image
    with pytest.raises(ValueError, match="exact pinned image"):
        policy.validate_compose(compose)


@pytest.mark.parametrize(
    "service,field,wrong_value",
    [
        ("timescaledb", "mem_limit", "1g"),
        ("redis", "mem_limit", "256m"),
        ("gate", "mem_limit", "2g"),
        ("gate", "cpus", 4.0),
        ("gate", "pids_limit", 256),
    ],
)
@pytest.mark.parametrize("change", ["missing", "changed"])
def test_exact_service_resource_limits_are_required(compose, service, field, wrong_value, change):
    if change == "missing":
        compose["services"][service].pop(field)
    else:
        compose["services"][service][field] = wrong_value
    with pytest.raises(ValueError, match="exact resource limits"):
        policy.validate_compose(compose)


@pytest.mark.parametrize(
    "field,value",
    [
        ("ports", ["5432:5432"]),
        ("volumes", ["existing:/data"]),
        ("secrets", ["real_key"]),
        ("env_file", [".env"]),
        ("extra_hosts", ["host.docker.internal:host-gateway"]),
        ("network_mode", "host"),
        ("privileged", True),
        ("devices", ["/dev/anything"]),
        ("container_name", "kairos-primary"),
        ("cap_add", ["SYS_ADMIN"]),
    ],
)
def test_service_escape_hatches_rejected(compose, field, value):
    compose["services"]["gate"][field] = value
    with pytest.raises(ValueError, match="unsafe release gate"):
        policy.validate_compose(compose)


@pytest.mark.parametrize(
    "change",
    [
        "external_network",
        "persistent_volume",
        "external_secret",
        "root_build",
        "writable_runner",
        "wrong_postgres",
        "no_digest",
        "non_tmpfs",
    ],
)
def test_shared_or_unguarded_infrastructure_rejected(compose, change):
    document = copy.deepcopy(compose)
    if change == "external_network":
        document["networks"]["isolated"] = {"external": True, "name": "kairos-paper-gate_paper-data"}
    elif change == "persistent_volume":
        document["volumes"] = {"existing": {"external": True}}
    elif change == "external_secret":
        document["secrets"] = {"real_key": {"file": "C:/Users/example/keys.txt"}}
    elif change == "root_build":
        document["services"]["gate"]["build"]["context"] = "../.."
    elif change == "writable_runner":
        document["services"]["gate"]["read_only"] = False
    elif change == "wrong_postgres":
        document["services"]["timescaledb"]["environment"]["POSTGRES_DB"] = "kairos"
    elif change == "no_digest":
        document["services"]["redis"]["image"] = "redis:latest"
    else:
        document["services"]["timescaledb"].pop("tmpfs")
    with pytest.raises(ValueError):
        policy.validate_compose(document)
