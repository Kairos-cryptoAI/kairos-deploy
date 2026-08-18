from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from scripts.validate_deployment import (
    APP_SERVICES,
    EXPECTED_REPOSITORIES,
    SOURCE_SERVICES,
    validate_compose,
    validate_environment,
    validate_source_lock,
)


class EnvironmentValidationTests(unittest.TestCase):
    def test_accepts_secret_free_base_environment(self) -> None:
        environment = {
            "KAIROS_SECRETS_DIR": "./secrets",
            "POSTGRES_USER": "kairos",
            "POSTGRES_DB": "kairos",
            "GRAFANA_ADMIN_USER": "kairos-admin",
            "KAIROS_DRY_RUN": "true",
        }
        self.assertEqual(validate_environment(environment), [])

    def test_rejects_secret_and_live_switch_in_base_environment(self) -> None:
        environment = {
            "KAIROS_SECRETS_DIR": "./secrets",
            "POSTGRES_USER": "kairos",
            "POSTGRES_DB": "kairos",
            "GRAFANA_ADMIN_USER": "kairos-admin",
            "KAIROS_DRY_RUN": "false",
            "KAIROS_OPENAI_API_KEY": "secret",
        }
        errors = validate_environment(environment)
        self.assertTrue(any("must not be stored" in error for error in errors))
        self.assertTrue(any("DRY_RUN=true" in error for error in errors))


def source_lock(revision: str = "a" * 40) -> dict[str, object]:
    services = {
        name: {
            "repository": EXPECTED_REPOSITORIES[name],
            "revision": revision,
            "package_dir": "kairos_persistence"
            if name == "ops-exporter"
            else name.replace("-", "_"),
            "command": "kairos-persistence-exporter"
            if name == "ops-exporter"
            else f"kairos-{name}",
            **({"extra": "evedex"} if name == "execution-engine" else {}),
        }
        for name in SOURCE_SERVICES
    }
    return {
        "schema_version": 1,
        "build": {"python": "3.11.15", "uv": "0.12.3"},
        "dependencies": {"kairos-core": "b" * 40, "kairos-llm": "c" * 40},
        "infrastructure": {
            "redis": {
                "image": "redis:8.2.8-alpine3.22@sha256:"
                "a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103",
                "required_feature": "XACKDEL ref_policy=ACKED",
            }
        },
        "services": services,
    }


class SourceLockValidationTests(unittest.TestCase):
    def test_rejects_non_immutable_revision(self) -> None:
        lock = source_lock("main")
        errors = validate_source_lock(lock)
        self.assertEqual(sum("full immutable Git SHA" in error for error in errors), 8)

    def test_repository_compose_revisions_match_source_lock(self) -> None:
        root = Path(__file__).resolve().parents[1]
        lock = json.loads((root / "sources.lock.json").read_text(encoding="utf-8"))
        compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
        for name, source in lock["services"].items():
            with self.subTest(service=name):
                self.assertIn(
                    f"service: {source['repository']}.git#{source['revision']}", compose
                )
                self.assertIn(f"SOURCE_REVISION: {source['revision']}", compose)


def rendered_config() -> tuple[dict[str, object], dict[str, object]]:
    lock = source_lock()
    services: dict[str, object] = {}
    for name in SOURCE_SERVICES:
        source = lock["services"][name]
        environment = {
            "KAIROS_SECRET_BINDINGS": (
                "KAIROS_REDIS_URL=/run/secrets/redis_url,"
                "KAIROS_PERSISTENCE_DATABASE_URL=/run/secrets/persistence_database_url"
            )
        }
        if name == "execution-engine":
            environment.update(
                {
                    "KAIROS_DRY_RUN": "true",
                    "KAIROS_ACCOUNT_SNAPSHOT_INTERVAL_S": "15",
                }
            )
        if name == "risk-manager":
            environment.update(
                {
                    "KAIROS_REQUIRE_RECONCILED_ACCOUNT": "true",
                    "KAIROS_REQUIRE_STRATEGIC_ALLOCATION": "true",
                    "KAIROS_ACCOUNT_SNAPSHOT_MAX_AGE_S": "60",
                }
            )
        secrets = [
            {"source": "redis_url", "target": "redis_url"},
            {
                "source": "persistence_database_url",
                "target": "persistence_database_url",
            },
        ]
        providers = {
            "text-scouts": (
                ("KAIROS_DEEPSEEK_API_KEY", "deepseek_api_key"),
                ("KAIROS_X_BEARER_TOKEN", "x_bearer_token"),
            ),
            "aggregator": (("KAIROS_OPENAI_API_KEY", "openai_api_key"),),
            "macro-strategist": (("KAIROS_OPENAI_API_KEY", "openai_api_key"),),
        }.get(name, ())
        for environment_name, provider in providers:
            secrets.append({"source": provider, "target": provider})
            environment["KAIROS_SECRET_BINDINGS"] += (
                f",{environment_name}=/run/secrets/{provider}"
            )
        services[name] = {
            "build": {
                "additional_contexts": {
                    "service": f"{source['repository']}.git#{source['revision']}"
                },
                "args": {
                    "SOURCE_REVISION": source["revision"],
                    "PACKAGE_DIR": source["package_dir"],
                    **(
                        {"SERVICE_EXTRA": "evedex"}
                        if name == "execution-engine"
                        else {}
                    ),
                },
            },
            "command": [source["command"]],
            "environment": environment,
            "secrets": secrets,
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "depends_on": {
                "redis": {"condition": "service_healthy"},
                "timescaledb": {"condition": "service_healthy"},
            },
            **(
                {"healthcheck": {"test": ["CMD", "http://127.0.0.1:9108/metrics"]}}
                if name == "ops-exporter"
                else {}
            ),
            "networks": {
                "bus": None,
                "data": None,
                "observability": None,
                **({"management": None} if name == "ops-exporter" else {}),
                **(
                    {"egress": None}
                    if name in APP_SERVICES
                    and name
                    in {
                        "quant-scouts",
                        "text-scouts",
                        "aggregator",
                        "macro-strategist",
                        "execution-engine",
                    }
                    else {}
                ),
            },
        }
    services.update(
        {
            "redis": {
                "image": lock["infrastructure"]["redis"]["image"],
                "command": ["requirepass", "/run/secrets/redis_password"],
                "healthcheck": {"test": ["CMD", "/run/secrets/redis_password"]},
                "secrets": [{"source": "redis_password"}],
            },
            "timescaledb": {
                "image": "timescale:1@sha256:" + "d" * 64,
                "environment": {
                    "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres_password"
                },
                "healthcheck": {"test": ["CMD-SHELL", "/proc/1/comm pg_isready"]},
            },
            "prometheus": {
                "image": "prometheus:1@sha256:" + "e" * 64,
                "ports": [{"host_ip": "127.0.0.1"}],
                "networks": {"observability": None, "management": None},
                "healthcheck": {"test": ["CMD", "http://127.0.0.1:9090/-/ready"]},
            },
            "grafana": {
                "image": "grafana:1@sha256:" + "f" * 64,
                "environment": {
                    "GF_SECURITY_ADMIN_PASSWORD__FILE": "/run/secrets/grafana_admin_password"
                },
                "ports": [{"host_ip": "127.0.0.1"}],
                "networks": {"observability": None, "management": None},
                "healthcheck": {"test": ["CMD", "http://127.0.0.1:3000/api/health"]},
            },
        }
    )
    config = {
        "services": services,
        "networks": {
            "bus": {"internal": True},
            "data": {"internal": True},
            "observability": {"internal": True},
            "management": {},
        },
    }
    return config, lock


class ComposeValidationTests(unittest.TestCase):
    def test_accepts_hardened_model(self) -> None:
        config, lock = rendered_config()
        self.assertEqual(validate_compose(config, lock), [])

    def test_rejects_secret_env_host_redis_and_live_base_execution(self) -> None:
        config, lock = rendered_config()
        broken = deepcopy(config)
        broken["services"]["router"]["environment"]["KAIROS_EVEDEX_PRIVATE_KEY"] = "x"
        broken["services"]["redis"]["ports"] = [{"published": 6379}]
        broken["services"]["execution-engine"]["environment"]["KAIROS_DRY_RUN"] = (
            "false"
        )
        errors = validate_compose(broken, lock)
        self.assertTrue(any("file-mounted" in error for error in errors))
        self.assertTrue(any("Redis must not publish" in error for error in errors))
        self.assertTrue(any("base Compose" in error for error in errors))

    def test_live_model_requires_file_mounted_evedex_secrets(self) -> None:
        config, lock = rendered_config()
        execution = config["services"]["execution-engine"]
        execution["environment"]["KAIROS_DRY_RUN"] = "false"
        execution["environment"]["KAIROS_SECRET_BINDINGS"] += (
            ",KAIROS_EVEDEX_JWT=/run/secrets/evedex_jwt,"
            "KAIROS_EVEDEX_PRIVATE_KEY=/run/secrets/evedex_private_key"
        )
        execution["secrets"].extend(
            [{"source": "evedex_jwt"}, {"source": "evedex_private_key"}]
        )
        self.assertEqual(validate_compose(config, lock, live=True), [])


if __name__ == "__main__":
    unittest.main()
