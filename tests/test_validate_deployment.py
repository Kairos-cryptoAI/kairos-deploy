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
        self.assertTrue(any("retired" in error for error in errors))


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
            **({"extra": "runtime"} if name == "strategy-engine" else {}),
        }
        for name in SOURCE_SERVICES
    }
    return {
        "schema_version": 1,
        "build": {"python": "3.11.15", "uv": "0.12.3"},
        "dependencies": {
            "kairos-core": "b" * 40,
            "kairos-llm": "c" * 40,
            "kairos-persistence": "a" * 40,
        },
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
    def test_source_revision_invalidates_remote_context_copy_cache(self) -> None:
        root = Path(__file__).resolve().parents[1]
        dockerfile = (root / "docker" / "Dockerfile").read_text(encoding="utf-8")
        identity_write = dockerfile.index("> /tmp/kairos-source-identity")
        source_copy = dockerfile.index("COPY --from=service pyproject.toml")

        self.assertLess(identity_write, source_copy)
        self.assertIn('printf \'%s\\n%s\\n\' "${SOURCE_REPOSITORY}" "${SOURCE_REVISION}"', dockerfile)
        self.assertIn(
            "COPY --from=builder --chown=kairos:kairos "
            "/tmp/kairos-source-identity /app/.source-identity",
            dockerfile,
        )

    def test_docker_context_is_deny_by_default_and_never_sends_local_secrets(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        rules = [
            line.strip()
            for line in (root / ".dockerignore")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(rules, ["**", "!docker/", "!docker/**", "!.dockerignore"])

    def test_rejects_non_immutable_revision(self) -> None:
        lock = source_lock("main")
        errors = validate_source_lock(lock)
        self.assertEqual(
            sum("full immutable Git SHA" in error for error in errors),
            len(SOURCE_SERVICES),
        )

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
            "KAIROS_ENVIRONMENT": "prod",
            "KAIROS_LOG_LEVEL": "INFO",
            "KAIROS_LOG_JSON": "true",
            "KAIROS_BUS_BACKEND": "redis",
            "KAIROS_TRADING_SYMBOLS": '["BTCUSDT","ETHUSDT","SOLUSDT","BNBUSDT","XRPUSDT"]',
            "KAIROS_SECRET_BINDINGS": (
                "KAIROS_REDIS_URL=/run/secrets/redis_url,"
                "KAIROS_PERSISTENCE_DATABASE_URL=/run/secrets/persistence_database_url"
            ),
        }
        if name == "execution-engine":
            environment.update(
                {
                    "KAIROS_EXCHANGE": "evedex",
                    "KAIROS_TRADING_MODE": "DRY_RUN",
                    "KAIROS_ACCOUNT_ID": "primary",
                    "KAIROS_ACCOUNT_SNAPSHOT_INTERVAL_S": "15",
                    "KAIROS_DRY_RUN_EQUITY_USD": "10000",
                    "KAIROS_EVEDEX_EXCHANGE_URL": "https://exchange-api.evedex.com",
                    "KAIROS_EVEDEX_CHAIN_ID": "1",
                }
            )
        if name == "text-scouts":
            environment.update(
                {
                    "KAIROS_REDDIT_USER_AGENT": "kairos-text-scouts/0.1 by Kairos-cryptoAI",
                    "KAIROS_X_MONTHLY_BUDGET_MICROUSD": "2000000",
                    "KAIROS_X_POST_READ_UNIT_COST_MICROUSD": "5000",
                    "KAIROS_X_USER_READ_UNIT_COST_MICROUSD": "10000",
                }
            )
        if name == "strategy-engine":
            environment.update(
                {
                    "KAIROS_TRADING_MODE": "DRY_RUN",
                    "KAIROS_ENABLED_STRATEGY_IDS": "[]",
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
        if name == "ops-exporter":
            environment.update(
                {
                    "KAIROS_METRICS_HOST": "0.0.0.0",
                    "KAIROS_METRICS_PORT": "9108",
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
                "context": ".",
                "dockerfile": "docker/Dockerfile",
                "pull": True,
                "additional_contexts": {
                    "service": f"{source['repository']}.git#{source['revision']}"
                },
                "args": {
                    "SOURCE_REVISION": source["revision"],
                    "SOURCE_REPOSITORY": source["repository"],
                    "PACKAGE_DIR": source["package_dir"],
                    **(
                        {"SERVICE_EXTRA": source["extra"]}
                        if source.get("extra")
                        else {}
                    ),
                },
            },
            "command": [source["command"]],
            "environment": environment,
            "secrets": secrets,
            "read_only": True,
            "init": True,
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
                "user": "redis:redis",
                "command": ["requirepass", "/run/secrets/redis_password"],
                "healthcheck": {"test": ["CMD", "/run/secrets/redis_password"]},
                "secrets": [{"source": "redis_password"}],
                "networks": {"bus": None},
                "volumes": [
                    {"type": "volume", "source": "redis-data", "target": "/data"}
                ],
            },
            "timescaledb": {
                "image": "timescale:1@sha256:" + "d" * 64,
                "user": "postgres:postgres",
                "environment": {
                    "POSTGRES_USER": "kairos",
                    "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres_password",
                    "POSTGRES_DB": "kairos",
                },
                "healthcheck": {"test": ["CMD-SHELL", "/proc/1/comm pg_isready"]},
                "secrets": [{"source": "postgres_password"}],
                "networks": {"data": None},
                "volumes": [
                    {
                        "type": "volume",
                        "source": "ts-data",
                        "target": "/var/lib/postgresql/data",
                    },
                    {
                        "type": "bind",
                        "source": "/repo/timescaledb/schema.sql",
                        "target": "/docker-entrypoint-initdb.d/001-kairos.sql",
                        "read_only": True,
                    },
                ],
            },
            "prometheus": {
                "image": "prometheus:1@sha256:" + "e" * 64,
                "ports": [{"host_ip": "127.0.0.1"}],
                "networks": {"observability": None, "management": None},
                "healthcheck": {"test": ["CMD", "http://127.0.0.1:9090/-/ready"]},
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/repo/monitoring/prometheus.yml",
                        "target": "/etc/prometheus/prometheus.yml",
                        "read_only": True,
                    },
                    {
                        "type": "bind",
                        "source": "/repo/monitoring/alerts.base.yml",
                        "target": "/etc/prometheus/alerts.yml",
                        "read_only": True,
                    },
                    {
                        "type": "volume",
                        "source": "prometheus-data",
                        "target": "/prometheus",
                    },
                ],
            },
            "grafana": {
                "image": "grafana:1@sha256:" + "f" * 64,
                "environment": {
                    "GF_SECURITY_ADMIN_USER": "kairos-admin",
                    "GF_SECURITY_ADMIN_PASSWORD__FILE": "/run/secrets/grafana_admin_password",
                    "GF_USERS_ALLOW_SIGN_UP": "false",
                    "GF_ANALYTICS_REPORTING_ENABLED": "false",
                    "GF_ANALYTICS_CHECK_FOR_UPDATES": "false",
                },
                "ports": [{"host_ip": "127.0.0.1"}],
                "networks": {"observability": None, "management": None},
                "healthcheck": {"test": ["CMD", "http://127.0.0.1:3000/api/health"]},
                "secrets": [{"source": "grafana_admin_password"}],
                "volumes": [
                    {
                        "type": "volume",
                        "source": "grafana-data",
                        "target": "/var/lib/grafana",
                    },
                    {
                        "type": "bind",
                        "source": "/repo/monitoring/grafana-datasource.yml",
                        "target": "/etc/grafana/provisioning/datasources/kairos.yml",
                        "read_only": True,
                    },
                ],
            },
        }
    )
    config = {
        "name": "kairos",
        "services": services,
        "secrets": {
            name: {"file": f"/secrets/{name}"}
            for name in (
                "redis_password",
                "redis_url",
                "postgres_password",
                "persistence_database_url",
                "grafana_admin_password",
                "deepseek_api_key",
                "openai_api_key",
                "x_bearer_token",
            )
        },
        "volumes": {
            "redis-data": {},
            "ts-data": {},
            "prometheus-data": {},
            "grafana-data": {},
        },
        "networks": {
            "bus": {"internal": True},
            "data": {"internal": True},
            "observability": {"internal": True},
            "management": {"internal": True},
            "egress": {},
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
        broken["services"]["execution-engine"]["environment"]["KAIROS_TRADING_MODE"] = (
            "LIVE"
        )
        errors = validate_compose(broken, lock)
        self.assertTrue(any("file-mounted" in error for error in errors))
        self.assertTrue(any("Redis must not publish" in error for error in errors))
        self.assertTrue(any("base Compose" in error for error in errors))

    def test_rejects_secret_alias_and_extra_binding_bypass(self) -> None:
        config, lock = rendered_config()
        execution = config["services"]["execution-engine"]
        execution["secrets"].append({"source": "foo", "target": "foo"})
        execution["environment"]["KAIROS_SECRET_BINDINGS"] += (
            ",KAIROS_EVEDEX_PRIVATE_KEY=/run/secrets/foo"
        )
        config["secrets"]["foo"] = {"file": "/secrets/evedex_private_key"}

        errors = validate_compose(config, lock)

        self.assertTrue(any("exact allow-list" in error for error in errors))

    def test_rejects_runtime_build_and_resource_alias_escape_hatches(self) -> None:
        config, lock = rendered_config()
        router = config["services"]["router"]
        router["user"] = "root"
        router["entrypoint"] = ["python", "-c", "raise SystemExit(0)"]
        router["cap_add"] = ["SYS_ADMIN"]
        router["environment"]["UNREVIEWED_TOKEN"] = "value"
        router["build"]["context"] = ".."
        config["services"]["redis"]["user"] = "root"
        config["volumes"]["ts-data"]["name"] = "another-project_ts-data"

        errors = validate_compose(config, lock)

        self.assertTrue(any("unsafe Compose option user" in error for error in errors))
        self.assertTrue(
            any("unsafe Compose option entrypoint" in error for error in errors)
        )
        self.assertTrue(
            any("unsafe Compose option cap_add" in error for error in errors)
        )
        self.assertTrue(any("environment keys" in error for error in errors))
        self.assertTrue(any("build context" in error for error in errors))
        self.assertTrue(any("pinned non-root image user" in error for error in errors))
        self.assertTrue(any("volume aliases" in error for error in errors))

    def test_live_model_is_explicit_and_rejects_static_evedex_secrets(self) -> None:
        config, lock = rendered_config()
        execution = config["services"]["execution-engine"]
        execution["environment"]["KAIROS_TRADING_MODE"] = "LIVE"
        self.assertEqual(validate_compose(config, lock, live=True), [])

        execution["environment"]["KAIROS_SECRET_BINDINGS"] += (
            ",KAIROS_EVEDEX_JWT=/run/secrets/evedex_jwt,"
            "KAIROS_EVEDEX_PRIVATE_KEY=/run/secrets/evedex_private_key"
        )
        execution["secrets"].extend(
            [{"source": "evedex_jwt"}, {"source": "evedex_private_key"}]
        )
        errors = validate_compose(config, lock, live=True)
        self.assertTrue(any("retired static EVEDEX" in error for error in errors))

    def test_rejects_x_budget_above_qualification_ceiling(self) -> None:
        config, lock = rendered_config()
        config["services"]["text-scouts"]["environment"][
            "KAIROS_X_MONTHLY_BUDGET_MICROUSD"
        ] = "2000001"

        errors = validate_compose(config, lock)

        self.assertTrue(any("$2 qualification ceiling" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
