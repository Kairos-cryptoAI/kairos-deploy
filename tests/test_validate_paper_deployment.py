from __future__ import annotations

import copy
import unittest
from pathlib import Path

from scripts.validate_deployment import EXPECTED_REDIS_FEATURE, EXPECTED_REDIS_IMAGE
from scripts.validate_paper_deployment import (
    COMMON_BINDINGS,
    PAPER_COMMANDS,
    PAPER_DEV_SYMBOL_MAP,
    PAPER_DEV_SYMBOLS,
    PAPER_ENDPOINTS,
    PAPER_REPOSITORIES,
    PAPER_SOURCE_SERVICES,
    validate_paper_compose,
    validate_paper_environment,
    validate_paper_source_lock,
)

SHA = "a" * 40
PERSISTENCE_SHA = "b" * 40
TIMESCALE_IMAGE = "timescale/timescaledb:2.29.1-pg16@sha256:" + "c" * 64
PROMETHEUS_IMAGE = "prom/prometheus:v3.13.2@sha256:" + "d" * 64
GRAFANA_IMAGE = "grafana/grafana:12.4.8@sha256:" + "e" * 64


def paper_lock() -> dict:
    packages = {
        "quant-scouts": "kairos_quant",
        "strategy-engine": "kairos_strategy",
        "risk-manager": "kairos_risk",
        "canary-controller": "kairos_risk",
        "execution-engine": "kairos_execution",
        "ops-exporter": "kairos_persistence",
    }
    services = {}
    for name in sorted(PAPER_SOURCE_SERVICES):
        services[name] = {
            "repository": PAPER_REPOSITORIES[name],
            "revision": PERSISTENCE_SHA if name == "ops-exporter" else SHA,
            "package_dir": packages[name],
            "command": PAPER_COMMANDS[name],
        }
    services["strategy-engine"]["extra"] = "runtime"
    services["execution-engine"]["extra"] = "evedex"
    return {
        "schema_version": 1,
        "build": {"python": "3.11.15", "uv": "0.12.3", "node": "22"},
        "dependencies": {
            "kairos-core": SHA,
            "kairos-persistence": PERSISTENCE_SHA,
        },
        "infrastructure": {
            "redis": {
                "image": EXPECTED_REDIS_IMAGE,
                "required_feature": EXPECTED_REDIS_FEATURE,
            }
        },
        "services": services,
    }


def _source_service(name: str, lock: dict) -> dict:
    source = lock["services"][name]
    environment = {
        "KAIROS_ENVIRONMENT": "paper",
        "KAIROS_LOG_LEVEL": "INFO",
        "KAIROS_LOG_JSON": "true",
        "KAIROS_BUS_BACKEND": "redis",
        "KAIROS_TRADING_SYMBOLS": PAPER_DEV_SYMBOLS,
        "KAIROS_SECRET_BINDINGS": ",".join(
            f"{key}={value}" for key, value in COMMON_BINDINGS.items()
        ),
    }
    if name in {
        "strategy-engine",
        "risk-manager",
        "canary-controller",
        "execution-engine",
    }:
        environment["KAIROS_TRADING_MODE"] = "PAPER"
    return {
        "build": {
            "context": ".",
            "dockerfile": (
                "docker/Dockerfile.paper-execution"
                if name == "execution-engine"
                else "docker/Dockerfile"
            ),
            "additional_contexts": {
                "service": f"{source['repository']}.git#{source['revision']}"
            },
            "pull": True,
            "args": {
                "PACKAGE_DIR": source["package_dir"],
                "SERVICE_EXTRA": source.get("extra", ""),
                "SOURCE_REPOSITORY": source["repository"],
                "SOURCE_REVISION": source["revision"],
            },
        },
        "command": [source["command"]],
        "environment": environment,
        "read_only": True,
        "init": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "depends_on": {
            "redis": {"condition": "service_healthy"},
            "timescaledb": {"condition": "service_healthy"},
        },
        "secrets": [
            {"source": "paper_redis_url", "target": "paper_redis_url"},
            {
                "source": "paper_persistence_database_url",
                "target": "paper_persistence_database_url",
            },
        ],
        "networks": [
            "paper-bus",
            "paper-data",
            "paper-observability",
            *(["paper-management"] if name == "ops-exporter" else []),
            *(["paper-egress"] if name in {"quant-scouts", "execution-engine"} else []),
        ],
    }


def paper_compose(lock: dict) -> dict:
    services = {name: _source_service(name, lock) for name in PAPER_SOURCE_SERVICES}
    services["strategy-engine"]["environment"]["KAIROS_ENABLED_STRATEGY_IDS"] = "[]"
    services["risk-manager"]["environment"].update(
        {
            "KAIROS_PAPER_ACCOUNT_ID": "kairos-paper-dev-01",
            "KAIROS_EVEDEX_PROFILE": "DEV",
            "KAIROS_PAPER_STRATEGY_ALLOWLIST": '["technical-canary@1"]',
            "KAIROS_REQUIRE_RECONCILED_ACCOUNT": "true",
            "KAIROS_REQUIRE_STRATEGIC_ALLOCATION": "true",
        }
    )
    services["canary-controller"]["environment"].update(
        {
            "KAIROS_PAPER_ACCOUNT_ID": "kairos-paper-dev-01",
            "KAIROS_EVEDEX_PROFILE": "DEV",
            "KAIROS_PAPER_STRATEGY_ALLOWLIST": '["technical-canary@1"]',
            "KAIROS_REQUIRE_RECONCILED_ACCOUNT": "true",
            "KAIROS_REQUIRE_STRATEGIC_ALLOCATION": "true",
        }
    )
    services["canary-controller"]["profiles"] = ["canary"]
    services["canary-controller"]["restart"] = "no"
    services["quant-scouts"]["environment"].update(
        {
            "KAIROS_ENABLE_VENUE_QUALITY_GATE": "true",
            "KAIROS_KLINE_RECONCILIATION_INTERVAL_S": "60",
            "KAIROS_EVEDEX_DEV_BASE_URL": "https://trading-api.evedex.tech",
            "KAIROS_VENUE_QUALITY_INTERVAL_S": "30",
            "KAIROS_MAXIMUM_ABS_BASIS_BPS": "25",
            "KAIROS_MAXIMUM_EVEDEX_SPREAD_BPS": "25",
            "KAIROS_MAXIMUM_EVEDEX_SLIPPAGE_BPS": "25",
            "KAIROS_MAXIMUM_VENUE_BOOK_AGE_MS": "5000",
            "KAIROS_MAXIMUM_VENUE_TIMESTAMP_SKEW_MS": "2000",
        }
    )
    services["execution-engine"]["environment"].update(
        {
            **PAPER_ENDPOINTS,
            "KAIROS_EXCHANGE": "evedex",
            "KAIROS_EVEDEX_PROFILE": "DEV",
            "KAIROS_ACCOUNT_ID": "kairos-paper-dev-01",
            "KAIROS_EVEDEX_DEV_EXPECTED_ACCOUNT_ID": "dev-account-123",
            "KAIROS_EVEDEX_DEV_SYMBOL_MAP": PAPER_DEV_SYMBOL_MAP,
            "KAIROS_EVEDEX_DEV_API_KEY_FILE": "/run/secrets/evedex_dev_api_key",
            "KAIROS_EVEDEX_DEV_PRIVATE_KEY_FILE": "/run/secrets/evedex_dev_private_key",
        }
    )
    services["execution-engine"]["secrets"].extend(
        [
            {"source": "evedex_dev_api_key", "target": "evedex_dev_api_key"},
            {
                "source": "evedex_dev_private_key",
                "target": "evedex_dev_private_key",
            },
        ]
    )
    services["ops-exporter"]["environment"].update(
        {
            "KAIROS_METRICS_HOST": "0.0.0.0",
            "KAIROS_METRICS_PORT": "9108",
        }
    )
    services.update(
        {
            "redis": {
                "image": EXPECTED_REDIS_IMAGE,
                "user": "redis:redis",
                "secrets": ["paper_redis_password"],
                "networks": ["paper-bus"],
                "volumes": [
                    {"type": "volume", "source": "paper-redis-data", "target": "/data"}
                ],
            },
            "timescaledb": {
                "image": TIMESCALE_IMAGE,
                "user": "postgres:postgres",
                "environment": {
                    "POSTGRES_USER": "kairos",
                    "POSTGRES_PASSWORD_FILE": "/run/secrets/paper_postgres_password",
                    "POSTGRES_DB": "kairos",
                },
                "secrets": [{"source": "paper_postgres_password"}],
                "networks": ["paper-data"],
                "volumes": [
                    {
                        "type": "volume",
                        "source": "paper-ts-data",
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
                "image": PROMETHEUS_IMAGE,
                "ports": [
                    {"host_ip": "127.0.0.1", "target": 9090, "published": "19090"}
                ],
                "networks": ["paper-observability", "paper-management"],
                "volumes": [
                    {
                        "type": "bind",
                        "source": "/repo/monitoring/prometheus.yml",
                        "target": "/etc/prometheus/prometheus.yml",
                        "read_only": True,
                    },
                    {
                        "type": "bind",
                        "source": "/repo/monitoring/alerts.yml",
                        "target": "/etc/prometheus/alerts.yml",
                        "read_only": True,
                    },
                    {
                        "type": "volume",
                        "source": "paper-prometheus-data",
                        "target": "/prometheus",
                    },
                ],
            },
            "grafana": {
                "image": GRAFANA_IMAGE,
                "environment": {
                    "GF_SECURITY_ADMIN_USER": "kairos-paper-admin",
                    "GF_SECURITY_ADMIN_PASSWORD__FILE": "/run/secrets/paper_grafana_admin_password",
                    "GF_USERS_ALLOW_SIGN_UP": "false",
                    "GF_ANALYTICS_REPORTING_ENABLED": "false",
                    "GF_ANALYTICS_CHECK_FOR_UPDATES": "false",
                },
                "ports": [
                    {"host_ip": "127.0.0.1", "target": 3000, "published": "13000"}
                ],
                "secrets": [{"source": "paper_grafana_admin_password"}],
                "networks": ["paper-observability", "paper-management"],
                "volumes": [
                    {
                        "type": "volume",
                        "source": "paper-grafana-data",
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
    services["ops-exporter"]["ports"] = [
        {"host_ip": "127.0.0.1", "target": 9108, "published": "19108"}
    ]
    return {
        "name": "kairos-paper",
        "services": services,
        "secrets": {
            name: {"file": f"/secrets-paper/{basename}"}
            for name, basename in {
                "paper_redis_password": "redis_password",
                "paper_redis_url": "redis_url",
                "paper_postgres_password": "postgres_password",
                "paper_persistence_database_url": "persistence_database_url",
                "paper_grafana_admin_password": "grafana_admin_password",
                "evedex_dev_api_key": "evedex_dev_api_key",
                "evedex_dev_private_key": "evedex_dev_private_key",
            }.items()
        },
        "volumes": {
            "paper-redis-data": {},
            "paper-ts-data": {},
            "paper-prometheus-data": {},
            "paper-grafana-data": {},
        },
        "networks": {
            "paper-bus": {"internal": True},
            "paper-data": {"internal": True},
            "paper-observability": {"internal": True},
            "paper-management": {"internal": True},
            "paper-egress": {},
        },
    }


class PaperSourceLockTests(unittest.TestCase):
    def test_accepts_exact_no_paid_api_source_set(self) -> None:
        self.assertEqual(validate_paper_source_lock(paper_lock()), [])

    def test_rejects_mutable_or_paid_source_set(self) -> None:
        lock = paper_lock()
        lock["services"]["aggregator"] = {
            "repository": "https://github.com/Kairos-cryptoAI/kairos-aggregator",
            "revision": "main",
        }
        errors = validate_paper_source_lock(lock)
        self.assertTrue(any("paid services" in error for error in errors))


class PaperComposeTests(unittest.TestCase):
    def test_accepts_isolated_fail_closed_paper_model(self) -> None:
        lock = paper_lock()
        self.assertEqual(validate_paper_compose(paper_compose(lock), lock), [])

    def test_rejects_prod_endpoint_paid_service_legacy_switch_and_host_port(
        self,
    ) -> None:
        lock = paper_lock()
        model = paper_compose(lock)
        model["services"]["execution-engine"]["environment"][
            "KAIROS_EVEDEX_EXCHANGE_URL"
        ] = "https://trading-api.evedex.io"
        model["services"]["execution-engine"]["environment"]["KAIROS_DRY_RUN"] = "false"
        model["services"]["risk-manager"]["ports"] = ["8080:8080"]
        model["services"]["aggregator"] = {}
        model["networks"]["paper-management"]["internal"] = False
        errors = validate_paper_compose(model, lock)
        self.assertTrue(any("official DEV" in error for error in errors))
        self.assertTrue(any("credential environment" in error for error in errors))
        self.assertTrue(any("ports must not" in error for error in errors))
        self.assertTrue(any("LLM/feed/review" in error for error in errors))
        self.assertTrue(any("paper-management" in error for error in errors))

    def test_rejects_secret_alias_and_extra_binding_bypass(self) -> None:
        lock = paper_lock()
        model = paper_compose(lock)
        execution = model["services"]["execution-engine"]
        execution["secrets"].append({"source": "foo", "target": "foo"})
        execution["environment"]["KAIROS_SECRET_BINDINGS"] += (
            ",KAIROS_OPENAI_API_KEY=/run/secrets/foo"
        )
        model["secrets"]["foo"] = {"file": "/secrets-paper/openai_api_key"}

        errors = validate_paper_compose(model, lock)

        self.assertTrue(any("exact PAPER allow-list" in error for error in errors))

    def test_rejects_runtime_build_network_and_resource_alias_escape_hatches(
        self,
    ) -> None:
        lock = paper_lock()
        model = paper_compose(lock)
        execution = model["services"]["execution-engine"]
        execution["user"] = "root"
        execution["entrypoint"] = ["python", "-c", "raise SystemExit(0)"]
        execution["cap_add"] = ["SYS_ADMIN"]
        execution["environment"]["UNREVIEWED_TOKEN"] = "value"
        execution["build"]["context"] = ".."
        model["services"]["timescaledb"]["user"] = "root"
        model["networks"]["paper-extra"] = {"internal": True}
        model["volumes"]["paper-ts-data"]["name"] = "kairos_ts-data"

        errors = validate_paper_compose(model, lock)

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
        self.assertTrue(any("top-level PAPER networks" in error for error in errors))
        self.assertTrue(any("volume aliases" in error for error in errors))

    def test_rejects_alpha_strategy_or_missing_dev_secret_split(self) -> None:
        lock = paper_lock()
        model = paper_compose(lock)
        model["services"]["strategy-engine"]["environment"][
            "KAIROS_ENABLED_STRATEGY_IDS"
        ] = '["range_mean_reversion_v1"]'
        model["services"]["execution-engine"]["secrets"] = [
            item
            for item in model["services"]["execution-engine"]["secrets"]
            if item["source"] != "evedex_dev_private_key"
        ]
        errors = validate_paper_compose(model, lock)
        self.assertIn("strategy-engine: PAPER alpha must remain REJECT_ALL", errors)
        self.assertTrue(any("separate DEV API" in error for error in errors))


class PaperEnvironmentTests(unittest.TestCase):
    def test_interpolation_file_contains_no_secret_or_legacy_authority(self) -> None:
        environment = {
            "KAIROS_PAPER_SECRETS_DIR": "./secrets-paper",
            "KAIROS_PAPER_ACCOUNT_ID": "kairos-paper-dev-01",
            "KAIROS_EVEDEX_DEV_EXPECTED_ACCOUNT_ID": "dev-account-123",
            "POSTGRES_USER": "kairos",
            "POSTGRES_DB": "kairos",
            "GRAFANA_ADMIN_USER": "kairos-paper-admin",
        }
        self.assertEqual(validate_paper_environment(environment), [])
        unsafe = copy.deepcopy(environment)
        unsafe["KAIROS_DRY_RUN"] = "false"
        unsafe["KAIROS_EVEDEX_DEV_PRIVATE_KEY"] = "secret"
        unsafe["KAIROS_PAPER_ACCOUNT_ID"] = "production-eu"
        errors = validate_paper_environment(unsafe)
        self.assertTrue(any("KAIROS_DRY_RUN" in error for error in errors))
        self.assertTrue(any("PRIVATE_KEY" in error for error in errors))
        self.assertTrue(any("kairos-paper-dev-*" in error for error in errors))

    def test_rejects_example_remote_account_and_mismatched_database_identity(
        self,
    ) -> None:
        environment = {
            "KAIROS_PAPER_SECRETS_DIR": "./secrets-paper",
            "KAIROS_PAPER_ACCOUNT_ID": "kairos-paper-dev-01",
            "KAIROS_EVEDEX_DEV_EXPECTED_ACCOUNT_ID": (
                "replace-with-dedicated-evedex-dev-account-id"
            ),
            "POSTGRES_USER": "wrong",
            "POSTGRES_DB": "wrong",
            "GRAFANA_ADMIN_USER": "kairos-paper-admin",
        }
        errors = validate_paper_environment(environment)
        self.assertTrue(any("sentinel" in error for error in errors))
        self.assertTrue(any("kairos/kairos" in error for error in errors))
        self.assertFalse(
            any(
                "sentinel" in error
                for error in validate_paper_environment(
                    {**environment, "POSTGRES_USER": "kairos", "POSTGRES_DB": "kairos"},
                    allow_example_values=True,
                )
            )
        )


class PaperExecutionDockerfileTests(unittest.TestCase):
    def test_recreates_npm_entrypoints_after_copying_node_modules(self) -> None:
        dockerfile = (
            Path(__file__).resolve().parents[1]
            / "docker"
            / "Dockerfile.paper-execution"
        ).read_text(encoding="utf-8")

        self.assertNotIn("COPY --from=node /usr/local/bin/npm", dockerfile)
        self.assertIn(
            "ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm",
            dockerfile,
        )
        self.assertIn(
            "ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx",
            dockerfile,
        )


if __name__ == "__main__":
    unittest.main()
