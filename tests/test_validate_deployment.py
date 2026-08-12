from __future__ import annotations

import unittest

from scripts.validate_deployment import validate_compose, validate_environment, validate_source_lock


class EnvironmentValidationTests(unittest.TestCase):
    def valid_environment(self) -> dict[str, str]:
        return {
            "KAIROS_REDIS_PASSWORD": "a" * 64,
            "POSTGRES_USER": "kairos",
            "POSTGRES_PASSWORD": "b" * 32,
            "POSTGRES_DB": "kairos",
            "GRAFANA_ADMIN_USER": "kairos-admin",
            "GRAFANA_ADMIN_PASSWORD": "c" * 32,
            "KAIROS_DEEPSEEK_API_KEY": "sk-" + "d" * 32,
            "KAIROS_OPENAI_API_KEY": "sk-" + "e" * 32,
            "KAIROS_EVEDEX_JWT": "jwt-" + "f" * 32,
            "KAIROS_EVEDEX_PRIVATE_KEY": "0x" + "1" * 64,
            "KAIROS_BRIGHTDATA_API_TOKEN": "",
            "KAIROS_BRIGHTDATA_X_DATASET_ID": "",
            "KAIROS_REDDIT_CLIENT_ID": "",
            "KAIROS_REDDIT_CLIENT_SECRET": "",
        }

    def test_accepts_distinct_url_safe_secrets(self) -> None:
        self.assertEqual(validate_environment(self.valid_environment()), [])

    def test_rejects_placeholder_and_unsafe_redis_password(self) -> None:
        environment = self.valid_environment()
        environment["KAIROS_REDIS_PASSWORD"] = "replace-with-password@host"

        errors = validate_environment(environment)

        self.assertTrue(any("placeholder" in error for error in errors))
        self.assertTrue(any("URL-safe" in error for error in errors))

    def test_optional_source_credentials_are_pairs(self) -> None:
        environment = self.valid_environment()
        environment["KAIROS_REDDIT_CLIENT_ID"] = "client-id"

        errors = validate_environment(environment)

        self.assertTrue(any("REDDIT_CLIENT_ID" in error for error in errors))


class SourceLockValidationTests(unittest.TestCase):
    @staticmethod
    def source_lock(revision: str) -> dict[str, object]:
        services = {
            name: {
                "repository": f"https://github.com/Kairos-cryptoAI/kairos-{name}",
                "revision": revision,
                "package_dir": name.replace("-", "_"),
                "command": f"kairos-{name}",
                **({"extra": "evedex"} if name == "execution-engine" else {}),
            }
            for name in {
                "quant-scouts",
                "text-scouts",
                "router",
                "aggregator",
                "macro-strategist",
                "risk-manager",
                "execution-engine",
            }
        }
        return {
            "schema_version": 1,
            "build": {"python": "3.11.15", "uv": "0.12.3"},
            "dependencies": {"kairos-core": "a" * 40, "kairos-llm": "b" * 40},
            "infrastructure": {
                "redis": {
                    "image": "redis:8.2.8-alpine3.22@sha256:"
                    + "a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103",
                    "required_feature": "XACKDEL ref_policy=ACKED",
                }
            },
            "services": services,
        }

    def test_rejects_non_immutable_revision(self) -> None:
        lock = self.source_lock("main")

        errors = validate_source_lock(lock)

        self.assertEqual(sum("full immutable Git SHA" in error for error in errors), 7)

    def test_rejects_redis_without_xackdel_acked_support(self) -> None:
        lock = self.source_lock("c" * 40)
        lock["infrastructure"]["redis"]["image"] = "redis:7.4-alpine@sha256:" + "d" * 64

        errors = validate_source_lock(lock)

        self.assertTrue(any("Redis 8.2.8 runtime" in error for error in errors))


class ComposeValidationTests(unittest.TestCase):
    def test_rejects_secret_leak_and_published_redis_port(self) -> None:
        sha = "a" * 40
        service_names = {
            "quant-scouts",
            "text-scouts",
            "router",
            "aggregator",
            "macro-strategist",
            "risk-manager",
            "execution-engine",
        }
        source_services = {
            name: {
                "repository": f"https://github.com/Kairos-cryptoAI/kairos-{name}",
                "revision": sha,
                "package_dir": name.replace("-", "_"),
                "command": f"kairos-{name}",
                **({"extra": "evedex"} if name == "execution-engine" else {}),
            }
            for name in service_names
        }
        application = {
            name: {
                "build": {
                    "additional_contexts": {
                        "service": f"https://github.com/Kairos-cryptoAI/kairos-{name}.git#{sha}"
                    },
                    "args": {
                        "SOURCE_REVISION": sha,
                        "PACKAGE_DIR": name.replace("-", "_"),
                        **({"SERVICE_EXTRA": "evedex"} if name == "execution-engine" else {}),
                    },
                },
                "command": [f"kairos-{name}"],
                "environment": {
                    "KAIROS_REDIS_URL": "redis://:password@redis:6379/0",
                    **(
                        {
                            "KAIROS_EVEDEX_JWT": "jwt",
                            "KAIROS_EVEDEX_PRIVATE_KEY": "key",
                            "KAIROS_ACCOUNT_SNAPSHOT_INTERVAL_S": "15",
                        }
                        if name == "execution-engine"
                        else {}
                    ),
                    **(
                        {
                            "KAIROS_REQUIRE_RECONCILED_ACCOUNT": "true",
                            "KAIROS_REQUIRE_STRATEGIC_ALLOCATION": "true",
                            "KAIROS_ACCOUNT_SNAPSHOT_MAX_AGE_S": "60",
                        }
                        if name == "risk-manager"
                        else {}
                    ),
                },
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "depends_on": {"redis": {"condition": "service_healthy"}},
                "networks": {
                    "bus": None,
                    "observability": None,
                    **({"egress": None} if name in {
                        "quant-scouts",
                        "text-scouts",
                        "aggregator",
                        "macro-strategist",
                        "execution-engine",
                    } else {}),
                },
            }
            for name in service_names
        }
        application["router"]["environment"]["KAIROS_EVEDEX_PRIVATE_KEY"] = "leaked"
        config = {
            "services": {
                **application,
                "redis": {
                    "image": "redis:7.4.10-alpine3.21@sha256:" + "b" * 64,
                    "ports": [{"target": 6379, "published": "6379"}],
                    "command": ["redis-server", "requirepass", "secret"],
                    "environment": {"REDIS_PASSWORD": "secret"},
                    "healthcheck": {"test": ["CMD", "redis-cli", "ping"]},
                },
                "timescaledb": {"image": "timescale:1@sha256:" + "c" * 64},
                "prometheus": {
                    "image": "prometheus:1@sha256:" + "d" * 64,
                    "ports": [{"host_ip": "127.0.0.1"}],
                },
                "grafana": {
                    "image": "grafana:1@sha256:" + "e" * 64,
                    "ports": [{"host_ip": "127.0.0.1"}],
                },
            },
            "networks": {
                "bus": {"internal": True},
                "data": {"internal": True},
                "observability": {"internal": True},
            },
        }
        lock = {
            "services": source_services,
            "dependencies": {"kairos-core": "f" * 40, "kairos-llm": "1" * 40},
            "infrastructure": {
                "redis": {
                    "image": "redis:8.2.8-alpine3.22@sha256:"
                    + "a7859ed111db3c1f5404a973a4747505d559fb5ca32d37e447afc0ef845a2103",
                    "required_feature": "XACKDEL ref_policy=ACKED",
                }
            },
        }

        errors = validate_compose(config, lock)

        self.assertTrue(any("router: must not receive KAIROS_EVEDEX_PRIVATE_KEY" in e for e in errors))
        self.assertTrue(any("Redis must not publish a host port" in e for e in errors))
        self.assertTrue(any("Redis image must match the pinned 8.2.8 runtime" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
