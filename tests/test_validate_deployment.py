from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from scripts.validate_deployment import (
    APP_SERVICES,
    EXPECTED_REPOSITORIES,
    LLM_SERVICES,
    PERSISTENCE_SERVICES,
    SOURCE_SERVICES,
    SYNTHETIC_PROCESSING_SCOPE_SHA256,
    parse_dotenv,
    validate_compose,
    validate_environment,
    validate_source_lock,
    verify_remote_sources,
)


class EnvironmentValidationTests(unittest.TestCase):
    def test_accepts_secret_free_base_environment(self) -> None:
        environment = {
            "KAIROS_SECRETS_DIR": "./secrets",
            "POSTGRES_USER": "kairos",
            "POSTGRES_DB": "kairos",
            "GRAFANA_ADMIN_USER": "kairos-admin",
            "KAIROS_PROCESSING_SCOPE_SHA256": "1" * 64,
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

    def test_processing_scope_requires_operator_provisioned_lowercase_sha256(self) -> None:
        root = Path(__file__).resolve().parents[1]
        example_path = root / ".env.example"
        example = example_path.read_text(encoding="utf-8")
        self.assertIn("Synthetic render/CI fixture only", example)
        self.assertIn(SYNTHETIC_PROCESSING_SCOPE_SHA256, example)
        example_errors = validate_environment(parse_dotenv(example_path))
        self.assertTrue(any("synthetic CI fixture" in error for error in example_errors))
        for value in ("", "abc", "A" * 64, "g" * 64):
            with self.subTest(value=value):
                environment = {
                    "KAIROS_SECRETS_DIR": "./secrets",
                    "POSTGRES_USER": "kairos",
                    "POSTGRES_DB": "kairos",
                    "GRAFANA_ADMIN_USER": "kairos-admin",
                    "KAIROS_PROCESSING_SCOPE_SHA256": value,
                }
                errors = validate_environment(environment)
                self.assertTrue(any("KAIROS_PROCESSING_SCOPE_SHA256" in error for error in errors))


def source_lock(revision: str = "a" * 40) -> dict[str, object]:
    services = {
        name: {
            "repository": EXPECTED_REPOSITORIES[name],
            "revision": revision,
            "package_dir": "kairos_persistence" if name == "ops-exporter" else name.replace("-", "_"),
            "command": "kairos-persistence-exporter" if name == "ops-exporter" else f"kairos-{name}",
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


NATIVE_INPUT_DECLARATIONS = [
    "kairos-text-scouts>=0.2,<0.3",
    "kairos-macro-strategist>=0.2,<0.3",
    "kairos-router>=0.2,<0.3",
    "kairos-aggregator>=0.2,<0.3",
    "kairos-llm>=0.1,<0.2",
]
NATIVE_INPUT_REPOSITORIES = {
    "kairos-text-scouts": "text-scouts",
    "kairos-macro-strategist": "macro-strategist",
    "kairos-router": "router",
    "kairos-aggregator": "aggregator",
    "kairos-llm": "kairos-llm",
}


def remote_pyproject_for(lock, name, *, native_inputs=True, mutation=None):
    source = lock["services"][name]
    dependencies = lock["dependencies"]
    service_sources = lock["services"]
    uv_sources = {
        "kairos-core": (
            "https://github.com/Kairos-cryptoAI/kairos-core.git",
            dependencies["kairos-core"],
        ),
    }
    if name in PERSISTENCE_SERVICES:
        uv_sources["kairos-persistence"] = (
            "https://github.com/Kairos-cryptoAI/kairos-persistence.git",
            dependencies["kairos-persistence"],
        )
    if name in LLM_SERVICES or (name == "execution-engine" and native_inputs):
        uv_sources["kairos-llm"] = (
            "https://github.com/Kairos-cryptoAI/kairos-llm.git",
            dependencies["kairos-llm"],
        )
    if name == "execution-engine" and mutation == "missing-extra-with-llm":
        uv_sources["kairos-llm"] = (
            "https://github.com/Kairos-cryptoAI/kairos-llm.git",
            dependencies["kairos-llm"],
        )
    declarations = list(NATIVE_INPUT_DECLARATIONS) if native_inputs else None
    if name == "execution-engine" and native_inputs:
        for package, service_name in NATIVE_INPUT_REPOSITORIES.items():
            repository = (
                "https://github.com/Kairos-cryptoAI/kairos-llm.git"
                if package == "kairos-llm"
                else EXPECTED_REPOSITORIES[service_name] + ".git"
            )
            revision = (
                dependencies["kairos-llm"]
                if package == "kairos-llm"
                else service_sources[service_name]["revision"]
            )
            uv_sources[package] = (repository, revision)
    if mutation == "wrong-revision":
        repository, _revision = uv_sources["kairos-router"]
        uv_sources["kairos-router"] = (repository, "0" * 40)
    elif mutation == "private-url":
        _repository, revision = uv_sources["kairos-router"]
        uv_sources["kairos-router"] = ("https://private.example/kairos-router.git", revision)
    elif mutation == "wrong-version":
        declarations[0] = "kairos-text-scouts>=0.3,<0.4"
    elif mutation == "unknown-extra":
        declarations.append("kairos-unlisted>=0.1,<0.2")

    lines = [
        "[project]",
        'name = "fixture-package"',
        'version = "0.1.0"',
        "[project.scripts]",
        f'"{source["command"]}" = "fixture:main"',
    ]
    if name == "execution-engine":
        lines.extend(
            [
                "[project.optional-dependencies]",
                'evedex = ["coincurve>=20"]',
            ]
        )
        if declarations is not None:
            lines.append("native-inputs = [")
            lines.extend(f'  "{item}",' for item in declarations)
            lines.append("]")
    lines.extend(["[tool.uv]", 'required-version = "==0.12.3"', "[tool.uv.sources]"])
    for package, (repository, revision) in uv_sources.items():
        lines.append(f'"{package}" = {{ git = "{repository}", rev = "{revision}" }}')
    lines.extend(
        [
            "[tool.hatch.build.targets.wheel]",
            f'packages = ["{source["package_dir"]}"]',
        ]
    )
    return "\n".join(lines) + "\n"


def remote_uv_lock_for(lock, name, *, native_inputs=True, mutation=None):
    dependencies = lock["dependencies"]
    services = lock["services"]
    package_sources = {
        "kairos-core": (
            "https://github.com/Kairos-cryptoAI/kairos-core.git",
            dependencies["kairos-core"],
            "0.4.0",
        ),
        "kairos-persistence": (
            "https://github.com/Kairos-cryptoAI/kairos-persistence.git",
            dependencies["kairos-persistence"],
            "0.1.0",
        ),
        "kairos-llm": (
            "https://github.com/Kairos-cryptoAI/kairos-llm.git",
            dependencies["kairos-llm"],
            "0.1.0",
        ),
    }
    if name == "execution-engine" and native_inputs:
        for package, service_name in NATIVE_INPUT_REPOSITORIES.items():
            repository = (
                "https://github.com/Kairos-cryptoAI/kairos-llm.git"
                if package == "kairos-llm"
                else EXPECTED_REPOSITORIES[service_name] + ".git"
            )
            revision = (
                dependencies["kairos-llm"] if package == "kairos-llm" else services[service_name]["revision"]
            )
            version = "0.1.0" if package == "kairos-llm" else "0.2.0"
            package_sources[package] = (repository, revision, version)
    if mutation == "wrong-lock-revision":
        repository, _revision, version = package_sources["kairos-router"]
        package_sources["kairos-router"] = (repository, "0" * 40, version)
    elif mutation == "wrong-lock-version":
        repository, revision, _version = package_sources["kairos-router"]
        package_sources["kairos-router"] = (repository, revision, "0.3.0")
    elif mutation == "missing-lock-source":
        package_sources.pop("kairos-router")
    lines = [
        "[[package]]",
        f'name = "kairos-{name}"',
        'version = "0.1.0"',
        'source = { editable = "." }',
    ]
    if name == "execution-engine" and native_inputs:
        lines.extend(["", "[package.optional-dependencies]", "native-inputs = ["])
        lines.extend(f'  {{ name = "{package}" }},' for package in sorted(NATIVE_INPUT_REPOSITORIES))
        lines.append("]")
    for package, (repository, revision, version) in package_sources.items():
        lines.extend(
            [
                "",
                "[[package]]",
                f'name = "{package}"',
                f'version = "{version}"',
                f'source = {{ git = "{repository}?rev={revision}#{revision}" }}',
            ]
        )
    return "\n".join(lines) + "\n"


class SourceLockValidationTests(unittest.TestCase):
    def verify_mocked_remote(self, lock, *, mutation=None):
        service_by_slug = {
            source["repository"].removeprefix("https://github.com/"): name
            for name, source in lock["services"].items()
        }

        def request(url, *, token=None, accept=""):
            if "/commits/" in url:
                slug, revision = url.split("/repos/", 1)[1].split("/commits/", 1)
                return json.dumps({"sha": revision}).encode()
            parts = url.removeprefix("https://raw.githubusercontent.com/").split("/")
            slug, name = "/".join(parts[:2]), service_by_slug["/".join(parts[:2])]
            filename = "/".join(parts[3:])
            if filename == ".python-version":
                return b"3.11\n"
            if filename == "pyproject.toml":
                service_mutation = mutation if name == "execution-engine" else None
                return remote_pyproject_for(
                    lock,
                    name,
                    native_inputs=service_mutation != "missing-extra-with-llm",
                    mutation=service_mutation,
                ).encode()
            if filename == "uv.lock":
                service_mutation = mutation if name == "execution-engine" else None
                return remote_uv_lock_for(
                    lock,
                    name,
                    native_inputs=service_mutation != "missing-extra-with-llm",
                    mutation=service_mutation,
                ).encode()
            raise AssertionError(f"unexpected mocked URL for {slug}")

        with patch("scripts.validate_deployment._github_request", side_effect=request):
            return verify_remote_sources(lock)

    def test_execution_optional_native_inputs_are_admitted_at_exact_source_pins(self) -> None:
        lock = source_lock()
        self.assertNotIn("execution-engine", LLM_SERVICES)
        errors = self.verify_mocked_remote(lock)
        self.assertFalse(errors, errors)

    def test_execution_llm_source_without_native_inputs_is_rejected(self) -> None:
        lock = source_lock()
        errors = self.verify_mocked_remote(lock, mutation="missing-extra-with-llm")
        self.assertTrue(
            any("native-inputs must declare the exact five" in error for error in errors),
            errors,
        )

    def test_execution_native_inputs_reject_wrong_pin_version_private_url_and_extra(self) -> None:
        lock = source_lock()
        for mutation in (
            "wrong-revision",
            "private-url",
            "wrong-version",
            "unknown-extra",
            "wrong-lock-revision",
            "wrong-lock-version",
            "missing-lock-source",
        ):
            with self.subTest(mutation=mutation):
                errors = self.verify_mocked_remote(lock, mutation=mutation)
                self.assertTrue(errors, mutation)

    def test_source_revision_invalidates_remote_context_copy_cache(self) -> None:
        root = Path(__file__).resolve().parents[1]
        dockerfile = (root / "docker" / "Dockerfile").read_text(encoding="utf-8")
        identity_write = dockerfile.index("> /tmp/kairos-source-identity")
        source_copy = dockerfile.index("COPY --from=service pyproject.toml")

        self.assertLess(identity_write, source_copy)
        self.assertIn(
            'printf \'%s\\n%s\\n\' "${SOURCE_REPOSITORY}" "${SOURCE_REVISION}"',
            dockerfile,
        )
        self.assertIn(
            "COPY --from=builder --chown=kairos:kairos /tmp/kairos-source-identity /app/.source-identity",
            dockerfile,
        )

    def test_docker_context_is_deny_by_default_and_never_sends_local_secrets(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        rules = [
            line.strip()
            for line in (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
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
                self.assertIn(f"service: {source['repository']}.git#{source['revision']}", compose)
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
            "KAIROS_PERSISTENCE_MIGRATION_PROFILE": "controlled-runtime",
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
                    "KAIROS_PROCESSING_SCOPE_SHA256": "a" * 64,
                }
            )
        if name == "strategy-engine":
            environment.update(
                {
                    "KAIROS_TRADING_MODE": "DRY_RUN",
                    "KAIROS_ENABLED_STRATEGY_IDS": "[]",
                }
            )
        if name == "aggregator":
            environment.update(
                {
                    "KAIROS_CANDIDATE_REQUIRE_MACRO_CONTEXT": "true",
                    "KAIROS_CANDIDATE_REQUIRE_TEXT_CONTEXT": "true",
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
                ("KAIROS_OPENAI_API_KEY", "openai_api_key"),
                ("KAIROS_X_BEARER_TOKEN", "x_bearer_token"),
            ),
            "aggregator": (("KAIROS_OPENAI_API_KEY", "openai_api_key"),),
            "macro-strategist": (("KAIROS_OPENAI_API_KEY", "openai_api_key"),),
        }.get(name, ())
        for environment_name, provider in providers:
            secrets.append({"source": provider, "target": provider})
            environment["KAIROS_SECRET_BINDINGS"] += f",{environment_name}=/run/secrets/{provider}"
        services[name] = {
            "build": {
                "context": ".",
                "dockerfile": "docker/Dockerfile",
                "pull": True,
                "additional_contexts": {"service": f"{source['repository']}.git#{source['revision']}"},
                "args": {
                    "SOURCE_REVISION": source["revision"],
                    "SOURCE_REPOSITORY": source["repository"],
                    "PACKAGE_DIR": source["package_dir"],
                    **({"SERVICE_EXTRA": source["extra"]} if source.get("extra") else {}),
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
                "volumes": [{"type": "volume", "source": "redis-data", "target": "/data"}],
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

    def test_all_shared_database_services_require_controlled_runtime_profile(self) -> None:
        for name in SOURCE_SERVICES:
            with self.subTest(service=name):
                config, lock = rendered_config()
                environment = config["services"][name]["environment"]
                self.assertEqual(
                    environment["KAIROS_PERSISTENCE_MIGRATION_PROFILE"],
                    "controlled-runtime",
                )
                environment["KAIROS_PERSISTENCE_MIGRATION_PROFILE"] = "runtime"
                errors = validate_compose(config, lock)
                self.assertIn(
                    f"{name}: shared database requires the controlled-runtime profile",
                    errors,
                )

    def test_text_processing_scope_rejects_missing_empty_or_malformed_values(self) -> None:
        for value in (None, "", "abc", "A" * 64, "g" * 64):
            with self.subTest(value=value):
                config, lock = rendered_config()
                text_environment = config["services"]["text-scouts"]["environment"]
                if value is None:
                    del text_environment["KAIROS_PROCESSING_SCOPE_SHA256"]
                else:
                    text_environment["KAIROS_PROCESSING_SCOPE_SHA256"] = value
                errors = validate_compose(config, lock)
                self.assertIn(
                    "text-scouts: operator-provisioned processing scope must be a lowercase SHA-256",
                    errors,
                )

    def test_synthetic_processing_scope_is_ci_only_opt_in(self) -> None:
        config, lock = rendered_config()
        config["services"]["text-scouts"]["environment"]["KAIROS_PROCESSING_SCOPE_SHA256"] = (
            SYNTHETIC_PROCESSING_SCOPE_SHA256
        )

        errors = validate_compose(config, lock)
        self.assertIn(
            "text-scouts: synthetic CI processing scope is not deployment authority",
            errors,
        )
        self.assertEqual(validate_compose(config, lock, allow_example_values=True), [])

    def test_aggregator_requires_macro_and_text_context(self) -> None:
        for key, label in (
            ("KAIROS_CANDIDATE_REQUIRE_MACRO_CONTEXT", "Macro"),
            ("KAIROS_CANDIDATE_REQUIRE_TEXT_CONTEXT", "Text"),
        ):
            with self.subTest(key=key, value="missing"):
                config, lock = rendered_config()
                del config["services"]["aggregator"]["environment"][key]
                errors = validate_compose(config, lock)
                self.assertIn(
                    f"aggregator: candidate {label} context must be required",
                    errors,
                )
            for value in ("false", ""):
                with self.subTest(key=key, value=value):
                    config, lock = rendered_config()
                    config["services"]["aggregator"]["environment"][key] = value
                    errors = validate_compose(config, lock)
                    self.assertIn(
                        f"aggregator: candidate {label} context must be required",
                        errors,
                    )

    def test_text_scouts_current_openai_and_x_scope_keeps_legacy_definition_dormant(
        self,
    ) -> None:
        config, lock = rendered_config()
        text = config["services"]["text-scouts"]

        self.assertNotIn("deepseek_api_key", config["secrets"])
        self.assertEqual(
            {secret["source"] for secret in text["secrets"]},
            {
                "redis_url",
                "persistence_database_url",
                "openai_api_key",
                "x_bearer_token",
            },
        )
        self.assertNotIn("KAIROS_DEEPSEEK_API_KEY", text["environment"]["KAIROS_SECRET_BINDINGS"])
        self.assertEqual(validate_compose(config, lock), [])

    def test_rendered_base_and_live_secret_sets_are_exactly_active(self) -> None:
        for live in (False, True):
            with self.subTest(live=live):
                config, lock = rendered_config()
                if live:
                    config["services"]["execution-engine"]["environment"]["KAIROS_TRADING_MODE"] = "LIVE"
                referenced_secrets = {
                    secret["source"]
                    for service in config["services"].values()
                    for secret in service.get("secrets", [])
                }

                self.assertEqual(set(config["secrets"]), referenced_secrets)
                self.assertNotIn("deepseek_api_key", referenced_secrets)
                self.assertEqual(validate_compose(config, lock, live=live), [])

    def test_rejects_dormant_legacy_secret_in_rendered_active_inventory(self) -> None:
        config, lock = rendered_config()
        config["secrets"]["deepseek_api_key"] = {"file": "/secrets/deepseek_api_key"}

        errors = validate_compose(config, lock)

        self.assertIn(
            "top-level secret definitions must match the exact active base allow-list",
            errors,
        )
        self.assertFalse(any(error.startswith("deepseek_api_key:") for error in errors))

    def test_repository_text_scouts_secret_scope_matches_current_gateway_default(
        self,
    ) -> None:
        # The central gateway's TEXT_SCOUTS default is OpenAI gpt-6-luna/low.
        # Verify the actual Compose source, not just a synthetic rendered fixture,
        # without importing the LLM package or loading local environment files.
        root = Path(__file__).resolve().parents[1]
        compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn(
            "\n  deepseek_api_key:\n    file: ${KAIROS_SECRETS_DIR:-./secrets}/deepseek_api_key\n",
            compose,
        )
        text = compose.split("\n  text-scouts:\n", 1)[1].split("\n  router:\n", 1)[0]
        bindings = next(
            line.strip().partition(": ")[2]
            for line in text.splitlines()
            if line.strip().startswith("KAIROS_SECRET_BINDINGS:")
        )
        self.assertEqual(
            bindings,
            "KAIROS_REDIS_URL=/run/secrets/redis_url,"
            "KAIROS_PERSISTENCE_DATABASE_URL=/run/secrets/persistence_database_url,"
            "KAIROS_OPENAI_API_KEY=/run/secrets/openai_api_key,"
            "KAIROS_X_BEARER_TOKEN=/run/secrets/x_bearer_token",
        )
        mounts = text.split("\n    secrets:\n", 1)[1].split("\n    networks:\n", 1)[0]
        self.assertEqual(
            [line.strip() for line in mounts.splitlines() if line.strip()],
            [
                "- *redis-url-secret",
                "- *persistence-url-secret",
                "- *openai-secret",
                "- *x-bearer-secret",
            ],
        )

    def test_text_scouts_rejects_missing_openai_mount_or_binding(self) -> None:
        for missing_mount, missing_binding in (
            (True, False),
            (False, True),
            (True, True),
        ):
            with self.subTest(missing_mount=missing_mount, missing_binding=missing_binding):
                config, lock = rendered_config()
                text = config["services"]["text-scouts"]
                if missing_mount:
                    text["secrets"] = [
                        secret for secret in text["secrets"] if secret["source"] != "openai_api_key"
                    ]
                if missing_binding:
                    text["environment"]["KAIROS_SECRET_BINDINGS"] = ",".join(
                        binding
                        for binding in text["environment"]["KAIROS_SECRET_BINDINGS"].split(",")
                        if not binding.startswith("KAIROS_OPENAI_API_KEY=")
                    )

                errors = validate_compose(config, lock)

                if missing_mount:
                    self.assertIn(
                        "text-scouts: expected provider secret file openai_api_key is missing",
                        errors,
                    )
                if missing_binding:
                    self.assertIn(
                        "text-scouts: expected provider binding KAIROS_OPENAI_API_KEY is missing",
                        errors,
                    )

    def test_text_scouts_rejects_legacy_only_deepseek_runtime_scope(self) -> None:
        config, lock = rendered_config()
        text = config["services"]["text-scouts"]
        for secret in text["secrets"]:
            if secret["source"] == "openai_api_key":
                secret.update(source="deepseek_api_key", target="deepseek_api_key")
        text["environment"]["KAIROS_SECRET_BINDINGS"] = text["environment"]["KAIROS_SECRET_BINDINGS"].replace(
            "KAIROS_OPENAI_API_KEY=/run/secrets/openai_api_key",
            "KAIROS_DEEPSEEK_API_KEY=/run/secrets/deepseek_api_key",
        )

        errors = validate_compose(config, lock)

        self.assertIn(
            "text-scouts: expected provider secret file openai_api_key is missing",
            errors,
        )
        self.assertIn(
            "text-scouts: expected provider binding KAIROS_OPENAI_API_KEY is missing",
            errors,
        )
        self.assertIn("text-scouts: secret source set must match the exact allow-list", errors)
        self.assertIn("text-scouts: secret bindings must match the exact allow-list", errors)

    def test_text_scouts_rejects_extra_legacy_deepseek_runtime_scope(self) -> None:
        config, lock = rendered_config()
        text = config["services"]["text-scouts"]
        text["secrets"].append({"source": "deepseek_api_key", "target": "deepseek_api_key"})
        text["environment"]["KAIROS_SECRET_BINDINGS"] += (
            ",KAIROS_DEEPSEEK_API_KEY=/run/secrets/deepseek_api_key"
        )

        errors = validate_compose(config, lock)

        self.assertIn("text-scouts: secret source set must match the exact allow-list", errors)
        self.assertIn("text-scouts: secret bindings must match the exact allow-list", errors)

    def test_rejects_secret_env_host_redis_and_live_base_execution(self) -> None:
        config, lock = rendered_config()
        broken = deepcopy(config)
        broken["services"]["router"]["environment"]["KAIROS_EVEDEX_PRIVATE_KEY"] = "x"
        broken["services"]["redis"]["ports"] = [{"published": 6379}]
        broken["services"]["execution-engine"]["environment"]["KAIROS_TRADING_MODE"] = "LIVE"
        errors = validate_compose(broken, lock)
        self.assertTrue(any("file-mounted" in error for error in errors))
        self.assertTrue(any("Redis must not publish" in error for error in errors))
        self.assertTrue(any("base Compose" in error for error in errors))

    def test_rejects_secret_alias_and_extra_binding_bypass(self) -> None:
        config, lock = rendered_config()
        execution = config["services"]["execution-engine"]
        execution["secrets"].append({"source": "foo", "target": "foo"})
        execution["environment"]["KAIROS_SECRET_BINDINGS"] += ",KAIROS_EVEDEX_PRIVATE_KEY=/run/secrets/foo"
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
        self.assertTrue(any("unsafe Compose option entrypoint" in error for error in errors))
        self.assertTrue(any("unsafe Compose option cap_add" in error for error in errors))
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
        execution["secrets"].extend([{"source": "evedex_jwt"}, {"source": "evedex_private_key"}])
        errors = validate_compose(config, lock, live=True)
        self.assertTrue(any("retired static EVEDEX" in error for error in errors))

    def test_rejects_x_budget_above_qualification_ceiling(self) -> None:
        config, lock = rendered_config()
        config["services"]["text-scouts"]["environment"]["KAIROS_X_MONTHLY_BUDGET_MICROUSD"] = "2000001"

        errors = validate_compose(config, lock)

        self.assertTrue(any("$2 qualification ceiling" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
