PYTHON ?= python
COMPOSE ?= docker compose
COMPOSE_FILE ?= docker-compose.yml
ENV_FILE ?= .env
STATIC_ENV_FILE ?= .env.example
SECRETS_DIR ?= secrets
LIVE_COMPOSE_FILE ?= docker-compose.live.yml
PAPER_COMPOSE_FILE ?= docker-compose.paper.yml
PAPER_ENV_FILE ?= .env.paper
PAPER_STATIC_ENV_FILE ?= .env.paper.example
PAPER_SECRETS_DIR ?= secrets-paper
OUTBOX_RECONCILIATION_COMPOSE_FILE ?= docker-compose.outbox-reconciliation.yml
OUTBOX_RECONCILIATION_STATIC_ENV_FILE ?= .env.outbox-reconciliation.example
OUTBOX_DRAIN_COMPOSE_FILE ?= docker-compose.outbox-drain.yml
OUTBOX_DRAIN_STATIC_ENV_FILE ?= .env.outbox-drain.example

COMPOSE_CMD = $(COMPOSE) --env-file $(ENV_FILE) -f $(COMPOSE_FILE)
STATIC_COMPOSE_CMD = $(COMPOSE) --env-file $(STATIC_ENV_FILE) -f $(COMPOSE_FILE)

.PHONY: validate validate-config validate-sources preflight live-boundary live-preflight paper-validate paper-preflight paper-canary-report outbox-reconciliation-validate outbox-drain-validate build up down logs ps pull

validate: validate-sources
	$(STATIC_COMPOSE_CMD) config --quiet
	$(STATIC_COMPOSE_CMD) config --format json > .compose.resolved.json
	$(PYTHON) scripts/validate_deployment.py --compose-json .compose.resolved.json
	$(COMPOSE) --env-file $(STATIC_ENV_FILE) -f $(COMPOSE_FILE) -f $(LIVE_COMPOSE_FILE) config --format json > .compose.resolved.json
	$(PYTHON) scripts/validate_deployment.py --compose-json .compose.resolved.json --live
	$(MAKE) outbox-reconciliation-validate
	$(MAKE) outbox-drain-validate
	$(PYTHON) -m unittest discover -s tests -v
	$(RM) .compose.resolved.json

validate-config:
	$(COMPOSE_CMD) config --quiet

validate-sources:
	$(PYTHON) scripts/validate_deployment.py --verify-remote
	$(PYTHON) scripts/validate_offline_outbox_reconciliation.py --verify-remote
	$(PYTHON) scripts/validate_offline_outbox_drain.py --verify-remote

preflight: validate validate-config
	$(PYTHON) scripts/provision_secrets.py --secrets-dir $(SECRETS_DIR)

live-boundary: validate
	$(COMPOSE) --env-file $(STATIC_ENV_FILE) -f $(COMPOSE_FILE) -f $(LIVE_COMPOSE_FILE) config --format json > .compose.live.resolved.json
	$(PYTHON) scripts/validate_deployment.py --compose-json .compose.live.resolved.json --live
	$(RM) .compose.live.resolved.json

live-preflight:
	@echo "LIVE is intentionally unavailable; use live-boundary to validate the fail-closed overlay." 1>&2
	@exit 2

paper-validate:
	$(PYTHON) scripts/validate_paper_deployment.py --verify-remote
	$(COMPOSE) --profile canary --env-file $(PAPER_STATIC_ENV_FILE) -f $(PAPER_COMPOSE_FILE) config --format json > .compose.paper.resolved.json
	$(PYTHON) scripts/validate_paper_deployment.py --compose-json .compose.paper.resolved.json --env-file $(PAPER_STATIC_ENV_FILE) --allow-example-values
	$(RM) .compose.paper.resolved.json

paper-preflight: paper-validate
	$(PYTHON) scripts/provision_secrets.py --secrets-dir $(PAPER_SECRETS_DIR) --paper
	$(COMPOSE) --profile canary --env-file $(PAPER_ENV_FILE) -f $(PAPER_COMPOSE_FILE) config --format json > .compose.paper.resolved.json
	$(PYTHON) scripts/validate_paper_deployment.py --compose-json .compose.paper.resolved.json --env-file $(PAPER_ENV_FILE)
	$(RM) .compose.paper.resolved.json

paper-canary-report:
	$(PYTHON) scripts/paper_canary_acceptance.py --compose-file $(PAPER_COMPOSE_FILE) --env-file $(PAPER_ENV_FILE)

outbox-reconciliation-validate:
	$(PYTHON) scripts/validate_offline_outbox_reconciliation.py --verify-remote
	$(COMPOSE) --env-file $(OUTBOX_RECONCILIATION_STATIC_ENV_FILE) -f $(OUTBOX_RECONCILIATION_COMPOSE_FILE) config --format json > .compose.outbox-reconciliation-normal-up.resolved.json
	$(PYTHON) scripts/validate_offline_outbox_reconciliation.py --normal-up-compose-json .compose.outbox-reconciliation-normal-up.resolved.json
	$(COMPOSE) --profile offline-outbox-inspect --profile offline-outbox-apply --env-file $(OUTBOX_RECONCILIATION_STATIC_ENV_FILE) -f $(OUTBOX_RECONCILIATION_COMPOSE_FILE) config --format json > .compose.outbox-reconciliation.resolved.json
	$(PYTHON) scripts/validate_offline_outbox_reconciliation.py --compose-json .compose.outbox-reconciliation.resolved.json
	$(COMPOSE) --profile offline-outbox-inspect --profile offline-outbox-apply --env-file $(OUTBOX_RECONCILIATION_STATIC_ENV_FILE) -f $(OUTBOX_RECONCILIATION_COMPOSE_FILE) config --quiet
	$(RM) .compose.outbox-reconciliation-normal-up.resolved.json
	$(RM) .compose.outbox-reconciliation.resolved.json

outbox-drain-validate:
	$(PYTHON) scripts/validate_offline_outbox_drain.py --verify-remote
	$(COMPOSE) --env-file $(OUTBOX_DRAIN_STATIC_ENV_FILE) -f $(OUTBOX_DRAIN_COMPOSE_FILE) config --format json > .compose.outbox-drain-normal-up.resolved.json
	$(PYTHON) scripts/validate_offline_outbox_drain.py --normal-up-compose-json .compose.outbox-drain-normal-up.resolved.json
	$(COMPOSE) --profile offline-outbox-drain-inspect --profile offline-outbox-drain-apply --env-file $(OUTBOX_DRAIN_STATIC_ENV_FILE) -f $(OUTBOX_DRAIN_COMPOSE_FILE) config --format json > .compose.outbox-drain.resolved.json
	$(PYTHON) scripts/validate_offline_outbox_drain.py --compose-json .compose.outbox-drain.resolved.json
	$(COMPOSE) --profile offline-outbox-drain-inspect --profile offline-outbox-drain-apply --env-file $(OUTBOX_DRAIN_STATIC_ENV_FILE) -f $(OUTBOX_DRAIN_COMPOSE_FILE) config --quiet
	$(RM) .compose.outbox-drain-normal-up.resolved.json
	$(RM) .compose.outbox-drain.resolved.json

build: preflight
	$(COMPOSE_CMD) build --pull

up: preflight
	$(COMPOSE_CMD) up --detach --build

down:
	$(COMPOSE_CMD) down

logs:
	$(COMPOSE_CMD) logs --follow --tail=100

ps:
	$(COMPOSE_CMD) ps

pull:
	$(COMPOSE_CMD) pull --ignore-buildable
