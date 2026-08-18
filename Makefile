PYTHON ?= python
COMPOSE ?= docker compose
COMPOSE_FILE ?= docker-compose.yml
ENV_FILE ?= .env
STATIC_ENV_FILE ?= .env.example
SECRETS_DIR ?= secrets
LIVE_COMPOSE_FILE ?= docker-compose.live.yml

COMPOSE_CMD = $(COMPOSE) --env-file $(ENV_FILE) -f $(COMPOSE_FILE)
STATIC_COMPOSE_CMD = $(COMPOSE) --env-file $(STATIC_ENV_FILE) -f $(COMPOSE_FILE)

.PHONY: validate validate-config validate-sources preflight live-preflight build up down logs ps pull

validate: validate-sources
	$(STATIC_COMPOSE_CMD) config --quiet
	$(STATIC_COMPOSE_CMD) config --format json > .compose.resolved.json
	$(PYTHON) scripts/validate_deployment.py --compose-json .compose.resolved.json
	$(COMPOSE) --env-file $(STATIC_ENV_FILE) -f $(COMPOSE_FILE) -f $(LIVE_COMPOSE_FILE) config --format json > .compose.resolved.json
	$(PYTHON) scripts/validate_deployment.py --compose-json .compose.resolved.json --live
	$(PYTHON) -m unittest discover -s tests -v
	$(RM) .compose.resolved.json

validate-config:
	$(COMPOSE_CMD) config --quiet

validate-sources:
	$(PYTHON) scripts/validate_deployment.py --verify-remote

preflight: validate validate-config
	$(PYTHON) scripts/provision_secrets.py --secrets-dir $(SECRETS_DIR)

live-preflight: preflight
	$(PYTHON) scripts/provision_secrets.py --secrets-dir $(SECRETS_DIR) --live
	$(COMPOSE) --env-file $(ENV_FILE) -f $(COMPOSE_FILE) -f $(LIVE_COMPOSE_FILE) config --quiet

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
