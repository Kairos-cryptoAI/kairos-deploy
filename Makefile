.PHONY: up down logs ps build clone
COMPOSE = docker compose --project-directory .. -f docker-compose.yml

build:
	$(COMPOSE) build
up:
	$(COMPOSE) up -d
down:
	$(COMPOSE) down
logs:
	$(COMPOSE) logs -f --tail=100
ps:
	$(COMPOSE) ps
# Clone every Kairos repo as a sibling (run from the parent directory).
clone:
	for r in core llm quant-scouts text-scouts router aggregator macro-strategist risk-manager execution-engine; do \
		git clone https://github.com/TheLitis/kairos-$$r.git ../kairos-$$r; \
	done
