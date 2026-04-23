COMPOSE := docker compose

.PHONY: build build-kbs build-plugin up down test logs

build: build-kbs build-plugin

build-kbs:
	$(COMPOSE) build kbs

build-plugin:
	$(COMPOSE) build ai-gatekeeper

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down -v --remove-orphans

test: build
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up -d
	bash tests/e2e.sh; EXIT=$$?; $(COMPOSE) down -v --remove-orphans; exit $$EXIT



logs:
	$(COMPOSE) logs -f
