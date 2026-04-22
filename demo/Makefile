COMPOSE := docker compose

.PHONY: up down test demo logs

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down -v --remove-orphans

test:
	bash tests/demo.sh

demo:
	$(COMPOSE) down -v --remove-orphans
	$(COMPOSE) up -d --build
	bash tests/demo.sh; EXIT=$$?; $(COMPOSE) down -v --remove-orphans; exit $$EXIT

logs:
	$(COMPOSE) logs -f
