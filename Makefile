IMAGE  ?= ai-gatekeeper
CONFIG ?= $(PWD)/config.yaml
POLICY ?= $(PWD)/policy.rego

.PHONY: install test build run e2e

install:
	pip install -e ".[dev]"

test:
	pytest tests/

build:
	docker build -t $(IMAGE) .

run:
	IMAGE=$(IMAGE) CONFIG=$(CONFIG) POLICY=$(POLICY) docker compose up

e2e:
	$(MAKE) -C e2e test
