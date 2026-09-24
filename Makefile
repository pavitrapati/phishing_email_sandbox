SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help build build-wine up down restart logs ps samples test test-unit test-integration clean nuke shell-worker verify-isolation

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the api, fakenet and worker images
	$(COMPOSE) build
	docker build -t sbx-worker:latest services/worker

build-wine: build ## Additionally build the Wine worker for real PE detonation (~1.5 GB)
	docker build -f services/worker/Dockerfile.wine -t sbx-worker-wine:latest services/worker
	@echo "Built. Set ENABLE_WINE=1 in .env and run 'make restart' to use it."

up: ## Start the stack
	@test -f .env || (echo "No .env -- copy .env.example and set SANDBOX_HOST_DATA"; exit 1)
	@mkdir -p data/jobs data/net && chmod 0777 data/jobs data/net
	$(COMPOSE) up -d
	@echo "API on http://127.0.0.1:$${SANDBOX_PORT:-8090}"

down: ## Stop the stack
	$(COMPOSE) down

restart: down up ## Restart the stack

logs: ## Follow logs
	$(COMPOSE) logs -f

ps: ## Show stack status
	$(COMPOSE) ps

samples: ## Regenerate the inert test samples
	python3 tests/make_samples.py

pe-scenarios: ## Cross-compile the inert PE + build the .exe/.dll/embedded/nested scenarios
	docker run --rm -v "$(CURDIR)/tests:/t" -w /t/pebuild debian:bookworm-slim bash -c \
	  "apt-get update -qq >/dev/null && apt-get install -y -qq gcc-mingw-w64-x86-64 >/dev/null && \
	   x86_64-w64-mingw32-gcc dropper.c -o /t/samples/dropper.exe -lwininet -ladvapi32 -O2 -s"
	python3 tests/make_pe_scenarios.py

test-unit: ## Run analyzer/scoring unit tests inside the worker image (no daemon needed)
	docker run --rm --network none \
	  -v "$(CURDIR)/tests:/tests:ro" \
	  -v "$(CURDIR)/services/api:/api:ro" \
	  --entrypoint python sbx-worker:latest /tests/test_unit.py

test-integration: ## Detonate every sample against the running stack
	bash tests/test_integration.sh

test: test-unit test-integration ## Run the whole suite

verify-isolation: ## Prove the detonation network really has no route out
	bash tests/verify_isolation.sh

shell-worker: ## Interactive shell in the worker image (for debugging analyzers)
	docker run --rm -it --network none --entrypoint bash sbx-worker:latest

clean: ## Remove job data and reports
	rm -rf data/jobs/* data/net/*.jsonl
	@echo "job data cleared"

nuke: down clean ## Stop everything and remove images
	-docker rmi sbx-api:latest sbx-fakenet:latest sbx-worker:latest sbx-worker-wine:latest
