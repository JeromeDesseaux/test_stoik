# Auto-detect docker-compose command (support both v1 and v2)
DOCKER_COMPOSE := $(shell command -v docker-compose 2>/dev/null)
ifndef DOCKER_COMPOSE
	DOCKER_COMPOSE := docker compose
endif

.PHONY: help build test test-coverage run docker-build docker-up docker-down docker-logs docker-rebuild clean fmt deps

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the Docker image
	$(DOCKER_COMPOSE) build app

test: ## Run tests
	$(DOCKER_COMPOSE) run --rm app sh -c "go test -v -cover ./..."

run: ## Run the application
	$(DOCKER_COMPOSE) up

down: ## Stop services
	$(DOCKER_COMPOSE) down

logs: ## View logs
	$(DOCKER_COMPOSE) logs -f app

clean: ## Clean build artifacts and stop containers
	rm -rf bin/
	rm -f coverage.out coverage.html
	$(DOCKER_COMPOSE) down -v

.DEFAULT_GOAL := help
