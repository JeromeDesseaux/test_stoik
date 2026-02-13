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

test: docker-up ## Run tests
	$(DOCKER_COMPOSE) run --rm app sh -c "go test -v -cover ./..."

docker-up: ## Start PostgreSQL and services
	$(DOCKER_COMPOSE) up -d
	@echo "Waiting for PostgreSQL to be ready..."
	@sleep 3

run: docker-up ## Start containers and run the application
	$(DOCKER_COMPOSE) up app

docker-build: ## Build Docker image
	docker build -t email-security:latest .

docker-down: ## Stop services
	$(DOCKER_COMPOSE) down

docker-logs: ## View logs
	$(DOCKER_COMPOSE) logs -f app

docker-rebuild: docker-down docker-build docker-up ## Rebuild and restart containers

clean: ## Clean build artifacts and stop containers
	rm -rf bin/
	rm -f coverage.out coverage.html
	$(DOCKER_COMPOSE) down -v

.DEFAULT_GOAL := help
