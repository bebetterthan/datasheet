# Makefile for Security Dataset Scraper
# ======================================
# Usage: make <target>

.PHONY: help install dev-install test lint format clean docker-build docker-run scrape

PYTHON := python
PIP := pip
PROJECT_NAME := security-dataset-scraper

# Colors for terminal output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Security Dataset Scraper - Makefile Commands$(NC)"
	@echo "=============================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Install production dependencies
	$(PIP) install -e .
	playwright install chromium

dev-install: ## Install development dependencies
	$(PIP) install -e ".[dev,ai,docs]"
	playwright install chromium
	@echo "$(GREEN)Development environment ready!$(NC)"

test: ## Run all tests
	pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing
	@echo "$(GREEN)Coverage report generated in htmlcov/$(NC)"

lint: ## Run linting checks
	@echo "$(BLUE)Running flake8...$(NC)"
	flake8 src/ --max-line-length=100 --ignore=E501,W503
	@echo "$(BLUE)Running mypy...$(NC)"
	mypy src/ --ignore-missing-imports

format: ## Format code with black and isort
	@echo "$(BLUE)Running isort...$(NC)"
	isort src/ tests/
	@echo "$(BLUE)Running black...$(NC)"
	black src/ tests/
	@echo "$(GREEN)Code formatted!$(NC)"

format-check: ## Check code formatting without modifying
	isort src/ tests/ --check-only
	black src/ tests/ --check

clean: ## Clean build artifacts and cache
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "$(GREEN)Cleaned!$(NC)"

# Docker commands
docker-build: ## Build Docker image
	docker build -t $(PROJECT_NAME):latest .
	@echo "$(GREEN)Docker image built: $(PROJECT_NAME):latest$(NC)"

docker-run: ## Run scraper in Docker
	docker run -v $(PWD)/data:/app/data -v $(PWD)/config:/app/config $(PROJECT_NAME):latest

docker-shell: ## Open shell in Docker container
	docker run -it -v $(PWD)/data:/app/data -v $(PWD)/config:/app/config $(PROJECT_NAME):latest /bin/bash

docker-compose-up: ## Start all services with Docker Compose
	docker-compose up -d
	@echo "$(GREEN)Services started!$(NC)"

docker-compose-down: ## Stop all services
	docker-compose down

# Scraping commands
scrape-all: ## Scrape all configured sources
	$(PYTHON) main.py scrape all

scrape-hacktricks: ## Scrape HackTricks only
	$(PYTHON) main.py scrape hacktricks

scrape-owasp: ## Scrape OWASP only
	$(PYTHON) main.py scrape owasp

scrape-cve: ## Scrape CVE details only
	$(PYTHON) main.py scrape cve

# Processing commands
process: ## Process raw scraped data
	$(PYTHON) main.py process

dedupe: ## Deduplicate dataset
	$(PYTHON) main.py dedupe

export-axolotl: ## Export dataset for Axolotl
	$(PYTHON) main.py export axolotl

export-llama: ## Export dataset for LLaMA Factory
	$(PYTHON) main.py export llama-factory

export-unsloth: ## Export dataset for Unsloth
	$(PYTHON) main.py export unsloth

analyze: ## Analyze dataset statistics
	$(PYTHON) main.py analyze

# Documentation
docs-serve: ## Serve documentation locally
	mkdocs serve

docs-build: ## Build documentation
	mkdocs build

# Development helpers
setup-pre-commit: ## Setup pre-commit hooks
	pip install pre-commit
	pre-commit install
	@echo "$(GREEN)Pre-commit hooks installed!$(NC)"

check-all: format-check lint test ## Run all checks (format, lint, test)
	@echo "$(GREEN)All checks passed!$(NC)"

# Database commands
db-reset: ## Reset progress database
	rm -f data/progress.db
	@echo "$(YELLOW)Progress database reset$(NC)"

cache-clear: ## Clear scraping cache
	rm -rf data/cache/*
	@echo "$(YELLOW)Cache cleared$(NC)"

# Quick start
quickstart: dev-install ## Quick setup for new developers
	mkdir -p data/raw data/processed data/cache
	cp config/config.example.yaml config/config.yaml 2>/dev/null || true
	@echo ""
	@echo "$(GREEN)=====================================$(NC)"
	@echo "$(GREEN)Setup complete! Quick start:$(NC)"
	@echo "$(GREEN)=====================================$(NC)"
	@echo ""
	@echo "1. Edit config/config.yaml"
	@echo "2. Run: make scrape-hacktricks"
	@echo "3. Run: make process"
	@echo "4. Run: make export-axolotl"
	@echo ""
