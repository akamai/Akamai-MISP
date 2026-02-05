.PHONY: help install dev-install test test-unit test-integration lint format security-scan clean validate pre-commit-install pre-commit-run

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install production dependencies
	pip install -e .

dev-install: ## Install development dependencies
	pip install -e ".[dev]"
	@echo "✓ Development dependencies installed"
	@echo "Run 'make pre-commit-install' to set up pre-commit hooks"

test: ## Run all tests with coverage
	pytest tests/ -v --cov=. --cov-report=term-missing --cov-report=html
	@echo "✓ Coverage report generated in htmlcov/index.html"

test-unit: ## Run only unit tests
	pytest tests/ -v -m "not integration"

test-integration: ## Run only integration tests
	pytest tests/ -v -m integration

lint: ## Run linting checks (ruff, mypy)
	@echo "Running ruff..."
	ruff check akamai_ioc.py tests/
	@echo "Running mypy..."
	mypy akamai_ioc.py
	@echo "✓ Linting passed"

format: ## Format code with ruff
	ruff format akamai_ioc.py tests/
	@echo "✓ Code formatted"

security-scan: ## Run security scans (bandit)
	@echo "Running bandit security scan..."
	bandit -r akamai_ioc.py -ll
	@echo "✓ Security scan complete"

validate: lint security-scan test ## Run full validation (lint + security + tests)
	@echo "✓ Full validation passed"

pre-commit-install: ## Install pre-commit hooks
	pre-commit install
	@echo "✓ Pre-commit hooks installed"

pre-commit-run: ## Run pre-commit hooks on all files
	pre-commit run --all-files

clean: ## Clean build artifacts and cache
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .ruff_cache/ .mypy_cache/
	rm -rf htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.log" -delete
	@echo "✓ Cleaned build artifacts and cache"

check-deps: ## Check for outdated dependencies
	pip list --outdated

update-deps: ## Update dependencies (use with caution)
	pip install --upgrade pip
	pip install --upgrade -r requirements.txt -r requirements-dev.txt

# MISP-specific targets
validate-module: ## Validate module before deployment
	@bash validate_module.sh

install-to-misp: ## Install module to MISP (requires MISP_MODULES_BASE env var)
	@if [ -z "$$MISP_MODULES_BASE" ]; then \
		echo "ERROR: MISP_MODULES_BASE environment variable not set"; \
		echo "Example: export MISP_MODULES_BASE=/usr/local/lib/python3.10/dist-packages"; \
		exit 1; \
	fi
	@echo "Installing to: $$MISP_MODULES_BASE/misp_modules/modules/expansion/"
	cp akamai_ioc.py "$$MISP_MODULES_BASE/misp_modules/modules/expansion/"
	@echo "✓ Module installed. Remember to restart misp-modules service"

.PHONY: version
version: ## Show current version
	@echo "Akamai-MISP version 2.0.0"
