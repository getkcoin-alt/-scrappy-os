PYTHON ?= python3.12
VENV := .venv
BIN := $(VENV)/bin

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

$(BIN)/python:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip

.PHONY: install
install: $(BIN)/python ## Install the package with dev extras
	$(BIN)/python -m pip install -e '.[dev]'

.PHONY: lint
lint: ## Run ruff
	$(BIN)/ruff check .

.PHONY: format
format: ## Autoformat and autofix
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

.PHONY: typecheck
typecheck: ## Run mypy
	$(BIN)/mypy

.PHONY: test
test: ## Run the full test suite
	$(BIN)/pytest

.PHONY: security-test
security-test: ## Run only the safety-boundary tests
	$(BIN)/pytest tests/security -v

.PHONY: check
check: lint test ## Gate for the v0.1 definition of done

.PHONY: doctor
doctor: ## Run the environment self-check
	$(BIN)/scrappy doctor

.PHONY: serve
serve: ## Run the local API
	$(BIN)/scrappy serve

.PHONY: clean
clean: ## Remove build and tooling caches (never touches data/)
	rm -rf build dist *.egg-info src/*.egg-info
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	find . -path ./$(VENV) -prune -o -name __pycache__ -type d -print0 | xargs -0 rm -rf
