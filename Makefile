PY := .venv/bin/python
PIP := $(PY) -m pip

.PHONY: dev wheelhouse offline-dev gate gate-image gate-docker pre-commit preflight preflight-docker

dev:
	@if [ ! -d ".venv" ]; then python -m venv .venv; fi
	$(PY) preflight.py --mode host
	$(PY) -m ensurepip --upgrade
	$(PIP) install -U pip
	$(PIP) install -e ".[dev]"

preflight:
	@if [ ! -d ".venv" ]; then python -m venv .venv; fi
	$(PY) preflight.py --mode any

preflight-docker:
	python preflight.py --mode docker

wheelhouse:
	mkdir -p .wheels
	python -m pip download -d .wheels pip setuptools wheel ruff pytest

offline-dev:
	@if [ ! -d ".wheels" ]; then echo ".wheels directory missing; run `make wheelhouse` on an online machine and copy it here."; exit 1; fi
	@if [ ! -d ".venv" ]; then python -m venv .venv; fi
	$(PY) -m ensurepip --upgrade || true
	$(PIP) install --no-index --find-links .wheels pip setuptools wheel
	$(PIP) install --no-index --find-links .wheels ruff pytest
	$(PIP) install --no-build-isolation --no-index --find-links .wheels -e ".[dev]"

gate:
	PYTHONPATH=src python tools/forbidden_patterns_check.py && \
	PYTHONPATH=src python -m ruff format --check . && \
	PYTHONPATH=src python -m ruff check . && \
	PYTHONPATH=src python -m pytest -q

pre-commit:
	@command -v pre-commit >/dev/null 2>&1 || { echo 'pre-commit not found on PATH; install dev extras (.[dev]) and retry.'; exit 1; }
	pre-commit install
	pre-commit run --all-files

gate-image: preflight-docker
	@if [ -d ".wheels" ]; then \
		docker build --build-arg OFFLINE_WHEELS=1 -f Dockerfile.gate -t mcp-scansage-gate .; \
	else \
		docker build --build-arg OFFLINE_WHEELS=0 -f Dockerfile.gate -t mcp-scansage-gate .; \
	fi

gate-docker: gate-image
	docker run --rm mcp-scansage-gate
