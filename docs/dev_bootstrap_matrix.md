# Development Bootstrap Matrix

Start every session with:

```
make preflight
```

If the preflight result shows a “Recommended path”, follow the matching command below. If it prints a “Recommended next step”, complete that step (usually creating `.venv`, running `ensurepip`, or installing OS `python-setuptools`) before continuing.

## Host dev (online / OS tooling available)

```
python -m venv .venv && \
.venv/bin/python -m ensurepip --upgrade && \
.venv/bin/python -m pip install -U pip && \
.venv/bin/python preflight.py --mode host && \
.venv/bin/python -m pip install -e ".[dev]" && \
PYTHONPATH=src python tools/forbidden_patterns_check.py && \
PYTHONPATH=src python -m ruff format --check . && \
PYTHONPATH=src python -m ruff check . && \
PYTHONPATH=src python -m pytest -q
```

This path requires a working `pip`/`setuptools` inside `.venv` plus `ruff`/`pytest`. If those packages are missing, the command will fail—gates cannot run until the tooling is installed (see the preflight output for guidance).

## Offline wheelhouse (one-time download + offline host)

On an online machine:

```
make wheelhouse
```

Copy the resulting `.wheels/` directory to the offline host, then run:

```
make offline-dev && make gate
```

This sequence installs `pip`, `setuptools`, and the gate tooling from the wheelhouse before running the gates without touching PyPI.

## Docker gate-runner (useful when the host Python is stripped or you need isolation)

```
make gate-docker
```

`make gate-docker` builds `Dockerfile.gate` (automatically using `.wheels/` when present) and runs the bundled gate command inside the container, so it works even if the host lacks setuptools or ruff. If Docker cannot access `/var/run/docker.sock`, rerun `make preflight` for troubleshooting hints.

### Why some sandboxes cannot run gates
Stripped hosts often lack `pip`, `setuptools`, or the gate tooling (`ruff`/`pytest`). Those missing packages make the host path fail until you bootstrap using OS packages or the wheelhouse. If Docker is also blocked (permission denied on the daemon), the container path will surface that via `make preflight` and cannot succeed until the permissions are fixed.
