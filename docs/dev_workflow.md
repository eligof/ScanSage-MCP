# Developer workflow

This repo is intentionally set up so local checks match CI as closely as possible.

## Bootstrap
- Start with `README.md` (Development section) for the supported bootstrap paths.
- If you need the full “host vs wheelhouse vs docker” matrix, see `docs/dev_bootstrap_matrix.md`.
- `make dev` can bootstrap a local `.venv` and install `.[dev]` using the recommended host path.
- Run `make preflight` first if you’re unsure which path your machine can support.

## Daily workflow
- Install and run the repo’s pre-commit hook once per clone:
  - `make pre-commit`
- Before pushing (or whenever you want CI-parity validation), run:
  - `make gate`

## Pre-commit
- The hook definition lives in `.pre-commit-config.yaml`.
- After installation, it will run automatically on `git commit`.
- If you want to run the hook without committing, use `make pre-commit`.

## CI parity
- GitHub Actions runs the same gates as `make gate` (see `.github/workflows/ci.yml`).
- Branch protections/rulesets require the CI checks to pass before merge.

## Troubleshooting
- If `make pre-commit` fails because `pre-commit` is missing, install the dev dependencies (see `README.md`).
- If a hook fails, run `make gate` to reproduce the same checks with full output.
- If you see an unexpectedly dirty working tree, start with `git status -sb` (runtime artifacts should be ignored).
- If you prefer containerized checks, `make gate-docker` runs the same gate sequence in `Dockerfile.gate`.
