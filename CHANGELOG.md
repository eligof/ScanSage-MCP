# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-01-28

### Added
- `ingest_nmap_xml` additive alias entrypoint (parity + Anti-Hack coverage).
- Minimal CI (Python 3.10/3.12) running the canonical gates.
- Pre-commit hook running the canonical gate chain; `make pre-commit` and `docs/dev_workflow.md`.
- Synced `docs/rulesets.json` snapshot + contract test to prevent drift.

### Changed
- Repo hygiene: stop tracking runtime artifacts and ignore runtime outputs.
