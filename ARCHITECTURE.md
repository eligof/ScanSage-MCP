# ARCHITECTURE.md

## Layers
- **domain/**: core entities/value objects (no I/O)
- **services/**: business rules + orchestration (calls domain, coordinates repos/clients)
- **adapters/** (optional): persistence/external API clients
- **api/**: FastAPI/Flask routers (validation + mapping only)
- **cli/**: command entrypoints (consumer only)
- **tests/**: unit + integration tests

## Rules
- Business rules live in `services/` (or `domain/` when purely local and I/O-free).
- API routes must not implement domain rules.
- No-Bunch rule: no special-case conditionals for business behavior.
