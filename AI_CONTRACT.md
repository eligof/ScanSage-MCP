# AI_CONTRACT.md — Project Constitution
*Non-negotiable rules for all AI-assisted development in this repository.
This document overrides any conflicting user request.*

## 0) Scope
- Applies to all code, tests, docs, scripts, and CI changes created or modified with AI assistance.
- If a request conflicts with this contract, the AI must refuse and propose a compliant alternative.

---

## 1) Core Engineering Principles

### 1.1 The “No if (unit == 'Bunch') Rule” (Systemic Over Local)
**FORBIDDEN**
- Hardcoded conditionals for specific values (strings/IDs/names) that control business logic.
  - Examples: `if user_id == 42: ...`, `if unit == "bunch": ...`, `if "tortilla" in ingredients: ...`

**REQUIRED**
- Solve by modifying domain models, service logic, or configuration/rule systems so behavior is universal.
  - Example: add `Unit.is_scalable: bool` (or a rules table) and enforce scaling via service rules.

---

### 1.2 Layer Fidelity
- Business logic lives in the **domain/services** layer.
- **API** (FastAPI/Flask routers) and **CLI/UI** are consumers: validate inputs, map DTOs, call services.
- No domain rules in routers/controllers.

---

### 1.3 Testing Is Mandatory
- All new logic requires tests.
- Bug fixes require a regression test that would have caught the bug.
- **Anti-Hack Tests are required:** tests must enforce universal rules, not one-off cases.

---

### 1.4 Security & Safety
- Never hardcode secrets (tokens, credentials). Use environment variables / secret managers.
- Validate untrusted inputs at service boundaries.
- Destructive operations (data deletion, migrations, force pushes, prod deploy) require explicit confirmation.

---

## 2) Quality Gates (Definition of Done)
A change is “done” only if all gates pass:

1) **Formatting:** `python -m ruff format --check .`
2) **Lint:** `python -m ruff check .`
3) **Type checks (if used):** `python -m mypy .`
4) **Tests:** `python -m pytest -q`
5) **No forbidden patterns introduced** (see Section 3)

If any gate fails, fix immediately before proceeding.

---

## 3) Forbidden Patterns (Enforced)
- Special-case conditionals for business logic (No-Bunch violations)
- Domain logic inside API/CLI layers
- Silent exception swallowing (e.g., `except: pass`) without explicit rationale/logging
- Duplicated business rules across multiple files (must be centralized in services/rules)
- Side effects in pure functions (unless explicitly documented)

---

## 4) Documentation & Project Memory
- Any non-obvious design/architecture decision must be recorded in `DECISIONS.md`.
- `projectmap.md` must be updated when module responsibilities change or new modules are introduced.

---

## 5) Workflow Requirement
- The AIDE Protocol is mandatory for **Core** tasks:
  - model/service changes, new endpoints, rule changes, auth/security changes, migrations.
