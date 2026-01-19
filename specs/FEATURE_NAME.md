# specs/FEATURE_NAME.md
**Status:** Draft | Approved | Implemented
**Last Updated:** YYYY-MM-DD

## 1) Problem Statement
What is broken/missing? Who is affected? What is the expected outcome?

## 2) Requirements & Invariants
### Requirements
- [ ] R1:
- [ ] R2:

### Invariants (must remain true)
- [ ] I1:
- [ ] I2:

## 3) Architecture & Placement
Where will changes live and why?
- Domain models:
- Services/rules:
- API/CLI (consumer only):
Justification: cite `AI_CONTRACT.md` + relevant sections of `ARCHITECTURE.md`.

## 4) Implementation Slices (Ordered)
1) Slice 1 — Domain Model
   - Files:
   - Changes:
   - Notes:
2) Slice 2 — Service Logic
   - Files:
   - Changes:
3) Slice 3 — API/CLI Wiring
   - Files:
   - Changes:
4) Slice 4 — Tests & Docs
   - Files:
   - Changes:

## 5) Test Strategy
- Unit tests:
- Integration tests (if applicable):
- **Anti-Hack Test(s):** state the universal rule(s) you will enforce.
  - Example: “All non-scalable units remain unchanged when servings are doubled.”

## 6) Risks & Pre-Mortem (Mandatory)
List 1–2 likely failure modes or “future hacks,” and how we prevent them.
- Failure mode:
  - Mitigation (design):
  - Mitigation (test/gate):

## 7) Rollout & Rollback Plan
- Backwards compatible: Yes/No
- Migration required: Yes/No
- Rollback steps:

## 8) Context Strategy for AIDE
- Phase 1 (Pre-Retrieve): `AI_CONTRACT.md`, `ARCHITECTURE.md`, `projectmap.md`, plus:
- Phase 2 (JIT Retrieval): list expected files to open during slices.

## 9) Exit Criteria (Must Be True to Close)
- [ ] Plan approved explicitly by user (Phase 1 gate)
- [ ] All slices implemented
- [ ] Anti-Hack tests added
- [ ] All quality gates pass (ruff format/check, pytest, mypy if used)
- [ ] No forbidden patterns introduced
- [ ] `DECISIONS.md` updated (if non-obvious decision)
- [ ] `projectmap.md` updated (if structure/responsibilities changed)
