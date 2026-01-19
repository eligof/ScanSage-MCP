# specs/nmap_public_ingestion_v0.1.md
**Status:** Draft
**Last Updated:** 2026-01-19

## 1) Problem Statement
PUBLIC tooling lacks a safe FastMCP entrypoint that can accept Nmap XML payloads without leaking raw identifiers or echoing entire scans. Analysts and automation pipelines need a schema-governed ingestion contract plus a placeholder service so later slices can safely build the real parser while the router just mediates contracts.

## 2) Requirements & Invariants
### Requirements
- [ ] R1: Define input/output JSON schemas that bound Nmap XML payloads and mandate PUBLIC-safe response shapes (operation, summary metadata, empty findings).
- [ ] R2: Implement a service that size-checks the payload, records a digest, never echoes identifiers, and replies with placeholder findings/next steps.
- [ ] R3: Wire a PUBLIC FastMCP resource to validate inputs/outputs, sanitize errors, and emit reason codes for gated failures.
### Invariants (must remain true)
- [ ] I1: No business logic escapes services/domain (Layer Fidelity from `ARCHITECTURE.md`).
- [ ] I2: No special-cased strings/identifiers (No-Bunch from `AI_CONTRACT.md`); sanitizer/anti-hack guards cover all inputs.

## 3) Architecture & Placement
Where will changes live and why?
- Domain models: none for this slice; future parsed findings can reuse `domain.Finding`.
- Services/rules: new `services/nmap_ingest.py` implements universal payload guarding, digest summary, and constant next steps.
- API/CLI (consumer only): new PUBLIC resource under `mcp/server.py` validates via `schema_registry`, sanitizes errors, and routes to the service.
Justification: following `AI_CONTRACT.md` (No-Bunch + Layer Fidelity) and `ARCHITECTURE.md`, business rules remain in services while FastMCP routes only validate/marshal.

## 4) Implementation Slices (Ordered)
1) Slice 1 — PUBLIC-safe ingestion scaffolding (this slice)
   - Files: `specs/nmap_public_ingestion_v0.1.md`, `schemas/nmap_ingest_*`, `services/nmap_ingest.py`, `mcp/schema_registry.py`, `mcp/reason_codes.py`, `mcp/server.py`, `tests/test_nmap_ingestion_public.py`, `tests/test_anti_hack.py`, `DECISIONS.md`, `projectmap.md`
   - Changes: add schemas/examples, stub service, schema registry, reason codes, resource wiring, and contract/anti-hack tests; update docs.
   - Notes: avoid parsing, keep `parsed=false`, ensure sanitized responses/denials, enforce schema validation.
2) Slice 2 — (future) xml parser + finding extraction
   - Files: future service/parser modules plus domain models for actual findings.
   - Changes: implement XML parsing, populate `findings`, keep PUBLIC protections.
3) Slice 3 — (future) router/gateway enhancements
   - Files: routing/wiring, metrics, maybe adapters.
   - Changes: integrate actual parsing service with existing exposure plus caching/auditing.
4) Slice 4 — (future) extended testing & docs
   - Files: additional tests, docs, runbooks.
   - Changes: more anti-hack cases, sample payloads, user docs.

## 5) Test Strategy
- Unit tests: service-level checks on byte limits, digest creation, sanitized summaries; schema validation via `schema_registry`.
- Integration tests: FastMCP resource invoked via `server.RESOURCE_REGISTRY` to assert schema compliance and sanitized responses/denials.
- **Anti-Hack Test(s):** enforce that serialized response JSON never contains random IP/MAC/hostname patterns even when present in the incoming payload.

## 6) Risks & Pre-Mortem (Mandatory)
List 1–2 likely failure modes or “future hacks,” and how we prevent them.
- Failure mode: future parsing accidentally reintroduces raw identifiers into PUBLIC responses.
  - Mitigation (design): keep ingestion summary limited to digest metadata and enforce `parsed=false`.
  - Mitigation (test/gate): contract + anti-hack tests scan serialized response for identifier regexes.
- Failure mode: oversized payloads slip through and trigger memory or audit leaks.
  - Mitigation (design): service enforces `MAX_PAYLOAD_BYTES` and raises sanitized errors with reason codes.
  - Mitigation (test/gate): deny-path sanitization test asserts no payload echo and presence of reason code.

## 7) Rollout & Rollback Plan
- Backwards compatible: Yes
- Migration required: No
- Rollback steps: remove new schema files, revert `services/mcp` changes, drop tests; no data migration necessary.

## 8) Context Strategy for AIDE
- Phase 1 (Pre-Retrieve): `AI_CONTRACT.md`, `ARCHITECTURE.md`, `projectmap.md`, `DECISIONS.md`
- Phase 2 (JIT Retrieval): `schemas/README.md`, `tests/test_anti_hack.py`, `tests/test_smoke_server.py`, `src/mcp_scansage/services/sanitizer.py`, `src/mcp_scansage/mcp/server.py`

## 9) Exit Criteria (Must Be True to Close)
- [ ] Plan approved explicitly by user (Phase 1 gate)
- [ ] All slices implemented
- [ ] Anti-Hack tests added
- [ ] All quality gates pass (`ruff format/check`, `pytest`)
- [ ] No forbidden patterns introduced
- [ ] `DECISIONS.md` updated (if non-obvious decision)
- [ ] `projectmap.md` updated (if structure/responsibilities changed)
