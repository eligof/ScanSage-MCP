# specs/ingest_nmap_xml_v0.1.md
**Status:** Implemented
**Last Updated:** 2026-01-25

## 1) Problem Statement
ScanSage already supports PUBLIC Nmap ingestion via `public://nmap/ingest`, but MCP clients often want a single-purpose entrypoint that is unambiguously “Nmap XML ingest” without requiring callers to remember a `format` selector or any internal routing details. We need a dedicated MCP tool/resource named `ingest_nmap_xml` that routes to the existing ingestion service while preserving the repo’s PUBLIC guarantees (no raw identifiers, no raw paths, strict size limits, and safe XML handling).

## 2) Requirements & Invariants
### Requirements
- [x] R1: Provide exactly one MCP tool/resource named `ingest_nmap_xml` that accepts an Nmap XML payload and returns the existing PUBLIC-safe ingestion response shape.
- [x] R2: Enforce strict payload size limits at the service boundary using `services/nmap_limits.py` (no unbounded reads/processing).
- [x] R3: Parse XML only through the safe boundary (reject DTD/ENTITY/external references; no entity expansion; no network access) as defined by `services/nmap_parser.parse_xml_safely`.
- [x] R4: Default to PUBLIC-safe output (no raw identifiers or raw paths); do not echo the input payload and do not persist raw XML.
- [x] R5: Keep behavior rule-driven (limits + parser selection via env) and avoid special-case conditionals (No-Bunch).

### Invariants (must remain true)
- [x] I1: PUBLIC outputs never include identifier-like tokens (IP/MAC/hostname) or raw filesystem paths, regardless of where they appear in the input.
- [x] I2: XML payloads containing DTD/entity declarations or external references are rejected before traversal.
- [x] I3: Business rules remain in `services/` (Layer Fidelity); the MCP layer only validates/marshals and calls services.

## 3) Architecture & Placement
Where will changes live and why?
- Domain models: existing `src/mcp_scansage/domain/models.py` remains the pure data layer; no new I/O introduced.
- Services/rules: reuse `src/mcp_scansage/services/nmap_ingest.py` (orchestration + caps), `src/mcp_scansage/services/nmap_parser.py` (safe parsing + parser seam), `src/mcp_scansage/services/nmap_limits.py` (caps source of truth), and `src/mcp_scansage/services/sanitizer.py` (PUBLIC scrubbing rules).
- MCP wiring (consumer only): add the new entrypoint to `src/mcp_scansage/mcp/server.py`, mapping directly to the existing service and keeping schema validation + sanitized error handling in the MCP layer.
Justification: `AI_CONTRACT.md` requires Layer Fidelity + No-Bunch behavior, and `ARCHITECTURE.md` defines `services/` as the business-rule/orchestration layer; the MCP layer must remain a thin consumer.

## 4) Implementation Slices (Ordered)
1) Slice 1 — Planning only (this slice)
   - Files: `specs/ingest_nmap_xml_v0.1.md`, `projectmap.md`, `DECISIONS.md` (only if needed)
   - Changes: specify the entrypoint contract, layering, safety invariants, and test plan; update the repo map to match the current layout/flows.
2) Slice 2 — MCP entrypoint wiring
   - Files: `src/mcp_scansage/mcp/server.py`, `schemas/` (only if a new input schema is needed), `src/mcp_scansage/mcp/schema_registry.py` (if registering a new schema)
   - Changes:
     - Add `ingest_nmap_xml` resource that accepts `{ "payload": "<xml>", "meta": { ... } }` and calls `services.nmap_ingest.ingest_nmap_public(format="nmap_xml", payload=payload, meta=meta)`.
     - Keep the response schema identical to the existing PUBLIC ingest response (no new public fields that could carry identifiers).
     - Keep `public://nmap/ingest` intact (backwards compatible); treat `ingest_nmap_xml` as an additive alias entrypoint.
3) Slice 3 — Tests (required)
   - Files: `tests/test_smoke_server.py`, `tests/test_anti_hack.py`, and/or a new `tests/test_ingest_nmap_xml_resource.py`
   - Changes:
     - Add contract tests that invoke the new resource and validate schema compliance.
     - Add Anti-Hack tests that scan the serialized response for identifier-like tokens and raw paths, regardless of the payload contents.
4) Slice 4 — Docs / runbook touch-ups (if needed)
   - Files: `projectmap.md`, `docs/runbook_nmap_caps_limits.md`
   - Changes: document the new entrypoint name and how it relates to the existing PUBLIC ingestion resource(s).

## 5) Test Strategy
- Unit tests:
  - Resource-level validation for missing/invalid payloads.
  - Payload size limit behavior (reject oversized payloads with sanitized error + stable reason).
- Integration tests (if applicable):
  - Invoke `server.RESOURCE_REGISTRY["ingest_nmap_xml"](...)` and validate the response schema.
- **Anti-Hack Test(s):** Universal rule — the PUBLIC response must never contain identifier-like tokens or raw filesystem paths, even if they appear in XML text/attributes, and must never echo the original payload.

## 6) Risks & Pre-Mortem (Mandatory)
- Failure mode: the new entrypoint accidentally becomes a “format selector” or duplicates business logic in the MCP layer.
  - Mitigation (design): MCP layer only maps inputs to the existing service and reuses shared schema validation.
  - Mitigation (test/gate): tests assert the MCP resource does not accept/branch on format flags; no logic beyond validation/mapping.
- Failure mode: identifier leakage via new response fields or meta echoing.
  - Mitigation (design): ignore unknown meta keys for PUBLIC output; keep response schema unchanged and rely on existing sanitizer/redaction rules.
  - Mitigation (test/gate): Anti-Hack tests scan the full serialized response for identifier-like patterns and raw path fragments.

## 7) Rollout & Rollback Plan
- Backwards compatible: Yes (additive alias; existing resources stay intact).
- Migration required: No.
- Rollback steps: remove the `ingest_nmap_xml` resource entry and any new schema/tests; keep existing PUBLIC ingestion untouched.

## 8) Context Strategy for AIDE
- Phase 1 (Pre-Retrieve): `AI_CONTRACT.md`, `ARCHITECTURE.md`, `projectmap.md`, plus this spec.
- Phase 2 (JIT Retrieval): `src/mcp_scansage/mcp/server.py`, `src/mcp_scansage/services/nmap_ingest.py`, `src/mcp_scansage/services/nmap_parser.py`, `src/mcp_scansage/services/sanitizer.py`, `tests/test_anti_hack.py`.

## 9) Exit Criteria (Must Be True to Close)
- [x] Plan approved explicitly by user (Slice 1 gate)
- [x] `ingest_nmap_xml` resource implemented
- [x] Anti-Hack tests added/updated for the new resource
- [x] All quality gates pass (`tools/forbidden_patterns_check.py`, `ruff format`, `ruff check`, `pytest`)
- [x] No forbidden patterns introduced (No-Bunch, layer fidelity)
- [x] `DECISIONS.md` updated (if non-obvious decisions were made)
- [x] `projectmap.md` updated (if responsibilities/flows changed)
