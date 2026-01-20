# specs/nmap_real_xml_parser_v0.1.md
**Status:** Draft
**Last Updated:** 2026-01-20

## 1) Problem Statement
The repo already includes a minimal XML parser seam and a basic real XML parser implementation, but the slice is not formally specified as a discrete, reviewable deliverable. The next slice should harden and document the PUBLIC-safe real XML parsing behavior, ensuring the parser is explicit about what it supports, enforces strict safety rules, and is backed by universal Anti-Hack tests.

## 2) Requirements & Invariants
### Requirements
- [ ] R1: Implement a documented, PUBLIC-safe “real minimal XML” parser slice that only emits findings from a safe subset of Nmap XML and never returns identifier-like tokens.
- [ ] R2: Enforce the XML safety boundary (no DTD/entity declarations, no external references, no network access) for every real XML parse.
- [ ] R3: Enforce caps consistently (payload size, hosts, ports per host, and findings) and surface deterministic caps metadata when limits are hit.
- [ ] R4: Keep parser selection rule-driven (env/config) without special-case strings or IDs.

### Invariants (must remain true)
- [ ] I1: PUBLIC outputs must never include raw identifiers or raw file paths.
- [ ] I2: No business logic moves into the MCP layer; parsing and caps stay in services.
- [ ] I3: Schema validation remains required for all PUBLIC responses.

## 3) Architecture & Placement
Where will changes live and why?
- Domain models: Add or refine data models only if new structured findings require it.
- Services/rules: Parser logic and caps enforcement remain in `src/mcp_scansage/services/`.
- API/CLI (consumer only): FastMCP resources continue to orchestrate validation and call services without embedding domain rules.
Justification: Layer Fidelity and No-Bunch rules from `AI_CONTRACT.md` and `ARCHITECTURE.md` require business logic to live in services, not API/MCP layers.

## 4) Implementation Slices (Ordered)
1) Slice 1 — Parser contract hardening
   - Files: `src/mcp_scansage/services/nmap_parser.py`
   - Changes: Formalize the supported XML subset in code comments and ensure unsafe XML is rejected before traversal; ensure identifier redaction is applied to all emitted text.
   - Notes: No schema or MCP changes in this slice.
2) Slice 2 — Caps + metadata alignment
   - Files: `src/mcp_scansage/services/nmap_ingest.py`, `src/mcp_scansage/services/nmap_limits.py`
   - Changes: Ensure caps metadata reflects host/port/findings processing counts deterministically and is emitted consistently for real XML parsing.
3) Slice 3 — Tests + fixtures
   - Files: `tests/test_nmap_real_xml_minimal.py`, `tests/test_nmap_ingest_limits.py`, new fixtures under `tests/fixtures/nmap_xml/`
   - Changes: Add universal Anti-Hack tests for identifier redaction and XML safety; extend caps coverage for real XML.
4) Slice 4 — Documentation
   - Files: `docs/runbook_nmap_caps_limits.md` (if updates are needed), `docs/status_code_level.md`
   - Changes: Document real XML parser behavior, supported subset, and the caps/limit semantics.

## 5) Test Strategy
- Unit tests: Parser boundary tests for DTD/ENTITY rejection and UTF-8 validation.
- Integration tests: PUBLIC ingestion with real XML parser enabled, including caps metadata and persistence flow.
- **Anti-Hack Test(s):** Enforce the universal rule that identifier-like tokens are always redacted, regardless of where they appear in XML text or attributes.

## 6) Risks & Pre-Mortem (Mandatory)
- Failure mode: Parser starts emitting identifier-like tokens because new XML elements are added without redaction.
  - Mitigation (design): Centralize redaction in the parser’s output mapping and reuse the existing sanitizer utilities.
  - Mitigation (test/gate): Add Anti-Hack tests that feed identifier-like tokens through multiple XML locations and assert universal redaction.
- Failure mode: Caps enforcement diverges between parser and ingestion layers.
  - Mitigation (design): Keep caps configuration in `nmap_limits.py` and ensure both parser and ingest read from the same config path.
  - Mitigation (test/gate): Add deterministic caps tests that compare repeat runs and enforce stable metadata.

## 7) Rollout & Rollback Plan
- Backwards compatible: Yes (existing noop/synthetic parser paths remain unchanged).
- Migration required: No.
- Rollback steps: Revert parser enhancements and related tests/doc changes; keep existing parser seam intact.

## 8) Context Strategy for AIDE
- Phase 1 (Pre-Retrieve): `AI_CONTRACT.md`, `ARCHITECTURE.md`, `projectmap.md`, `DECISIONS.md`.
- Phase 2 (JIT Retrieval): `src/mcp_scansage/services/nmap_parser.py`, `src/mcp_scansage/services/nmap_ingest.py`, `src/mcp_scansage/services/nmap_limits.py`, relevant tests and fixtures.

## 9) Exit Criteria (Must Be True to Close)
- [ ] Plan approved explicitly by user (Phase 1 gate)
- [ ] All slices implemented
- [ ] Anti-Hack tests added
- [ ] All quality gates pass (ruff format/check, pytest, mypy if used)
- [ ] No forbidden patterns introduced
- [ ] `DECISIONS.md` updated (if non-obvious decision)
- [ ] `projectmap.md` updated (if structure/responsibilities changed)
