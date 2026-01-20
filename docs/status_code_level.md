# Code-Level Status Report
**Status:** Draft
**Last Updated:** 2026-01-20

## Implemented Surface Area (Code + Tests)
### FastMCP Resources (PUBLIC-safe)
- `health` — health status resource returning sanitized strings. Implemented in `src/mcp_scansage/mcp/server.py` via `HealthResource`. Tested in `tests/test_smoke_server.py`.
- `public://nmap/ingest` — PUBLIC ingestion endpoint handling schema validation, parsing, caps enforcement, and sanitized errors. Implemented in `src/mcp_scansage/mcp/server.py` and `src/mcp_scansage/services/nmap_ingest.py`. Tested across `tests/test_nmap_ingestion_public.py`, `tests/test_nmap_ingest_limits.py`, `tests/test_nmap_ingest_synthetic.py`, `tests/test_nmap_parser_contract.py`, `tests/test_nmap_real_xml_minimal.py`, and `tests/test_nmap_ingest_fuzz_corpus.py`.
- `public://nmap/ingests` — list endpoint for persisted ingest summaries. Implemented in `src/mcp_scansage/mcp/server.py` with storage in `src/mcp_scansage/services/nmap_ingest_store.py`. Tested in `tests/test_nmap_ingest_records.py`.
- `public://nmap/ingest/{ingest_id}` — get endpoint for a single persisted record. Implemented in `src/mcp_scansage/mcp/server.py` and `src/mcp_scansage/services/nmap_ingest_store.py`. Tested in `tests/test_nmap_ingest_records.py`.

### Service Entry Points
- Ingestion orchestration: `ingest_nmap_public()` in `src/mcp_scansage/services/nmap_ingest.py` (payload bounds, parser invocation, caps metadata, persistence).
- Parser seam + implementations: `src/mcp_scansage/services/nmap_parser.py` provides `NmapParser`, `NoopNmapParser`, `SyntheticNmapParser`, `SafeNmapXmlParser`, and `MinimalNmapXmlParser`.
- Limits + caps: `src/mcp_scansage/services/nmap_limits.py` exposes `NmapLimitConfig` and default caps.
- Storage: `src/mcp_scansage/services/nmap_ingest_store.py` persists PUBLIC-safe summaries to `state/public`.
- Sanitization: `src/mcp_scansage/services/sanitizer.py` enforces identifier and path redaction.
- Audit: `src/mcp_scansage/services/cap_audit.py` and `src/mcp_scansage/services/audit_log.py` log cap events to JSONL.

### Schemas + Examples
- Input schemas: `schemas/nmap_ingest_input_schema_v0.1.json`, `schemas/nmap_ingest_input_schema_v0.2.json` with example payloads in `schemas/examples/`.
- Public response schemas: `schemas/nmap_ingest_public_response_schema_v0.1.json`, `schemas/nmap_ingest_public_response_schema_v0.2.json`.
- List/get schemas: `schemas/nmap_ingests_list_response_schema_v0.1.json`, `schemas/nmap_ingest_get_response_schema_v0.1.json`.
- Parsed findings schema: `schemas/nmap_parsed_findings_schema_v0.1.json`.
- Schema/example validation registry in `src/mcp_scansage/mcp/schema_registry.py` with tests in `tests/test_schema_examples.py`.

### CLI/Tooling
- Local dry-run CLI: `scripts/dry_run_ingest.py` (PUBLIC-safe summary output, no persistence). Covered by `tests/test_dry_run_ingest.py`.

## Implemented Guarantees (with tests)
- **PUBLIC boundary + sanitization**: Public responses scrub raw paths and identifiers via `sanitize_public_response()` and redaction utilities. Verified in `tests/test_anti_hack.py` and `tests/test_nmap_ingestion_public.py`.
- **Schema validation**: Input and output are validated against JSON schemas in the MCP layer and in tests (`tests/test_schema_examples.py`, `tests/test_nmap_ingestion_public.py`).
- **Payload size caps**: Payload size enforced in `ingest_nmap_public()` and reflected in schema maxLength, with cap audit events on rejection. Verified in `tests/test_nmap_ingestion_public.py` and `tests/test_nmap_ingest_limits.py`.
- **Parser selection precedence**: Explicit parser env var wins; authorized lab mode defaults to real minimal; otherwise noop. Verified in `tests/test_nmap_ingest_persist_e2e.py`.
- **XML safety boundary**: DTD/XXE payloads rejected in safe/minimal parser paths. Verified in `tests/test_nmap_parser_contract.py` and `tests/test_nmap_real_xml_minimal.py`.
- **Caps metadata determinism**: Findings are sorted/truncated deterministically and caps metadata is stable across repeat runs. Verified in `tests/test_nmap_ingest_limits.py` and `tests/test_nmap_ingest_fuzz_corpus.py`.
- **Persistence guarantees**: Stored records remain PUBLIC-safe, retention enforced, and list/get schemas enforced. Verified in `tests/test_nmap_ingest_records.py` and `tests/test_nmap_ingest_persist_e2e.py`.

## Planned or Referenced but Not Implemented
- **PROJECT_ANCHOR.md**: Referenced in the current request but no file exists in-repo. If required, it must be authored to avoid drifting expectations.
- **Adapters layer**: `adapters/` is a placeholder without persistence clients beyond the local JSON file store; no external storage integration is implemented yet.
- **API/CLI layer expansion**: Only the local dry-run CLI exists; no public CLI or API beyond FastMCP resources is implemented.

## Risks / Likely Failure Modes
1) **Parser coverage limited to a minimal safe subset**: The real XML parser only covers basic TCP/port/service nodes; broader Nmap XML constructs are ignored, which can under-report findings. Mitigation: extend parser in a controlled, schema-backed way with strict caps and redaction.
2) **Sanitization relies on regex patterns**: New identifier-like formats could slip past the redaction rules. Mitigation: add universal anti-hack tests with varied identifier patterns and ensure redaction is applied to all text fields.
3) **Audit sink failure visibility**: The audit logger logs warnings and returns on I/O errors, which can still leave dropped audit events unnoticed if log collection is missing. Mitigation: keep warning rate-limits tuned and add telemetry/health checks if audit durability becomes required.
