# projectmap.md
*A living high-level map of module responsibilities. Keep this updated.*

## Modules
- domain/ — pure data models (for example, `src/mcp_scansage/domain/models.py`) that capture what is being analyzed without I/O.
- services/ — universal rules + orchestration in `src/mcp_scansage/services/` (sanitization, caps, parsing seam, ingestion, persistence).
- adapters/ — placeholder layer for future persistence or API clients that will be wired in by services.
- mcp/ — FastMCP orchestrator + resource registry + entrypoint logic in `src/mcp_scansage/mcp/` (not a business-logic layer).
- schemas/ — schema directory reserved for future shared contracts.
- docs/ — supporting documentation for the hybrid analyzer effort.
- `docs/runbook_nmap_caps_limits.md` explains how to configure/interpret PUBLIC Nmap caps without reading the code.
- `scripts/dry_run_ingest.py` is a LOCAL-only helper that exercises caps without persistence, printing the sanitized summary metadata for ops to inspect.
- tests/ — regression, smoke, and anti-hack verifications. `test_schema_examples.py` ensures every schema/example pair validates (guards against accidental `$defs` removal). `test_anti_hack.py` enforces universal/public guarantees.

## Key Flows
- FastMCP health resource calls the sanitizer service before exposing payloads to any consumer.
- PUBLIC Nmap ingestion routes through `services/nmap_ingest.py` and the `public://nmap/ingest` FastMCP resource.
- `ingest_nmap_xml` is an additive alias that maps `{payload, meta}` to the same PUBLIC ingest flow without requiring a format selector.
- Kali Nmap XML → `public://nmap/ingest` → schema validate → caps/size check (`services/nmap_limits.py`) → safe XML boundary + parser seam (`services/nmap_parser.py`) → findings/metadata → PUBLIC response (+ caps audit) + persisted PUBLIC metadata (`state/public`, no raw XML).
- Stored PUBLIC ingestion metadata lives in `state/public` and is accessed through `public://nmap/ingests` and `public://nmap/ingest/{ingest_id}` without ever returning raw XML.
- Parser metadata (version, findings_count) is produced via `services/nmap_parser.py` before persisting, keeping PUBLIC responses schema-compliant while avoiding raw payload exposure.
- Schemas + examples validation gate ensures the schema `$defs` stay intact and every example can be validated before PUBLIC ingestion.

## Config
- `SCANSAGE_NMAP_XML_PARSER` controls the parser implementation (e.g., `safe_xml`, `real_minimal`) while the ingestion service keeps the noop parser as the default.
- `SCANSAGE_AUTHORIZED_LAB` enables lab mode; when truthy and no explicit parser is configured, the service falls back to `real_minimal` to exercise the safe real XML subset.
- Explicit parser environment values always win and only that env var, so deployments never silently flip parser behavior without updating `SCANSAGE_NMAP_XML_PARSER`.
- `services/nmap_limits.py` is the single source of truth for all `SCANSAGE_MAX_*` caps so the parser and ingestion layers share sane defaults, env parsing, and PUBLIC-safe fallbacks.

## Notes
- Keep this file short and current.
