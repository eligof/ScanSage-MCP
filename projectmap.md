# projectmap.md
*A living high-level map of module responsibilities. Keep this updated.*

## Modules
- domain/ — pure data models (for example, `Finding`) that capture what is being analyzed without I/O.
- services/ — universal rules (like response sanitization) that orchestrate domain primitives and enforce safety.
- adapters/ — placeholder layer for future persistence or API clients that will be wired in by services.
- mcp/ — FastMCP orchestrator, resource registry, and entrypoint logic.
- schemas/ — schema directory reserved for future shared contracts.
- docs/ — supporting documentation for the hybrid analyzer effort.
- `docs/runbook_nmap_caps_limits.md` explains how to configure/interpret PUBLIC Nmap caps without reading the code.
- `scripts/dry_run_ingest.py` is a LOCAL-only helper that exercises caps without persistence, printing the sanitized summary metadata for ops to inspect.
- tests/ — regression, smoke, and anti-hack verifications. `test_schema_examples.py` ensures every schema/example pair validates (guards against accidental `$defs` removal). `test_anti_hack.py` enforces universal/public guarantees.

## Key Flows
- FastMCP health resource calls the sanitizer service before exposing payloads to any consumer.
- PUBLIC Nmap ingestion routes through `services/nmap_ingest.py` and the `public://nmap/ingest` FastMCP resource.
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
