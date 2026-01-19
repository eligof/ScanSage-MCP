# Schemas

Placeholders for shared schema definitions (JSON Schema, Pydantic, etc.).

- `nmap_ingest_input_schema_v0.1.json` and `nmap_ingest_public_response_schema_v0.1.json` describe PUBLIC-safe Nmap ingestion contracts; their examples live in `examples/`.
- `nmap_ingest_input_schema_v0.2.json` mirrors v0.1 while allowing the synthetic parser flag/format; its example lives in `examples/`.
- `nmap_ingest_public_response_schema_v0.2.json` expands the response with parser metadata and parsed findings (see `nmap_parsed_findings_schema_v0.1.json`); the list/get schemas describe the persisted metadata surfaces.
- `nmap_ingests_list_response_schema_v0.1.json` and `nmap_ingest_get_response_schema_v0.1.json` describe PUBLIC-safe metadata surfaces for persisted ingestion records; their examples also live in `examples/`.
