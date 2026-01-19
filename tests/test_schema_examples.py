"""Ensure each JSON schema is exercised by its published example."""

from mcp_scansage.mcp import schema_registry

SCHEMA_EXAMPLE_MAP = {
    "nmap_ingest_input_v0.1": "nmap_ingest_input_example_min",
    "nmap_ingest_input_v0.2": "nmap_ingest_input_example_v0.2",
    "nmap_ingest_public_response_v0.1": "nmap_ingest_public_response_example_min",
    "nmap_ingest_public_response_v0.2": "nmap_ingest_public_response_example_v0.2",
    "nmap_ingests_list_response_v0.1": "nmap_ingests_list_response_example_min",
    "nmap_ingest_get_response_v0.1": "nmap_ingest_get_response_example_min",
    "nmap_parsed_findings_v0.1": "nmap_parsed_findings_example_min",
}


def test_all_examples_validate_against_their_schemas() -> None:
    """Every example file should match its declared schema contract."""

    for schema_name, example_name in SCHEMA_EXAMPLE_MAP.items():
        example = schema_registry.get_example(example_name)
        schema_registry.validate(schema_name, example)
