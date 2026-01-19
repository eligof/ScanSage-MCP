"""Tests covering the synthetic parser path for PUBLIC ingestion."""

import json

from mcp_scansage.mcp import reason_codes, schema_registry, server


def _synthetic_request(payload: str) -> dict[str, object]:
    return {
        "format": "synthetic_v1",
        "payload": payload,
        "meta": {"parser": "synthetic_v1"},
    }


def test_synthetic_ingest_returns_parsed_findings() -> None:
    """Synthetic parser delivers parsed findings without leaking identifiers."""

    payload = (
        "PORT_OPEN 22/tcp service=ssh\nPORT_OPEN 80/tcp service=http ip=192.0.2.123"
    )
    resource = server.RESOURCE_REGISTRY["public://nmap/ingest"]
    response = resource(_synthetic_request(payload))

    schema_registry.validate("nmap_ingest_public_response_v0.2", response)
    assert response["summary"]["parsed"] is True
    assert response["parser_version"] == "synthetic_v1"
    assert response["findings_count"] > 0
    assert response["parsed_findings"]
    serialized = json.dumps(response)
    assert "192.0.2.123" not in serialized


def test_synthetic_ingest_malformed_line_is_sanitized() -> None:
    """Malformed synthetic lines produce sanitized error responses."""

    resource = server.RESOURCE_REGISTRY["public://nmap/ingest"]
    payload = "PORT_OPEN ABC/tcp service=ssh"
    response = resource(_synthetic_request(payload))

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT
    assert "ABC" not in response["detail"]


def test_synthetic_input_example_validates_schema() -> None:
    """The synthetic input example matches the v0.2 schema."""

    example = schema_registry.get_example("nmap_ingest_input_example_v0.2")
    schema_registry.validate("nmap_ingest_input_v0.2", example)
