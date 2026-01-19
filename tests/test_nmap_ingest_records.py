"""Contract tests for PUBLIC Nmap ingestion record resources."""

import json

import pytest

from mcp_scansage.mcp import reason_codes, schema_registry, server
from mcp_scansage.services import nmap_ingest_store


@pytest.fixture(autouse=True)
def clean_ingest_records() -> None:
    """Ensure ingestion records are isolated between tests."""

    nmap_ingest_store.clear_records()
    yield
    nmap_ingest_store.clear_records()


def _run_ingest(payload: str) -> str:
    resource = server.RESOURCE_REGISTRY["public://nmap/ingest"]
    response = resource({"format": "nmap_xml", "payload": payload})
    return response["ingest_id"]


def test_nmap_ingests_list_returns_newest_first() -> None:
    """Listing returns stored metadata sorted with the newest records first."""

    ingest_ids = [
        _run_ingest(f"<nmaprun><host><address>{i}</address></host></nmaprun>")
        for i in range(3)
    ]
    resource = server.RESOURCE_REGISTRY["public://nmap/ingests"]
    response = resource({})

    schema_registry.validate("nmap_ingests_list_response_v0.1", response)

    assert response["count"] == len(ingest_ids)
    assert response["max_records"] == nmap_ingest_store.MAX_STORED_RECORDS
    assert [item["ingest_id"] for item in response["ingests"]] == list(
        reversed(ingest_ids)
    )
    for item in response["ingests"]:
        assert item["parser_version"] == "noop-0.1"
        assert item["parsed"] is False
        assert item["findings_count"] == 0
        assert item["next_steps"]


def test_nmap_ingest_get_response_matches_stored_record() -> None:
    """Get returns the stored record and validates the PUBLIC schema."""

    ingest_id = _run_ingest("<nmaprun></nmaprun>")
    resource = server.RESOURCE_REGISTRY["public://nmap/ingest/{ingest_id}"]
    response = resource({"ingest_id": ingest_id})

    schema_registry.validate("nmap_ingest_get_response_v0.1", response)
    assert response["ingest"]["ingest_id"] == ingest_id
    assert response["ingest"]["parser_version"] == "noop-0.1"
    assert response["ingest"]["parsed"] is False
    assert response["ingest"]["findings_count"] == 0


def test_nmap_ingest_get_not_found_is_sanitized() -> None:
    """Missing records should produce a sanitized NOT_FOUND response."""

    resource = server.RESOURCE_REGISTRY["public://nmap/ingest/{ingest_id}"]
    response = resource({"ingest_id": "missing-id"})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.RECORD_NOT_FOUND
    serialized = json.dumps(response)
    assert "missing-id" not in serialized


def test_retention_drops_oldest_records() -> None:
    """Only MAX_STORED_RECORDS records remain; older ones are evicted."""

    total = nmap_ingest_store.MAX_STORED_RECORDS + 2
    ingest_ids = [
        _run_ingest(f"<nmaprun><host><address>{i}</address></host></nmaprun>")
        for i in range(total)
    ]
    response = server.RESOURCE_REGISTRY["public://nmap/ingests"]({})

    assert response["count"] == nmap_ingest_store.MAX_STORED_RECORDS
    recorded_ids = [item["ingest_id"] for item in response["ingests"]]
    assert ingest_ids[0] not in recorded_ids
    assert recorded_ids[0] == ingest_ids[-1]


def test_parsed_findings_schema_example_is_valid() -> None:
    """Parsed findings schema must accept the example payload."""

    example = schema_registry.get_example("nmap_parsed_findings_example_min")
    schema_registry.validate("nmap_parsed_findings_v0.1", example)
