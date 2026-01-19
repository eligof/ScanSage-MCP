"""Contract and sanitization tests for PUBLIC Nmap ingestion."""

import json
import re
from copy import deepcopy
from typing import Mapping

import pytest

from mcp_scansage.mcp import reason_codes, schema_registry, server
from mcp_scansage.services.nmap_ingest import (
    MAX_PAYLOAD_BYTES,
    PayloadTooLargeError,
    ingest_nmap_public,
)

INPUT_EXAMPLE = "nmap_ingest_input_example_min"
PUBLIC_SCHEMA = "nmap_ingest_public_response_v0.2"
RESOURCE_NAME = "public://nmap/ingest"

IPv4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPv6_PATTERN = re.compile(r"\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2,7}\b", re.IGNORECASE)
MAC_PATTERN = re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.IGNORECASE)
HOSTNAME_PATTERN = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z]{2,}\b", re.IGNORECASE
)


def _serialize_response(response: Mapping[str, object]) -> str:
    return json.dumps(response, sort_keys=True)


def test_nmap_ingest_contract_response_validates_schema() -> None:
    """PUBLIC responses must match the schema and stay identifier-free."""

    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    request = deepcopy(schema_registry.get_example(INPUT_EXAMPLE))
    response = resource(request)

    schema_registry.validate(PUBLIC_SCHEMA, response)

    assert response["summary"]["payload_bytes"] == len(
        request["payload"].encode("utf-8")
    )
    assert response["summary"]["parsed"] is False
    assert response["findings"] == []
    assert response["next_steps"]
    assert response["parser_version"] == "noop-0.1"
    assert response["findings_count"] == 0
    assert response["parsed_findings"] == []

    serialized = _serialize_response(response)
    assert request["payload"] not in serialized
    for pattern in (IPv4_PATTERN, IPv6_PATTERN, MAC_PATTERN, HOSTNAME_PATTERN):
        assert not pattern.search(serialized)


def test_nmap_ingest_oversized_payload_is_sanitized() -> None:
    """Deny paths must return sanitized errors with a reason code."""

    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    payload = "A" * (MAX_PAYLOAD_BYTES + 1)
    response = resource({"format": "nmap_xml", "payload": payload})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT
    assert response["detail"]

    serialized = _serialize_response(response)
    assert payload not in serialized


def test_input_schema_payload_limit_matches_service_constant() -> None:
    """The schema maxLength must match the service-level payload boundary."""

    schema = schema_registry.get_schema("nmap_ingest_input_v0.1")
    payload_limit = schema["properties"]["payload"]["maxLength"]
    assert payload_limit == MAX_PAYLOAD_BYTES


def test_error_responses_never_echo_marker_string() -> None:
    """Any deny/error path must strip even unique payload markers."""

    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    marker = "UNSAFE_MARKER_13624-XYZ"
    payload = "A" * (MAX_PAYLOAD_BYTES + 10) + marker
    response = resource({"format": "nmap_xml", "payload": payload})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT
    assert marker not in response["detail"]
    serialized = _serialize_response(response)
    assert marker not in serialized


def test_service_rejects_payload_over_limit() -> None:
    """The service enforces MAX_PAYLOAD_BYTES regardless of schema filtering."""

    payload = "A" * (MAX_PAYLOAD_BYTES + 1)
    with pytest.raises(PayloadTooLargeError):
        ingest_nmap_public("nmap_xml", payload)
