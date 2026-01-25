"""Parity tests for the ingest_nmap_xml alias resource."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Mapping

import pytest

from mcp_scansage.mcp import reason_codes, schema_registry, server
from mcp_scansage.services.nmap_ingest import MAX_PAYLOAD_BYTES, NMAP_XML_FORMAT

BASE_RESOURCE = "public://nmap/ingest"
ALIAS_RESOURCE = "ingest_nmap_xml"
PUBLIC_RESPONSE_SCHEMA = "nmap_ingest_public_response_v0.2"


def _strip_ephemeral_fields(response: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(response)
    normalized.pop("ingest_id", None)
    return normalized


def _assert_error_shape(response: Mapping[str, Any]) -> None:
    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT
    assert response["detail"]


def test_alias_resource_is_exposed_in_registry() -> None:
    assert ALIAS_RESOURCE in server.RESOURCE_REGISTRY


def test_alias_response_matches_public_ingest_for_same_request() -> None:
    base = server.RESOURCE_REGISTRY[BASE_RESOURCE]
    alias = server.RESOURCE_REGISTRY[ALIAS_RESOURCE]

    request = deepcopy(schema_registry.get_example("nmap_ingest_input_example_min"))
    alias_request = dict(request)
    alias_request.pop("format", None)

    base_response = base(request)
    alias_response = alias(alias_request)

    schema_registry.validate(PUBLIC_RESPONSE_SCHEMA, base_response)
    schema_registry.validate(PUBLIC_RESPONSE_SCHEMA, alias_response)

    assert _strip_ephemeral_fields(alias_response) == _strip_ephemeral_fields(
        base_response
    )


def test_alias_calls_shared_ingest_service_with_fixed_format(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = server.RESOURCE_REGISTRY[BASE_RESOURCE]
    alias = server.RESOURCE_REGISTRY[ALIAS_RESOURCE]

    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    original = server.ingest_nmap_public

    def spy(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(server, "ingest_nmap_public", spy)

    payload = "<nmaprun></nmaprun>"
    base({"format": NMAP_XML_FORMAT, "payload": payload})
    alias({"payload": payload})

    assert len(calls) == 2
    assert calls[0][0][0] == NMAP_XML_FORMAT
    assert calls[1][0][0] == NMAP_XML_FORMAT


@pytest.mark.parametrize(
    "alias_request",
    [
        {"payload": "A" * (MAX_PAYLOAD_BYTES + 1)},
        {"payload": "<nmaprun></nmaprun>", "meta": {"parser": "synthetic_v1"}},
        {"payload": "<nmaprun></nmaprun>", "hack": "extra"},
        {},
    ],
)
def test_alias_negative_parity_for_validation_errors(
    alias_request: Mapping[str, Any],
) -> None:
    """Alias must behave like public://nmap/ingest for deny paths."""

    base = server.RESOURCE_REGISTRY[BASE_RESOURCE]
    alias = server.RESOURCE_REGISTRY[ALIAS_RESOURCE]

    base_request = {"format": NMAP_XML_FORMAT, **alias_request}

    base_response = base(base_request)
    alias_response = alias(alias_request)

    assert base_response == alias_response
    _assert_error_shape(alias_response)


@pytest.mark.parametrize(
    "payload",
    [
        "<nmaprun><host></nmaprun>",
        """<?xml version=\"1.0\"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\
]>
<nmaprun>&xxe;</nmaprun>""",
    ],
)
def test_alias_negative_parity_for_unsafe_or_invalid_xml(
    monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    base = server.RESOURCE_REGISTRY[BASE_RESOURCE]
    alias = server.RESOURCE_REGISTRY[ALIAS_RESOURCE]

    monkeypatch.setenv("SCANSAGE_NMAP_XML_PARSER", "safe_xml")

    base_response = base({"format": NMAP_XML_FORMAT, "payload": payload})
    alias_response = alias({"payload": payload})

    assert base_response == alias_response
    _assert_error_shape(alias_response)

    serialized = json.dumps(alias_response)
    assert payload not in serialized


def test_alias_negative_parity_for_unsupported_parser_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = server.RESOURCE_REGISTRY[BASE_RESOURCE]
    alias = server.RESOURCE_REGISTRY[ALIAS_RESOURCE]

    monkeypatch.setenv("SCANSAGE_NMAP_XML_PARSER", "not-a-real-parser")

    payload = "<nmaprun></nmaprun>"
    base_response = base({"format": NMAP_XML_FORMAT, "payload": payload})
    alias_response = alias({"payload": payload})

    assert base_response == alias_response
    _assert_error_shape(alias_response)
