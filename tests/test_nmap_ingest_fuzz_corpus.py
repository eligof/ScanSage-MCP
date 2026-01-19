"""Regression tests over a small noisy Nmap XML corpus."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from mcp_scansage.mcp import reason_codes, schema_registry, server

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "nmap_xml"
PUBLIC_SCHEMA = "nmap_ingest_public_response_v0.2"
RESOURCE_NAME = "public://nmap/ingest"
ALLOWED_ERROR_REASONS = frozenset(
    {
        reason_codes.INVALID_INPUT,
        reason_codes.PAYLOAD_TOO_LARGE,
        reason_codes.RESPONSE_VALIDATION_FAILED,
    }
)

IPv4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPv6_PATTERN = re.compile(r"\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2,7}\b", re.IGNORECASE)
MAC_PATTERN = re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.IGNORECASE)
HOSTNAME_PATTERN = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z]{2,}\b",
    re.IGNORECASE,
)


def _load_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def _assert_no_identifiers(payload: str) -> None:
    for pattern in (IPv4_PATTERN, IPv6_PATTERN, MAC_PATTERN, HOSTNAME_PATTERN):
        assert not pattern.search(payload)


@pytest.mark.parametrize(
    "fixture_name",
    sorted(p.name for p in FIXTURE_DIR.glob("*.xml")),
)
def test_fuzz_corpus_ingest_safe(
    monkeypatch: pytest.MonkeyPatch, fixture_name: str
) -> None:
    """Each noisy XML payload returns a sanitized response instead of crashing."""

    monkeypatch.setenv("SCANSAGE_NMAP_XML_PARSER", "real_minimal")
    monkeypatch.delenv("SCANSAGE_AUTHORIZED_LAB", raising=False)
    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    payload = _load_fixture(fixture_name)

    response = resource({"format": "nmap_xml", "payload": payload})

    serialized = json.dumps(response)
    assert "_sort_key" not in serialized
    assert "sort_key" not in serialized

    if response.get("status"):
        assert response["reason"] in ALLOWED_ERROR_REASONS
        assert response["detail"]
        _assert_no_identifiers(json.dumps(response))
        return

    schema_registry.validate(PUBLIC_SCHEMA, response)
    _assert_no_identifiers(serialized)


def test_caps_metadata_deterministic_for_noisy_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caps metadata stays identical when the same noisy input exceeds limits."""

    monkeypatch.setenv("SCANSAGE_NMAP_XML_PARSER", "real_minimal")
    monkeypatch.setenv("SCANSAGE_MAX_NMAP_FINDINGS", "2")
    monkeypatch.setenv("SCANSAGE_MAX_NMAP_HOSTS", "10")
    monkeypatch.setenv("SCANSAGE_MAX_NMAP_PORTS_PER_HOST", "5")
    monkeypatch.delenv("SCANSAGE_AUTHORIZED_LAB", raising=False)

    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    payload = _load_fixture("caps_trigger.xml")

    first = resource({"format": "nmap_xml", "payload": payload})
    second = resource({"format": "nmap_xml", "payload": payload})

    assert first["parsed_findings"] == second["parsed_findings"]
    assert first.get("metadata") == second.get("metadata")
    metadata = first.get("metadata")
    assert metadata is not None
    caps = metadata["caps"]
    assert caps["cap_reason"] == "MAX_FINDINGS"
    assert caps["limits"]["max_findings"] == 2

    serialized = json.dumps(first)
    _assert_no_identifiers(serialized)
