"""Contract tests for the Nmap XML parser boundary and redaction helpers."""

import json

import pytest

from mcp_scansage.mcp import reason_codes, server
from mcp_scansage.services.sanitizer import redact_identifiers


def test_safe_xml_parser_rejects_dtd(monkeypatch: pytest.MonkeyPatch) -> None:
    """The safe XML parser flag blocks DTD/entity payloads without leakage."""

    monkeypatch.setenv("SCANSAGE_NMAP_XML_PARSER", "safe_xml")
    payload = """<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun>&xxe;</nmaprun>"""

    resource = server.RESOURCE_REGISTRY["public://nmap/ingest"]
    response = resource({"format": "nmap_xml", "payload": payload})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT

    serialized = json.dumps(response)
    assert "<!DOCTYPE" not in serialized
    assert "file:///etc/passwd" not in serialized


def test_unknown_parser_env_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any unsupported parser selection results in a sanitized INVALID_INPUT error."""

    monkeypatch.setenv("SCANSAGE_NMAP_XML_PARSER", "unsupported")
    payload = "<nmaprun></nmaprun>"
    resource = server.RESOURCE_REGISTRY["public://nmap/ingest"]
    response = resource({"format": "nmap_xml", "payload": payload})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT


@pytest.mark.parametrize(
    "identifier",
    [
        "192.0.2.123",
        "2001:db8::1",
        "FF:FF:FF:FF:FF:FF",
        "router.example.com",
        "mail.internal-01.example.org",
    ],
)
def test_redact_identifiers_applies_to_any_token(identifier: str) -> None:
    """Identifier redaction is universal, not keyed to single examples."""

    sanitized = redact_identifiers(f"detected {identifier} in synthesis")
    assert identifier not in sanitized
    assert "[redacted]" in sanitized
