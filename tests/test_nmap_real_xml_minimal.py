"""Regression tests for the minimal real Nmap XML parser path."""

import json
from pathlib import Path

import pytest

from mcp_scansage.mcp import reason_codes, schema_registry, server
from mcp_scansage.services.nmap_parser import MinimalNmapXmlParser

RESOURCE_NAME = "public://nmap/ingest"
PUBLIC_SCHEMA = "nmap_ingest_public_response_v0.2"
PARSER_ENV = "SCANSAGE_NMAP_XML_PARSER"

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "nmap_xml"


def _load_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


def _call_real_parser(
    monkeypatch: pytest.MonkeyPatch, payload: str
) -> dict[str, object]:
    """Run the ingestion endpoint with the real XML parser enabled."""

    monkeypatch.setenv(PARSER_ENV, "real_minimal")
    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    return resource({"format": "nmap_xml", "payload": payload})


def test_real_parser_happy_path_emits_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real parser creates schema-compliant findings while redacting identifiers."""

    payload = """<nmaprun>
  <host>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

    response = _call_real_parser(monkeypatch, payload)
    schema_registry.validate(PUBLIC_SCHEMA, response)

    assert response["summary"]["parsed"] is True
    assert response["parser_version"] == MinimalNmapXmlParser.VERSION
    assert response["findings_count"] == 1
    finding = response["parsed_findings"][0]
    assert finding["title"] == "Port 22 open"
    assert "ssh" in finding["detail"]
    assert "OpenSSH" in finding["detail"]
    assert "7.4" in finding["detail"]
    assert "192.0.2.1" not in json.dumps(response)


def test_real_parser_includes_service_extrainfo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Service extrainfo attributes are reflected in the sanitized detail string."""

    payload = _load_fixture("real_parser_example.xml")
    response = _call_real_parser(monkeypatch, payload)

    assert response["findings_count"] == 2
    serialized = json.dumps(response)
    assert "198.51.100.10" not in serialized
    details = [finding["detail"] for finding in response["parsed_findings"]]
    assert any("protocols routed through" in detail for detail in details)
    assert all("audit.example.com" not in detail for detail in details)
    assert any("[redacted]" in detail for detail in details)


def test_real_parser_handles_multiple_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Multiple hosts and ports produce stable, additive findings."""

    payload = """<nmaprun>
  <host>
    <address addr="198.51.100.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="198.51.100.6" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.21"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.21"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

    response = _call_real_parser(monkeypatch, payload)
    assert response["findings_count"] == 3
    titles = [finding["title"] for finding in response["parsed_findings"]]
    assert titles == ["Port 22 open", "Port 80 open", "Port 443 open"]


def test_real_parser_rejects_dtd_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """DTD/XXE payloads remain blocked even when the real parser is active."""

    payload = """<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun>&xxe;</nmaprun>"""

    response = _call_real_parser(monkeypatch, payload)
    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT

    serialized = json.dumps(response)
    assert "<!DOCTYPE" not in serialized
    assert "file:///etc/passwd" not in serialized


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
def test_real_parser_redacts_identifiers(
    monkeypatch: pytest.MonkeyPatch, identifier: str
) -> None:
    """Anti-Hack: identifier-like tokens must not escape into PUBLIC fields."""

    payload = f"""<nmaprun>
  <host>
    <address addr="{identifier}" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

    response = _call_real_parser(monkeypatch, payload)
    serialized = json.dumps(response)
    assert identifier not in serialized
