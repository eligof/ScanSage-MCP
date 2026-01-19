"""End-to-end regression tests for the real minimal parser path."""

import json

import pytest

from mcp_scansage.mcp import reason_codes, schema_registry, server
from mcp_scansage.services import nmap_ingest_store
from mcp_scansage.services.nmap_parser import CapReason, MinimalNmapXmlParser

RESOURCE_NAME = "public://nmap/ingest"
PUBLIC_SCHEMA = "nmap_ingest_public_response_v0.2"
PARSER_ENV = "SCANSAGE_NMAP_XML_PARSER"


@pytest.fixture(autouse=True)
def clean_ingest_records() -> None:
    """Ensure ingestion records are isolated for each test."""

    nmap_ingest_store.clear_records()
    yield
    nmap_ingest_store.clear_records()


def _run_ingest_with_parser(
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
    parser: str | None,
    lab_mode: bool = False,
) -> dict[str, object]:
    if parser is None:
        monkeypatch.delenv(PARSER_ENV, raising=False)
    else:
        monkeypatch.setenv(PARSER_ENV, parser)
    if lab_mode:
        monkeypatch.setenv("SCANSAGE_AUTHORIZED_LAB", "1")
    else:
        monkeypatch.delenv("SCANSAGE_AUTHORIZED_LAB", raising=False)
    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    return resource({"format": "nmap_xml", "payload": payload})


def _build_hosts_payload(host_count: int, ports_per_host: int) -> str:
    """Return XML with sequential hosts/ports to trigger limit behavior."""

    hosts = []
    for idx in range(host_count):
        port_lines = []
        for port in range(ports_per_host):
            number = port + 1
            port_lines.append(
                f"""      <port protocol="tcp" portid="{number}">
        <state state="open"/>
        <service name="svc{number}"/>
      </port>"""
            )
        hosts.append(
            f"""  <host>
    <address addr="192.0.2.{idx + 1}" addrtype="ipv4"/>
    <ports>
{chr(10).join(port_lines)}
    </ports>
  </host>"""
        )
    return "<nmaprun>\n" + "\n".join(hosts) + "\n</nmaprun>"


def test_real_parser_e2e_persists_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real parser stores schema-valid records without leaking identifiers."""

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
</nmaprun>"""

    response = _run_ingest_with_parser(monkeypatch, payload, "real_minimal")
    schema_registry.validate(PUBLIC_SCHEMA, response)
    assert response["summary"]["parsed"] is True
    assert response["parser_version"] == MinimalNmapXmlParser.VERSION
    assert response["findings_count"] == 1
    serialized_response = json.dumps(response)
    assert "198.51.100.5" not in serialized_response

    record = nmap_ingest_store.get_ingest(response["ingest_id"])
    assert record is not None
    assert record["parser_version"] == MinimalNmapXmlParser.VERSION
    record_serialized = json.dumps(record)
    assert "198.51.100.5" not in record_serialized


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
def test_real_parser_e2e_redacts_identifiers(
    monkeypatch: pytest.MonkeyPatch, identifier: str
) -> None:
    """Anti-Hack: every identifier-like token is redacted in PUBLIC outputs
    and records."""

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

    response = _run_ingest_with_parser(monkeypatch, payload, "real_minimal")
    serialized = json.dumps(response)
    assert identifier not in serialized

    record = nmap_ingest_store.get_ingest(response["ingest_id"])
    assert record is not None
    record_serialized = json.dumps(record)
    assert identifier not in record_serialized


def test_real_parser_e2e_blocks_dtd(monkeypatch: pytest.MonkeyPatch) -> None:
    """The safe parser remains resistant to DTD/XXE even end-to-end."""

    payload = """<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<nmaprun>&xxe;</nmaprun>"""

    response = _run_ingest_with_parser(monkeypatch, payload, "real_minimal")
    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT
    serialized = json.dumps(response)
    assert "<!DOCTYPE" not in serialized
    assert "file:///etc/passwd" not in serialized
    assert not nmap_ingest_store.list_ingests()


def test_authorized_lab_mode_defaults_to_real_minimal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lab mode should pick real_minimal when no parser is explicitly set."""

    payload = """<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

    response = _run_ingest_with_parser(monkeypatch, payload, None, lab_mode=True)
    assert response["parser_version"] == MinimalNmapXmlParser.VERSION
    assert response["findings_count"] == 1


def test_explicit_parser_env_overrides_lab_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicitly requested parser must win even when lab mode is enabled."""

    response = _run_ingest_with_parser(
        monkeypatch, "<nmaprun></nmaprun>", "safe_xml", lab_mode=True
    )
    assert response["parser_version"] == "safe-xml-0.1"
    assert response["summary"]["parsed"] is False
    records = nmap_ingest_store.list_ingests()
    assert records
    assert records[0]["parser_version"] == "safe-xml-0.1"


def test_noop_parser_default_behaves_as_before(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no parser env flag the noop path continues to drive PUBLIC ingestion."""

    response = _run_ingest_with_parser(monkeypatch, "<nmaprun></nmaprun>", None)
    assert response["summary"]["parsed"] is False
    assert response["parser_version"] == "noop-0.1"
    records = nmap_ingest_store.list_ingests()
    assert records
    assert records[0]["parser_version"] == "noop-0.1"


def test_capped_response_persists_and_stays_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capped ingests persist safely and their records stay identifier-free."""

    monkeypatch.setenv("SCANSAGE_MAX_NMAP_FINDINGS", "3")
    monkeypatch.setenv("SCANSAGE_MAX_NMAP_HOSTS", "10")
    monkeypatch.setenv("SCANSAGE_MAX_NMAP_PORTS_PER_HOST", "8")
    monkeypatch.delenv("SCANSAGE_AUTHORIZED_LAB", raising=False)

    payload = _build_hosts_payload(5, 1)
    response = _run_ingest_with_parser(monkeypatch, payload, "real_minimal")
    metadata = response.get("metadata")
    assert metadata is not None
    caps = metadata["caps"]
    assert caps["capped"] is True
    assert caps["cap_reason"] == CapReason.MAX_FINDINGS.value

    record_resource = server.RESOURCE_REGISTRY["public://nmap/ingest/{ingest_id}"]
    record_response = record_resource({"ingest_id": response["ingest_id"]})
    schema_registry.validate("nmap_ingest_get_response_v0.1", record_response)
    serialized = json.dumps(record_response)
    assert "_sort_key" not in serialized
    assert "sort_key" not in serialized
    assert "192.0.2." not in serialized
    assert record_response["ingest"]["findings_count"] == response["findings_count"]
