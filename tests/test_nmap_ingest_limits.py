"""Limits regression tests for PUBLIC Nmap ingestion."""

from __future__ import annotations

import json

import pytest

from mcp_scansage.mcp import reason_codes, server
from mcp_scansage.services import nmap_ingest_store
from mcp_scansage.services.cap_audit import EVENT_NAME, clear_cap_events, get_cap_events
from mcp_scansage.services.cap_reason import CapReason
from mcp_scansage.services.nmap_ingest import PayloadTooLargeError, ingest_nmap_public
from mcp_scansage.services.nmap_limits import DEFAULT_NMAP_LIMITS, NmapLimitConfig

RESOURCE_NAME = "public://nmap/ingest"
PUBLIC_SCHEMA = "nmap_ingest_public_response_v0.2"


@pytest.fixture(autouse=True)
def clean_records() -> None:
    """Keep persisted ingestion records isolated per test."""

    nmap_ingest_store.clear_records()
    yield
    nmap_ingest_store.clear_records()


@pytest.fixture(autouse=True)
def clear_audit_events() -> None:
    """Ensure cap audit events don't leak between limits tests."""

    clear_cap_events()
    yield
    clear_cap_events()


def _build_hosts(host_count: int, ports_per_host: int) -> str:
    """Build a simple XML payload with the requested hosts and ports."""

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


def _configure_caps_env(
    monkeypatch: pytest.MonkeyPatch,
    findings_limit: int,
    host_limit: int = 10,
    ports_limit: int = 8,
) -> None:
    """Set the parser + cap env vars for deterministic limit testing."""

    monkeypatch.setenv("SCANSAGE_NMAP_XML_PARSER", "real_minimal")
    monkeypatch.setenv("SCANSAGE_MAX_NMAP_FINDINGS", str(findings_limit))
    monkeypatch.setenv("SCANSAGE_MAX_NMAP_HOSTS", str(host_limit))
    monkeypatch.setenv("SCANSAGE_MAX_NMAP_PORTS_PER_HOST", str(ports_limit))
    monkeypatch.delenv("SCANSAGE_AUTHORIZED_LAB", raising=False)


def _assert_cap_event_structure(event: dict[str, object]) -> None:
    """Verify the audit event uses the allowed keys only."""

    assert set(event.keys()) == {
        "event",
        "cap_reason",
        "limits",
        "counts_seen",
        "counts_returned",
    }
    assert event["event"] == EVENT_NAME


def test_oversized_payload_rejected_and_not_persisted() -> None:
    """Oversized XML must be sanitized and never stored."""

    config = NmapLimitConfig.from_env()
    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    payload = "A" * (config.max_xml_bytes + 1)
    response = resource({"format": "nmap_xml", "payload": payload})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT
    assert not nmap_ingest_store.list_ingests()


def test_payload_cap_generates_audit_event() -> None:
    """Rejecting oversized payloads should still produce a cap audit event."""

    config = NmapLimitConfig.from_env()
    payload = "A" * (config.max_xml_bytes + 1)
    with pytest.raises(PayloadTooLargeError):
        ingest_nmap_public("nmap_xml", payload)

    events = get_cap_events()
    assert len(events) == 1
    event = events[0]
    _assert_cap_event_structure(event)
    assert event["cap_reason"] == "MAX_PAYLOAD_BYTES"
    assert event["counts_seen"]["payload_bytes"] == len(payload)
    counts_returned = event["counts_returned"]
    assert counts_returned["findings_returned"] == 0
    assert counts_returned["ports_returned"] == 0
    assert counts_returned["hosts_returned"] == 0
    serialized_event = json.dumps(event)
    assert payload not in serialized_event


def test_caps_metadata_emitted_when_findings_limit_hit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Limit violations should reject with sanitized errors."""

    _configure_caps_env(monkeypatch, findings_limit=6)

    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    payload = _build_hosts(10, 1)
    response = resource({"format": "nmap_xml", "payload": payload})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT

    serialized = json.dumps(response)
    assert "192.0.2." not in serialized
    assert payload not in serialized


def test_caps_emit_to_production_sink(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cap activations should also be recorded in the production audit log."""

    captured: list[dict[str, object]] = []

    def fake_append(event: dict[str, object]) -> None:
        captured.append(event)

    _configure_caps_env(monkeypatch, findings_limit=4)
    monkeypatch.setattr(
        "mcp_scansage.services.cap_audit.append_audit_event", fake_append
    )

    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    payload = _build_hosts(10, 1)
    response = resource({"format": "nmap_xml", "payload": payload})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT
    assert captured
    event = captured[0]
    assert event["event"] == EVENT_NAME
    assert event["cap_reason"] == CapReason.MAX_FINDINGS.value
    assert event["limits"]["max_findings"] == 4
    serialized_event = json.dumps(event)
    assert "192.0.2." not in serialized_event
    assert payload not in serialized_event


def test_caps_ignore_audit_write_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Audit failures must not bubble up to PUBLIC ingestion flows."""

    def fail(_: dict[str, object]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(
        "mcp_scansage.services.audit_log.append_audit_event",
        fail,
    )
    _configure_caps_env(monkeypatch, findings_limit=4)
    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    payload = _build_hosts(10, 1)
    response = resource({"format": "nmap_xml", "payload": payload})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT
    events = get_cap_events()
    assert events
    assert events[0]["cap_reason"] == CapReason.MAX_FINDINGS.value


def test_caps_rejections_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated limit violations should reject consistently."""

    _configure_caps_env(monkeypatch, findings_limit=5, host_limit=20, ports_limit=2)
    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    payload = _build_hosts(10, 2)

    first = resource({"format": "nmap_xml", "payload": payload})
    second = resource({"format": "nmap_xml", "payload": payload})

    assert first["status"] == "error"
    assert first["reason"] == reason_codes.INVALID_INPUT
    assert first == second
    serialized = json.dumps(first)
    assert "192.0.2." not in serialized


@pytest.mark.parametrize(
    "invalid_value",
    ["", "nope", "-1", "   "],
)
@pytest.mark.parametrize(
    "env_var, limit_key",
    [
        ("SCANSAGE_MAX_NMAP_HOSTS", "max_hosts"),
        ("SCANSAGE_MAX_NMAP_PORTS_PER_HOST", "max_ports_per_host"),
        ("SCANSAGE_MAX_NMAP_FINDINGS", "max_findings"),
    ],
)
def test_invalid_env_values_default_to_safe_limits(
    monkeypatch: pytest.MonkeyPatch, env_var: str, limit_key: str, invalid_value: str
) -> None:
    """Non-numeric env values fall back to defaults and reject unsafe payloads."""

    env_values = {
        "SCANSAGE_MAX_NMAP_HOSTS": "10",
        "SCANSAGE_MAX_NMAP_PORTS_PER_HOST": "5",
        "SCANSAGE_MAX_NMAP_FINDINGS": "3",
    }
    special_overrides = {
        "SCANSAGE_MAX_NMAP_FINDINGS": ("1", "1"),
    }
    host_override = special_overrides.get(env_var)
    if host_override:
        (
            env_values["SCANSAGE_MAX_NMAP_HOSTS"],
            env_values["SCANSAGE_MAX_NMAP_PORTS_PER_HOST"],
        ) = host_override

    for key, value in env_values.items():
        monkeypatch.setenv(key, invalid_value if key == env_var else value)
    monkeypatch.setenv("SCANSAGE_NMAP_XML_PARSER", "real_minimal")
    monkeypatch.delenv("SCANSAGE_AUTHORIZED_LAB", raising=False)

    resource = server.RESOURCE_REGISTRY[RESOURCE_NAME]
    payload = _build_hosts(6, 2)
    response = resource({"format": "nmap_xml", "payload": payload})

    assert response["status"] == "error"
    assert response["reason"] == reason_codes.INVALID_INPUT
    assert getattr(DEFAULT_NMAP_LIMITS, limit_key)
    serialized = json.dumps(response)
    assert "192.0.2." not in serialized
