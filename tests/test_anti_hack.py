"""Anti-hack test ensuring raw paths never leak in public responses."""

import json

import pytest

from mcp_scansage.mcp import server
from mcp_scansage.services import nmap_ingest_store
from mcp_scansage.services.sanitizer import RAW_PATH_PATTERN, sanitize_public_response


@pytest.mark.parametrize(
    "payload",
    [
        "/home/eli/secret/db.sqlite",
        "C:\\Users\\admin\\keys.txt",
        "./raw/scan-output.txt",
        "../tmp/debug.log",
        "/etc/passwd",
    ],
)
def test_sanitized_responses_drop_raw_paths(payload: str) -> None:
    """Public responses must not contain raw path fragments."""

    sanitized = sanitize_public_response({"detail": payload})
    assert not RAW_PATH_PATTERN.search(sanitized["detail"])


@pytest.mark.parametrize(
    "identifier",
    [
        "192.0.2.123",
        "2001:db8::1",
        "AA:BB:CC:DD:EE:FF",
        "wireless-target.local",
        "public-server.example.com",
    ],
)
def test_anti_hack_nmap_ingest_never_leaks_identifiers(identifier: str) -> None:
    """Anti-Hack: PUBLIC ingestion may not echo IP/MAC/hostname fragments."""

    payload = f"<nmaprun><host><address>{identifier}</address></host></nmaprun>"

    for resource_name, request in (
        ("public://nmap/ingest", {"format": "nmap_xml", "payload": payload}),
        ("ingest_nmap_xml", {"payload": payload}),
    ):
        resource = server.RESOURCE_REGISTRY[resource_name]
        response = resource(request)

        serialized = json.dumps(response)
        assert identifier not in serialized


@pytest.mark.parametrize(
    "identifier",
    [
        "203.0.113.45",
        "2001:db8:1::1",
        "FF:FF:FF:FF:FF:FF",
        "host.example.com",
    ],
)
def test_anti_hack_synthetic_payloads_drop_identifiers(identifier: str) -> None:
    """Synthetic parser outputs must never contain identifier fragments."""

    resource = server.RESOURCE_REGISTRY["public://nmap/ingest"]
    payload = (
        f"PORT_OPEN 22/tcp service=ssh\nPORT_OPEN 80/tcp service=http ip={identifier}"
    )
    response = resource(
        {
            "format": "synthetic_v1",
            "payload": payload,
            "meta": {"parser": "synthetic_v1"},
        }
    )

    serialized = json.dumps(response)
    assert identifier not in serialized


@pytest.mark.parametrize(
    "identifier",
    [
        "192.0.2.123",
        "58.1.0.42",
        "2001:db8::dead:beef",
        "AA:BB:CC:DD:EE:FF",
        "router.local",
    ],
)
def test_anti_hack_ingest_records_never_echo_identifiers(identifier: str) -> None:
    """Anti-Hack: stored records must not leak IP/MAC/hostname fragments."""

    nmap_ingest_store.clear_records()

    ingest_resource = server.RESOURCE_REGISTRY["ingest_nmap_xml"]
    payload = f"<nmaprun><host><address>{identifier}</address></host></nmaprun>"
    response = ingest_resource({"payload": payload})
    ingest_id = response["ingest_id"]

    list_resource = server.RESOURCE_REGISTRY["public://nmap/ingests"]
    list_response = list_resource({})
    assert identifier not in json.dumps(list_response)

    get_resource = server.RESOURCE_REGISTRY["public://nmap/ingest/{ingest_id}"]
    get_response = get_resource({"ingest_id": ingest_id})
    assert identifier not in json.dumps(get_response)
