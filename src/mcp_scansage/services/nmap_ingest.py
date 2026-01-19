"""PUBLIC-safe Nmap ingestion helpers."""

from __future__ import annotations

import hashlib
import uuid
from typing import Mapping

from .cap_audit import record_cap_event
from .cap_reason import CapReason
from .nmap_ingest_store import persist_ingest_record
from .nmap_limits import DEFAULT_NMAP_LIMITS, NmapLimitConfig
from .nmap_parser import (
    NmapParser,
    ParsedFinding,
    ParsedNmapResult,
    get_configured_nmap_parser,
)

MAX_PAYLOAD_BYTES = DEFAULT_NMAP_LIMITS.max_xml_bytes
"""Default maximum allowed payload size in bytes for PUBLIC ingestion."""

NEXT_STEPS = [
    "Await a dedicated parser before acting on any findings.",
    "Confirm the ingestion digest matches downstream expectations.",
]


class PayloadTooLargeError(ValueError):
    """Raised when an incoming payload exceeds the sanctioned size."""


def ingest_nmap_public(
    format: str,
    payload: str,
    meta: Mapping[str, str] | None = None,
    parser: NmapParser | None = None,
    persist_record: bool = True,
) -> dict[str, object]:
    """
    Create a PUBLIC-safe ingestion summary for Nmap XML payloads.

    Args:
        format: Expected to be "nmap_xml".
        payload: The raw XML text (bounded by MAX_PAYLOAD_BYTES).
        meta: Optional metadata (ignored for now to avoid echoing extra data).

    Returns:
        A schema-compliant dictionary ready for PUBLIC consumption.
    """

    if format not in ("nmap_xml", "synthetic_v1"):
        raise ValueError("Unsupported format for PUBLIC ingestion.")

    limit_config = NmapLimitConfig.from_env()
    payload_bytes = payload.encode("utf-8")
    byte_count = len(payload_bytes)
    if byte_count > limit_config.max_xml_bytes:
        _emit_payload_cap(limit_config, byte_count)
        raise PayloadTooLargeError("Payload exceeds maximum allowed size.")

    digest = hashlib.sha256(payload_bytes).hexdigest()
    parser = parser or get_configured_nmap_parser()
    parser_result = parser.parse(payload_bytes)
    final_findings, metadata = _apply_findings_limit(parser_result, limit_config)
    findings_count = len(final_findings)
    ingest_id = uuid.uuid4().hex
    if persist_record:
        persist_ingest_record(
            ingest_id=ingest_id,
            format=format,
            payload_bytes=byte_count,
            payload_sha256=digest,
            parsed=parser_result.parsed,
            findings_count=findings_count,
            parser_version=parser_result.parser_version,
            next_steps=NEXT_STEPS,
        )

    response: dict[str, object] = {
        "operation": "nmap_ingest",
        "ingest_id": ingest_id,
        "format": format,
        "summary": {
            "payload_bytes": byte_count,
            "payload_sha256": digest,
            "parsed": parser_result.parsed,
        },
        "findings": [],
        "next_steps": list(NEXT_STEPS),
        "parser_version": parser_result.parser_version,
        "findings_count": findings_count,
        "parsed_findings": [finding.to_mapping() for finding in final_findings],
    }
    if metadata:
        response["metadata"] = metadata

    return response


def stable_findings_sort_key(finding: ParsedFinding) -> tuple[int, int, str, str]:
    """Stable ordering key used before truncating findings."""

    return finding.sort_key


def _apply_findings_limit(
    parser_result: ParsedNmapResult, limit_config: NmapLimitConfig
) -> tuple[tuple[ParsedFinding, ...], dict[str, object] | None]:
    """Truncate parser findings and prepare cap metadata if needed."""

    ordered_findings = tuple(
        sorted(parser_result.findings, key=stable_findings_sort_key)
    )
    raw_count = len(ordered_findings)
    max_findings = limit_config.max_findings
    truncated = raw_count > max_findings
    final_findings = (
        ordered_findings if not truncated else ordered_findings[:max_findings]
    )
    reason: CapReason | None = None
    counts: dict[str, int] | None = None
    cap_info = parser_result.cap_info

    if cap_info and cap_info.capped:
        reason = cap_info.reason
        counts = {
            "hosts_processed": cap_info.hosts_processed,
            "ports_processed": cap_info.ports_processed,
            "findings_processed": cap_info.findings_processed,
        }
    if truncated:
        reason = CapReason.MAX_FINDINGS
        counts = counts or {}
        counts["findings_processed"] = raw_count

    metadata = None
    if reason is not None:
        metadata = _build_caps_metadata(reason, limit_config, counts)
        _emit_cap_event(
            reason.value,
            limit_config,
            counts or {},
            final_findings,
        )

    return final_findings, metadata


def _build_caps_metadata(
    reason: CapReason,
    limit_config: NmapLimitConfig,
    counts: Mapping[str, int] | None = None,
) -> dict[str, object]:
    """Create the PUBLIC-safe caps metadata block."""

    caps: dict[str, object] = {
        "capped": True,
        "cap_reason": reason.value,
        "limits": {
            "max_hosts": limit_config.max_hosts,
            "max_ports_per_host": limit_config.max_ports_per_host,
            "max_findings": limit_config.max_findings,
        },
    }
    if counts:
        caps["counts"] = dict(counts)
    return {"caps": caps}


def _build_cap_limits(limit_config: NmapLimitConfig) -> dict[str, int]:
    """Summarize the configured cap settings for audit events."""

    return {
        "max_payload_bytes": limit_config.max_xml_bytes,
        "max_hosts": limit_config.max_hosts,
        "max_ports_per_host": limit_config.max_ports_per_host,
        "max_findings": limit_config.max_findings,
    }


def _counts_returned_from_findings(
    findings: tuple[ParsedFinding, ...],
) -> dict[str, int]:
    """Return host/port/finding counts that were emitted to PUBLIC clients."""

    hosts_returned = len({finding.sort_key[0] for finding in findings})
    ports_returned = len(findings)
    return {
        "hosts_returned": hosts_returned,
        "ports_returned": ports_returned,
        "findings_returned": ports_returned,
    }


def _emit_cap_event(
    reason: str,
    limit_config: NmapLimitConfig,
    counts_seen: Mapping[str, int],
    final_findings: tuple[ParsedFinding, ...],
) -> None:
    """Emit a non-sensitive cap audit event for the ingestion attempt."""

    record_cap_event(
        reason=reason,
        limits=_build_cap_limits(limit_config),
        counts_seen=counts_seen,
        counts_returned=_counts_returned_from_findings(final_findings),
    )


def _emit_payload_cap(limit_config: NmapLimitConfig, payload_bytes: int) -> None:
    """Log a cap event for oversized payloads before rejecting."""

    record_cap_event(
        reason=CapReason.MAX_PAYLOAD_BYTES.value,
        limits=_build_cap_limits(limit_config),
        counts_seen={"payload_bytes": payload_bytes},
        counts_returned=_counts_returned_from_findings(()),
    )
