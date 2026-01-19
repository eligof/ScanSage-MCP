"""Parser interface + helper scaffolding for PUBLIC Nmap payloads.

Real XML parsers must satisfy the following invariants:
1. No identifier token (IPv4/IPv6/MAC/hostname) is ever emitted into a public field.
2. Any XML document that contains a DTD, entity declaration, or an external reference
   must be rejected before traversal occurs.
3. Overly large or non-UTF-8 payloads are declined by the parser boundary.
4. Redaction helpers from :mod:`mcp_scansage.services.sanitizer` are applied in every
   textual channel, and nothing is fetched from the network during parsing.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Protocol

from .cap_reason import CapReason
from .nmap_limits import NmapLimitConfig
from .sanitizer import IDENTIFIER_PATTERN, redact_identifiers

try:
    from defusedxml.common import DefusedXmlException
    from defusedxml.ElementTree import fromstring as _defused_fromstring
except ImportError:  # pragma: no cover - optional dependency
    _defused_fromstring = None  # type: ignore[assignment]
    DefusedXmlException = ET.ParseError  # type: ignore[assignment]

_UNSAFE_XML_PATTERN = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)
"""Regex that detects DTD declarations or entity blocks."""


def parse_xml_safely(xml_bytes: bytes) -> ET.Element:
    """
    Deserialize XML bytes using an XXE-safe boundary.

    Over-limit payloads, invalid UTF-8, and DTD/entity declarations raise a
    :class:`ValueError` with a sanitized message so errors can be surfaced safely.
    """

    max_bytes = NmapLimitConfig.from_env().max_xml_bytes
    if len(xml_bytes) > max_bytes:
        raise ValueError("XML payload exceeds the maximum allowed size.")

    try:
        xml_text = xml_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("XML payload is not valid UTF-8.") from exc

    if _UNSAFE_XML_PATTERN.search(xml_text):
        raise ValueError("XML payload contains forbidden declarations.")

    parser = _defused_fromstring or ET.fromstring
    try:
        return parser(xml_text)
    except (DefusedXmlException, ET.ParseError) as exc:
        raise ValueError("Malformed XML payload.") from exc


@dataclass(frozen=True)
class ParsedFinding:
    """Minimal PUBLIC-safe finding representation."""

    title: str
    detail: str
    confidence: str
    _sort_key: tuple[int, int, str, str] = field(default=(0, 0, "", ""))

    def to_mapping(self) -> dict[str, str]:
        return {
            "title": self.title,
            "detail": self.detail,
            "confidence": self.confidence,
        }

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", redact_identifiers(self.title))
        object.__setattr__(self, "detail", redact_identifiers(self.detail))

    @property
    def sort_key(self) -> tuple[int, int, str, str]:
        return self._sort_key


@dataclass(frozen=True)
class CapInfo:
    """Metadata describing exactly how parser limits were hit."""

    reason: CapReason | None
    hosts_processed: int
    ports_processed: int
    findings_processed: int
    max_hosts: int
    max_ports_per_host: int
    max_findings: int

    @property
    def capped(self) -> bool:
        return self.reason is not None


@dataclass(frozen=True)
class ParsedNmapResult:
    """Parser output that feeds into PUBLIC responses and stores."""

    parsed: bool
    findings: tuple[ParsedFinding, ...]
    parser_version: str
    cap_info: CapInfo | None = None

    @property
    def findings_count(self) -> int:
        return len(self.findings)


class NmapParser(Protocol):
    """Parser contract that drivers must implement."""

    def parse(self, payload: bytes) -> ParsedNmapResult: ...


class NoopNmapParser(NmapParser):
    """Parser that never emits findings and is safe to reuse everywhere."""

    VERSION = "noop-0.1"

    def parse(self, payload: bytes) -> ParsedNmapResult:
        return ParsedNmapResult(parsed=False, findings=(), parser_version=self.VERSION)


class SyntheticNmapParser(NmapParser):
    """Synthetic parser for developer payloads that already avoid identifiers."""

    VERSION = "synthetic_v1"
    _PORT_PATTERN = re.compile(
        r"^PORT_OPEN\s+(\d{1,5})/tcp\s+service=([a-z]+)$", re.IGNORECASE
    )

    def parse(self, payload: bytes) -> ParsedNmapResult:
        if not payload:
            return ParsedNmapResult(
                parsed=False, findings=(), parser_version=self.VERSION
            )

        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Synthetic payload is not valid UTF-8.") from exc

        findings: list[ParsedFinding] = []
        line_index = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if IDENTIFIER_PATTERN.search(line):
                continue
            match = self._PORT_PATTERN.match(line)
            if not match:
                raise ValueError("Synthetic payload line malformed.")
            port, service = match.groups()
            sort_key = (0, line_index, int(port), service.lower())
            line_index += 1
            findings.append(
                ParsedFinding(
                    title=f"Port {port} open",
                    detail=f"{service.lower()} service noted on TCP/{port}",
                    confidence="medium",
                    _sort_key=sort_key,
                )
            )

        parsed = bool(findings)
        return ParsedNmapResult(
            parsed=parsed, findings=tuple(findings), parser_version=self.VERSION
        )


class SafeNmapXmlParser(NmapParser):
    """Placeholder parser that enforces the XML safety boundary."""

    VERSION = "safe-xml-0.1"

    def parse(self, payload: bytes) -> ParsedNmapResult:
        parse_xml_safely(payload)
        return ParsedNmapResult(parsed=False, findings=(), parser_version=self.VERSION)


class MinimalNmapXmlParser(NmapParser):
    """Minimal real parser for a safe subset of Nmap XML."""

    VERSION = "real-minimal-0.2"

    def parse(self, payload: bytes) -> ParsedNmapResult:
        root = parse_xml_safely(payload)
        config = NmapLimitConfig.from_env()
        tracker = _LimitTracker(config)
        findings: list[ParsedFinding] = []
        stop_due_to_findings = False

        for host_index, host in enumerate(root.findall(".//host")):
            if tracker.hosts_processed >= tracker.max_hosts:
                tracker.mark_limit(CapReason.MAX_HOSTS)
                break
            tracker.hosts_processed += 1
            ports = host.find("ports")
            if ports is None:
                continue
            ports_seen = 0
            for port_index, port_elem in enumerate(ports.findall("port")):
                if ports_seen >= tracker.max_ports_per_host:
                    tracker.mark_limit(CapReason.MAX_PORTS)
                    break
                ports_seen += 1
                tracker.ports_processed += 1
                if tracker.findings_processed >= tracker.max_findings:
                    tracker.mark_limit(CapReason.MAX_FINDINGS)
                    stop_due_to_findings = True
                    break
                finding = self._finding_from_port(port_elem, host_index, port_index)
                if finding is None:
                    continue
                findings.append(finding)
                tracker.findings_processed += 1
                if tracker.findings_processed >= tracker.max_findings:
                    tracker.mark_limit(CapReason.MAX_FINDINGS)
                    stop_due_to_findings = True
                    break
            if stop_due_to_findings:
                break

        parsed = bool(findings)
        cap_info = tracker.to_cap_info() if tracker.cap_reason else None
        return ParsedNmapResult(
            parsed=parsed,
            findings=tuple(findings),
            parser_version=self.VERSION,
            cap_info=cap_info,
        )

    @staticmethod
    def _finding_from_port(
        port_elem: ET.Element, host_index: int, port_index: int
    ) -> ParsedFinding | None:
        if port_elem.get("protocol", "").lower() != "tcp":
            return None
        state = port_elem.find("state")
        if state is None or state.get("state", "").lower() != "open":
            return None
        port_id = port_elem.get("portid")
        if not port_id:
            return None
        service_elem = port_elem.find("service")
        if service_elem is None:
            return None
        service_name = service_elem.get("name")
        if not service_name:
            return None
        detail_parts = [service_name]
        product = service_elem.get("product")
        version = service_elem.get("version")
        extrainfo = service_elem.get("extrainfo")
        if product:
            detail_parts.append(product)
        if version:
            detail_parts.append(version)
        if extrainfo:
            detail_parts.append(extrainfo)
        detail = f"{' '.join(detail_parts)} service noted on TCP/{port_id}"
        try:
            port_number = int(port_id)
        except ValueError:
            port_number = 0
        sort_key = (
            host_index,
            port_index,
            port_number,
            service_name.lower(),
        )
        return ParsedFinding(
            title=f"Port {port_id} open",
            detail=detail,
            confidence="medium",
            _sort_key=sort_key,
        )


class _LimitTracker:
    """Internal tracker that records how many elements were processed."""

    def __init__(self, config: NmapLimitConfig) -> None:
        self.max_hosts = config.max_hosts
        self.max_ports_per_host = config.max_ports_per_host
        self.max_findings = config.max_findings
        self.hosts_processed = 0
        self.ports_processed = 0
        self.findings_processed = 0
        self._cap_reason: CapReason | None = None

    def mark_limit(self, reason: CapReason) -> None:
        """Record the most recent limit that had to be enforced."""

        self._cap_reason = reason

    @property
    def cap_reason(self) -> CapReason | None:
        return self._cap_reason

    def to_cap_info(self) -> CapInfo:
        """Expose the accumulated state as immutable metadata."""

        return CapInfo(
            reason=self._cap_reason,
            hosts_processed=self.hosts_processed,
            ports_processed=self.ports_processed,
            findings_processed=self.findings_processed,
            max_hosts=self.max_hosts,
            max_ports_per_host=self.max_ports_per_host,
            max_findings=self.max_findings,
        )


DEFAULT_PARSER: NmapParser = NoopNmapParser()
"""Fallback parser used unless the env flag requests a safer implementation."""


XML_PARSER_ENV = "SCANSAGE_NMAP_XML_PARSER"
"""Env var used to opt into a safer XML parser implementation."""

AUTHORIZED_LAB_ENV = "SCANSAGE_AUTHORIZED_LAB"
"""Env var that enables authorized lab mode."""

XML_PARSER_REGISTRY: dict[str, type[NmapParser]] = {
    "safe_xml": SafeNmapXmlParser,
    "real_minimal": MinimalNmapXmlParser,
}
"""Registry enumerating supported XML parser implementations."""


def _lab_mode_enabled() -> bool:
    """Return True when authorized lab mode is on."""

    return os.getenv(AUTHORIZED_LAB_ENV, "").lower() in {"1", "true", "yes"}


def get_configured_nmap_parser() -> NmapParser:
    """
    Return the parser implementation requested via :mod:`XML_PARSER_ENV`.

    Authorized lab mode opts into :class:`MinimalNmapXmlParser` when the parser
    selection env var is absent; otherwise, fall back to :class:`NoopNmapParser`.
    """

    parser_choice = os.getenv(XML_PARSER_ENV)
    if parser_choice:
        parser_cls = XML_PARSER_REGISTRY.get(parser_choice.lower())
        if parser_cls:
            return parser_cls()
        raise ValueError("Requested parser is not supported.")
    if _lab_mode_enabled():
        parser_cls = XML_PARSER_REGISTRY.get("real_minimal")
        if parser_cls:
            return parser_cls()
    return DEFAULT_PARSER
