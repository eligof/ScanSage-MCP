"""Configurable limits for PUBLIC Nmap ingestion."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_MAX_NMAP_XML_BYTES = 32_768
"""Conservative default for XML payload size in bytes."""

DEFAULT_MAX_NMAP_HOSTS = 64
"""Default cap on the number of hosts processed in a single payload."""

DEFAULT_MAX_NMAP_PORTS_PER_HOST = 128
"""Default cap on how many ports are examined per host."""

DEFAULT_MAX_NMAP_FINDINGS = 100
"""Default cap on the number of parsed findings reported."""


def _env_int(
    name: str,
    default: int,
    *,
    min_value: int = 0,
    max_value: int | None = None,
) -> int:
    """Return a bounded integer limit sourced from the environment."""

    raw = os.getenv(name)
    if not raw or not raw.strip():
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    if parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return max_value
    return parsed


@dataclass(frozen=True)
class NmapLimitConfig:
    """Container describing every configurable ingest limit."""

    max_xml_bytes: int
    max_hosts: int
    max_ports_per_host: int
    max_findings: int

    @classmethod
    def from_env(cls) -> "NmapLimitConfig":
        """Return a limit set using the configured environment variables."""

        return cls(
            max_xml_bytes=_env_int(
                "SCANSAGE_MAX_NMAP_XML_BYTES",
                DEFAULT_MAX_NMAP_XML_BYTES,
                min_value=1,
            ),
            max_hosts=_env_int(
                "SCANSAGE_MAX_NMAP_HOSTS",
                DEFAULT_MAX_NMAP_HOSTS,
                min_value=1,
            ),
            max_ports_per_host=_env_int(
                "SCANSAGE_MAX_NMAP_PORTS_PER_HOST",
                DEFAULT_MAX_NMAP_PORTS_PER_HOST,
                min_value=1,
            ),
            max_findings=_env_int(
                "SCANSAGE_MAX_NMAP_FINDINGS",
                DEFAULT_MAX_NMAP_FINDINGS,
                min_value=1,
            ),
        )


DEFAULT_NMAP_LIMITS = NmapLimitConfig(
    DEFAULT_MAX_NMAP_XML_BYTES,
    DEFAULT_MAX_NMAP_HOSTS,
    DEFAULT_MAX_NMAP_PORTS_PER_HOST,
    DEFAULT_MAX_NMAP_FINDINGS,
)
