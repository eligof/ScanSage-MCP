"""Shared cap reason taxonomy for PUBLIC Nmap ingestion."""

from __future__ import annotations

from enum import Enum


class CapReason(Enum):
    """Enumerate count-based limits that can truncate parsing or ingestion."""

    MAX_HOSTS = "MAX_HOSTS"
    MAX_PORTS = "MAX_PORTS"
    MAX_FINDINGS = "MAX_FINDINGS"
    MAX_PAYLOAD_BYTES = "MAX_PAYLOAD_BYTES"
