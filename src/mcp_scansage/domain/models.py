"""Core entities without I/O for ScanSage MCP."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """Minimal finding representation owned by domain logic."""

    severity: str
    description: str
