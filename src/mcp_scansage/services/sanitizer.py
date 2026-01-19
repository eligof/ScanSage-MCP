"""Business rules to keep public responses scrubbed."""

from __future__ import annotations

import re
from typing import Any, Mapping

RAW_PATH_PATTERN = re.compile(r"(?i)(?:[A-Za-z]:\\\\|/home/|\./|\.\.)")
"""Pattern that catches obvious raw paths as a universal anti-hack rule."""

IDENTIFIER_PATTERNS = [
    r"(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)",
    r"(?:\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2,7}\b)",
    r"(?:\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?\b)",
    r"(?:\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b)",
    r"(?:\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z]{2,}\b)",
]
"""Regex fragments describing IPv4/IPv6/MAC/hostname identifiers to redact."""

IDENTIFIER_PATTERN = re.compile("|".join(IDENTIFIER_PATTERNS), re.IGNORECASE)
"""Compiled pattern that matches any identifier-like fragment."""


def redact_identifiers(value: str) -> str:
    """Replace identifier tokens (IP/MAC/hostname) with a placeholder."""

    return IDENTIFIER_PATTERN.sub("[redacted]", value)


def _scrub_value(value: str) -> str:
    """Remove raw path fragments from a single string."""

    scrubbed = RAW_PATH_PATTERN.sub("[redacted]", value)
    return redact_identifiers(scrubbed)


def sanitize_public_response(payload: Mapping[str, Any]) -> dict[str, str]:
    """Return a copy with every value stripped of raw path fragments."""

    return {key: _scrub_value(str(value)) for key, value in payload.items()}
