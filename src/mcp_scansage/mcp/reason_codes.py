"""Reason codes used for PUBLIC routing/audit responses."""

from __future__ import annotations

PAYLOAD_TOO_LARGE = "payload_too_large"
"""Input rejected because it exceeded the sanctioned size bound."""

INVALID_INPUT = "invalid_input"
"""Input failed schema validation or format checks."""

RESPONSE_VALIDATION_FAILED = "response_validation_failed"
"""The service produced output that violated the public response schema."""

RECORD_NOT_FOUND = "record_not_found"
"""The requested PUBLIC ingestion record could not be located."""
