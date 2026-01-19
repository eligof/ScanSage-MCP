"""Audit helpers for PUBLIC Nmap ingestion caps."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping, MutableSequence, Protocol

from .audit_log import append_audit_event

_LOG = logging.getLogger(__name__)
_EVENTS: MutableSequence[dict[str, object]] = []
EVENT_NAME = "NMAP_INGEST_CAP_APPLIED"


class CapAuditSink(Protocol):
    """Protocol describing a cap audit sink."""

    def emit(self, entry: dict[str, object]) -> None:  # pragma: no cover - trivial
        ...


@dataclass
class InMemoryCapAuditSink:
    """Simple sink used for tests."""

    events: MutableSequence[dict[str, object]]

    def emit(self, entry: dict[str, object]) -> None:
        self.events.append(dict(entry))


class ProductionCapAuditSink:
    """Sink that writes events to the persistent audit log."""

    __slots__ = ()

    def emit(self, entry: dict[str, object]) -> None:
        try:
            append_audit_event(entry)
        except Exception as exc:  # pragma: no cover - defensive
            _LOG.warning("Unable to record cap audit event: %s", exc)


_IN_MEMORY_SINK = InMemoryCapAuditSink(events=_EVENTS)
_DEFAULT_PRODUCTION_SINK: CapAuditSink = ProductionCapAuditSink()
_PRODUCTION_SINK: CapAuditSink | None = _DEFAULT_PRODUCTION_SINK


def set_production_cap_audit_sink(sink: CapAuditSink | None) -> None:
    """Override the production audit sink (for testing)."""

    global _PRODUCTION_SINK
    _PRODUCTION_SINK = sink


def record_cap_event(
    reason: str,
    limits: Mapping[str, int],
    counts_seen: Mapping[str, int],
    counts_returned: Mapping[str, int],
) -> None:
    """Record a non-sensitive cap event for auditing."""

    entry = {
        "event": EVENT_NAME,
        "cap_reason": reason,
        "limits": dict(limits),
        "counts_seen": dict(counts_seen),
        "counts_returned": dict(counts_returned),
    }
    _IN_MEMORY_SINK.emit(entry)
    if _PRODUCTION_SINK is not None:
        _PRODUCTION_SINK.emit(entry)


def get_cap_events() -> list[dict[str, object]]:
    """Return a snapshot of recorded cap events."""

    return list(_EVENTS)


def clear_cap_events() -> None:
    """Clear the recorded cap events (testing aid)."""

    _EVENTS.clear()
