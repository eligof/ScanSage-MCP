"""Unit coverage for the JSONL audit sink."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from mcp_scansage.services.audit_log import (
    AuditConfig,
    append_audit_event,
    reset_audit_config,
    reset_audit_warning_state,
    set_audit_config,
    set_audit_warning_interval,
)


def _sample_event() -> dict[str, object]:
    return {
        "event": "NMAP_INGEST_CAP_APPLIED",
        "cap_reason": "MAX_FINDINGS",
        "limits": {},
        "counts_seen": {},
        "counts_returned": {},
    }


def test_append_rotates_when_limit_exceeded(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_file = audit_dir / "audit.jsonl"
    config = AuditConfig(audit_file=audit_file, max_bytes=1)
    audit_dir.mkdir(parents=True)
    audit_file.write_text("old-value", encoding="utf-8")
    set_audit_config(config)

    append_audit_event(_sample_event())

    rotated = audit_file.with_name(audit_file.name + ".1")
    assert rotated.exists()
    assert rotated.read_text(encoding="utf-8") == "old-value"
    assert audit_file.exists()
    assert audit_file.read_text(encoding="utf-8")

    reset_audit_config()


def test_append_handles_unwritable_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    audit_dir = tmp_path / "audit"
    audit_file = audit_dir / "audit.jsonl"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_file.write_text("", encoding="utf-8")
    config = AuditConfig(audit_file=audit_file, max_bytes=None)
    set_audit_config(config)

    def fail_open(self: Path, *args: object, **kwargs: object) -> None:
        raise OSError("no space")

    monkeypatch.setattr(
        "mcp_scansage.services.audit_log.Path.open",
        fail_open,
    )

    append_audit_event(_sample_event())

    reset_audit_config()


def test_warning_rate_limiting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    audit_dir = tmp_path / "audit"
    audit_file = audit_dir / "audit.jsonl"
    config = AuditConfig(audit_file=audit_file, max_bytes=None)
    set_audit_config(config)
    reset_audit_warning_state()
    set_audit_warning_interval(10.0)

    def fail_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        raise OSError("boom")

    monkeypatch.setattr(
        "mcp_scansage.services.audit_log.Path.mkdir",
        fail_mkdir,
    )

    class TimeStub:
        def __init__(self, values: list[float]) -> None:
            self.values = values

        def __call__(self) -> float:
            if self.values:
                return self.values.pop(0)
            return 999.0

    monkeypatch.setattr(
        "mcp_scansage.services.audit_log.time.monotonic",
        TimeStub([1.0, 1.0, 12.0]),
    )

    caplog.set_level(logging.WARNING)
    append_audit_event(_sample_event())
    append_audit_event(_sample_event())
    append_audit_event(_sample_event())

    warnings = [
        record
        for record in caplog.records
        if "Unable to create audit directory" in record.getMessage()
    ]
    assert len(warnings) == 2

    reset_audit_warning_state()
    set_audit_warning_interval(None)
    reset_audit_config()
