"""Simple JSONL audit logger for PUBLIC ScanSage services."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .nmap_ingest_store import STATE_DIR

_LOG = logging.getLogger(__name__)
DEFAULT_MAX_AUDIT_BYTES = 1_000_000
AUDIT_DIR_ENV = "SCANSAGE_AUDIT_DIR"
AUDIT_MAX_BYTES_ENV = "SCANSAGE_AUDIT_MAX_BYTES"

_WARNING_INTERVAL_SECONDS = 60.0
_LAST_WARN: dict[str, float] = {}


@dataclass(frozen=True)
class AuditConfig:
    """Configuration for the audit log sink."""

    audit_file: Path
    max_bytes: int | None

    @classmethod
    def from_env(cls) -> "AuditConfig":
        """Create a config using the current environment."""

        base_dir = Path(os.getenv(AUDIT_DIR_ENV, str(STATE_DIR)))
        audit_file = base_dir / "audit.jsonl"
        raw_bytes = os.getenv(AUDIT_MAX_BYTES_ENV)
        max_bytes = _parse_max_bytes(raw_bytes)
        return cls(audit_file=audit_file, max_bytes=max_bytes)


_GLOBAL_CONFIG: AuditConfig | None = None
_CUSTOM_CONFIG: AuditConfig | None = None


def _parse_max_bytes(raw: str | None) -> int | None:
    if not raw or not raw.strip():
        return DEFAULT_MAX_AUDIT_BYTES
    try:
        parsed = int(raw)
    except ValueError:
        return DEFAULT_MAX_AUDIT_BYTES
    if parsed <= 0:
        return None
    return parsed


def set_audit_config(config: AuditConfig | None) -> None:
    """Override the audit config (used by tests)."""

    global _CUSTOM_CONFIG, _GLOBAL_CONFIG
    _CUSTOM_CONFIG = config
    _GLOBAL_CONFIG = None


def reset_audit_config() -> None:
    """Reset the audit config to the environment defaults."""

    set_audit_config(None)


def _get_audit_config() -> AuditConfig:
    global _GLOBAL_CONFIG
    if _CUSTOM_CONFIG is not None:
        return _CUSTOM_CONFIG
    if _GLOBAL_CONFIG is None:
        _GLOBAL_CONFIG = AuditConfig.from_env()
    return _GLOBAL_CONFIG


def set_audit_warning_interval(seconds: float | None) -> None:
    """Adjust the warning rate limit (tests can set to None for unlimited)."""

    global _WARNING_INTERVAL_SECONDS
    if seconds is None:
        _WARNING_INTERVAL_SECONDS = 0.0
    else:
        _WARNING_INTERVAL_SECONDS = max(seconds, 0.0)


def reset_audit_warning_state() -> None:
    """Reset warning rate-limit tracking (tests only)."""

    _LAST_WARN.clear()


def _should_warn(key: str) -> bool:
    if _WARNING_INTERVAL_SECONDS <= 0:
        return True
    now = time.monotonic()
    last = _LAST_WARN.get(key)
    if last is None or now - last >= _WARNING_INTERVAL_SECONDS:
        _LAST_WARN[key] = now
        return True
    return False


def append_audit_event(event: dict[str, object]) -> None:
    """Append a serialized audit event to the PUBLIC audit log."""

    config = _get_audit_config()
    try:
        config.audit_file.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        if _should_warn("mkdir"):
            _LOG.warning(
                "Unable to create audit directory %s: %s",
                config.audit_file.parent,
                exc,
            )
        return

    _rotate_if_needed(config)

    line = json.dumps(event, ensure_ascii=False)
    try:
        with config.audit_file.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")
    except OSError as exc:
        if _should_warn("write"):
            _LOG.warning(
                "Unable to write audit event to %s: %s", config.audit_file, exc
            )


def _rotate_if_needed(config: AuditConfig) -> None:
    if config.max_bytes is None:
        return

    path = config.audit_file
    if not path.exists():
        return

    try:
        size = path.stat().st_size
    except OSError as exc:
        if _should_warn("stat"):
            _LOG.warning("Unable to stat audit log %s: %s", path, exc)
        return

    if size < config.max_bytes:
        return

    backup = path.with_name(path.name + ".1")
    try:
        if backup.exists():
            backup.unlink()
        path.rename(backup)
    except OSError as exc:
        if _should_warn("rotate"):
            _LOG.warning("Unable to rotate audit log %s: %s", path, exc)
