"""Persistent storage for PUBLIC Nmap ingestion metadata."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

PROJECT_ROOT = Path(__file__).resolve().parents[3]
STATE_DIR = PROJECT_ROOT / "state" / "public"
RECORD_FILE = STATE_DIR / "nmap_ingest_records.json"

MAX_STORED_RECORDS = 16
"""Maximum number of PUBLIC ingestion records to retain."""


def _ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def _load_records() -> list[Mapping[str, Any]]:
    if not RECORD_FILE.exists():
        return []
    try:
        return json.loads(RECORD_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _save_records(records: list[Mapping[str, Any]]) -> None:
    _ensure_state_dir()
    RECORD_FILE.write_text(
        json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def persist_ingest_record(
    *,
    ingest_id: str,
    format: str,
    payload_bytes: int,
    payload_sha256: str,
    parsed: bool,
    findings_count: int,
    parser_version: str,
    next_steps: list[str],
) -> dict[str, Any]:
    """Append a new ingestion record and enforce retention."""

    record = {
        "ingest_id": ingest_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "format": format,
        "summary": {
            "payload_bytes": payload_bytes,
            "payload_sha256": payload_sha256,
            "parsed": False,
        },
        "next_steps": list(next_steps),
        "parser_version": parser_version,
        "parsed": parsed,
        "findings_count": findings_count,
    }

    records = _load_records()
    records.append(record)
    if len(records) > MAX_STORED_RECORDS:
        records = records[-MAX_STORED_RECORDS:]
    _save_records(records)
    return record


def list_ingests(limit: int | None = None) -> list[dict[str, Any]]:
    """Return newest-first ingests respecting the configured limit."""

    records = _load_records()
    newest = list(reversed(records))
    if limit is None:
        limit = MAX_STORED_RECORDS
    else:
        limit = max(min(limit, MAX_STORED_RECORDS), 0)
    limited = newest[:limit]
    return [copy.deepcopy(record) for record in limited]


def get_ingest(ingest_id: str) -> dict[str, Any] | None:
    """Retrieve a single record by ingest_id."""

    for record in _load_records():
        if record.get("ingest_id") == ingest_id:
            return copy.deepcopy(record)
    return None


def clear_records() -> None:
    """Remove any persisted ingestion records (useful for tests)."""

    if RECORD_FILE.exists():
        RECORD_FILE.unlink()
