"""Smoke test for the local dry-run ingestion CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _sample_payload(tmp_path: Path) -> Path:
    payload = tmp_path / "scan.xml"
    payload.write_text(
        """<nmaprun>
  <host>
    <address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>""",
        encoding="utf-8",
    )
    return payload


def test_dry_run_ingest_outputs_sanitized(tmp_path: Path) -> None:
    payload = _sample_payload(tmp_path)
    result = subprocess.run(
        [sys.executable, "scripts/dry_run_ingest.py", str(payload)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "192.0.2." not in result.stdout
    assert "<nmaprun>" not in result.stdout
    data = json.loads(result.stdout.strip())
    assert isinstance(data["summary"]["parsed"], bool)
    assert data["findings_count"] >= 0
    metadata = data.get("metadata")
    if metadata:
        caps = metadata.get("caps")
        if caps:
            assert "cap_reason" in caps
