#!/usr/bin/env python3
"""
Heuristic "Forbidden Patterns" checker for AI_CONTRACT.md.

What it flags (best-effort):
- Special-case business logic conditionals on string/IDs (No-Bunch style)
- Broad exception swallowing ("except: pass")

This is intentionally conservative and configurable;
treat findings as prompts for review.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[1]

# Adjust/extend patterns as your repo evolves.
PATTERNS: List[Tuple[str, re.Pattern]] = [
    (
        "NO_BUNCH_STRING_EQ",
        re.compile(r"\bif\s+.+==\s*['\"][^'\"]+['\"]\s*:", re.IGNORECASE),
    ),
    (
        "NO_BUNCH_IN_LIST",
        re.compile(r"\bif\s+['\"][^'\"]+['\"]\s+in\s+\w+\s*:", re.IGNORECASE),
    ),
    ("SILENT_EXCEPT_PASS", re.compile(r"\bexcept\b\s*:\s*\n\s*pass\b", re.IGNORECASE)),
]

IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
}
IGNORE_FILES = {"preflight.py", "tools/forbidden_patterns_check.py"}
INCLUDE_SUFFIXES = {".py"}


def iter_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        parts = set(p.parts)
        if any(d in parts for d in IGNORE_DIRS):
            continue
        if p.name in IGNORE_FILES:
            continue
        if p.suffix in INCLUDE_SUFFIXES:
            yield p


def main() -> int:
    findings: List[str] = []
    for f in iter_files(ROOT):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for name, rx in PATTERNS:
            for m in rx.finditer(text):
                snippet = text[m.start() : m.end()]
                if "__name__" in snippet:
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                findings.append(f"{name}: {f.relative_to(ROOT)}:{line_no}")
    if findings:
        sys.stdout.write("FORBIDDEN PATTERN CHECK: FOUND POTENTIAL ISSUES\n")
        for item in findings:
            sys.stdout.write(f"- {item}\n")
        sys.stdout.write(
            "\nNote: This is heuristic. Review each finding "
            "and refactor if it violates AI_CONTRACT.md.\n"
        )
        return 2
    sys.stdout.write("FORBIDDEN PATTERN CHECK: OK (no findings)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
