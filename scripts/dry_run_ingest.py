"""LOCAL-only CLI to dry-run PUBLIC Nmap ingestion without persistence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "src"))

MINIMAL_PARSER_KEY = "minimal_xml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dry-run an Nmap XML ingestion without persistence.",
    )
    parser.add_argument(
        "xml_path",
        type=Path,
        help="Path to the Nmap XML payload to evaluate locally.",
    )
    parser.add_argument(
        "--parser",
        choices=[MINIMAL_PARSER_KEY],
        default=MINIMAL_PARSER_KEY,
        help="Parser implementation to use when evaluating caps.",
    )
    return parser.parse_args()


def load_payload(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def build_parser(name: str):
    if name == MINIMAL_PARSER_KEY:
        from mcp_scansage.services.nmap_parser import MinimalNmapXmlParser

        return MinimalNmapXmlParser()
    return None


def main() -> None:
    args = parse_args()
    payload = load_payload(args.xml_path)
    parser = build_parser(args.parser)

    from mcp_scansage.services.nmap_ingest import ingest_nmap_public

    response = ingest_nmap_public(
        format="nmap_xml",
        payload=payload,
        parser=parser,
        persist_record=False,
    )

    summary: dict[str, object] = {
        "summary": response["summary"],
        "findings_count": response.get("findings_count", 0),
    }
    if metadata := response.get("metadata"):
        summary["metadata"] = metadata

    sys.stdout.write(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
