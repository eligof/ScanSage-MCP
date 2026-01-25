"""Utility to surface shared JSON schemas and examples."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft7Validator, ValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_DIR = PROJECT_ROOT / "schemas"
EXAMPLE_DIR = SCHEMA_DIR / "examples"

SchemaValidationError = ValidationError
"""Alias for jsonschema.ValidationError.
Keeps callers unaware of the implementation.
"""

SCHEMA_FILES = {
    "nmap_ingest_input_v0.1": "nmap_ingest_input_schema_v0.1.json",
    "nmap_ingest_public_response_v0.1": "nmap_ingest_public_response_schema_v0.1.json",
    "nmap_ingest_public_response_v0.2": "nmap_ingest_public_response_schema_v0.2.json",
    "nmap_parsed_findings_v0.1": "nmap_parsed_findings_schema_v0.1.json",
    "nmap_ingest_input_v0.2": "nmap_ingest_input_schema_v0.2.json",
    "nmap_ingests_list_response_v0.1": "nmap_ingests_list_response_schema_v0.1.json",
    "nmap_ingest_get_response_v0.1": "nmap_ingest_get_response_schema_v0.1.json",
    "nmap_ingest_nmap_xml_input_v0.1": "nmap_ingest_nmap_xml_input_schema_v0.1.json",
}

EXAMPLE_FILES = {
    "nmap_ingest_input_example_min": "nmap_ingest_input_example_min.json",
    "nmap_ingest_public_response_example_min": (
        "nmap_ingest_public_response_example_min.json"
    ),
    "nmap_ingests_list_response_example_min": (
        "nmap_ingests_list_response_example_min.json"
    ),
    "nmap_ingest_get_response_example_min": (
        "nmap_ingest_get_response_example_min.json"
    ),
    "nmap_ingest_public_response_example_v0.2": (
        "nmap_ingest_public_response_example_v0.2.json"
    ),
    "nmap_parsed_findings_example_min": "nmap_parsed_findings_example_min.json",
    "nmap_ingest_input_example_v0.2": "nmap_ingest_input_example_v0.2.json",
    "nmap_ingest_nmap_xml_input_example_min": (
        "nmap_ingest_nmap_xml_input_example_min.json"
    ),
}

_SCHEMAS: dict[str, Mapping[str, Any]] = {}
_EXAMPLES: dict[str, Mapping[str, Any]] = {}


def _load_json_file(path: Path) -> Mapping[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _schema_path(name: str) -> Path:
    filename = SCHEMA_FILES[name]
    return SCHEMA_DIR / filename


def _example_path(name: str) -> Path:
    filename = EXAMPLE_FILES[name]
    return EXAMPLE_DIR / filename


def get_schema(name: str) -> Mapping[str, Any]:
    """Return the JSON schema with the given registry name."""

    if name not in _SCHEMAS:
        _SCHEMAS[name] = _load_json_file(_schema_path(name))
    return _SCHEMAS[name]


def get_example(name: str) -> Mapping[str, Any]:
    """Return a representative example payload by name."""

    if name not in _EXAMPLES:
        _EXAMPLES[name] = _load_json_file(_example_path(name))
    return _EXAMPLES[name]


def validate(name: str, instance: Any) -> None:
    """Validate an instance against a named schema."""

    schema = get_schema(name)
    Draft7Validator(schema).validate(instance)
