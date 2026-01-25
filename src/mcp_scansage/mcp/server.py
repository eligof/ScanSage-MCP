"""Minimal FastMCP server entrypoint for ScanSage."""

from __future__ import annotations

import sys
from typing import Any, Mapping

from ..services import nmap_ingest_store
from ..services.nmap_ingest import (
    NMAP_XML_FORMAT,
    PayloadTooLargeError,
    ingest_nmap_public,
)
from ..services.nmap_parser import SyntheticNmapParser
from ..services.sanitizer import sanitize_public_response
from . import reason_codes, schema_registry
from .schema_registry import SchemaValidationError

INPUT_SCHEMA = "nmap_ingest_input_v0.1"
SYNTHETIC_FORMAT = "synthetic_v1"
NMAP_XML_ALIAS_INPUT_SCHEMA = "nmap_ingest_nmap_xml_input_v0.1"
PUBLIC_RESPONSE_SCHEMA = "nmap_ingest_public_response_v0.2"
LIST_RESPONSE_SCHEMA = "nmap_ingests_list_response_v0.1"
GET_RESPONSE_SCHEMA = "nmap_ingest_get_response_v0.1"

FORMAT_SCHEMAS = {
    NMAP_XML_FORMAT: "nmap_ingest_input_v0.1",
    SYNTHETIC_FORMAT: "nmap_ingest_input_v0.2",
}


def _sanitized_error(reason: str, detail: str) -> dict[str, str]:
    """Return a sanitized error payload with a stable reason code."""

    payload = {"status": "error", "reason": reason, "detail": detail}
    return sanitize_public_response(payload)


class HealthResource:
    """Simple wellbeing resource returning sanitized payloads."""

    __slots__ = ()

    def get_status(self) -> Mapping[str, str]:
        """Return a public-safe status digest."""

        raw_payload = {
            "status": "ok",
            "detail": "ScanSage MCP FastMCP server ready",
        }
        return sanitize_public_response(raw_payload)

    def __call__(self) -> Mapping[str, str]:
        """Mimic callable resources in FastMCP registries."""

        return self.get_status()


class NmapIngestResource:
    """PUBLIC entrypoint that validates Nmap ingestion payloads."""

    __slots__ = ()

    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.ingest(request)

    def get_status(self) -> Mapping[str, str]:
        """Expose a sanitized status for diagnostic tooling."""

        payload = {
            "status": "ok",
            "detail": "PUBLIC nmap ingestion resource ready",
        }
        return sanitize_public_response(payload)

    def ingest(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        report_format = request["format"]
        schema_name = FORMAT_SCHEMAS.get(report_format)
        if schema_name is None:
            return _sanitized_error(
                reason_codes.INVALID_INPUT, "Request format is not supported."
            )

        try:
            schema_registry.validate(schema_name, request)
        except SchemaValidationError:
            return _sanitized_error(
                reason_codes.INVALID_INPUT, "Request failed validation."
            )

        payload = request["payload"]
        meta = request.get("meta") or {}
        parser = None
        if report_format == SYNTHETIC_FORMAT:
            parser_hint = meta.get("parser")
            if parser_hint != SYNTHETIC_FORMAT:
                return _sanitized_error(
                    reason_codes.INVALID_INPUT,
                    "Synthetic parser requires explicit parser flag.",
                )
            parser = SyntheticNmapParser()

        try:
            response = ingest_nmap_public(report_format, payload, meta, parser=parser)
        except PayloadTooLargeError:
            return _sanitized_error(
                reason_codes.PAYLOAD_TOO_LARGE,
                "Payload exceeds the allowed size.",
            )
        except ValueError:
            return _sanitized_error(
                reason_codes.INVALID_INPUT,
                "Unable to process the ingestion payload.",
            )

        try:
            schema_registry.validate(PUBLIC_RESPONSE_SCHEMA, response)
        except SchemaValidationError:
            return _sanitized_error(
                reason_codes.RESPONSE_VALIDATION_FAILED,
                "Service output did not meet the public contract.",
            )

        return response


class IngestNmapXmlResource:
    """Alias entrypoint for Nmap XML ingestion.

    Accepts the same payload/meta as the PUBLIC ingest resource but does not
    require callers to supply the format selector.
    """

    __slots__ = ()

    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.ingest(request)

    def get_status(self) -> Mapping[str, str]:
        payload = {
            "status": "ok",
            "detail": "ingest_nmap_xml alias resource ready",
        }
        return sanitize_public_response(payload)

    def ingest(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            schema_registry.validate(NMAP_XML_ALIAS_INPUT_SCHEMA, request)
        except SchemaValidationError:
            return _sanitized_error(
                reason_codes.INVALID_INPUT, "Request failed validation."
            )

        mapped_request = {
            "format": NMAP_XML_FORMAT,
            "payload": request.get("payload"),
            "meta": request.get("meta") or {},
        }
        return NmapIngestResource().ingest(mapped_request)


class NmapIngestsListResource:
    """PUBLIC resource that lists stored Nmap ingestion records."""

    __slots__ = ()

    def __call__(self, request: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        limit = self._normalize_limit(request)
        ingests = nmap_ingest_store.list_ingests(limit=limit)
        response = {
            "operation": "nmap_ingests_list",
            "count": len(ingests),
            "max_records": nmap_ingest_store.MAX_STORED_RECORDS,
            "ingests": ingests,
        }

        try:
            schema_registry.validate(LIST_RESPONSE_SCHEMA, response)
        except SchemaValidationError:
            return _sanitized_error(
                reason_codes.RESPONSE_VALIDATION_FAILED,
                "List response violated the public contract.",
            )

        return response

    @staticmethod
    def _normalize_limit(
        request: Mapping[str, Any] | None,
    ) -> int | None:
        if not request:
            return None
        limit = request.get("limit")
        if limit is None:
            return None
        try:
            return int(limit)
        except (TypeError, ValueError):
            return None


class NmapIngestGetResource:
    """PUBLIC resource returning a single stored ingestion metadata record."""

    __slots__ = ()

    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        ingest_id = request.get("ingest_id")
        if not ingest_id or not isinstance(ingest_id, str):
            return _sanitized_error(
                reason_codes.INVALID_INPUT,
                "An ingest_id is required for PUBLIC retrieval.",
            )

        record = nmap_ingest_store.get_ingest(ingest_id)
        if record is None:
            return _sanitized_error(
                reason_codes.RECORD_NOT_FOUND,
                "The requested ingestion record could not be located.",
            )

        response = {"operation": "nmap_ingest_get", "ingest": record}

        try:
            schema_registry.validate(GET_RESPONSE_SCHEMA, response)
        except SchemaValidationError:
            return _sanitized_error(
                reason_codes.RESPONSE_VALIDATION_FAILED,
                "Get response violated the public contract.",
            )

        return response


RESOURCE_REGISTRY = {
    "health": HealthResource(),
    "public://nmap/ingest": NmapIngestResource(),
    "ingest_nmap_xml": IngestNmapXmlResource(),
    "public://nmap/ingests": NmapIngestsListResource(),
    "public://nmap/ingest/{ingest_id}": NmapIngestGetResource(),
}
"""Resource registry for FastMCP tooling."""


def create_server() -> Mapping[str, Mapping[str, str]]:
    """Return the configured resources for this FastMCP server."""

    return {"resources": RESOURCE_REGISTRY}


def main() -> None:
    """Log available resources without launching networking."""

    sys.stdout.write("FastMCP ScanSage server initialized with resources:\n\n")
    for name, resource in RESOURCE_REGISTRY.items():
        sys.stdout.write(f"- {name}: {resource.get_status()}\n")


if __name__ == "__main__":
    main()
