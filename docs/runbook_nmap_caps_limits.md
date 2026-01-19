# PUBLIC Nmap Caps Runbook

Purpose: explain how to configure and interpret the ingest caps without reading the services code.

## Configuring caps

| Env var | Default | Behavior |
| --- | --- | --- |
| `SCANSAGE_MAX_NMAP_XML_BYTES` | `32768` | Payload bytes allowed before denial. Blank/non-numeric/negative returns the default. |
| `SCANSAGE_MAX_NMAP_HOSTS` | `64` | Max hosts processed when parsing XML. Invalid values default back to `64`. |
| `SCANSAGE_MAX_NMAP_PORTS_PER_HOST` | `128` | Limits ports scanned per host. Invalid inputs revert to `128`. |
| `SCANSAGE_MAX_NMAP_FINDINGS` | `100` | Caps synthesized findings before truncation. Blank/non-numeric/negative falls back to `100`. |

All caps share the same helper in `services/nmap_limits.py`, so the parser and ingestion layers always read and clamp the same values. There is no runtime fallback other than the defaults listed above; supplying a malformed value simply causes the parser/ingest to act as if the env var was unset.

## Interpreting responses

* `metadata.caps` appears only when a cap triggers. Its structure:
  * `capped`: `true`.
  * `cap_reason`: one of `MAX_HOSTS`, `MAX_PORTS`, `MAX_FINDINGS`.
  * `limits`: the three configured caps (hosts, ports per host, findings).
  * `counts`: how many hosts/ports/findings were processed.
* Findings are deterministically ordered by host/port before truncation, so repeated ingests of the same XML yield identical `parsed_findings` and metadata.
* Internal helpers such as `_sort_key` never surface in PUBLIC payloads; regression tests guard against accidental leaks.

## Persistence nuance

Persistent records live under `state/public` and expose `public://nmap/ingest/{ingest_id}`.

* The persisted `summary.parsed` field is always `false` (schema requirement) even when the parser actually parsed findings. The truth about parsing lives at the top level of the PUBLIC ingest response (`"summary": { "parsed": <actual bool> }`).
* This keeps list/get contracts stable while still letting consumers know when parsing succeeded.

## Anti-hack reminder

All textual fields (titles/details/errors) go through identifier redaction, so even when caps trigger, no IP/MAC/hostname fragments ever escape into PUBLIC responses or persisted records.

Keep this runbook updated if new caps or metadata fields are introduced.

## Local dry-run helper

Use `scripts/dry_run_ingest.py <xml_file>` (run from the repository root) to validate how a payload interacts with the caps without writing ingestion records. It prints the sanitized `summary` + `metadata` (caps) JSON that matches PUBLIC outputs, so operators can double-check cap behavior safely; nothing is shipped, stored, or published.
