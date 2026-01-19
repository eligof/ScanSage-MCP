# DECISIONS.md

## 2026-01-19 — Docker-first src layout bootstrap
**Context:** Kick-starting the FastMCP hybrid analyzer while honoring the constitution and layer rules.
**Decision:** Establish the src/mcp_scansage package with domain/services/adapters/mcp, add a sanitizing business rule plus FastMCP health resource, and treat Docker as the primary runtime with a simple smoke server entrypoint.
**Rationale:** Aligns with the No-Bunch rule, keeps business logic in services/domain, ensures a public-safe entrypoint, and delivers a runnable artifact for Docker CI.
**Alternatives Considered:** Keeping a single flat module or delaying Docker setup would slow validation and obscure the required layering commitments.
**Consequences:** The repo now carries the minimal runtime, tests, and gating configs; future work can extend adapters without reshaping this layout.
**Rollback:** Remove the new modules/entries, delete Docker scaffolding, and revert `pyproject.toml`/doc updates if a different bootstrap is chosen.

## 2026-01-19 — Dev tooling via PEP 621 dev extras
**Context:** Gate commands previously failed because ruff/pytest weren’t installable without an explicit dev extra.
**Decision:** Declare a `[project.optional-dependencies] dev` extra that installs ruff and pytest, document single command gates, and treat Docker builds as runtime-only (`pip install .`).
**Rationale:** Keeps tooling installable via standard pip flows, keeps runtime images lean, and surfaces a deterministic gate invocation across CI/developers.
**Alternatives Considered:** Vendoring binaries or splitting documentation by env; rejected to stay standard and align with platform constraints.
**Consequences:** Devs must install dev extras before running gates, README/Makefile reflect the workflow, and Docker builds remain unaffected.
**Rollback:** Remove the dev extra declaration, revert README/makefile guidance, and stop advertising the bundled gate command; Dockerfile already runtime-only so no rollback needed there.

## 2026-01-19 — Legacy setup.cfg packaging bootstrap
**Context:** Offline installs previously failed because pip had to download `setuptools` to honor the `[build-system]` table in `pyproject.toml`.
**Decision:** Move metadata + extras into `setup.cfg`/`setup.py` so editable installs rely on whatever setuptools ships with the platform, leaving `pyproject.toml` for tool configs only.
**Rationale:** Legacy build metadata keeps tooling installable offline while still declaring dev extras; the Docker image keeps calling `pip install .` so runtime stays clean.
**Alternatives Considered:** Shipping a wheelhouse inside the repo or vendorizing setuptools; both were rejected because they violate the “no vendor binaries” guideline and complicate maintenance.
**Consequences:** Developers must ensure the host distro provides `setuptools` and can follow the documented wheelhouse workflow when offline; future moves back to PEP 621 require rewriting the setup files.
**Rollback:** Revert to the PEP 621 `pyproject.toml` metadata, remove `setup.cfg/setup.py`, and reintroduce any build-system fields that were dropped.

## 2026-01-19 — Ensurepip + wheelhouse offline bootstrap
**Context:** Some Python distributions ship `ensurepip` without bundled `setuptools`, so offline `pip install -e ".[dev]"` still tries to download missing build deps.
**Decision:** Run `ensurepip --upgrade` + a preflight import check inside `make dev`, and provide `make wheelhouse` / `make offline-dev` so an online host can download the required wheels and offline hosts can reuse them (or install OS `python-setuptools` if ensurepip is disabled).
**Rationale:** Preflight fails fast when setuptools is missing while the wheelhouse path gives a deterministic offline install path without vendoring tooling.
**Alternatives Considered:** Relying solely on OS packages or building a locked wheel bundle for every change; rejected because they are brittle or contradict the no-vendor rule.
**Consequences:** The dev workflow now includes ensurepip, wheelhouse, and offline-install docs plus Makefile targets; offline hosts must copy `.wheels/` or install distro packages to satisfy pip/setuptools.
**Rollback:** Remove the ensurepip/wheelhouse targets and docs, and rely on OS packages plus online pip downloads as before.

## 2026-01-19 — Docker gate-runner for stripped hosts
**Context:** Host environments without setuptools block `make dev` or running gates directly, even in the wheelhouse path.
**Decision:** Provide `Dockerfile.gate` plus `make gate-image`/`make gate-docker` so gates run inside a container; the build accepts `OFFLINE_WHEELS=1` when `.wheels/` is present and installs from that wheelhouse.
**Rationale:** Containers isolate the gate tooling from the host’s missing packaging while still supporting the offline wheelhouse instructions, keeping runtime Docker artifacts untouched.
**Alternatives Considered:** Requiring every host to install OS packages or replicating wheels in the repo; rejected because they violate the workflow or no-vendoring rule.
**Consequences:** Developers can run `make gate-docker` online or offline, with the container picking the appropriate install strategy; the README and Makefile document this path.
**Rollback:** Remove `Dockerfile.gate` and the new Makefile targets, and rely solely on host tooling plus the existing wheelhouse/offline-dev instructions.

## 2026-01-19 — Preflight v2 selects the gate path
**Context:** Developers needed a deterministic way to know whether host Python, the wheelhouse, or Docker would run the contract gates.
**Decision:** Implement `preflight.py` plus `make preflight` that checks ensurepip/pip/setuptools, wheelhouse, and Docker daemon access, prints a stable set of `PREFLIGHT …` lines, recommends the best path, and supports `--require-path` for `make dev`, `make offline-dev`, and `make gate-docker`.
**Rationale:** Centralizing the path selection keeps instructions consistent, surfaces docker permission issues early, and lets building/testing scripts fail fast rather than digging through pip errors.
**Alternatives Considered:** Hardcoding logic in separate shell snippets or relying on manual inspection; rejected because they were brittle and not easily scriptable.
**Consequences:** The README, Makefile, and gate tooling lean on `preflight.py`, and the feature runs before `make dev`/`make gate-docker`. When no path is available, the script exits non-zero so the caller can bail early.
**Rollback:** Remove `preflight.py`, revert README/Makefile to the prior multi-path documentation, and let developers manually inspect `pip`/`docker` before running the gates.

## 2026-01-19 — Preflight v3 mode-aware recommendations
**Context:** Stripped Python hosts cannot satisfy the host path, Docker permissions vary wildly, and the previous preflight often emitted “Recommended path: None.”
**Decision:** Replace `preflight.py` with a mode-aware implementation that reports the venv/system context, exits per mode (`any`, `host`, `offline`, `docker`), prints either `Recommended path: …` or `Recommended next step: …` containing exact commands, and wires `make preflight`, `make dev`, and `make gate-docker` to the new modes.
**Rationale:** The deterministic exit codes allow `make` targets to fail fast when a path is unavailable, the explicit next-step commands guide stripped hosts to create `.venv`, run `ensurepip`, or fall back to the wheelhouse, and the docker checks surface permission issues without manual inspection.
**Alternatives Considered:** Keep the previous versione and rely on `--require-path`, or parse the recommendation text in shell scripts; rejected because those approaches do not offer reliable automation or a clear “next command.”
**Consequences:** Developers must run `make preflight` (which bootstraps `.venv` for them) before other targets, and the README/doc updates clarify the host/offline/docker workflows. The new unit tests guard the planner logic and `preflight.py` now acts as the single decision point.
**Rollback:** Restore the earlier `preflight.py`, revert the Makefile/README changes, and rely on the basic recommendation flow plus manual gating guidance again.

## 2026-01-19 — Dev bootstrap matrix doc
**Context:** Stripped sandboxes, offline environments, and varying Docker access make it hard to remember the exact command sequence for each gate path.
**Decision:** Add `docs/dev_bootstrap_matrix.md` (and mirror the commands in the README) so every path (host, offline wheelhouse, Docker) has a single copy/paste command plus a note explaining why it exists.
**Rationale:** A concise bootstrap matrix keeps developers aligned on how to reach the gates and documents why stripped hosts can’t run them when tooling is missing.
**Alternatives Considered:** Keeping the command mix inside README only; rejected because the matrix deserves its own reference page and supports future expansion without bloating README.
**Consequences:** The docs now house a deterministic matrix, README points to it, and new text warns that absent `ruff/pytest` makes gates impossible until tooling is bootstrapped.
**Rollback:** Remove `docs/dev_bootstrap_matrix.md` and revert the README/decisions text, returning to the older guidance that scattered commands across sections.

## YYYY-MM-DD — [Short Decision Title]
**Context:** What triggered this decision?
**Decision:** What did we choose?
**Rationale:** Why is this the best option?
**Alternatives Considered:** What else, and why rejected?
**Consequences:** What changes (good/bad) does this introduce?
**Rollback:** How to revert safely if needed?

## 2026-01-20 — Authorized lab mode defaults to `real_minimal`
**Context:** Trusted lab deployments need a smoother path to the minimal real XML parser without changing the conservative noop default for general PUBLIC exposure.
**Decision:** Introduce `SCANSAGE_AUTHORIZED_LAB`; when it evaluates truthy (`1/true/yes`) and `SCANSAGE_NMAP_XML_PARSER` is unset, `get_configured_nmap_parser()` returns `MinimalNmapXmlParser`. Explicit parser env values continue to win, and everything else defaults to `NoopNmapParser`.
**Rationale:** Lab teams can opt into safe real parsing automatically while the rest of the fleet keeps the protective noop baseline; the rule remains in services/domain so no new logic leaches into FastMCP resources.
**Alternatives Considered:** (a) Flip the default parser globally (rejected for safety), (b) add a separate feature flag that requires touching multiple config paths (too heavy), (c) leave the parser env as the only selector (requires manual updates in every lab run).
**Consequences:** The service boundary now reads two env flags when picking a parser, tests must cover the new precedence, and documentation must describe the authorized lab behavior to avoid surprise deployments.
**Rollback:** Remove `SCANSAGE_AUTHORIZED_LAB`, revert `get_configured_nmap_parser()` to the previous single-env logic, and adjust tests/backfill docs accordingly.

## 2026-01-19 — PUBLIC ingestion reason codes
**Context:** PUBLIC routes must report why requests fail without echoing identifiers, and we need a reusable reason taxonomy for the new Nmap ingestion tool.
**Decision:** Introduce `mcp/reason_codes.py` with universal strings (`payload_too_large`, `invalid_input`, `response_validation_failed`) and consume them in the public FastMCP resource.
**Rationale:** Having explicit reason codes keeps audits consistent, satisfies Layer Fidelity/No-Bunch by centralizing the rule, and lets the resource safely sanitize messages while still conveying actionable signals.
**Alternatives Considered:** Hardcode reasons locally in the resource or skip reason codes; rejected because both approaches leak business logic into the routing layer or reduce observability and violate the constitution.
**Consequences:** Error handling paths now return sanitized responses with stable reason strings; new module becomes part of the public ingestion surface.
**Rollback:** Remove the reason code module and resource wiring, revert tests/schema changes, and drop the new FastMCP entry.

## 2026-01-19 — PUBLIC ingestion persistence
**Context:** Slice 2 must persist PUBLIC ingest metadata without ever storing raw payloads while still presenting safe list/get resources within FastMCP.
**Decision:** Add `services/nmap_ingest_store.py` backed by `state/public/nmap_ingest_records.json`, retain only `MAX_STORED_RECORDS` newest entries, and expose `public://nmap/ingests` + `public://nmap/ingest/{ingest_id}` resources that validate list/get schemas and return sanitized errors for missing records.
**Rationale:** Keeping ingestion metadata local but retrievable satisfies the PUBLIC contract, follows Layer Fidelity by isolating persistence logic in services, and avoids No-Bunch leaks by applying universal retention trims and sanitized errors.
**Alternatives Considered:** Store records purely in memory (hard to inspect across calls) or persist payloads (unsafe); both were rejected.
**Consequences:** FastMCP now surfaces list/get tooling and tests must cover retention and sanitize not-found paths; `state/public/.gitkeep` plus `.gitignore` guard the data file.
**Rollback:** Remove the persistence service, delete the new schema/examples/tests, and revert the server registry to its prior state.

## 2026-01-19 — PUBLIC parser seam v0.1
**Context:** We need a parsing seam so future slices can plug actual XML parsing without altering the PUBLIC contract or exposing raw identifiers.
**Decision:** Introduce `services/nmap_parser.py` with a parser protocol/`ParsedNmapResult`, provide a no-op default parser (`noop-0.1`), upgrade the public response to schema v0.2 (including parser metadata + parsed findings), and extend stored records with parser metadata/retention data without persisting raw XML.
**Rationale:** The parser interface keeps Layer Fidelity by placing parsing responsibilities in services; the schema bump ensures new metadata and findings placeholders remain PUBLIC-safe, and the store still binds to `state/public` with sanitized reason codes.
**Alternatives Considered:** Keep response at v0.1 and add fields outside schema (rejected since it breaks contract) or implement parsing now (forbidden), so a schema v0.2 + parser seam is the least disruptive option.
**Consequences:** New parser/schema/tests ensure parsed metadata is tracked but empty; `nmap_parsed_findings` now has its own schema while the list/get records include parser_version, parsed, and findings_count metadata.
**Rollback:** Remove the parser module, revert to schema v0.1 (plus earlier responses), drop the new schema/examples/tests, and keep store records before metadata expansion.

## 2026-01-19 — Synthetic parser v0.1
**Context:** Slice 4 must validate the parser seam end-to-end using a synthetic, PUBLIC-safe input format while leaving real Nmap parsing for future work.
**Decision:** Add `SyntheticNmapParser` (accepting `synthetic_v1` format) that emits placeholder findings, drops lines containing identifier-like tokens, and raises sanitized errors on malformed rows; extend the input schema to v0.2 to cover the new format + parser flag while keeping v0.1 live.
**Rationale:** This lets us test parsed metadata, retention, and anti-hack guards without tackling actual Nmap XML, keeps business logic out of routing (server still orchestrates validation/selection), and ensures sanitized errors/outputs never echo identifiers.
**Alternatives Considered:** Hardcode synthetic parsing logic directly in the resource (violates Layer Fidelity) or expand the Noop parser (would not exercise parsed fields); both were rejected.
**Consequences:** PUBLIC ingestion now supports synthetic payloads via the new schema and parser, with associated contract/anti-hack tests; any malformed synthetic payload yields sanitized errors with stable reason codes.
**Rollback:** Drop the synthetic parser/schema, revert the input schema to v0.1, and keep `SyntheticNmapParser` references (and tests) removed.

## 2026-01-19 — Make nmap_ingest_public_response_schema_v0.2 self-contained
**Context:** jsonschema attempted a remote fetch because the PUBLIC response schema referenced external files; deterministic, offline validation must avoid any network-dependent `$ref`.
**Decision:** Keep `nmap_ingest_public_response_schema_v0.2.json` self-contained by moving every `$defs` reference into the schema itself so every `$ref` resolves locally without hitting an external resolver.
**Rationale:** Local `$defs` keep validation reliable with no network, avoid security risks from arbitrary downloads, stabilize CI/tests, and reduce fragility during every gate run.
**Alternatives Considered:** (a) retain the remote `$ref` hierarchy and rely on schema resolution over the network, (b) vendor or bundle dependent schemas via a build step and feed them through the resolver, (c) author a custom resolver that caps remote loads and handles the PUBLIC contract manually.
**Consequences:** Validation can run entirely offline with fewer moving parts; keeping the `$defs` aligned with the response schema requires discipline, which `tests/test_schema_examples.py` guards against.
**Rollback:** Restore the external references, reintroduce bundling or resolver logic, and update the schema tests to reflect the new resolution strategy.

## 2026-01-21 — PUBLIC ingestion caps + deterministic metadata
**Context:** PUBLIC Nmap ingestion must tolerate noisy/oversized XML while returning reproducible outputs so downstream contracts never chase incidental ordering or invalid env inputs.
**Decision:** Centralize `SCANSAGE_MAX_*` parsing inside `services/nmap_limits.py`, enforce those caps across both parser and ingest helpers, sort findings with a stable key before truncation, expose the deterministic `metadata.caps` block, and keep persisted summaries’ `parsed` flag forced to `False` while letting the top-level response signal the actual parse state.
**Rationale:** Sharing a single limit helper prevents divergent env behavior, stable sorting guarantees identical truncated findings/metadata on repeated runs, and the persistence nuance preserves the existing schema while still exposing truthful parsed flags where clients expect them.
**Alternatives Considered:** 1) Skip the caps metadata and limit visibility (rejected because it leaves clients blind to truncation and non-deterministic); 2) Allow persisted summaries to flip `parsed` (rejected because it would violate the current get/list schema); 3) Keep environment parsing scattered in each service (rejected because it would make invalid values crash or diverge from parser usage).
**Consequences:** All new tests/docs must reflect deterministic truncation, env fallbacks, and the persistence behavior; future slices need to honor `metadata.caps` and the `services/nmap_limits.py` contract.
**Rollback:** Revert to the previous parser/ingest implementations, drop the metadata block plus `nmap_limits.py`, and accept that repeated ingests may produce non-deterministic caps while persisted summaries always claim `parsed=False`.
