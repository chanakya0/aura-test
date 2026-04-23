## Spec bundle: Vendor-neutral Asset Discovery ELT

This directory is the **single source of truth** for behavior and interfaces of the asset discovery ELT system.

- **Start here**: `specs/catalog.json`
- **Top-level requirements**: `specs/spec.yaml`
- **JSON Schemas**: `specs/schemas/*.schema.json`
- **Entity resolution / dedup**: `specs/dedup/rules.yaml`
- **Agentic/pipeline contracts**: `specs/pipeline/contract.yaml` (and `specs/schemas/pipeline-event.schema.json`)

### Versioning rules
- Each artifact carries a `version` (YAML) or `schema_version` (JSON payloads) and is intended to evolve with **backward-compatible** changes whenever possible.
- Producers and consumers must treat these artifacts as authoritative; implementation must conform to them.
