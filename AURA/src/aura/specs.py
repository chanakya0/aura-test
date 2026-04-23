from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import yaml
from jsonschema import Draft202012Validator


@dataclass(frozen=True)
class SpecBundle:
    specs_dir: Path
    catalog: Dict[str, Any]
    spec_yaml: Dict[str, Any]
    schemas: Dict[str, Dict[str, Any]]
    dedup_rules: Dict[str, Any]
    pipeline_contract: Dict[str, Any]

    @property
    def frozen(self) -> bool:
        return bool(self.catalog.get("frozen")) and bool(self.spec_yaml.get("spec_set", {}).get("frozen"))

    def validator(self, schema_id: str) -> Draft202012Validator:
        schema = self.schemas[schema_id]
        return Draft202012Validator(schema)


def _read_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def _read_yaml(p: Path) -> Dict[str, Any]:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def load_spec_bundle(specs_dir: str) -> SpecBundle:
    base = Path(specs_dir)
    catalog = _read_json(base / "catalog.json")
    spec_yaml = _read_yaml(base / "spec.yaml")
    dedup_rules = _read_yaml(base / "dedup" / "rules.yaml")
    pipeline_contract = _read_yaml(base / "pipeline" / "contract.yaml")

    schemas: Dict[str, Dict[str, Any]] = {}
    for artifact in catalog.get("artifacts", []):
        if artifact.get("kind") != "json_schema":
            continue
        schema_id = artifact["id"]
        rel_path = artifact["path"]
        # catalog paths are relative to repo root; spec bundle is rooted at specs_dir
        # so we strip leading "specs/" if present.
        rel = Path(rel_path)
        if rel.parts and rel.parts[0] == "specs":
            rel = Path(*rel.parts[1:])
        schemas[schema_id] = _read_json(base / rel)

    return SpecBundle(
        specs_dir=base,
        catalog=catalog,
        spec_yaml=spec_yaml,
        schemas=schemas,
        dedup_rules=dedup_rules,
        pipeline_contract=pipeline_contract,
    )

