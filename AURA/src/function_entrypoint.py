from __future__ import annotations

import json
from typing import Any, Dict

from aura.config import Config
from aura.specs import load_spec_bundle
from main import stage_entity_resolve_merge, stage_normalize_validate, stage_orchestrate, stage_scan_shard


def aura_http(request):  # Cloud Functions / Cloud Run functions-framework style
    """
    Minimal HTTP entrypoint (single endpoint) with explicit stage selection.

    Request JSON:
      { "stage": "<stage>", "payload": { ... } }
    """
    cfg = Config()
    bundle = load_spec_bundle(cfg.specs_dir)
    if not bundle.frozen:
        return ("Spec bundle must be frozen", 500)

    body: Dict[str, Any] = request.get_json(silent=True) or {}
    stage = body.get("stage")
    payload = body.get("payload") or {}
    if stage not in {"orchestrate", "scan_shard", "normalize_validate", "entity_resolve_merge"}:
        return ("Invalid stage", 400)

    try:
        if stage == "orchestrate":
            out = stage_orchestrate(cfg, bundle, payload)
        elif stage == "scan_shard":
            out = stage_scan_shard(cfg, bundle, payload)
        elif stage == "normalize_validate":
            out = stage_normalize_validate(cfg, bundle, payload)
        else:
            out = stage_entity_resolve_merge(cfg, bundle, payload)
        return (json.dumps(out), 200, {"Content-Type": "application/json"})
    except Exception as e:
        return (json.dumps({"error": str(e)}), 500, {"Content-Type": "application/json"})

