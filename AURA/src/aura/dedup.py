from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


def _stable_hash(parts: Iterable[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()[:32]


def _normalize_str(s: str, ops: List[str]) -> str:
    out = s
    for op in ops:
        if op == "trim":
            out = out.strip()
        elif op == "lowercase":
            out = out.lower()
    return out


def _extract_values(observation: Dict[str, Any], field: str) -> List[str]:
    # Minimal field extractor for the specific patterns used in `specs/dedup/rules.yaml`.
    # Supports:
    # - subject.addresses[*].mac
    # - subject.addresses[*].ip
    # - subject.names[*]
    if field == "subject.names[*]":
        return [str(x) for x in observation.get("subject", {}).get("names", []) if x]
    if field == "subject.addresses[*].ip":
        return [str(a.get("ip")) for a in observation.get("subject", {}).get("addresses", []) if a.get("ip")]
    if field == "subject.addresses[*].mac":
        return [str(a.get("mac")) for a in observation.get("subject", {}).get("addresses", []) if a.get("mac")]
    return []


@dataclass(frozen=True)
class IdentityMatch:
    key_class: str
    value: str


def compute_identity_matches(dedup_rules: Dict[str, Any], observation: Dict[str, Any]) -> List[IdentityMatch]:
    matches: List[IdentityMatch] = []
    for kc in dedup_rules.get("identity_key_classes", []):
        kc_id = kc["id"]
        any_of = kc.get("match", {}).get("any_of", [])
        for clause in any_of:
            field = clause["field"]
            ops = clause.get("normalize", [])
            for v in _extract_values(observation, field):
                nv = _normalize_str(v, ops)
                if nv:
                    matches.append(IdentityMatch(key_class=kc_id, value=nv))
    # Deterministic ordering
    matches.sort(key=lambda m: (m.key_class, m.value))
    return matches


def choose_primary_key_class(dedup_rules: Dict[str, Any], matches: List[IdentityMatch]) -> Optional[IdentityMatch]:
    precedence = dedup_rules.get("merge_policy", {}).get("primary_key_precedence", [])
    by_class: Dict[str, List[IdentityMatch]] = {}
    for m in matches:
        by_class.setdefault(m.key_class, []).append(m)
    for kc in precedence:
        vals = by_class.get(kc)
        if vals:
            # deterministically pick smallest value if multiple
            return sorted(vals, key=lambda x: x.value)[0]
    return None


def compute_asset_id(dedup_rules: Dict[str, Any], tenant_ref: str, zone_ref: str, primary: IdentityMatch) -> str:
    # Follow `asset_id_strategy.type: stable_hash` inputs in rules.yaml
    if primary.key_class == "mac_address":
        parts = [tenant_ref, zone_ref, f"mac:{primary.value}"]
    elif primary.key_class == "ip_address":
        parts = [tenant_ref, zone_ref, f"ip:{primary.value}"]
    else:
        parts = [tenant_ref, zone_ref, f"host:{primary.value}"]
    return _stable_hash(parts)


def merge_asset(current: Optional[Dict[str, Any]], new_obs: Dict[str, Any], now: str, precedence: List[str]) -> Dict[str, Any]:
    """
    Minimal deterministic merge:
    - Union names/addresses/services
    - last_seen := max(last_seen, now)
    - first_seen := min(first_seen, now) if unset
    - evidence append
    """
    if current is None:
        current = {}

    asset = dict(current)
    asset.setdefault("identity", {"names": [], "addresses": []})
    asset.setdefault("services", [])
    asset.setdefault("attributes", {})
    asset.setdefault("labels", {})
    asset.setdefault("evidence", [])
    asset.setdefault("resolution", {"strategy": "deterministic_rules"})
    asset["resolution"]["precedence"] = precedence

    # Times
    asset["first_seen"] = min(asset.get("first_seen", now), now)
    asset["last_seen"] = max(asset.get("last_seen", now), now)

    # Identity names
    for name in new_obs.get("subject", {}).get("names", []) or []:
        if not name:
            continue
        item = {
            "kind": "hostname",
            "value": name,
            "first_seen": now,
            "last_seen": now,
            "confidence": 0.5,
            "confidence_class": "low",
        }
        if item not in asset["identity"]["names"]:
            asset["identity"]["names"].append(item)

    # Addresses
    for addr in new_obs.get("subject", {}).get("addresses", []) or []:
        if not addr.get("ip"):
            continue
        item = {
            "ip": addr["ip"],
            "mac": addr.get("mac"),
            "first_seen": now,
            "last_seen": now,
            "confidence": 0.7,
            "confidence_class": "medium",
            "source_hints": [],
        }
        if item not in asset["identity"]["addresses"]:
            asset["identity"]["addresses"].append(item)

    # Services
    for svc in new_obs.get("services", []) or []:
        if "protocol" not in svc or "port" not in svc:
            continue
        item = {
            "protocol": svc["protocol"],
            "port": svc["port"],
            "states": [svc.get("state", "unknown")],
            "service_name": svc.get("service_name"),
            "product": svc.get("product"),
            "version": svc.get("version"),
            "cpe": svc.get("cpe", []),
            "first_seen": now,
            "last_seen": now,
            "evidence": [],
        }
        if item not in asset["services"]:
            asset["services"].append(item)

    # Evidence
    ev = {
        "run_id": new_obs["run_id"],
        "shard_id": new_obs.get("shard_id"),
        "observation_id": new_obs["observation_id"],
        "observed_at": new_obs["observed_at"],
        "raw_uri": new_obs.get("evidence", {}).get("raw_uri"),
    }
    if ev not in asset["evidence"]:
        asset["evidence"].append(ev)

    # Lifecycle: evidence freshness (spec requires). Constant is specified by dedup ruleset (v1.0.0 => 30 days).
    asset.setdefault("lifecycle", {})
    asset["lifecycle"]["evidence_freshness_days"] = 30
    asset["lifecycle"]["staleness_state"] = "fresh"

    # Active derived (minimal: true if fresh)
    asset["active"] = True

    return asset


def compute_change_event(asset_id: str, tenant_ref: str, zone_ref: str, run_id: str, observed_at: str, prior: Optional[Dict[str, Any]], current: Dict[str, Any]) -> Dict[str, Any]:
    # Minimal diff: treat as created if prior missing, else updated without field-level enumeration.
    change_type = "created" if prior is None else "updated"
    diff = {
        "format": "field_list",
        "changes": [{"path": "/", "op": "add" if prior is None else "replace", "from": prior, "to": current, "semantic_type": "other"}],
    }
    return {
        "schema_version": "1.0.0",
        "change_id": _stable_hash([tenant_ref, zone_ref, asset_id, run_id, observed_at]),
        "tenant_ref": tenant_ref,
        "zone_ref": zone_ref,
        "asset_id": asset_id,
        "run_id": run_id,
        "observed_at": observed_at,
        "change_type": change_type,
        "diff": diff,
        "evidence": current.get("evidence", [])[:1] or [],
    }

