from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any, Dict, Iterable, Optional


def utc_now_rfc3339() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_json_dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_targets_hash(targets: Iterable[Dict[str, Any]]) -> str:
    # Canonicalize by stable ordering of dicts as JSON strings.
    items = sorted(stable_json_dumps(t) for t in targets)
    return sha256_hex(("\n".join(items)).encode("utf-8"))


def days_ago_rfc3339(days: int, now: Optional[dt.datetime] = None) -> str:
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    t = now - dt.timedelta(days=days)
    return t.replace(microsecond=0).isoformat().replace("+00:00", "Z")

