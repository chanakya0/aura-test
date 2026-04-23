from __future__ import annotations

import argparse
import json
import os
import subprocess
import datetime as dt
from typing import Any, Dict, List, Optional

import ulid
from google.cloud import logging as cloud_logging

from aura.config import Config
from aura.specs import load_spec_bundle
from aura.util import sha256_hex, stable_targets_hash, utc_now_rfc3339
from aura import bq as aura_bq
from aura import gcs as aura_gcs
from aura.dedup import (
    choose_primary_key_class,
    compute_asset_id,
    compute_change_event,
    compute_identity_matches,
    merge_asset,
)


def _init_logging() -> None:
    try:
        cloud_logging.Client().setup_logging()
    except Exception:
        pass


def _tables(cfg: Config) -> aura_bq.BQTables:
    return aura_bq.BQTables(
        project=cfg.bq_project,
        dataset=cfg.bq_dataset,
        raw_runs=cfg.bq_table_raw_runs,
        raw_observations=cfg.bq_table_raw_observations,
        assets_current=cfg.bq_table_assets_current,
        assets_history=cfg.bq_table_assets_history,
        asset_changes=cfg.bq_table_asset_changes,
        quarantine=cfg.bq_table_quarantine,
    )


def stage_orchestrate(cfg: Config, bundle, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal orchestrator:
    - Validates payload into a run manifest (per schema)
    - Writes run manifest to BigQuery raw_runs and to GCS (optional)
    - Returns run_manifest

    Periodicity is intentionally out-of-scope (no extra components); call this on a schedule externally.
    """
    cfg.require()
    run_id = payload.get("run_id") or str(ulid.new())
    started_at = payload.get("started_at") or utc_now_rfc3339()

    tenant_ref = payload.get("tenant_ref", "default")
    zone_ref = payload.get("zone_ref", "default")

    targets = payload["target_set"]["targets"]
    targets_hash = payload["target_set"].get("targets_hash") or stable_targets_hash(targets)

    run_manifest = {
        "schema_version": "1.0.0",
        "run_id": run_id,
        "tenant_ref": tenant_ref,
        "zone_ref": zone_ref,
        "trigger": payload.get("trigger", {"type": "adhoc"}),
        "target_set": {"targets_hash": targets_hash, "targets": targets},
        "scan_profile": payload["scan_profile"],
        "started_at": started_at,
        "status": payload.get("status", "running"),
        "scanner": payload.get("scanner", {"name": "nmap"}),
    }

    # Autonomy boundary: only operate within this manifest.
    v = bundle.validator("run_manifest")
    errs = sorted(v.iter_errors(run_manifest), key=lambda e: e.path)
    if errs:
        raise ValueError("run_manifest schema validation failed: " + "; ".join([e.message for e in errs]))

    # Persist manifest as immutable-ish artifact
    gcs = aura_gcs.client()
    bq = aura_bq.client(cfg.bq_project)
    tables = _tables(cfg)

    manifest_bytes = json.dumps(run_manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
    manifest_hash = sha256_hex(manifest_bytes)
    obj = f"{cfg.gcs_raw_prefix}/runs/{run_id}/manifest.json"
    loc = aura_gcs.upload_bytes(gcs, cfg.gcs_bucket, obj, manifest_bytes, content_type="application/json")

    run_manifest["artifacts"] = {"manifest_uri": loc.uri, "raw_prefix_uri": f"gs://{cfg.gcs_bucket}/{cfg.gcs_raw_prefix}/runs/{run_id}/"}
    # Idempotency per N4: MERGE by (run_id, tenant_ref, zone_ref)
    bq.query(
        f"""
        MERGE `{tables.fq(tables.raw_runs)}` T
        USING (SELECT
          @run_id AS run_id,
          @tenant_ref AS tenant_ref,
          @zone_ref AS zone_ref,
          @started_at AS started_at,
          @status AS status,
          @manifest_uri AS manifest_uri,
          @manifest_hash AS manifest_hash,
          @manifest_json AS manifest_json
        ) S
        ON T.run_id = S.run_id AND T.tenant_ref = S.tenant_ref AND T.zone_ref = S.zone_ref
        WHEN MATCHED THEN UPDATE SET
          started_at = S.started_at,
          status = S.status,
          manifest_uri = S.manifest_uri,
          manifest_hash = S.manifest_hash,
          manifest_json = S.manifest_json
        WHEN NOT MATCHED THEN INSERT (run_id, tenant_ref, zone_ref, started_at, status, manifest_uri, manifest_hash, manifest_json)
        VALUES (S.run_id, S.tenant_ref, S.zone_ref, S.started_at, S.status, S.manifest_uri, S.manifest_hash, S.manifest_json)
        """,
        job_config=__import__("google.cloud.bigquery").cloud.bigquery.QueryJobConfig(
            query_parameters=[
                __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("run_id", "STRING", run_id),
                __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("tenant_ref", "STRING", tenant_ref),
                __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("zone_ref", "STRING", zone_ref),
                __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("started_at", "STRING", started_at),
                __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("status", "STRING", run_manifest["status"]),
                __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("manifest_uri", "STRING", loc.uri),
                __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("manifest_hash", "STRING", manifest_hash),
                __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("manifest_json", "JSON", run_manifest),
            ]
        ),
    ).result()
    return run_manifest


def _canonical_target_key(t: Dict[str, Any]) -> str:
    # Autonomy boundary uses exact target objects (type+value+labels) from manifest.
    return json.dumps(t, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _assert_targets_within_manifest(run_manifest: Dict[str, Any], shard_targets: List[Dict[str, Any]]) -> None:
    manifest_targets = run_manifest["target_set"]["targets"]
    manifest_set = {_canonical_target_key(t) for t in manifest_targets}
    shard_set = {_canonical_target_key(t) for t in shard_targets}
    extra = shard_set - manifest_set
    if extra:
        raise ValueError("Autonomy boundary violation: shard targets not in run_manifest.target_set.targets")


def _nmap_cmd_from_scan_profile(scan_profile: Dict[str, Any], targets_args: List[str]) -> List[str]:
    # Only uses scan_profile fields defined in frozen run-manifest schema.
    cmd: List[str] = ["nmap", "-oX", "-"]

    mode = scan_profile.get("mode", "tcp")
    if mode == "udp":
        cmd += ["-sU"]
    elif mode == "tcp_udp":
        cmd += ["-sS", "-sU"]
    else:
        cmd += ["-sS"]

    port_spec = scan_profile.get("port_spec")
    if port_spec:
        cmd += ["-p", str(port_spec)]

    if bool(scan_profile.get("service_fingerprinting", True)):
        cmd += ["-sV"]
    if bool(scan_profile.get("os_fingerprinting", False)):
        cmd += ["-O"]

    timing = scan_profile.get("timing_template")
    timing_map = {"paranoid": "0", "sneaky": "1", "polite": "2", "normal": "3", "aggressive": "4", "insane": "5"}
    if timing in timing_map:
        cmd += [f"-T{timing_map[timing]}"]

    # Host discovery behavior is scanner-specific; only add minimal safe flag when provided by profile is absent.
    # (No additional scan scope is introduced; targets are still bounded by manifest.)
    cmd += ["-Pn"]
    cmd += targets_args
    return cmd


def stage_scan_shard(cfg: Config, bundle, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal scan stage:
    - Requires run_manifest in payload (autonomy boundary)
    - Runs nmap if present; otherwise accepts pre-provided raw payload bytes (for testing/replay)
    - Writes raw artifact to GCS and pointer row to BigQuery raw_observations
    """
    cfg.require()
    run_manifest = payload["run_manifest"]
    run_id = run_manifest["run_id"]
    tenant_ref = run_manifest["tenant_ref"]
    zone_ref = run_manifest["zone_ref"]
    shard_id = payload.get("shard_id", "shard-0")

    # Targets must be subset of manifest targets
    shard_targets = payload.get("targets") or run_manifest["target_set"]["targets"]
    _assert_targets_within_manifest(run_manifest, shard_targets)

    observed_at = utc_now_rfc3339()
    observation_id = str(ulid.new())

    raw_bytes: Optional[bytes] = None
    raw_format = payload.get("raw_format", "xml")

    if "raw_bytes_b64" in payload:
        import base64

        raw_bytes = base64.b64decode(payload["raw_bytes_b64"])
    else:
        # Execute scanner (minimal): nmap -oX - <targets...>
        # This stays vendor-neutral at the schema layer; adapter name/version is recorded in observation later.
        targets_args: List[str] = []
        for t in shard_targets:
            if t["type"] in ("ip", "hostname", "cidr"):
                targets_args.append(t["value"])
        cmd = _nmap_cmd_from_scan_profile(run_manifest["scan_profile"], targets_args)
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        raw_bytes = proc.stdout or b""
        if proc.returncode != 0:
            # Still persist raw stderr for replay/forensics.
            raw_bytes = (raw_bytes + b"\n\nSTDERR:\n" + proc.stderr)

    raw_hash = sha256_hex(raw_bytes)

    gcs = aura_gcs.client()
    bq = aura_bq.client(cfg.bq_project)
    tables = _tables(cfg)

    obj = f"{cfg.gcs_raw_prefix}/runs/{run_id}/shards/{shard_id}/observations/{observation_id}.{raw_format}"
    loc = aura_gcs.upload_bytes(gcs, cfg.gcs_bucket, obj, raw_bytes, content_type="application/octet-stream")

    # Raw observation pointer row
    aura_bq.insert_json_rows(
        bq,
        tables.fq(tables.raw_observations),
        [
            {
                "run_id": run_id,
                "tenant_ref": tenant_ref,
                "zone_ref": zone_ref,
                "shard_id": shard_id,
                "observation_id": observation_id,
                "observed_at": observed_at,
                "source": {"kind": "network_scanner", "name": run_manifest.get("scanner", {}).get("name", "nmap")},
                "payload_gcs_uri": loc.uri,
                "payload_hash": raw_hash,
                "payload_format": raw_format,
                "parse_status": "raw_only",
            }
        ],
    )
    return {"observation_id": observation_id, "raw_uri": loc.uri, "raw_hash": raw_hash, "observed_at": observed_at}


def _parse_nmap_xml_to_observation(run_manifest: Dict[str, Any], raw_xml: str, observation_id: str, shard_id: str, observed_at: str) -> Dict[str, Any]:
    # Minimal parser: extract addresses and open ports from nmap XML without adding assumptions.
    import xml.etree.ElementTree as ET

    root = ET.fromstring(raw_xml)
    # Choose the first host element if present (minimal)
    host = root.find("host")
    names: List[str] = []
    addrs: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    if host is not None:
        for hn in host.findall("./hostnames/hostname"):
            n = hn.attrib.get("name")
            if n:
                names.append(n)
        for addr in host.findall("address"):
            atype = addr.attrib.get("addrtype")
            aval = addr.attrib.get("addr")
            if not aval:
                continue
            if atype == "mac":
                # attach MAC to first address if exists, otherwise add placeholder ip-less entry (will be ignored by schema).
                if addrs:
                    addrs[0]["mac"] = aval.lower()
            else:
                addrs.append({"ip": aval})
        for port in host.findall("./ports/port"):
            proto = port.attrib.get("protocol", "tcp")
            portid = int(port.attrib.get("portid", "0"))
            state_el = port.find("state")
            state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"
            svc_el = port.find("service")
            services.append(
                {
                    "protocol": proto if proto in ("tcp", "udp") else "other",
                    "port": portid,
                    "state": state if state in ("open", "closed", "filtered", "open|filtered") else "unknown",
                    "service_name": svc_el.attrib.get("name") if svc_el is not None else None,
                    "product": svc_el.attrib.get("product") if svc_el is not None else None,
                    "version": svc_el.attrib.get("version") if svc_el is not None else None,
                    "cpe": [],
                }
            )

    # Spec justification: observation.subject.addresses must contain at least one IP (schema).
    # If scanner output cannot provide an address, treat as invalid and quarantine upstream.
    if not any(a.get("ip") for a in addrs):
        raise ValueError("Parsed nmap output contained no IP addresses for host")

    obs = {
        "schema_version": "1.0.0",
        "observation_id": observation_id,
        "run_id": run_manifest["run_id"],
        "tenant_ref": run_manifest["tenant_ref"],
        "zone_ref": run_manifest["zone_ref"],
        "shard_id": shard_id,
        "observed_at": observed_at,
        "source": {
            "kind": "network_scanner",
            "name": run_manifest.get("scanner", {}).get("name", "nmap"),
            "version": run_manifest.get("scanner", {}).get("version"),
            "adapter": {"name": "nmap_xml_v1", "version": "1.0.0"},
        },
        "subject": {"names": names, "addresses": addrs},
        "services": services,
        "evidence": {
            "raw_uri": "",
            "raw_content_type": "application/xml",
            "raw_hash": "",
            "scanner_output_format": "xml",
        },
    }
    return obs


def stage_normalize_validate(cfg: Config, bundle, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal normalize/validate:
    - Reads raw observation pointers for run_id (or accepts direct raw_uri list)
    - Parses nmap XML into canonical Observation wrapper
    - Validates against observation schema; invalid => quarantine row
    - Writes canonical Observation JSON into raw_observations row (no new tables/components)
    """
    cfg.require()
    run_manifest = payload["run_manifest"]
    run_id = run_manifest["run_id"]

    bq = aura_bq.client(cfg.bq_project)
    gcs = aura_gcs.client()
    tables = _tables(cfg)

    rows = list(
        aura_bq.query(
            bq,
            f"SELECT run_id, tenant_ref, zone_ref, shard_id, observation_id, observed_at, payload_gcs_uri, payload_hash, payload_format "
            f"FROM `{tables.fq(tables.raw_observations)}` WHERE run_id=@run_id",
            {"run_id": run_id},
        )
    )

    v = bundle.validator("raw_observation")
    written = 0
    invalid = 0
    for r in rows:
        uri = r["payload_gcs_uri"]
        if not uri.startswith("gs://"):
            continue
        _, rest = uri.split("gs://", 1)
        bucket, obj = rest.split("/", 1)
        raw = gcs.bucket(bucket).blob(obj).download_as_text(encoding="utf-8")

        try:
            obs = _parse_nmap_xml_to_observation(run_manifest, raw, r["observation_id"], r.get("shard_id") or "shard-0", r["observed_at"])
        except Exception as e:
            invalid += 1
            aura_bq.insert_json_rows(
                bq,
                tables.fq(tables.quarantine),
                [
                    {
                        "run_id": run_id,
                        "tenant_ref": run_manifest["tenant_ref"],
                        "zone_ref": run_manifest["zone_ref"],
                        "stage": "normalize_validate",
                        "reason_code": "OBSERVATION_SCHEMA_VALIDATION_FAILED",
                        "errors": [str(e)],
                        "payload_gcs_uri": uri,
                        "record_json": {"observation_id": r["observation_id"], "run_id": run_id},
                    }
                ],
            )
            continue
        obs["evidence"]["raw_uri"] = uri
        obs["evidence"]["raw_hash"] = r.get("payload_hash", "")
        obs["evidence"]["scanner_output_format"] = r.get("payload_format", "xml")

        errs = sorted(v.iter_errors(obs), key=lambda e: e.path)
        if errs:
            invalid += 1
            aura_bq.insert_json_rows(
                bq,
                tables.fq(tables.quarantine),
                [
                    {
                        "run_id": run_id,
                        "tenant_ref": run_manifest["tenant_ref"],
                        "zone_ref": run_manifest["zone_ref"],
                        "stage": "normalize_validate",
                        "reason_code": "OBSERVATION_SCHEMA_VALIDATION_FAILED",
                        "errors": [e.message for e in errs],
                        "payload_gcs_uri": uri,
                        "record_json": obs,
                    }
                ],
            )
            continue

        # Update the raw_observations row with canonical observation JSON (idempotent by observation_id)
        sql = (
            f"UPDATE `{tables.fq(tables.raw_observations)}` "
            f"SET parse_status='normalized', canonical_observation=@obs "
            f"WHERE run_id=@run_id AND observation_id=@observation_id"
        )
        job = bq.query(
            sql,
            job_config=__import__("google.cloud.bigquery").cloud.bigquery.QueryJobConfig(
                query_parameters=[
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("run_id", "STRING", run_id),
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("observation_id", "STRING", r["observation_id"]),
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("obs", "JSON", obs),
                ]
            ),
        )
        job.result()
        written += 1

    return {"normalized_written": written, "invalid": invalid}


def stage_entity_resolve_merge(cfg: Config, bundle, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal entity resolution:
    - Reads canonical observations from BigQuery raw_observations.canonical_observation
    - Deterministically chooses primary key class per `specs/dedup/rules.yaml`
    - Generates asset_id and merges into assets_current (JSON) and assets_history (append-only JSON)
    - Writes minimal asset_change events
    """
    cfg.require()
    run_manifest = payload["run_manifest"]
    run_id = run_manifest["run_id"]
    tenant_ref = run_manifest["tenant_ref"]
    zone_ref = run_manifest["zone_ref"]
    now = utc_now_rfc3339()

    bq = aura_bq.client(cfg.bq_project)
    tables = _tables(cfg)

    precedence = bundle.dedup_rules.get("merge_policy", {}).get("primary_key_precedence", [])

    obs_rows = list(
        aura_bq.query(
            bq,
            f"SELECT observation_id, shard_id, observed_at, canonical_observation "
            f"FROM `{tables.fq(tables.raw_observations)}` "
            f"WHERE run_id=@run_id AND parse_status='normalized'",
            {"run_id": run_id},
        )
    )

    assets_upserted = 0
    for r in obs_rows:
        obs = r["canonical_observation"]
        if not isinstance(obs, dict):
            continue

        matches = compute_identity_matches(bundle.dedup_rules, obs)
        primary = choose_primary_key_class(bundle.dedup_rules, matches)
        if primary is None:
            aura_bq.insert_json_rows(
                bq,
                tables.fq(tables.quarantine),
                [
                    {
                        "run_id": run_id,
                        "tenant_ref": tenant_ref,
                        "zone_ref": zone_ref,
                        "stage": "entity_resolve_merge",
                        "reason_code": "NO_IDENTITY_KEYS",
                        "errors": ["No identity keys found for observation"],
                        "record_json": obs,
                    }
                ],
            )
            continue

        asset_id = compute_asset_id(bundle.dedup_rules, tenant_ref, zone_ref, primary)

        # Fetch current asset (if any)
        prior_rows = list(
            aura_bq.query(
                bq,
                f"SELECT asset_json FROM `{tables.fq(tables.assets_current)}` WHERE asset_id=@asset_id AND tenant_ref=@tenant_ref AND zone_ref=@zone_ref",
                {"asset_id": asset_id, "tenant_ref": tenant_ref, "zone_ref": zone_ref},
            )
        )
        prior = prior_rows[0]["asset_json"] if prior_rows else None

        merged = merge_asset(prior, obs, now=now, precedence=precedence)
        merged.update(
            {
                "schema_version": "1.0.0",
                "asset_id": asset_id,
                "tenant_ref": tenant_ref,
                "zone_ref": zone_ref,
            }
        )

        # Validate asset schema
        av = bundle.validator("asset")
        errs = sorted(av.iter_errors(merged), key=lambda e: e.path)
        if errs:
            aura_bq.insert_json_rows(
                bq,
                tables.fq(tables.quarantine),
                [
                    {
                        "run_id": run_id,
                        "tenant_ref": tenant_ref,
                        "zone_ref": zone_ref,
                        "stage": "entity_resolve_merge",
                        "reason_code": "ASSET_SCHEMA_VALIDATION_FAILED",
                        "errors": [e.message for e in errs],
                        "record_json": merged,
                    }
                ],
            )
            continue

        # Idempotency per N4: MERGE assets_current by (asset_id, tenant_ref, zone_ref)
        bq.query(
            f"""
            MERGE `{tables.fq(tables.assets_current)}` T
            USING (SELECT
              @asset_id AS asset_id,
              @tenant_ref AS tenant_ref,
              @zone_ref AS zone_ref,
              @first_seen AS first_seen,
              @last_seen AS last_seen,
              @active AS active,
              @asset_json AS asset_json
            ) S
            ON T.asset_id=S.asset_id AND T.tenant_ref=S.tenant_ref AND T.zone_ref=S.zone_ref
            WHEN MATCHED THEN UPDATE SET
              first_seen = LEAST(T.first_seen, S.first_seen),
              last_seen = GREATEST(T.last_seen, S.last_seen),
              active = S.active,
              asset_json = S.asset_json
            WHEN NOT MATCHED THEN INSERT (asset_id, tenant_ref, zone_ref, first_seen, last_seen, active, asset_json)
            VALUES (S.asset_id, S.tenant_ref, S.zone_ref, S.first_seen, S.last_seen, S.active, S.asset_json)
            """,
            job_config=__import__("google.cloud.bigquery").cloud.bigquery.QueryJobConfig(
                query_parameters=[
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("asset_id", "STRING", asset_id),
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("tenant_ref", "STRING", tenant_ref),
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("zone_ref", "STRING", zone_ref),
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("first_seen", "STRING", merged["first_seen"]),
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("last_seen", "STRING", merged["last_seen"]),
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("active", "BOOL", bool(merged["active"])),
                    __import__("google.cloud.bigquery").cloud.bigquery.ScalarQueryParameter("asset_json", "JSON", merged),
                ]
            ),
        ).result()
        aura_bq.insert_json_rows(
            bq,
            tables.fq(tables.assets_history),
            [
                {
                    "asset_id": asset_id,
                    "tenant_ref": tenant_ref,
                    "zone_ref": zone_ref,
                    "valid_from": now,
                    "valid_to": None,
                    "run_id": run_id,
                    "asset_json": merged,
                }
            ],
        )

        change = compute_change_event(asset_id, tenant_ref, zone_ref, run_id, now, prior, merged)
        cv = bundle.validator("asset_change")
        cerrs = sorted(cv.iter_errors(change), key=lambda e: e.path)
        if not cerrs:
            aura_bq.insert_json_rows(bq, tables.fq(tables.asset_changes), [change])

        assets_upserted += 1

    return {"assets_upserted": assets_upserted}


def main() -> None:
    _init_logging()

    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=["orchestrate", "scan_shard", "normalize_validate", "entity_resolve_merge"])
    parser.add_argument("--payload", required=True, help="JSON payload string, or @path/to/file.json")
    args = parser.parse_args()

    payload_arg = args.payload
    if payload_arg.startswith("@"):
        payload = json.loads(open(payload_arg[1:], "r", encoding="utf-8").read())
    else:
        payload = json.loads(payload_arg)

    cfg = Config()
    bundle = load_spec_bundle(cfg.specs_dir)
    if not bundle.frozen:
        raise RuntimeError("Spec bundle must be frozen to run implementation.")

    if args.stage == "orchestrate":
        out = stage_orchestrate(cfg, bundle, payload)
    elif args.stage == "scan_shard":
        out = stage_scan_shard(cfg, bundle, payload)
    elif args.stage == "normalize_validate":
        out = stage_normalize_validate(cfg, bundle, payload)
    else:
        out = stage_entity_resolve_merge(cfg, bundle, payload)

    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()

