from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Config:
    # Spec bundle location (must match frozen SSoT).
    specs_dir: str = os.getenv("AURA_SPECS_DIR", "/specs")

    # BigQuery locations (BigQuery is the system of record).
    bq_project: str = os.getenv("AURA_BQ_PROJECT", "")
    bq_dataset: str = os.getenv("AURA_BQ_DATASET", "aura")
    bq_table_raw_runs: str = os.getenv("AURA_BQ_TABLE_RAW_RUNS", "raw_runs")
    bq_table_raw_observations: str = os.getenv("AURA_BQ_TABLE_RAW_OBSERVATIONS", "raw_observations")
    bq_table_assets_current: str = os.getenv("AURA_BQ_TABLE_ASSETS_CURRENT", "assets_current")
    bq_table_assets_history: str = os.getenv("AURA_BQ_TABLE_ASSETS_HISTORY", "assets_history")
    bq_table_asset_changes: str = os.getenv("AURA_BQ_TABLE_ASSET_CHANGES", "asset_changes")
    bq_table_quarantine: str = os.getenv("AURA_BQ_TABLE_QUARANTINE", "quarantine_invalid")

    # GCS (immutable raw artifacts).
    gcs_bucket: str = os.getenv("AURA_GCS_BUCKET", "")
    gcs_raw_prefix: str = os.getenv("AURA_GCS_RAW_PREFIX", "raw")

    # Evidence freshness (mirrors dedup rule constant; repeated here only for runtime config override).
    evidence_freshness_days: int = int(os.getenv("AURA_EVIDENCE_FRESHNESS_DAYS", "30"))

    def require(self) -> None:
        missing = []
        if not self.bq_project:
            missing.append("AURA_BQ_PROJECT")
        if not self.gcs_bucket:
            missing.append("AURA_GCS_BUCKET")
        if missing:
            raise RuntimeError(f"Missing required env vars: {', '.join(missing)}")

