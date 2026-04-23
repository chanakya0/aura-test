from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from google.cloud import bigquery


@dataclass(frozen=True)
class BQTables:
    project: str
    dataset: str
    raw_runs: str
    raw_observations: str
    assets_current: str
    assets_history: str
    asset_changes: str
    quarantine: str

    def fq(self, table: str) -> str:
        return f"{self.project}.{self.dataset}.{table}"


def client(project: Optional[str] = None) -> bigquery.Client:
    return bigquery.Client(project=project) if project else bigquery.Client()


def insert_json_rows(bq: bigquery.Client, table_fq: str, rows: List[Dict[str, Any]]) -> None:
    errors = bq.insert_rows_json(table_fq, rows)
    if errors:
        raise RuntimeError(f"BigQuery insert errors for {table_fq}: {errors}")


def query(bq: bigquery.Client, sql: str, params: Optional[Dict[str, Any]] = None) -> Iterable[Dict[str, Any]]:
    job_config = bigquery.QueryJobConfig()
    if params:
        job_config.query_parameters = [
            bigquery.ScalarQueryParameter(k, "STRING" if isinstance(v, str) else "INT64" if isinstance(v, int) else "STRING", v)
            for k, v in params.items()
        ]
    it = bq.query(sql, job_config=job_config).result()
    for row in it:
        yield dict(row)

