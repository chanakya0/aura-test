from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from google.cloud import storage


@dataclass(frozen=True)
class GCSLocation:
    bucket: str
    object_name: str

    @property
    def uri(self) -> str:
        return f"gs://{self.bucket}/{self.object_name}"


def client() -> storage.Client:
    return storage.Client()


def upload_bytes(
    gcs: storage.Client,
    bucket: str,
    object_name: str,
    data: bytes,
    content_type: Optional[str] = None,
) -> GCSLocation:
    b = gcs.bucket(bucket)
    blob = b.blob(object_name)
    blob.upload_from_string(data, content_type=content_type)
    return GCSLocation(bucket=bucket, object_name=object_name)

