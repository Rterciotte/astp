from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from pydantic import BaseModel, Field


class ReportBundleFile(BaseModel):
    path: str
    sha256: str
    size: int


class ReportBundleManifest(BaseModel):
    schema_version: str = "1"
    files: list[ReportBundleFile] = Field(default_factory=list)


def _file_record(path: Path, arcname: str) -> ReportBundleFile:
    data = path.read_bytes()
    return ReportBundleFile(path=arcname, sha256=hashlib.sha256(data).hexdigest(), size=len(data))


def create_report_bundle(
    output: Path,
    *,
    report_path: Path,
    structured_result_path: Path,
    extra_files: list[Path] | None = None,
) -> ReportBundleManifest:
    candidates = [report_path, structured_result_path, *(extra_files or [])]
    records = [_file_record(path, path.name) for path in candidates]
    manifest = ReportBundleManifest(files=records)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in candidates:
            archive.write(path, path.name)
        archive.writestr(
            "manifest.json",
            json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        )
    return manifest


def verify_report_bundle(path: Path) -> bool:
    with zipfile.ZipFile(path, "r") as archive:
        manifest = ReportBundleManifest.model_validate_json(archive.read("manifest.json"))
        for record in manifest.files:
            data = archive.read(record.path)
            if len(data) != record.size:
                return False
            if hashlib.sha256(data).hexdigest() != record.sha256:
                return False
    return True
