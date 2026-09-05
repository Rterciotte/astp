from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

from astp.assessment_manifest import AssessmentManifest
from astp.operator_review import OperatorReview


class PortableAssessmentEntry(BaseModel):
    path: str
    sha256: str


class PortableAssessmentIndex(BaseModel):
    schema_version: str = "1"
    manifest_hash: str
    entries: list[PortableAssessmentEntry] = Field(default_factory=list)


def export_portable_assessment(
    output: Path,
    *,
    manifest: AssessmentManifest,
    review: OperatorReview,
    report_path: Path,
    result_path: Path,
) -> PortableAssessmentIndex:
    if review.assessment_manifest_hash != manifest.manifest_hash:
        raise ValueError("operator review does not bind to this assessment manifest")
    payloads = {
        "assessment-manifest.json": manifest.model_dump_json(indent=2).encode(),
        "operator-review.json": review.model_dump_json(indent=2).encode(),
        "report.md": report_path.read_bytes(),
        "assessment-result.yaml": result_path.read_bytes(),
    }
    entries = [
        PortableAssessmentEntry(path=name, sha256=hashlib.sha256(data).hexdigest())
        for name, data in sorted(payloads.items())
    ]
    index = PortableAssessmentIndex(manifest_hash=manifest.manifest_hash, entries=entries)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in payloads.items():
            archive.writestr(name, data)
        archive.writestr(
            "index.json",
            json.dumps(index.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        )
    return index


def verify_portable_assessment(path: Path) -> bool:
    with zipfile.ZipFile(path, "r") as archive:
        index = PortableAssessmentIndex.model_validate_json(archive.read("index.json"))
        for entry in index.entries:
            if hashlib.sha256(archive.read(entry.path)).hexdigest() != entry.sha256:
                return False
    return True
