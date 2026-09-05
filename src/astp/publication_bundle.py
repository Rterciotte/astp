from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from pydantic import BaseModel, Field

from astp.report_finalization import ReportFinalization


class PublicationEntry(BaseModel):
    name: str
    sha256: str


class PublicationBundleIndex(BaseModel):
    schema_version: str = "1"
    manifest_hash: str
    entries: list[PublicationEntry] = Field(default_factory=list)


def build_publication_bundle(
    output: Path,
    finalization: ReportFinalization,
    artifacts: list[Path],
) -> PublicationBundleIndex:
    if not finalization.publishable:
        raise ValueError("assessment has not been approved for publication")
    names = [path.name for path in artifacts]
    if len(names) != len(set(names)):
        raise ValueError("publication artifacts require unique basenames")
    entries = [
        PublicationEntry(name=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        for path in artifacts
    ]
    index = PublicationBundleIndex(
        manifest_hash=finalization.manifest_hash,
        entries=entries,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in artifacts:
            archive.write(path, path.name)
        archive.writestr("publication-index.json", index.model_dump_json(indent=2))
    return index


def verify_publication_bundle(path: Path) -> bool:
    with zipfile.ZipFile(path) as archive:
        index = PublicationBundleIndex.model_validate_json(archive.read("publication-index.json"))
        for entry in index.entries:
            if hashlib.sha256(archive.read(entry.name)).hexdigest() != entry.sha256:
                return False
    return True
