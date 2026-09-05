from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class AssessmentBundleManifest(BaseModel):
    model_config = ConfigDict(frozen=True)

    engagement_id: str
    report_path: str
    findings_path: str
    evidence_manifest_path: str
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    assessment_complete: bool = False
    network_actions: int = 0
    permits_consumed: int = 0


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_assessment_bundle(
    output_directory: Path,
    *,
    engagement_id: str,
    report_markdown: str,
    findings_payload: dict[str, object],
    evidence_manifest_text: str = "",
    network_actions: int = 0,
    permits_consumed: int = 0,
) -> AssessmentBundleManifest:
    output_directory.mkdir(parents=True, exist_ok=True)
    report_path = output_directory / "report.md"
    findings_path = output_directory / "findings.json"
    evidence_path = output_directory / "evidence-manifest.jsonl"
    report_path.write_text(report_markdown, encoding="utf-8")
    findings_path.write_text(
        json.dumps(findings_payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    evidence_path.write_text(evidence_manifest_text, encoding="utf-8")
    hashes = {
        "report.md": _sha256(report_path),
        "findings.json": _sha256(findings_path),
        "evidence-manifest.jsonl": _sha256(evidence_path),
    }
    complete = permits_consumed == network_actions and network_actions >= 0
    manifest = AssessmentBundleManifest(
        engagement_id=engagement_id,
        report_path=str(report_path),
        findings_path=str(findings_path),
        evidence_manifest_path=str(evidence_path),
        artifact_hashes=hashes,
        assessment_complete=complete,
        network_actions=network_actions,
        permits_consumed=permits_consumed,
    )
    (output_directory / "assessment-summary.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def verify_assessment_bundle(output_directory: Path) -> tuple[bool, tuple[str, ...]]:
    summary = AssessmentBundleManifest.model_validate_json(
        (output_directory / "assessment-summary.json").read_text(encoding="utf-8")
    )
    blockers: list[str] = []
    for name, expected in summary.artifact_hashes.items():
        path = output_directory / name
        if not path.is_file():
            blockers.append(f"missing bundle artifact: {name}")
        elif _sha256(path) != expected:
            blockers.append(f"bundle artifact hash mismatch: {name}")
    if summary.permits_consumed != summary.network_actions:
        blockers.append("network action / permit consumption counts do not match")
    return not blockers, tuple(blockers)
