from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from astp.assessment import AssessmentResult
from astp.assessment_manifest import AssessmentManifest, build_assessment_manifest
from astp.io import dump_yaml
from astp.lineage import AssessmentLineage, build_assessment_lineage


class ReviewPackageResult(BaseModel):
    manifest: AssessmentManifest
    lineage: AssessmentLineage
    report_path: Path
    result_path: Path
    manifest_path: Path
    lineage_path: Path
    network_execution_performed: bool = False


def build_review_package(
    result: AssessmentResult,
    output_dir: Path,
) -> ReviewPackageResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "report.md"
    result_path = output_dir / "assessment-result.yaml"
    manifest_path = output_dir / "assessment-manifest.yaml"
    lineage_path = output_dir / "lineage.yaml"
    report_path.write_text(result.report_markdown, encoding="utf-8")
    dump_yaml(result, result_path)
    manifest = build_assessment_manifest(result)
    lineage = build_assessment_lineage(result)
    dump_yaml(manifest, manifest_path)
    dump_yaml(lineage, lineage_path)
    return ReviewPackageResult(
        manifest=manifest,
        lineage=lineage,
        report_path=report_path,
        result_path=result_path,
        manifest_path=manifest_path,
        lineage_path=lineage_path,
    )
