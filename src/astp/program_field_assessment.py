from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from astp.io import dump_yaml, load_model
from astp.models import Engagement, RiskClass, TestDefinition, target_in_scope
from astp.program_preflight import ProgramPreflightReport
from astp.target_registry import empty_registry, save_registry
from astp.work_queue import WorkQueue, WorkQueueItem


class FieldAssessmentPreparation(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    assessment_id: str
    program_id: str
    target: str
    prepared_at: datetime
    preflight_report_hash: str
    engagement_path: str
    attestation_path: str
    test_path: str
    queue_path: str
    registry_path: str
    evidence_dir: str
    report_path: str
    result_path: str
    semantic_exclusion_clear_ids: tuple[str, ...] = Field(default_factory=tuple)
    requested_rps: float
    max_actions: int = 1
    max_requests: int = 1
    state_changing_allowed: bool = False
    brute_force_allowed: bool = False
    broad_scanning_allowed: bool = False
    preparation_hash: str


def _sha256_json(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _report_hash(report: ProgramPreflightReport) -> str:
    payload = report.model_dump(mode="json")
    payload.pop("report_hash", None)
    return _sha256_json(payload)


def _persist_yaml_immutable(path: Path, value: object) -> None:
    rendered = dump_yaml(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            raise ValueError(f"immutable assessment artifact collision: {path}")
        return
    path.write_text(rendered, encoding="utf-8")


def _persist_json_immutable(path: Path, payload: dict[str, object]) -> None:
    rendered = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            raise ValueError(f"immutable assessment artifact collision: {path}")
        return
    path.write_text(rendered, encoding="utf-8")


def prepare_bounded_field_assessment(
    root: Path,
    *,
    preflight_path: Path,
    target: str,
    requested_rps: float | None = None,
    max_preflight_age_seconds: int = 300,
    now: datetime | None = None,
) -> tuple[FieldAssessmentPreparation, Path]:
    current = now or datetime.now(UTC)
    raw_report = json.loads(preflight_path.read_text(encoding="utf-8"))
    report = ProgramPreflightReport.model_validate(raw_report)
    expected_name = f"preflight-{report.report_hash}.json"
    if preflight_path.name != expected_name:
        raise ValueError("preflight report path is not bound to its immutable report hash")
    if not report.execution_eligible or report.status.value != "execution_eligible":
        raise ValueError("preflight report is not execution eligible")
    if report.policy_status != "ready":
        raise ValueError("program policy is not READY")
    if report.policy_drift.value == "security_relevant":
        raise ValueError("security-relevant policy drift blocks assessment")
    if report.operational_status != "online":
        raise ValueError("program is not freshly attested ONLINE")
    if not report.full_pentest_ready:
        raise ValueError("full-pentest readiness is not satisfied")
    if report.evaluated_at.tzinfo is None or report.evaluated_at.utcoffset() is None:
        raise ValueError("preflight timestamp is not timezone-aware")
    age = (current - report.evaluated_at.astimezone(UTC)).total_seconds()
    if age < 0 or age > max_preflight_age_seconds:
        raise ValueError("preflight report is stale; run a fresh live preflight")
    if not report.engagement_path or not report.attestation_path:
        raise ValueError("preflight did not produce engagement and attestation artifacts")

    engagement_path = Path(report.engagement_path)
    attestation_path = Path(report.attestation_path)
    if not engagement_path.is_absolute():
        engagement_path = root / engagement_path
    if not attestation_path.is_absolute():
        attestation_path = root / attestation_path
    engagement = load_model(engagement_path, Engagement)

    parsed = urlsplit(target)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("first field assessment requires one exact HTTPS target")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("target must not contain credentials or a fragment")
    if not target_in_scope(target, engagement.scope):
        raise ValueError("exact field target is outside compiled engagement scope")

    reviewed_rps = report.reviewed_max_requests_per_second
    if reviewed_rps is None:
        raise ValueError("no reviewed numeric execution rate is available")
    rps = reviewed_rps if requested_rps is None else requested_rps
    if rps <= 0 or rps > reviewed_rps or rps > engagement.constraints.max_requests_per_second:
        raise ValueError("requested rate exceeds reviewed/compiled execution rate")

    if engagement.methods.state_changing.value == "allow":
        raise ValueError(
            "first field assessment refuses engagements that allow state-changing tests"
        )
    if engagement.methods.intrusive.value == "allow":
        raise ValueError("first field assessment refuses engagements that allow intrusive tests")

    test = TestDefinition(
        id="field-safe-http-observation-v1",
        title="Bounded HTTP observation",
        category="observation",
        risk_class=RiskClass.SAFE_ACTIVE,
        evidence_required=["http_status", "response_headers"],
        description=(
            "One permit-gated GET observation. No state change, brute force, broad scanning, "
            "or exploit payloads. Redirects remain subject to separate authorization."
        ),
    )
    stamp = current.strftime("%Y%m%dT%H%M%SZ")
    assessment_id = f"{report.program_id}-{stamp}"
    base = root / ".astp" / "field-assessments" / assessment_id
    evidence_dir = base / "evidence"
    test_path = base / "test.yaml"
    queue_path = base / "queue.yaml"
    registry_path = base / "target-registry.yaml"
    report_path = base / "report.md"
    result_path = base / "assessment-result.yaml"

    queue = WorkQueue(
        created_at=current,
        max_active_programs=1,
        items=[
            WorkQueueItem(
                queue_id="field-0001",
                engagement_id=engagement.id,
                test_id=test.id,
                plan_item_id="field-exact-root-observation",
                target=target,
                method="GET",
                requires_new_permit=True,
            )
        ],
    )
    registry = empty_registry(engagement.id, now=current)
    _persist_yaml_immutable(test_path, test)
    _persist_yaml_immutable(queue_path, queue)
    if registry_path.exists():
        existing = registry_path.read_text(encoding="utf-8")
        expected = dump_yaml(registry)
        if existing != expected:
            raise ValueError(f"immutable assessment artifact collision: {registry_path}")
    else:
        save_registry(registry, registry_path)

    clear_ids = tuple(rule.id for rule in engagement.constraints.semantic_exclusions)
    payload: dict[str, object] = {
        "schema_version": "1",
        "assessment_id": assessment_id,
        "program_id": report.program_id,
        "target": target,
        "prepared_at": current.isoformat(),
        "preflight_report_hash": report.report_hash,
        "engagement_path": str(engagement_path),
        "attestation_path": str(attestation_path),
        "test_path": str(test_path),
        "queue_path": str(queue_path),
        "registry_path": str(registry_path),
        "evidence_dir": str(evidence_dir),
        "report_path": str(report_path),
        "result_path": str(result_path),
        "semantic_exclusion_clear_ids": clear_ids,
        "requested_rps": rps,
        "max_actions": 1,
        "max_requests": 1,
        "state_changing_allowed": False,
        "brute_force_allowed": False,
        "broad_scanning_allowed": False,
    }
    payload["preparation_hash"] = _sha256_json(payload)
    preparation = FieldAssessmentPreparation.model_validate(payload)
    preparation_path = base / f"preparation-{preparation.preparation_hash}.json"
    _persist_json_immutable(preparation_path, preparation.model_dump(mode="json"))
    return preparation, preparation_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare one fail-closed bounded field assessment")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--rps", type=float, default=None)
    parser.add_argument("--max-preflight-age-seconds", type=int, default=300)
    args = parser.parse_args()
    root = args.root.resolve()
    preflight = args.preflight if args.preflight.is_absolute() else root / args.preflight
    try:
        preparation, path = prepare_bounded_field_assessment(
            root,
            preflight_path=preflight,
            target=args.target,
            requested_rps=args.rps,
            max_preflight_age_seconds=args.max_preflight_age_seconds,
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"FIELD_ASSESSMENT_BLOCKED: {exc}")
        return 2
    print(
        json.dumps(
            {**preparation.model_dump(mode="json"), "preparation_path": str(path)},
            indent=2,
            sort_keys=True,
        )
    )
    print("FIELD_ASSESSMENT_PREPARED: TRUE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
