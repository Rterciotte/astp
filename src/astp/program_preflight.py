from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import threading
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

from astp.browser_intake import BrowserCapture, load_capture
from astp.full_pentest_readiness import evaluate_local_full_pentest_readiness
from astp.io import dump_yaml, load_model
from astp.models import OperationalStatus, ProgramOperationalAttestation
from astp.program_catalog import BugBountyWorkspace, CatalogProgram, sync_program_capture
from astp.program_intake import compile_program
from astp.program_models import BugBountyProgram, ProgramImportStatus
from astp.program_runtime import create_operational_attestation
from astp.program_server import create_program_intake_server


class PreflightStatus(StrEnum):
    EXECUTION_ELIGIBLE = "execution_eligible"
    BLOCKED = "blocked"


class PolicyDriftStatus(StrEnum):
    NONE = "none"
    NON_SECURITY_TEXT_ONLY = "non_security_text_only"
    SECURITY_RELEVANT = "security_relevant"


class PreflightGate(BaseModel):
    model_config = ConfigDict(frozen=True)

    execution_eligible: bool
    blocking_reasons: tuple[str, ...] = Field(default_factory=tuple)


class ProgramPreflightReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1"] = "1"
    program_id: str
    program_name: str
    platform: str
    status: PreflightStatus
    execution_eligible: bool
    evaluated_at: datetime
    source_capture_fresh: bool
    capture_age_seconds: float
    policy_status: str
    policy_drift: PolicyDriftStatus
    previous_policy_fingerprint: str | None = None
    current_policy_fingerprint: str
    previous_source_sha256: str | None = None
    current_source_sha256: str
    operational_status: str
    operational_status_source: str | None = None
    operational_status_evidence: str | None = None
    operational_attestation_id: str | None = None
    full_pentest_ready: bool
    readiness_report_hash: str | None = None
    engagement_path: str | None = None
    attestation_path: str | None = None
    semantic_exclusions: tuple[str, ...] = Field(default_factory=tuple)
    reviewed_max_requests_per_second: float | None = None
    blocking_reasons: tuple[str, ...] = Field(default_factory=tuple)
    report_hash: str


def _canonical_url(value: str) -> str:
    parsed = urlsplit(value)
    path = parsed.path.rstrip("/") or "/"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, query, ""))


def _same_program_url(observed: str, expected: str) -> bool:
    return _canonical_url(observed) == _canonical_url(expected)


def _sha256_json(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def program_security_fingerprint(program: BugBountyProgram) -> str:
    """Hash only execution-relevant normalized policy semantics, not page cosmetics."""
    payload = {
        "scope": sorted(
            (
                entry.effect.value,
                entry.selector.kind.value,
                entry.selector.value,
            )
            for entry in program.scope
        ),
        "constraints": sorted(
            (
                item.code,
                item.effect.value,
                json.dumps(item.value, sort_keys=True, ensure_ascii=False),
            )
            for item in program.constraints
        ),
        "excluded_finding_types": sorted(program.excluded_finding_types),
        "recommended_user_agent": program.recommended_user_agent,
        "issues": sorted(
            (
                issue.code,
                issue.blocking,
                issue.source_text or "",
            )
            for issue in program.issues
        ),
    }
    return _sha256_json(payload)


def classify_policy_drift(
    previous: BugBountyProgram | None,
    current: BugBountyProgram,
) -> tuple[PolicyDriftStatus, str | None, str]:
    current_fingerprint = program_security_fingerprint(current)
    if previous is None:
        return PolicyDriftStatus.NONE, None, current_fingerprint
    previous_fingerprint = program_security_fingerprint(previous)
    if previous_fingerprint != current_fingerprint:
        return (
            PolicyDriftStatus.SECURITY_RELEVANT,
            previous_fingerprint,
            current_fingerprint,
        )
    if previous.source.content_sha256 != current.source.content_sha256:
        return (
            PolicyDriftStatus.NON_SECURITY_TEXT_ONLY,
            previous_fingerprint,
            current_fingerprint,
        )
    return PolicyDriftStatus.NONE, previous_fingerprint, current_fingerprint


def evaluate_preflight_gate(
    *,
    source_capture_fresh: bool,
    policy_ready: bool,
    policy_drift: PolicyDriftStatus,
    requires_online: bool,
    operational_status: OperationalStatus,
    full_pentest_ready: bool,
) -> PreflightGate:
    reasons: list[str] = []
    if not source_capture_fresh:
        reasons.append("program source capture is stale")
    if not policy_ready:
        reasons.append("program policy requires review")
    if policy_drift == PolicyDriftStatus.SECURITY_RELEVANT:
        reasons.append("security-relevant policy drift requires review")
    if requires_online and operational_status != OperationalStatus.ONLINE:
        if operational_status == OperationalStatus.OFFLINE:
            reasons.append("program is currently offline")
        else:
            reasons.append("current program online/offline status is not proven")
    if not full_pentest_ready:
        reasons.append("ASTP full-pentest readiness gate is not satisfied")
    return PreflightGate(execution_eligible=not reasons, blocking_reasons=tuple(reasons))


def _capture_status(
    capture: BrowserCapture,
    *,
    platform: str,
) -> tuple[OperationalStatus, str | None, str | None]:
    """Resolve current operational state from bounded authenticated-browser evidence.

    Explicit structured ONLINE/OFFLINE evidence always wins. For BugHunt only, an
    enabled visible `Submeter Relatório` control plus the program publication marker
    is accepted as a provider-specific positive operational affordance. An explicit
    offline/blocking signal always overrides positive affordances.
    """
    offline = next(
        (signal for signal in capture.operational_signals if signal.status == "offline"),
        None,
    )
    if offline is not None:
        return OperationalStatus.OFFLINE, "authenticated_browser_explicit_status", offline.evidence

    hint = capture.operational_status_hint
    if hint == "offline":
        return (
            OperationalStatus.OFFLINE,
            "authenticated_browser_explicit_status",
            capture.operational_status_evidence,
        )
    if hint == "online":
        return (
            OperationalStatus.ONLINE,
            "authenticated_browser_explicit_status",
            capture.operational_status_evidence,
        )

    if platform.strip().lower() == "bughunt":
        parsed = urlsplit(capture.url)
        bughunt_detail = (
            parsed.hostname is not None
            and parsed.hostname.lower().endswith("bughunt.com.br")
            and "/program/detail" in parsed.path.lower()
        )
        if bughunt_detail:
            enabled_submit = next(
                (
                    signal
                    for signal in capture.operational_signals
                    if signal.kind == "submission_control"
                    and signal.visible
                    and signal.enabled is True
                ),
                None,
            )
            published = next(
                (
                    signal
                    for signal in capture.operational_signals
                    if signal.kind == "published_marker" and signal.visible
                ),
                None,
            )
            if enabled_submit is not None and published is not None:
                evidence = f"{enabled_submit.evidence}; {published.evidence}"
                return (
                    OperationalStatus.ONLINE,
                    "authenticated_browser_bughunt_operational_affordance",
                    evidence,
                )

    return OperationalStatus.UNKNOWN, None, None


def _capture_age_seconds(capture: BrowserCapture, now: datetime) -> float:
    captured_at = capture.captured_at
    if captured_at.tzinfo is None or captured_at.utcoffset() is None:
        return float("inf")
    return max(0.0, (now - captured_at.astimezone(UTC)).total_seconds())


def _find_catalog_item(workspace: BugBountyWorkspace, program_id: str) -> CatalogProgram:
    item = next(
        (entry for entry in workspace.programs if entry.candidate.id == program_id),
        None,
    )
    if item is None:
        raise ValueError(f"unknown catalog program ID: {program_id}")
    return item


def _load_current_program(item: CatalogProgram) -> BugBountyProgram:
    if not item.normalized_path:
        raise ValueError("program has not been normalized yet")
    path = Path(item.normalized_path)
    if not path.exists():
        raise FileNotFoundError(f"normalized program file does not exist: {path}")
    return load_model(path, BugBountyProgram)


def _persist_yaml_hashed(directory: Path, prefix: str, model: BaseModel) -> Path:
    payload = model.model_dump(mode="json")
    digest = _sha256_json(payload)
    path = directory / f"{prefix}-{digest}.yaml"
    rendered = dump_yaml(model)
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            raise ValueError(f"immutable preflight artifact collision: {path}")
        return path
    directory.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    return path


def _report_hash(payload: dict[str, object]) -> str:
    without_hash = dict(payload)
    without_hash.pop("report_hash", None)
    return _sha256_json(without_hash)


def _persist_report(root: Path, report: ProgramPreflightReport) -> Path:
    directory = root / ".astp" / "preflight" / report.program_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"preflight-{report.report_hash}.json"
    rendered = json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2) + "\n"
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            raise ValueError("immutable preflight report collision")
        return path
    path.write_text(rendered, encoding="utf-8")
    return path


def evaluate_program_preflight(
    root: Path,
    *,
    program_id: str,
    catalog_path: Path,
    capture_path: Path,
    previous_program: BugBountyProgram | None,
    freshness_seconds: int,
) -> tuple[ProgramPreflightReport, Path]:
    workspace = load_model(catalog_path, BugBountyWorkspace)
    item = _find_catalog_item(workspace, program_id)
    program = _load_current_program(item)
    capture = load_capture(capture_path)

    if not _same_program_url(capture.url, item.candidate.detail_url):
        raise ValueError(
            "fresh capture is not bound to the requested program detail URL: "
            f"observed={capture.url} expected={item.candidate.detail_url}"
        )

    now = datetime.now(UTC)
    age = _capture_age_seconds(capture, now)
    source_fresh = age <= freshness_seconds
    drift, previous_fingerprint, current_fingerprint = classify_policy_drift(
        previous_program,
        program,
    )

    engagement = None
    engagement_path: Path | None = None
    compile_error: str | None = None
    try:
        engagement = compile_program(program)
        artifact_root = root / ".astp" / "preflight" / program_id / "artifacts"
        engagement_path = _persist_yaml_hashed(artifact_root, "engagement", engagement)
    except ValueError as exc:
        compile_error = str(exc)

    operational_status, operational_source, operational_evidence = _capture_status(
        capture,
        platform=program.platform,
    )
    attestation: ProgramOperationalAttestation | None = None
    attestation_path: Path | None = None
    requires_online = bool(engagement and engagement.program and engagement.program.requires_online)
    if requires_online and operational_status != OperationalStatus.UNKNOWN:
        attestation = create_operational_attestation(
            program,
            status=operational_status,
            source_type=operational_source or "authenticated_browser_operational_status",
            observed_at=capture.captured_at,
            note=operational_evidence,
        )
        artifact_root = root / ".astp" / "preflight" / program_id / "artifacts"
        attestation_path = _persist_yaml_hashed(
            artifact_root,
            "operational-attestation",
            attestation,
        )

    readiness, _readiness_path = evaluate_local_full_pentest_readiness(root)
    gate = evaluate_preflight_gate(
        source_capture_fresh=source_fresh,
        policy_ready=program.status == ProgramImportStatus.READY and compile_error is None,
        policy_drift=drift,
        requires_online=requires_online,
        operational_status=operational_status,
        full_pentest_ready=readiness.full_pentest_ready,
    )
    reasons = list(gate.blocking_reasons)
    if compile_error is not None and "program policy requires review" not in reasons:
        reasons.append(f"program compilation failed: {compile_error}")

    payload: dict[str, object] = {
        "schema_version": "1",
        "program_id": program.id,
        "program_name": program.name,
        "platform": program.platform,
        "status": (
            PreflightStatus.EXECUTION_ELIGIBLE.value
            if gate.execution_eligible and compile_error is None
            else PreflightStatus.BLOCKED.value
        ),
        "execution_eligible": gate.execution_eligible and compile_error is None,
        "evaluated_at": now.isoformat(),
        "source_capture_fresh": source_fresh,
        "capture_age_seconds": round(age, 3),
        "policy_status": program.status.value,
        "policy_drift": drift.value,
        "previous_policy_fingerprint": previous_fingerprint,
        "current_policy_fingerprint": current_fingerprint,
        "previous_source_sha256": (
            previous_program.source.content_sha256 if previous_program else None
        ),
        "current_source_sha256": program.source.content_sha256,
        "operational_status": operational_status.value,
        "operational_status_source": operational_source,
        "operational_status_evidence": operational_evidence,
        "operational_attestation_id": attestation.id if attestation else None,
        "full_pentest_ready": readiness.full_pentest_ready,
        "readiness_report_hash": readiness.report_hash,
        "engagement_path": str(engagement_path) if engagement_path else None,
        "attestation_path": str(attestation_path) if attestation_path else None,
        "semantic_exclusions": tuple(
            f"{rule.kind.value}={rule.value}" for rule in program.semantic_exclusions
        ),
        "reviewed_max_requests_per_second": program.reviewed_max_requests_per_second,
        "blocking_reasons": tuple(reasons),
    }
    payload["report_hash"] = _report_hash(payload)
    report = ProgramPreflightReport.model_validate(payload)
    return report, _persist_report(root, report)


def refresh_program_from_browser(
    root: Path,
    *,
    program_id: str,
    catalog_path: Path,
    platform: str,
    port: int,
    timeout_seconds: int,
) -> tuple[BugBountyProgram | None, Path]:
    workspace = load_model(catalog_path, BugBountyWorkspace)
    item = _find_catalog_item(workspace, program_id)
    previous = _load_current_program(item) if item.normalized_path else None

    latest_capture = root / ".astp" / "browser-capture.json"
    captures_dir = root / ".astp" / "program-captures"
    programs_dir = root / "programs"
    token = secrets.token_urlsafe(24)
    server = create_program_intake_server(
        intake_token=token,
        platform=platform,
        latest_capture_path=latest_capture,
        catalog_path=catalog_path,
        captures_dir=captures_dir,
        programs_dir=programs_dir,
        host="127.0.0.1",
        port=port,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    baseline_mtime = latest_capture.stat().st_mtime_ns if latest_capture.exists() else -1
    print(f"ASTP live pre-flight intake: http://127.0.0.1:{port}")
    print("Paste this token into the ASTP browser companion:")
    print(token)
    print()
    print("Open the requested authenticated program detail page and click 'Capture current page'.")
    print(f"Waiting up to {timeout_seconds}s for: {item.candidate.detail_url}")

    deadline = time.monotonic() + timeout_seconds
    wrong_url_reported: str | None = None
    try:
        while time.monotonic() < deadline:
            if latest_capture.exists() and latest_capture.stat().st_mtime_ns > baseline_mtime:
                capture = load_capture(latest_capture)
                if _same_program_url(capture.url, item.candidate.detail_url):
                    workspace = load_model(catalog_path, BugBountyWorkspace)
                    sync_program_capture(
                        workspace,
                        candidate_id=program_id,
                        capture=capture,
                        catalog_path=catalog_path,
                        captures_dir=captures_dir,
                        programs_dir=programs_dir,
                    )
                    return previous, captures_dir / f"{program_id}.json"
                if capture.url != wrong_url_reported:
                    wrong_url_reported = capture.url
                    print(
                        "Captured page does not match the requested program; still waiting: "
                        f"{capture.url}"
                    )
                baseline_mtime = latest_capture.stat().st_mtime_ns
            time.sleep(0.25)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    raise TimeoutError("timed out waiting for a fresh authenticated program capture")


def _summary(report: ProgramPreflightReport, path: Path) -> str:
    payload = {
        "program_id": report.program_id,
        "status": report.status.value,
        "execution_eligible": report.execution_eligible,
        "policy_status": report.policy_status,
        "policy_drift": report.policy_drift.value,
        "operational_status": report.operational_status,
        "operational_status_source": report.operational_status_source,
        "operational_status_evidence": report.operational_status_evidence,
        "source_capture_fresh": report.source_capture_fresh,
        "full_pentest_ready": report.full_pentest_ready,
        "blocking_reasons": list(report.blocking_reasons),
        "semantic_exclusions": list(report.semantic_exclusions),
        "reviewed_max_requests_per_second": report.reviewed_max_requests_per_second,
        "report_hash": report.report_hash,
        "report_path": str(path),
        "engagement_path": report.engagement_path,
        "attestation_path": report.attestation_path,
    }
    return json.dumps(payload, sort_keys=True, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one fail-closed ASTP program pre-flight flow")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--program-id", required=True)
    parser.add_argument("--catalog", type=Path, default=Path(".astp/program-catalog.yaml"))
    parser.add_argument("--platform", default="bughunt")
    parser.add_argument("--mode", choices=("live", "cached"), default="live")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--freshness-seconds", type=int, default=300)
    args = parser.parse_args()

    root = args.root.resolve()
    catalog = args.catalog if args.catalog.is_absolute() else root / args.catalog
    if args.freshness_seconds < 30 or args.freshness_seconds > 3600:
        parser.error("--freshness-seconds must be between 30 and 3600")
    if args.timeout_seconds < 10 or args.timeout_seconds > 1800:
        parser.error("--timeout-seconds must be between 10 and 1800")
    if args.port < 1024 or args.port > 65535:
        parser.error("--port must be between 1024 and 65535")

    try:
        previous: BugBountyProgram | None
        capture_path: Path
        if args.mode == "live":
            previous, capture_path = refresh_program_from_browser(
                root,
                program_id=args.program_id,
                catalog_path=catalog,
                platform=args.platform,
                port=args.port,
                timeout_seconds=args.timeout_seconds,
            )
        else:
            workspace = load_model(catalog, BugBountyWorkspace)
            item = _find_catalog_item(workspace, args.program_id)
            previous = _load_current_program(item)
            if not item.capture_path:
                raise ValueError("program has no synchronized authenticated capture")
            capture_path = Path(item.capture_path)

        report, report_path = evaluate_program_preflight(
            root,
            program_id=args.program_id,
            catalog_path=catalog,
            capture_path=capture_path,
            previous_program=previous,
            freshness_seconds=args.freshness_seconds,
        )
    except (FileNotFoundError, TimeoutError, ValueError, OSError) as exc:
        print(f"PREFLIGHT_BLOCKED: {exc}")
        return 2

    print(_summary(report, report_path))
    if report.execution_eligible:
        print("EXECUTION_ELIGIBLE: TRUE")
        return 0
    print("EXECUTION_ELIGIBLE: FALSE")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
