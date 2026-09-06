from __future__ import annotations

from pathlib import Path

import yaml

from astp import __version__
from astp.bug_bounty_acceptance import AcceptanceCheck, BugBountyV1Acceptance
from astp.ctf_acceptance import (
    CtfAcceptanceCaseResult,
    CtfAcceptanceMetrics,
    CtfAcceptanceResult,
)
from astp.release_readiness import (
    BUG_BOUNTY_REQUIRED_CHECKS,
    RELEASE_VERSION,
    evaluate_release_readiness,
    release_info,
)


def _write_yaml(path: Path, payload: dict) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _bug_bounty_report(path: Path, *, accepted: bool = True, permits: int = 1) -> Path:
    checks = tuple(
        AcceptanceCheck(name=name, passed=True, detail="qualified")
        for name in sorted(BUG_BOUNTY_REQUIRED_CHECKS)
    )
    report = BugBountyV1Acceptance(
        program_id="program-1",
        engagement_id="program-1",
        checks=checks,
        accepted=accepted,
        evidence_records=1,
        target_records=1,
        network_actions=1,
        permits_consumed=permits,
    )
    _write_yaml(path, report.model_dump(mode="json"))
    return path


def _ctf_case(index: int, *, passed: bool = True) -> CtfAcceptanceCaseResult:
    return CtfAcceptanceCaseResult(
        challenge_id=f"case-{index}",
        category="misc",
        difficulty="rc",
        expected_solved=True,
        solved=True,
        passed=passed,
        candidate_count=1,
        false_positive_flags=0,
        hypothesis_count=1,
        adapters_run=1,
        elapsed_ms=1.0,
        trace_sha256=f"{index:064x}",
        trace_reproducible=True,
    )


def _ctf_report(
    path: Path,
    *,
    accepted: bool = True,
    reproducibility: float = 1.0,
    network_performed: bool = False,
) -> Path:
    cases = tuple(_ctf_case(index) for index in range(8))
    metrics = CtfAcceptanceMetrics(
        total_cases=8,
        passed_cases=8,
        solved_cases=8,
        expected_solved_cases=8,
        solve_rate=1.0,
        false_positive_flags=0,
        average_time_ms=1.0,
        average_hypotheses=1.0,
        trace_reproducibility_rate=reproducibility,
    )
    report = CtfAcceptanceResult(
        suite_id="rc-suite",
        accepted=accepted,
        cases=cases,
        metrics=metrics,
        network_performed=network_performed,
    )
    _write_yaml(path, report.model_dump(mode="json"))
    return path


def test_release_version_metadata_is_synchronized() -> None:
    info = release_info()
    assert __version__ == RELEASE_VERSION == "1.0.0"
    assert info["version"] == "1.0.0"
    assert info["milestone"] == "M50.0"
    assert info["network_performed"] is False


def test_release_readiness_passes_with_qualified_reports(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    bug = _bug_bounty_report(tmp_path / "bug.yaml")
    ctf = _ctf_report(tmp_path / "ctf.yaml")

    result = evaluate_release_readiness(
        repo_root=repo_root,
        bug_bounty_acceptance_path=bug,
        ctf_acceptance_path=ctf,
    )

    assert result.accepted is True
    assert result.network_performed is False
    assert len(result.qualification_artifacts) == 2
    assert all(len(item.sha256) == 64 for item in result.qualification_artifacts)
    assert all(check.passed for check in result.checks)


def test_release_readiness_fails_on_permit_accounting_mismatch(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    bug = _bug_bounty_report(tmp_path / "bug.yaml", permits=0)
    ctf = _ctf_report(tmp_path / "ctf.yaml")

    result = evaluate_release_readiness(
        repo_root=repo_root,
        bug_bounty_acceptance_path=bug,
        ctf_acceptance_path=ctf,
    )

    assert result.accepted is False
    check = next(item for item in result.checks if item.name == "bug_bounty_permit_accounting")
    assert check.passed is False


def test_release_readiness_fails_on_nonreproducible_ctf_trace(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    bug = _bug_bounty_report(tmp_path / "bug.yaml")
    ctf = _ctf_report(tmp_path / "ctf.yaml", reproducibility=0.875)

    result = evaluate_release_readiness(
        repo_root=repo_root,
        bug_bounty_acceptance_path=bug,
        ctf_acceptance_path=ctf,
    )

    assert result.accepted is False
    check = next(item for item in result.checks if item.name == "ctf_trace_reproducibility")
    assert check.passed is False


def test_release_readiness_rejects_ctf_acceptance_that_used_network(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    bug = _bug_bounty_report(tmp_path / "bug.yaml")
    ctf = _ctf_report(tmp_path / "ctf.yaml", network_performed=True)

    result = evaluate_release_readiness(
        repo_root=repo_root,
        bug_bounty_acceptance_path=bug,
        ctf_acceptance_path=ctf,
    )

    assert result.accepted is False
    check = next(item for item in result.checks if item.name == "ctf_acceptance_offline")
    assert check.passed is False
