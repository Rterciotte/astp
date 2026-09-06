from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from astp.bug_bounty_acceptance import AcceptanceCheck, BugBountyV1Acceptance
from astp.cli import app
from astp.ctf_acceptance import (
    CtfAcceptanceCaseResult,
    CtfAcceptanceMetrics,
    CtfAcceptanceResult,
)
from astp.release_readiness import (
    BUG_BOUNTY_REQUIRED_CHECKS,
    evaluate_release_readiness,
)

runner = CliRunner()


def _write_yaml(path: Path, payload: dict) -> Path:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _valid_bug(path: Path) -> Path:
    checks = tuple(
        AcceptanceCheck(name=name, passed=True, detail="qualified")
        for name in sorted(BUG_BOUNTY_REQUIRED_CHECKS)
    )
    report = BugBountyV1Acceptance(
        program_id="program-1",
        engagement_id="engagement-1",
        checks=checks,
        evidence_records=1,
        target_records=1,
        network_actions=1,
        permits_consumed=1,
        accepted=True,
    )
    return _write_yaml(path, report.model_dump(mode="json"))


def _case(index: int, *, passed: bool = True) -> CtfAcceptanceCaseResult:
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


def _valid_ctf(path: Path) -> Path:
    cases = tuple(_case(index) for index in range(8))
    metrics = CtfAcceptanceMetrics(
        total_cases=8,
        passed_cases=8,
        solved_cases=8,
        expected_solved_cases=8,
        solve_rate=1.0,
        false_positive_flags=0,
        average_time_ms=1.0,
        average_hypotheses=1.0,
        trace_reproducibility_rate=1.0,
    )
    report = CtfAcceptanceResult(
        suite_id="rc-suite",
        accepted=True,
        cases=cases,
        metrics=metrics,
    )
    return _write_yaml(path, report.model_dump(mode="json"))


def _check(result, name: str):
    return next(item for item in result.checks if item.name == name)


def test_rc002_rejects_failed_m48_check_despite_accepted_true(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    bug = _valid_bug(tmp_path / "bug.yaml")
    ctf = _valid_ctf(tmp_path / "ctf.yaml")
    payload = yaml.safe_load(bug.read_text(encoding="utf-8"))
    payload["checks"][0]["passed"] = False
    _write_yaml(bug, payload)

    result = evaluate_release_readiness(
        repo_root=repo_root,
        bug_bounty_acceptance_path=bug,
        ctf_acceptance_path=ctf,
    )

    assert result.accepted is False
    assert _check(result, "bug_bounty_check_consistency").passed is False


def test_rc002_rejects_empty_m48_checks_despite_accepted_true(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    bug = _valid_bug(tmp_path / "bug.yaml")
    ctf = _valid_ctf(tmp_path / "ctf.yaml")
    payload = yaml.safe_load(bug.read_text(encoding="utf-8"))
    payload["checks"] = []
    _write_yaml(bug, payload)

    result = evaluate_release_readiness(
        repo_root=repo_root,
        bug_bounty_acceptance_path=bug,
        ctf_acceptance_path=ctf,
    )

    assert result.accepted is False
    assert _check(result, "bug_bounty_check_consistency").passed is False


def test_rc002_rejects_failed_ctf_case_despite_accepted_true(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    bug = _valid_bug(tmp_path / "bug.yaml")
    ctf = _valid_ctf(tmp_path / "ctf.yaml")
    payload = yaml.safe_load(ctf.read_text(encoding="utf-8"))
    payload["cases"][0]["passed"] = False
    _write_yaml(ctf, payload)

    result = evaluate_release_readiness(
        repo_root=repo_root,
        bug_bounty_acceptance_path=bug,
        ctf_acceptance_path=ctf,
    )

    assert result.accepted is False
    assert _check(result, "ctf_case_consistency").passed is False


def test_rc002_rejects_ctf_metric_case_count_mismatch(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    bug = _valid_bug(tmp_path / "bug.yaml")
    ctf = _valid_ctf(tmp_path / "ctf.yaml")
    payload = yaml.safe_load(ctf.read_text(encoding="utf-8"))
    payload["metrics"]["passed_cases"] = 7
    _write_yaml(ctf, payload)

    result = evaluate_release_readiness(
        repo_root=repo_root,
        bug_bounty_acceptance_path=bug,
        ctf_acceptance_path=ctf,
    )

    assert result.accepted is False
    assert _check(result, "ctf_case_consistency").passed is False


def test_rc001b_release_readiness_malformed_yaml_has_no_traceback(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("checks: [\n  -\n", encoding="utf-8")
    ctf = _valid_ctf(tmp_path / "ctf.yaml")
    output = tmp_path / "readiness.yaml"

    result = runner.invoke(
        app,
        [
            "release-readiness",
            str(malformed),
            str(ctf),
            "--repo-root",
            str(repo_root),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 7
    assert "Traceback" not in result.output
    assert "ParserError" not in result.output
    assert "bug_bounty_acceptance_parse" in result.output
    assert output.is_file()
    payload = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert payload["accepted"] is False
