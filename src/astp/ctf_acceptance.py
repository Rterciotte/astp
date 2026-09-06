from __future__ import annotations

import hashlib
import time
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from astp.ctf_analysis import analyze_ctf_challenge
from astp.ctf_mode import ChallengeDefinition
from astp.ctf_solver import run_local_ctf_solvers, verify_flag_candidates
from astp.io import load_model


class CtfAcceptanceCase(BaseModel):
    model_config = ConfigDict(frozen=True)

    challenge: str
    difficulty: str = "unknown"
    expected_solved: bool = True

    @field_validator("challenge")
    @classmethod
    def relative_challenge_path(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("acceptance challenge paths must stay inside the suite directory")
        return value


class CtfAcceptanceSuite(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    id: str
    cases: tuple[CtfAcceptanceCase, ...]


class CtfAcceptanceCaseResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    challenge_id: str
    category: str
    difficulty: str
    expected_solved: bool
    solved: bool
    passed: bool
    candidate_count: int
    false_positive_flags: int
    hypothesis_count: int
    adapters_run: int
    elapsed_ms: float
    trace_sha256: str
    trace_reproducible: bool
    network_performed: bool = False


class CtfAcceptanceMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)

    total_cases: int
    passed_cases: int
    solved_cases: int
    expected_solved_cases: int
    solve_rate: float
    false_positive_flags: int
    average_time_ms: float
    average_hypotheses: float
    trace_reproducibility_rate: float


class CtfAcceptanceResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    suite_id: str
    accepted: bool
    cases: tuple[CtfAcceptanceCaseResult, ...]
    metrics: CtfAcceptanceMetrics
    by_category: dict[str, CtfAcceptanceMetrics] = Field(default_factory=dict)
    by_difficulty: dict[str, CtfAcceptanceMetrics] = Field(default_factory=dict)
    network_performed: bool = False


def load_acceptance_suite(path: Path) -> CtfAcceptanceSuite:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("CTF acceptance suite must be a YAML mapping")
    return CtfAcceptanceSuite.model_validate(payload)


def _trace_digest(verification: object) -> str:
    # Pydantic model JSON is stable because trace ordering is deterministic.
    rendered = verification.model_dump_json()
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _metrics(rows: list[CtfAcceptanceCaseResult]) -> CtfAcceptanceMetrics:
    count = len(rows)
    if count == 0:
        return CtfAcceptanceMetrics(
            total_cases=0,
            passed_cases=0,
            solved_cases=0,
            expected_solved_cases=0,
            solve_rate=0.0,
            false_positive_flags=0,
            average_time_ms=0.0,
            average_hypotheses=0.0,
            trace_reproducibility_rate=0.0,
        )
    expected = sum(1 for row in rows if row.expected_solved)
    solved_expected = sum(1 for row in rows if row.expected_solved and row.solved)
    return CtfAcceptanceMetrics(
        total_cases=count,
        passed_cases=sum(1 for row in rows if row.passed),
        solved_cases=sum(1 for row in rows if row.solved),
        expected_solved_cases=expected,
        solve_rate=(solved_expected / expected if expected else 1.0),
        false_positive_flags=sum(row.false_positive_flags for row in rows),
        average_time_ms=sum(row.elapsed_ms for row in rows) / count,
        average_hypotheses=sum(row.hypothesis_count for row in rows) / count,
        trace_reproducibility_rate=sum(1 for row in rows if row.trace_reproducible) / count,
    )


def run_ctf_acceptance(suite_path: Path) -> CtfAcceptanceResult:
    suite = load_acceptance_suite(suite_path)
    suite_dir = suite_path.parent.resolve()
    rows: list[CtfAcceptanceCaseResult] = []

    for case in suite.cases:
        challenge_path = (suite_dir / case.challenge).resolve()
        if suite_dir not in challenge_path.parents and challenge_path != suite_dir:
            raise ValueError("acceptance challenge escaped suite directory")
        challenge = load_model(challenge_path, ChallengeDefinition)
        if not challenge.allow_automation:
            raise ValueError(f"acceptance case forbids automation: {challenge.id}")
        if challenge.authorized_endpoints:
            # Acceptance is intentionally local-only. Network-capable challenges may still
            # have local artifacts, but this suite never exercises their endpoint branch.
            pass

        started = time.perf_counter()
        analysis = analyze_ctf_challenge(challenge, challenge_path.parent)
        solve = run_local_ctf_solvers(challenge, challenge_path.parent, analysis)
        verification = verify_flag_candidates(challenge, solve)
        elapsed_ms = (time.perf_counter() - started) * 1000

        analysis2 = analyze_ctf_challenge(challenge, challenge_path.parent)
        solve2 = run_local_ctf_solvers(challenge, challenge_path.parent, analysis2)
        verification2 = verify_flag_candidates(challenge, solve2)
        digest1 = _trace_digest(verification)
        digest2 = _trace_digest(verification2)
        matched = sum(1 for item in verification.verified if item.matches_declared_pattern)
        false_flags = max(0, matched - (1 if verification.solved else 0))
        passed = verification.solved == case.expected_solved and digest1 == digest2
        rows.append(
            CtfAcceptanceCaseResult(
                challenge_id=challenge.id,
                category=challenge.category.value,
                difficulty=case.difficulty,
                expected_solved=case.expected_solved,
                solved=verification.solved,
                passed=passed,
                candidate_count=len(solve.candidates),
                false_positive_flags=false_flags,
                hypothesis_count=len(analysis.hypothesis_graph.hypotheses),
                adapters_run=len(solve.adapters_run),
                elapsed_ms=elapsed_ms,
                trace_sha256=digest1,
                trace_reproducible=digest1 == digest2,
            )
        )

    category_metrics = {
        key: _metrics([row for row in rows if row.category == key])
        for key in sorted({row.category for row in rows})
    }
    difficulty_metrics = {
        key: _metrics([row for row in rows if row.difficulty == key])
        for key in sorted({row.difficulty for row in rows})
    }
    metrics = _metrics(rows)
    return CtfAcceptanceResult(
        suite_id=suite.id,
        accepted=bool(rows) and all(row.passed for row in rows),
        cases=tuple(rows),
        metrics=metrics,
        by_category=category_metrics,
        by_difficulty=difficulty_metrics,
    )
