from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from astp import __version__
from astp.bug_bounty_acceptance import BugBountyV1Acceptance
from astp.ctf_acceptance import CtfAcceptanceResult

RELEASE_MILESTONE = "M49.0"
RELEASE_CHANNEL = "rc"
RELEASE_VERSION = "1.0.0rc2"

BUG_BOUNTY_REQUIRED_CHECKS = frozenset(
    {
        "program_review_complete",
        "engagement_program_binding",
        "target_registry_binding",
        "target_registry_populated",
        "stored_evidence_present",
        "evidence_manifest_integrity",
        "audit_chain_integrity",
        "assessment_bundle_integrity",
        "assessment_bundle_binding",
        "network_permit_accounting",
        "authorized_field_execution_recorded",
    }
)


class ReleaseReadinessCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    passed: bool
    detail: str


class ReleaseArtifactDigest(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    sha256: str
    size_bytes: int


class ReleaseReadinessReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    milestone: str = RELEASE_MILESTONE
    release_channel: str = RELEASE_CHANNEL
    version: str
    accepted: bool
    checks: tuple[ReleaseReadinessCheck, ...] = Field(default_factory=tuple)
    qualification_artifacts: tuple[ReleaseArtifactDigest, ...] = Field(default_factory=tuple)
    security_invariants: tuple[str, ...] = Field(default_factory=tuple)
    network_performed: bool = False


def _check(name: str, passed: bool, detail: str) -> ReleaseReadinessCheck:
    return ReleaseReadinessCheck(name=name, passed=passed, detail=detail)


def _digest(path: Path) -> ReleaseArtifactDigest:
    data = path.read_bytes()
    return ReleaseArtifactDigest(
        path=str(path.resolve()),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"expected YAML mapping: {path}")
    return payload


def _pyproject_version(repo_root: Path) -> str:
    payload = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = payload.get("project")
    if not isinstance(project, dict) or not isinstance(project.get("version"), str):
        raise TypeError("pyproject.toml is missing project.version")
    return project["version"]


def _bug_bounty_checks_consistent(report: BugBountyV1Acceptance) -> tuple[bool, str]:
    names = [item.name for item in report.checks]
    unique_names = set(names)
    missing = sorted(BUG_BOUNTY_REQUIRED_CHECKS - unique_names)
    duplicates = sorted({name for name in names if names.count(name) > 1})
    failed = sorted(item.name for item in report.checks if not item.passed)

    consistent = (
        not missing
        and not duplicates
        and not failed
        and len(names) == len(BUG_BOUNTY_REQUIRED_CHECKS)
        and report.accepted
    )
    detail_parts = [f"checks={len(names)}/{len(BUG_BOUNTY_REQUIRED_CHECKS)}"]
    if missing:
        detail_parts.append("missing=" + ",".join(missing))
    if duplicates:
        detail_parts.append("duplicates=" + ",".join(duplicates))
    if failed:
        detail_parts.append("failed=" + ",".join(failed))
    if not report.accepted:
        detail_parts.append("accepted=False")
    if consistent:
        detail_parts.append("all required M48.0 checks passed")
    return consistent, "; ".join(detail_parts)


def _ctf_case_consistency(report: CtfAcceptanceResult) -> tuple[bool, str]:
    cases = report.cases
    metrics = report.metrics
    total_cases = len(cases)
    passed_cases = sum(1 for item in cases if item.passed)
    solved_cases = sum(1 for item in cases if item.solved)
    expected_solved_cases = sum(1 for item in cases if item.expected_solved)
    false_positive_flags = sum(item.false_positive_flags for item in cases)
    reproducible_cases = sum(1 for item in cases if item.trace_reproducible)
    trace_rate = reproducible_cases / total_cases if total_cases else 0.0
    any_case_network = any(item.network_performed for item in cases)

    consistent = (
        total_cases > 0
        and all(item.passed for item in cases)
        and not any_case_network
        and metrics.total_cases == total_cases
        and metrics.passed_cases == passed_cases
        and metrics.solved_cases == solved_cases
        and metrics.expected_solved_cases == expected_solved_cases
        and metrics.false_positive_flags == false_positive_flags
        and abs(metrics.trace_reproducibility_rate - trace_rate) < 1e-12
        and report.accepted == all(item.passed for item in cases)
    )
    detail = (
        f"cases={total_cases}; passed={passed_cases}/{metrics.passed_cases}; "
        f"solved={solved_cases}/{metrics.solved_cases}; "
        f"expected={expected_solved_cases}/{metrics.expected_solved_cases}; "
        f"false_positive_flags={false_positive_flags}/{metrics.false_positive_flags}; "
        f"trace_rate={trace_rate:.3f}/{metrics.trace_reproducibility_rate:.3f}; "
        f"case_network={any_case_network}; accepted={report.accepted}"
    )
    return consistent, detail


def evaluate_release_readiness(
    *,
    repo_root: Path,
    bug_bounty_acceptance_path: Path,
    ctf_acceptance_path: Path,
) -> ReleaseReadinessReport:
    repo_root = repo_root.resolve()
    checks: list[ReleaseReadinessCheck] = []

    pyproject = repo_root / "pyproject.toml"
    init_file = repo_root / "src" / "astp" / "__init__.py"
    required_files = (
        repo_root / "README.md",
        repo_root / "docs" / "ARCHITECTURE.md",
        repo_root / "docs" / "NEXT_STEPS.md",
        repo_root / "docs" / "CTF_MODE_ROADMAP.md",
        repo_root / "docs" / "SECURITY_MODEL.md",
        repo_root / "docs" / "RELEASE_CHECKLIST.md",
        repo_root / "scripts" / "validate.ps1",
        repo_root / "docs" / "release" / "M49.0.md",
    )

    checks.append(_check("pyproject_present", pyproject.is_file(), str(pyproject)))
    checks.append(_check("package_init_present", init_file.is_file(), str(init_file)))

    try:
        project_version = _pyproject_version(repo_root)
    except (OSError, ValueError, TypeError, tomllib.TOMLDecodeError) as exc:
        project_version = "unknown"
        checks.append(_check("version_metadata_parse", False, str(exc)))
    else:
        checks.append(_check("version_metadata_parse", True, f"pyproject={project_version}"))

    version_match = project_version == __version__ == RELEASE_VERSION
    checks.append(
        _check(
            "version_consistency",
            version_match,
            f"pyproject={project_version}; package={__version__}; expected={RELEASE_VERSION}",
        )
    )

    missing = [str(path.relative_to(repo_root)) for path in required_files if not path.is_file()]
    checks.append(
        _check(
            "release_surface_complete",
            not missing,
            (
                "all required RC files are present"
                if not missing
                else "missing: " + ", ".join(missing)
            ),
        )
    )

    bug_bounty: BugBountyV1Acceptance | None = None
    try:
        bug_bounty = BugBountyV1Acceptance.model_validate(_load_yaml(bug_bounty_acceptance_path))
    except (OSError, ValueError, TypeError, UnicodeError, yaml.YAMLError) as exc:
        checks.append(_check("bug_bounty_acceptance_parse", False, str(exc)))
    else:
        checks.append(_check("bug_bounty_acceptance_parse", True, "valid M48.0 acceptance report"))
        bug_checks_ok, bug_checks_detail = _bug_bounty_checks_consistent(bug_bounty)
        checks.append(_check("bug_bounty_check_consistency", bug_checks_ok, bug_checks_detail))
        checks.append(
            _check(
                "bug_bounty_v1_accepted",
                bug_bounty.accepted and bug_bounty.network_actions > 0,
                (
                    f"accepted={bug_bounty.accepted}; actions={bug_bounty.network_actions}; "
                    f"permits={bug_bounty.permits_consumed}"
                ),
            )
        )
        checks.append(
            _check(
                "bug_bounty_permit_accounting",
                bug_bounty.network_actions == bug_bounty.permits_consumed,
                f"{bug_bounty.network_actions}/{bug_bounty.permits_consumed}",
            )
        )

    ctf: CtfAcceptanceResult | None = None
    try:
        ctf = CtfAcceptanceResult.model_validate(_load_yaml(ctf_acceptance_path))
    except (OSError, ValueError, TypeError, UnicodeError, yaml.YAMLError) as exc:
        checks.append(_check("ctf_acceptance_parse", False, str(exc)))
    else:
        checks.append(_check("ctf_acceptance_parse", True, "valid M48.6 acceptance report"))
        ctf_cases_ok, ctf_cases_detail = _ctf_case_consistency(ctf)
        checks.append(_check("ctf_case_consistency", ctf_cases_ok, ctf_cases_detail))
        checks.append(
            _check(
                "ctf_v1_accepted",
                ctf.accepted and ctf.metrics.total_cases > 0,
                f"accepted={ctf.accepted}; cases={ctf.metrics.total_cases}",
            )
        )
        checks.append(
            _check(
                "ctf_trace_reproducibility",
                ctf.metrics.trace_reproducibility_rate == 1.0,
                f"rate={ctf.metrics.trace_reproducibility_rate:.3f}",
            )
        )
        checks.append(
            _check(
                "ctf_acceptance_offline",
                not ctf.network_performed and not any(item.network_performed for item in ctf.cases),
                (
                    f"network_performed={ctf.network_performed}; "
                    f"case_network={any(item.network_performed for item in ctf.cases)}"
                ),
            )
        )

    artifacts: list[ReleaseArtifactDigest] = []
    for path in (bug_bounty_acceptance_path, ctf_acceptance_path):
        if path.is_file():
            artifacts.append(_digest(path))

    invariants = (
        "authorization precedes target execution",
        "discovery and analysis do not silently authorize network activity",
        "network actions require exact fresh permits",
        "consumed permits are never automatically replayed",
        "offline analyzers do not retrieve discovered URLs",
        "signals do not become confirmed vulnerabilities without proof",
        "CTF automation obeys challenge rules and uses bounded adapters",
        "CTF local acceptance never exercises the network branch",
    )
    accepted = all(item.passed for item in checks)
    return ReleaseReadinessReport(
        version=__version__,
        accepted=accepted,
        checks=tuple(checks),
        qualification_artifacts=tuple(artifacts),
        security_invariants=invariants,
    )


def release_info() -> dict[str, Any]:
    return {
        "version": __version__,
        "expected_version": RELEASE_VERSION,
        "milestone": RELEASE_MILESTONE,
        "release_channel": RELEASE_CHANNEL,
        "network_performed": False,
    }


def write_release_readiness(report: ReleaseReadinessReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        yaml.safe_dump(report.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
