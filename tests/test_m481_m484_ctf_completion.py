from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from astp.cli import app
from astp.ctf_analysis import CtfArtifactKind, analyze_ctf_challenge
from astp.ctf_mode import ChallengeDefinition, CtfCategory, CtfNetworkPolicy
from astp.ctf_network import ensure_ctf_http_target_authorized
from astp.ctf_solver import run_local_ctf_solvers, verify_flag_candidates

runner = CliRunner()


def _challenge(*, allow_automation: bool = True) -> ChallengeDefinition:
    return ChallengeDefinition(
        id="demo",
        title="Demo challenge",
        category=CtfCategory.MISC,
        artifacts=("note.txt",),
        authorized_endpoints=("https://ctf.example.test/challenge",),
        flag_pattern=r"FLAG\{[A-Za-z0-9_-]+\}",
        allow_ai=True,
        allow_automation=allow_automation,
        network_policy=CtfNetworkPolicy.DECLARED_ENDPOINTS_ONLY,
    )


def test_m481_classifies_artifacts_and_builds_network_gated_hypothesis(tmp_path: Path):
    (tmp_path / "note.txt").write_text("hello FLAG{demo}", encoding="utf-8")
    result = analyze_ctf_challenge(_challenge(), tmp_path)

    assert result.network_performed is False
    assert result.classifications[0].kind is CtfArtifactKind.TEXT
    assert result.classifications[0].eligible_adapters == ("text-pattern",)
    network_hypotheses = [
        item for item in result.hypothesis_graph.hypotheses if item.requires_network
    ]
    assert len(network_hypotheses) == 1
    assert network_hypotheses[0].requires_fresh_permit is True


def test_m482_local_solver_uses_structured_adapters_without_shell_or_network(tmp_path: Path):
    (tmp_path / "note.txt").write_text("prefix FLAG{demo} suffix", encoding="utf-8")
    challenge = _challenge()
    analysis = analyze_ctf_challenge(challenge, tmp_path)
    solve = run_local_ctf_solvers(challenge, tmp_path, analysis)

    assert solve.external_processes_spawned is False
    assert solve.network_performed is False
    assert "text-pattern" in solve.adapters_run
    assert [candidate.value for candidate in solve.candidates] == ["FLAG{demo}"]


def test_m482_local_solver_rejects_artifact_changed_after_analysis(tmp_path: Path):
    artifact = tmp_path / "note.txt"
    artifact.write_text("FLAG{demo}", encoding="utf-8")
    challenge = _challenge()
    analysis = analyze_ctf_challenge(challenge, tmp_path)
    artifact.write_text("FLAG{changed}", encoding="utf-8")

    with pytest.raises(ValueError, match="changed after analysis"):
        run_local_ctf_solvers(challenge, tmp_path, analysis)


def test_m482_local_solver_fails_closed_when_automation_is_disallowed(tmp_path: Path):
    (tmp_path / "note.txt").write_text("FLAG{demo}", encoding="utf-8")
    challenge = _challenge(allow_automation=False)
    analysis = analyze_ctf_challenge(challenge, tmp_path)

    with pytest.raises(ValueError, match="do not allow automation"):
        run_local_ctf_solvers(challenge, tmp_path, analysis)


def test_m483_ctf_network_path_requires_exact_declared_endpoint():
    challenge = _challenge()
    assert (
        ensure_ctf_http_target_authorized(challenge, "https://ctf.example.test/challenge")
        == "https://ctf.example.test/challenge"
    )
    with pytest.raises(ValueError, match="exact declared"):
        ensure_ctf_http_target_authorized(challenge, "https://ctf.example.test/other")


def test_m484_flag_verification_emits_reproducible_trace(tmp_path: Path):
    (tmp_path / "note.txt").write_text("FLAG{demo}", encoding="utf-8")
    challenge = _challenge()
    analysis = analyze_ctf_challenge(challenge, tmp_path)
    solve = run_local_ctf_solvers(challenge, tmp_path, analysis)
    verified = verify_flag_candidates(challenge, solve)

    assert verified.solved is True
    assert len(verified.verified) == 1
    assert verified.verified[0].matches_declared_pattern is True
    assert len(verified.solve_trace) > len(solve.trace)
    assert verified.network_performed is False


def test_m481_m484_commands_are_exposed():
    for command in ("ctf-analyze", "ctf-solve-local", "ctf-observe-http", "ctf-verify-flags"):
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0, result.stdout

    observe_help = runner.invoke(app, ["ctf-observe-http", "--help"])
    assert "permit" in observe_help.stdout.lower()
    assert "GET or HEAD" in observe_help.stdout
