from __future__ import annotations

import base64
from pathlib import Path

import yaml

from astp.ctf_acceptance import run_ctf_acceptance
from astp.ctf_analysis import analyze_ctf_challenge
from astp.ctf_mode import ChallengeDefinition
from astp.ctf_solver import run_local_ctf_solvers, verify_flag_candidates


def _challenge(tmp_path: Path, *, category: str, artifact: str, data: bytes) -> ChallengeDefinition:
    (tmp_path / artifact).write_bytes(data)
    return ChallengeDefinition.model_validate(
        {
            "id": f"case-{category}",
            "title": category,
            "category": category,
            "artifacts": [artifact],
            "flag_pattern": r"FLAG\{[A-Za-z0-9_-]+\}",
            "allow_ai": True,
            "allow_automation": True,
            "network_policy": "disabled",
        }
    )


def test_crypto_encoding_layer_finds_base64_flag(tmp_path: Path) -> None:
    encoded = base64.b64encode(b"FLAG{encoded_layer}")
    challenge = _challenge(tmp_path, category="crypto", artifact="cipher.txt", data=encoded)
    analysis = analyze_ctf_challenge(challenge, tmp_path)
    assert "encoding-layers" in analysis.classifications[0].eligible_adapters
    solve = run_local_ctf_solvers(challenge, tmp_path, analysis)
    verified = verify_flag_candidates(challenge, solve)
    assert verified.solved is True


def test_web_route_adapter_is_structured_and_local(tmp_path: Path) -> None:
    challenge = _challenge(
        tmp_path,
        category="web",
        artifact="app.js",
        data=b'const p="/api/challenge"; const f="FLAG{web_local}";',
    )
    analysis = analyze_ctf_challenge(challenge, tmp_path)
    assert "web-route-hints" in analysis.classifications[0].eligible_adapters
    solve = run_local_ctf_solvers(challenge, tmp_path, analysis)
    assert solve.network_performed is False
    assert solve.external_processes_spawned is False


def test_binary_category_metadata_adapters_are_bounded(tmp_path: Path) -> None:
    pe = _challenge(
        tmp_path,
        category="reverse",
        artifact="sample.exe",
        data=b"MZ" + b"\x00" * 100 + b"FLAG{reverse_strings}",
    )
    analysis = analyze_ctf_challenge(pe, tmp_path)
    assert "executable-metadata" in analysis.classifications[0].eligible_adapters
    solve = run_local_ctf_solvers(pe, tmp_path, analysis)
    assert verify_flag_candidates(pe, solve).solved is True


def test_acceptance_suite_tracks_metrics_and_reproducibility(tmp_path: Path) -> None:
    cases = [
        ("web", "web.js", b'const x="FLAG{web}";'),
        ("api", "api.json", b'{"flag":"FLAG{api}"}'),
        ("reverse", "rev.bin", b"\x00\xffFLAG{reverse}\x00"),
        ("pwn", "pwn.bin", b"\x00\xffFLAG{pwn}\x00"),
        ("crypto", "crypto.txt", base64.b64encode(b"FLAG{crypto}")),
        ("forensics", "forensics.bin", b"\x00\xffFLAG{forensics}\x00"),
        ("osint", "osint.txt", b"FLAG{osint}"),
        ("misc", "misc.txt", b"FLAG{misc}"),
    ]
    suite_cases = []
    for index, (category, artifact, data) in enumerate(cases):
        case_dir = tmp_path / f"case-{index}"
        case_dir.mkdir()
        (case_dir / artifact).write_bytes(data)
        challenge_path = case_dir / "challenge.yaml"
        challenge_path.write_text(
            yaml.safe_dump(
                {
                    "schema_version": "1",
                    "id": f"accept-{category}",
                    "title": category,
                    "category": category,
                    "artifacts": [artifact],
                    "flag_pattern": r"FLAG\{[A-Za-z0-9_-]+\}",
                    "allow_ai": True,
                    "allow_automation": True,
                    "network_policy": "disabled",
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        suite_cases.append(
            {
                "challenge": str(challenge_path.relative_to(tmp_path)),
                "difficulty": "synthetic",
                "expected_solved": True,
            }
        )
    suite_path = tmp_path / "suite.yaml"
    suite_path.write_text(
        yaml.safe_dump(
            {"schema_version": "1", "id": "synthetic-all-categories", "cases": suite_cases},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    result = run_ctf_acceptance(suite_path)
    assert result.accepted is True
    assert result.metrics.total_cases == 8
    assert result.metrics.solve_rate == 1.0
    assert result.metrics.trace_reproducibility_rate == 1.0
    assert result.network_performed is False
    assert set(result.by_category) == {item[0] for item in cases}


def test_acceptance_rejects_path_escape(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.yaml"
    suite_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "id": "bad",
                "cases": [{"challenge": "../challenge.yaml"}],
            }
        ),
        encoding="utf-8",
    )
    try:
        run_ctf_acceptance(suite_path)
    except ValueError as exc:
        assert "inside the suite directory" in str(exc)
    else:
        raise AssertionError("path escape should fail closed")
