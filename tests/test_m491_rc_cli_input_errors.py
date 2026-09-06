from pathlib import Path

import pytest
from typer.testing import CliRunner

from astp.cli import app

runner = CliRunner()


def _assert_clean_cli_failure(result) -> None:
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert result.exception is not None


@pytest.mark.parametrize(
    "args",
    [
        ["show-engagement", "missing.yaml"],
        ["compile-scope", "missing.yaml"],
        ["validate-test-dsl", "missing.yaml"],
        ["ctf-intake", "missing.yaml", "--output", "ctf-intake-output.yaml"],
        ["ctf-analyze", "missing.yaml", "--output", "ctf-analysis-output.yaml"],
        [
            "ctf-solve-local",
            "missing-challenge.yaml",
            "missing-analysis.yaml",
            "--output",
            "ctf-solve-output.yaml",
        ],
        [
            "ctf-verify-flags",
            "missing-challenge.yaml",
            "missing-solve.yaml",
            "--output",
            "ctf-verify-output.yaml",
        ],
    ],
)
def test_rc001_missing_input_file_is_clean_cli_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, args)

    _assert_clean_cli_failure(result)
    assert "input file does not exist" in result.output.lower()
    assert list(tmp_path.glob("*output.yaml")) == []


def test_rc001_malformed_yaml_is_clean_cli_error(tmp_path: Path) -> None:
    challenge = tmp_path / "broken.yaml"
    output = tmp_path / "output.yaml"
    challenge.write_text("id: broken\ntitle: [this is\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["ctf-intake", str(challenge), "--output", str(output)],
    )

    _assert_clean_cli_failure(result)
    assert "invalid yaml" in result.output.lower()
    assert not output.exists()


def test_rc001_non_mapping_yaml_is_clean_cli_error(tmp_path: Path) -> None:
    challenge = tmp_path / "list.yaml"
    output = tmp_path / "output.yaml"
    challenge.write_text("- one\n- two\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["ctf-intake", str(challenge), "--output", str(output)],
    )

    _assert_clean_cli_failure(result)
    assert "expected a yaml object" in result.output.lower()
    assert not output.exists()


def test_rc001_schema_validation_is_clean_cli_error(tmp_path: Path) -> None:
    challenge = tmp_path / "invalid-schema.yaml"
    output = tmp_path / "output.yaml"
    challenge.write_text(
        """\
    schema_version: "1"
    id: rc-negative
    title: RC negative test
    category: misc
    artifacts: []
    allow_ai: false
    allow_automation: false
    network_policy: invalid-policy
    """,
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["ctf-intake", str(challenge), "--output", str(output)],
    )

    _assert_clean_cli_failure(result)
    assert "input validation failed" in result.output.lower()
    assert "flag_pattern" in result.output
    assert "network_policy" in result.output
    assert not output.exists()


def test_rc001_invalid_utf8_is_clean_cli_error(tmp_path: Path) -> None:
    challenge = tmp_path / "invalid-utf8.yaml"
    output = tmp_path / "output.yaml"
    challenge.write_bytes(b"\xff\xfe\x00\x00")

    result = runner.invoke(
        app,
        ["ctf-intake", str(challenge), "--output", str(output)],
    )

    _assert_clean_cli_failure(result)
    assert "not valid utf-8" in result.output.lower()
    assert not output.exists()
