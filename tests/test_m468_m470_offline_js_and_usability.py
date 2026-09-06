from pathlib import Path

from typer.testing import CliRunner

from astp.cli import app
from astp.js_static_analysis import JavascriptSignalKind, analyze_javascript_file

runner = CliRunner()


def test_js_analyzer_hashes_exact_artifact_bytes(tmp_path: Path) -> None:
    artifact = tmp_path / "app.js"
    artifact.write_bytes(b'const api="/api/profile"; fetch(api); // TURBOPACK\n')
    result = analyze_javascript_file(artifact)
    assert result.artifact_size_bytes == artifact.stat().st_size
    assert result.network_performed is False
    kinds = {signal.kind for signal in result.signals}
    assert JavascriptSignalKind.API_HINT in kinds
    assert JavascriptSignalKind.NETWORK_CALL_HINT in kinds
    assert JavascriptSignalKind.FRAMEWORK_HINT in kinds


def test_analyze_javascript_cli_is_offline(tmp_path: Path) -> None:
    artifact = tmp_path / "app.js"
    output = tmp_path / "analysis.yaml"
    artifact.write_text('const route="/account";', encoding="utf-8")
    result = runner.invoke(app, ["analyze-javascript", str(artifact), "-o", str(output)])
    assert result.exit_code == 0, result.output
    assert "Network execution: NOT PERFORMED" in result.output
    assert "Evidence binding: NOT REQUESTED" in result.output
    assert output.is_file()


def test_doctor_is_offline() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "Network execution: NOT PERFORMED" in result.output
