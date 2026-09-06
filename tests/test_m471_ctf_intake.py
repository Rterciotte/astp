from pathlib import Path

import yaml
from typer.testing import CliRunner

from astp.cli import app
from astp.ctf_mode import ChallengeDefinition, CtfNetworkPolicy, inventory_challenge

runner = CliRunner()


def test_ctf_intake_hashes_local_artifacts_without_network(tmp_path: Path) -> None:
    artifact = tmp_path / "challenge.bin"
    artifact.write_bytes(b"CTF fixture")
    challenge = ChallengeDefinition(
        id="demo",
        title="Demo",
        category="reverse",
        artifacts=("challenge.bin",),
        flag_pattern=r"FLAG\\{.*\\}",
        allow_ai=True,
        allow_automation=True,
        network_policy=CtfNetworkPolicy.DISABLED,
    )
    result = inventory_challenge(challenge, tmp_path)
    assert result.autonomous_solving_allowed is True
    assert result.network_execution_allowed is False
    assert result.network_performed is False
    assert len(result.artifacts) == 1
    assert result.artifacts[0].sha256


def test_ctf_intake_cli_blocks_when_rules_disallow_automation(tmp_path: Path) -> None:
    challenge_path = tmp_path / "challenge.yaml"
    output = tmp_path / "intake.yaml"
    challenge_path.write_text(
        yaml.safe_dump(
            {
                "id": "demo",
                "title": "Demo",
                "category": "misc",
                "flag_pattern": r"FLAG\\{.*\\}",
                "allow_ai": False,
                "allow_automation": False,
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["ctf-intake", str(challenge_path), "-o", str(output)])
    assert result.exit_code == 0, result.output
    assert "Autonomous solving allowed by rules: NO" in result.output
    assert "Network execution: NOT PERFORMED" in result.output
    assert output.is_file()
