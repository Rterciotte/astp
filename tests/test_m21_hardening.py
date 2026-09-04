from datetime import UTC, datetime, timedelta
from pathlib import Path

from astp.action import canonical_http_target, http_action_id, http_target_rate_key
from astp.evidence_store import register_evidence, verify_evidence_manifest
from astp.rate_limit import acquire_rate_slot

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def test_canonical_http_target_normalizes_only_transport_identity() -> None:
    assert canonical_http_target("HTTPS://Example.COM:443/a/../b?x=1&x=2#fragment") == (
        "https://example.com/a/../b?x=1&x=2"
    )


def test_action_id_preserves_path_and_query_semantics() -> None:
    first = http_action_id("https://EXAMPLE.com:443/a?x=1", "get", "researcher")
    same = http_action_id("https://example.com/a?x=1#ignored", "GET", "researcher")
    different = http_action_id("https://example.com/a?x=2", "GET", "researcher")
    assert first == same
    assert first != different


def test_rate_key_cannot_be_bypassed_by_http_method_or_identity() -> None:
    target = "https://example.com/a?x=1"
    assert http_target_rate_key(target) == http_target_rate_key(target)
    assert http_action_id(target, "GET", "a") != http_action_id(target, "HEAD", "b")


def test_durable_rate_limiter_rejects_too_soon_and_allows_later(tmp_path: Path) -> None:
    state = tmp_path / "rate.json"
    accepted, wait = acquire_rate_slot(state, "target", 2, now=NOW)
    assert accepted is True
    assert wait == 0

    accepted, wait = acquire_rate_slot(state, "target", 2, now=NOW + timedelta(milliseconds=100))
    assert accepted is False
    assert 0.39 <= wait <= 0.41

    accepted, _ = acquire_rate_slot(state, "target", 2, now=NOW + timedelta(milliseconds=500))
    assert accepted is True


def test_evidence_manifest_detects_artifact_tampering(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.json"
    artifact.write_text('{"status": 200}\n', encoding="utf-8")
    manifest = tmp_path / "manifest.jsonl"
    entry = register_evidence(
        manifest,
        artifact,
        evidence_type="http.observation",
        evidence_id="evidence-1",
        action_id="action-1",
        now=NOW,
    )
    assert entry.evidence_id == "evidence-1"
    valid, _ = verify_evidence_manifest(manifest)
    assert valid is True

    artifact.write_text('{"status": 500}\n', encoding="utf-8")
    valid, message = verify_evidence_manifest(manifest)
    assert valid is False
    assert "Artifact hash mismatch" in message


def test_evidence_manifest_detects_chain_tampering(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.json"
    artifact.write_text("{}\n", encoding="utf-8")
    manifest = tmp_path / "manifest.jsonl"
    register_evidence(manifest, artifact, evidence_type="http.observation", now=NOW)
    content = manifest.read_text(encoding="utf-8").replace(
        '"evidence_type": "http.observation"', '"evidence_type": "changed"'
    )
    manifest.write_text(content, encoding="utf-8")
    valid, message = verify_evidence_manifest(manifest, verify_artifacts=False)
    assert valid is False
    assert "Entry hash mismatch" in message
