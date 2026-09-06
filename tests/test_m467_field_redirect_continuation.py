import hashlib
import json
from pathlib import Path

import pytest
import yaml

from astp.field_redirect_continuation import build_redirect_continuation_candidate
from astp.io import dump_yaml
from astp.models import Engagement, ScopeKind, ScopePolicy, ScopeRule


def _hash(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def _fixture(
    tmp_path: Path,
    *,
    followed: bool = False,
    requires: bool = True,
    target: str = "https://www.smartfit.com.br/",
):
    engagement = Engagement(
        id="e",
        name="E",
        scope=ScopePolicy(
            allowed=[
                ScopeRule(
                    kind=ScopeKind.WILDCARD_DOMAIN,
                    value="*.smartfit.com.br",
                )
            ]
        ),
    )
    engagement_path = tmp_path / "engagement.yaml"
    engagement_path.write_text(dump_yaml(engagement), encoding="utf-8")

    (tmp_path / "preparation-a.json").write_text(
        json.dumps({"engagement_path": str(engagement_path)}),
        encoding="utf-8",
    )

    provenance = {
        "schema_version": "1",
        "session_id": "s",
        "network_state": "HTTP_RESPONSE_OBSERVED",
        "network_execution_performed": True,
        "execution_status_hash": "x",
        "execution_status_path": "x",
        "response_evidence": [
            {
                "evidence_id": "ev",
                "permit_id": "p1",
                "action_id": "a1",
                "target": "https://smartfit.com/",
                "status_code": 301,
                "redirect_target": target,
                "redirect_followed": followed,
                "redirect_requires_new_permit": requires,
            }
        ],
    }
    provenance["provenance_hash"] = _hash(provenance)

    (tmp_path / f"network-provenance-{provenance['provenance_hash']}.json").write_text(
        json.dumps(provenance),
        encoding="utf-8",
    )

    result = {
        "session_id": "s",
        "network_execution_performed": True,
        "network_state": "HTTP_RESPONSE_OBSERVED",
        "network_provenance_hash": provenance["provenance_hash"],
    }
    (tmp_path / "assessment-result.yaml").write_text(
        yaml.safe_dump(result),
        encoding="utf-8",
    )


def test_builds_unfollowed_in_scope_redirect_candidate(tmp_path):
    _fixture(tmp_path)

    result = build_redirect_continuation_candidate(tmp_path)

    assert result.redirect_target == "https://www.smartfit.com.br/"
    assert result.requires_new_permit is True
    assert result.requires_fresh_preflight is True
    assert result.automatic_redirect_follow is False
    assert result.state_changing is False
    assert result.broad_scanning is False


def test_rejects_already_followed_redirect(tmp_path):
    _fixture(tmp_path, followed=True)

    with pytest.raises(ValueError, match="unfollowed"):
        build_redirect_continuation_candidate(tmp_path)


def test_rejects_redirect_without_new_permit_requirement(tmp_path):
    _fixture(tmp_path, requires=False)

    with pytest.raises(ValueError, match="new permit"):
        build_redirect_continuation_candidate(tmp_path)


def test_rejects_out_of_scope_redirect(tmp_path):
    _fixture(tmp_path, target="https://example.com/")

    with pytest.raises(ValueError, match="outside"):
        build_redirect_continuation_candidate(tmp_path)
