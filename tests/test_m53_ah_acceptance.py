import json

import pytest

from astp.m53_ah_acceptance import build_ah_acceptance


def _write_campaign(root):
    (root / "round-1" / "campaign" / "runs" / "run-a").mkdir(parents=True)
    programs = []
    scheduler_programs = {}
    leases = {}
    events = []
    for key in "ABCDEFGH":
        programs.append(
            {
                "program_id": key,
                "state": "BLOCKED_POLICY" if key == "B" else "COMPLETED",
                "reason": None,
            }
        )
        scheduler_programs[key] = {"revision": "2" if key == "F" else "1"}
        if key != "B":
            leases[f"lease-{key}"] = {"status": "active", "lease": {"program_id": key}}
    result = {
        "detector_run_id": "run-a",
        "target": "http://local.test/evidence",
        "authorization": {"payload": {"program_id": "A", "permit_id": "permit-a"}},
        "accounting": {
            "attempted": 0,
            "forwarded": 0,
            "responses": 0,
            "blocked_before_io": 0,
            "failed_after_io": 0,
            "unknown_outcomes": 0,
        },
        "artifacts": {"evidence_ids": ["evidence-a"]},
        "proof_after": "reproduced",
        "finding_id": "finding-a",
    }
    (root / "round-1" / "campaign" / "runs" / "run-a" / "result.json").write_text(
        json.dumps(result)
    )
    (root / "full-night-report.json").write_text(
        json.dumps({"campaign_id": "campaign", "programs": programs, "orphan_workers_remaining": 0})
    )
    (root / "scheduler-trace.json").write_text(
        json.dumps({"programs": scheduler_programs, "events": events})
    )
    (root / "operational-leases.json").write_text(json.dumps({"leases": leases}))
    (root / "round-1" / "campaign" / "revision-invalidation.json").write_text(
        json.dumps({"stale_permit_id": "permit-stale-f"})
    )


def test_ah_acceptance_reconstructs_all_required_program_fields(tmp_path):
    _write_campaign(tmp_path)
    report = build_ah_acceptance(tmp_path)
    assert report.status == "PASS"
    assert report.marker == "M53_LOCAL_AH_ACCEPTANCE_PASS"
    assert [row.program for row in report.programs] == list("ABCDEFGH")
    assert report.programs[1].authorization == "blocked_by_policy"
    assert report.programs[2].policy_status == "semantic_exclusion_blocked_then_reviewed_allowed"
    assert report.programs[5].revision == "2"
    assert report.invariants.model_dump() == {
        key: 0 for key in type(report.invariants).model_fields
    }


def test_ah_acceptance_oracle_rejects_permit_reuse(tmp_path):
    _write_campaign(tmp_path)
    source = tmp_path / "round-1" / "campaign" / "runs" / "run-a" / "result.json"
    duplicate = json.loads(source.read_text())
    duplicate["detector_run_id"] = "run-c"
    duplicate["authorization"]["payload"]["program_id"] = "C"
    target = tmp_path / "round-1" / "campaign" / "runs" / "run-c"
    target.mkdir()
    (target / "result.json").write_text(json.dumps(duplicate))
    with pytest.raises(RuntimeError, match="global acceptance invariant"):
        build_ah_acceptance(tmp_path)


def test_ah_acceptance_oracle_rejects_forward_without_proxy_ledger(tmp_path):
    _write_campaign(tmp_path)
    source = tmp_path / "round-1" / "campaign" / "runs" / "run-a" / "result.json"
    result = json.loads(source.read_text())
    result["accounting"].update({"attempted": 1, "forwarded": 1, "responses": 1})
    source.write_text(json.dumps(result))
    with pytest.raises(RuntimeError, match="global acceptance invariant"):
        build_ah_acceptance(tmp_path)
