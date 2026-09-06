from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict

from astp.io import load_model
from astp.models import Engagement, target_in_scope


class RedirectContinuationCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    source_session_id: str
    source_provenance_hash: str
    source_evidence_id: str
    source_permit_id: str
    source_action_id: str
    source_target: str
    redirect_target: str
    method: str = "GET"
    requires_fresh_preflight: bool = True
    requires_new_permit: bool = True
    automatic_redirect_follow: bool = False
    state_changing: bool = False
    broad_scanning: bool = False
    candidate_hash: str


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _load_json_mapping(path: Path) -> dict[str, object]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(f"expected JSON mapping: {path}")
    return raw


def _load_yaml_mapping(path: Path) -> dict[str, object]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(f"expected YAML mapping: {path}")
    return raw


def _verify_embedded_hash(payload: dict[str, object], field: str) -> str:
    claimed = str(payload.get(field) or "")
    if not claimed:
        raise ValueError(f"missing {field}")
    unhashed = dict(payload)
    unhashed.pop(field, None)
    if _sha256(unhashed) != claimed:
        raise ValueError(f"{field} integrity verification failed")
    return claimed


def _write_json_immutable(path: Path, payload: dict[str, object]) -> None:
    rendered = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            raise ValueError(f"immutable redirect candidate collision: {path}")
        return
    path.write_text(rendered, encoding="utf-8")


def _resolve_engagement_path(source_assessment_dir: Path, raw_path: object) -> Path:
    value = str(raw_path or "").strip()
    if not value:
        raise ValueError("source preparation does not contain an engagement path")

    path = Path(value)
    if path.is_absolute():
        return path

    # Preparation artifacts may contain repository-relative paths. Resolve those
    # from the current repository root first. For self-contained test/assessment
    # fixtures, also accept a path relative to the source assessment directory.
    cwd_candidate = (Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate

    assessment_candidate = (source_assessment_dir / path).resolve()
    if assessment_candidate.exists():
        return assessment_candidate

    return cwd_candidate


def build_redirect_continuation_candidate(
    source_assessment_dir: Path,
) -> RedirectContinuationCandidate:
    provenance_files = sorted(source_assessment_dir.glob("network-provenance-*.json"))
    if len(provenance_files) != 1:
        raise ValueError("source assessment must contain exactly one network provenance artifact")
    provenance_path = provenance_files[0]
    provenance = _load_json_mapping(provenance_path)
    provenance_hash = _verify_embedded_hash(provenance, "provenance_hash")
    if provenance_path.name != f"network-provenance-{provenance_hash}.json":
        raise ValueError("network provenance filename is not hash-bound")
    if provenance.get("network_state") != "HTTP_RESPONSE_OBSERVED":
        raise ValueError("source assessment does not prove HTTP_RESPONSE_OBSERVED")
    if provenance.get("network_execution_performed") is not True:
        raise ValueError("source assessment does not prove prior network execution")

    result = _load_yaml_mapping(source_assessment_dir / "assessment-result.yaml")
    if result.get("session_id") != provenance.get("session_id"):
        raise ValueError("assessment result/provenance session binding mismatch")
    if result.get("network_provenance_hash") != provenance_hash:
        raise ValueError("assessment result is not bound to source network provenance")
    if result.get("network_state") != "HTTP_RESPONSE_OBSERVED":
        raise ValueError("assessment result network state is not response-backed")
    if result.get("network_execution_performed") is not True:
        raise ValueError("assessment result does not record response-backed execution")

    rows = provenance.get("response_evidence")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError("redirect continuation requires exactly one response evidence record")
    row = rows[0]
    redirect_target = str(row.get("redirect_target") or "")
    if not redirect_target:
        raise ValueError("source response contains no redirect target")
    if row.get("redirect_followed") is not False:
        raise ValueError("source redirect must have remained unfollowed")
    if row.get("redirect_requires_new_permit") is not True:
        raise ValueError("source redirect must explicitly require a new permit")
    status_code = int(row.get("status_code", 0))
    if status_code < 300 or status_code > 399:
        raise ValueError("source response is not an HTTP redirect")

    parsed = urlsplit(redirect_target)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("redirect continuation requires an exact HTTPS target")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("redirect target must not contain credentials or a fragment")

    preparation_files = sorted(source_assessment_dir.glob("preparation-*.json"))
    if len(preparation_files) != 1:
        raise ValueError("source assessment must contain exactly one preparation artifact")
    preparation = _load_json_mapping(preparation_files[0])
    engagement_path = _resolve_engagement_path(
        source_assessment_dir,
        preparation.get("engagement_path"),
    )
    engagement = load_model(engagement_path, Engagement)
    if not target_in_scope(redirect_target, engagement.scope):
        raise ValueError("redirect target is outside the source compiled engagement scope")

    payload: dict[str, object] = {
        "schema_version": "1",
        "source_session_id": str(provenance["session_id"]),
        "source_provenance_hash": provenance_hash,
        "source_evidence_id": str(row.get("evidence_id") or ""),
        "source_permit_id": str(row.get("permit_id") or ""),
        "source_action_id": str(row.get("action_id") or ""),
        "source_target": str(row.get("target") or ""),
        "redirect_target": redirect_target,
        "method": "GET",
        "requires_fresh_preflight": True,
        "requires_new_permit": True,
        "automatic_redirect_follow": False,
        "state_changing": False,
        "broad_scanning": False,
    }
    if (
        not payload["source_evidence_id"]
        or not payload["source_permit_id"]
        or not payload["source_action_id"]
    ):
        raise ValueError("source response evidence lacks permit/action/evidence binding")
    payload["candidate_hash"] = _sha256(payload)
    return RedirectContinuationCandidate.model_validate(payload)


def persist_redirect_continuation_candidate(
    source_assessment_dir: Path,
) -> tuple[RedirectContinuationCandidate, Path]:
    candidate = build_redirect_continuation_candidate(source_assessment_dir)
    path = source_assessment_dir / f"redirect-candidate-{candidate.candidate_hash}.json"
    _write_json_immutable(path, candidate.model_dump(mode="json"))
    return candidate, path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Derive one fail-closed redirect continuation candidate from stored field evidence"
    )
    parser.add_argument("--source-assessment", type=Path, required=True)
    args = parser.parse_args()
    try:
        candidate, path = persist_redirect_continuation_candidate(args.source_assessment.resolve())
    except (OSError, TypeError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"REDIRECT_CONTINUATION_BLOCKED: {exc}")
        return 2
    print(
        json.dumps(
            {**candidate.model_dump(mode="json"), "candidate_path": str(path)},
            indent=2,
            sort_keys=True,
        )
    )
    print("REDIRECT_CONTINUATION_CANDIDATE: READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
