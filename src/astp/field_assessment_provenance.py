from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from astp.observation import HttpObservationEvidence, verify_observation_evidence


class ResponseEvidenceSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_id: str
    permit_id: str
    action_id: str
    target: str
    status_code: int
    redirect_target: str | None = None
    redirect_followed: bool | None = None
    redirect_requires_new_permit: bool | None = None


class FieldAssessmentNetworkProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    session_id: str
    network_state: str
    network_execution_performed: bool
    execution_status_hash: str
    execution_status_path: str
    response_evidence: tuple[ResponseEvidenceSummary, ...] = Field(default_factory=tuple)
    provenance_hash: str


def _canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _load_yaml_mapping(path: Path) -> dict[str, object]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(f"expected YAML mapping: {path}")
    return raw


def _write_json_immutable(path: Path, payload: dict[str, object]) -> None:
    rendered = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            raise ValueError(f"immutable provenance artifact collision: {path}")
        return
    path.write_text(rendered, encoding="utf-8")


def _find_response_evidence(
    evidence_dir: Path,
    expected_ids: set[str],
) -> tuple[ResponseEvidenceSummary, ...]:
    found: dict[str, ResponseEvidenceSummary] = {}
    for candidate in sorted(evidence_dir.glob("*.json")):
        try:
            evidence = HttpObservationEvidence.model_validate_json(
                candidate.read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            continue
        if evidence.evidence_id not in expected_ids:
            continue
        if not verify_observation_evidence(evidence):
            raise ValueError(
                f"response evidence failed integrity verification: {evidence.evidence_id}"
            )
        if evidence.transport_failure is not None:
            raise ValueError(
                f"response evidence contains transport failure: {evidence.evidence_id}"
            )
        redirect = evidence.redirect
        found[evidence.evidence_id] = ResponseEvidenceSummary(
            evidence_id=evidence.evidence_id,
            permit_id=evidence.permit_id,
            action_id=evidence.action_id,
            target=evidence.target,
            status_code=evidence.status_code,
            redirect_target=redirect.target if redirect else None,
            redirect_followed=redirect.followed if redirect else None,
            redirect_requires_new_permit=redirect.requires_new_permit if redirect else None,
        )
    missing = expected_ids - set(found)
    if missing:
        raise ValueError(
            f"execution status references missing/invalid response evidence: {sorted(missing)}"
        )
    return tuple(found[evidence_id] for evidence_id in sorted(found))


def build_network_provenance(
    *,
    status_path: Path,
    evidence_dir: Path,
    result_path: Path,
) -> FieldAssessmentNetworkProvenance:
    status = json.loads(status_path.read_text(encoding="utf-8"))
    result = _load_yaml_mapping(result_path)

    if status.get("network_state") != "HTTP_RESPONSE_OBSERVED":
        raise ValueError("execution status does not prove HTTP_RESPONSE_OBSERVED")
    if status.get("execution_succeeded") is not True:
        raise ValueError("execution status is not successful")
    if int(status.get("failed_actions", -1)) != 0:
        raise ValueError("execution status contains failed actions")
    if int(status.get("completed_actions", 0)) < 1:
        raise ValueError("execution status contains no completed action")

    session_id = str(status.get("session_id") or "")
    if not session_id or result.get("session_id") != session_id:
        raise ValueError("assessment result/session status binding mismatch")

    status_hash = str(status.get("status_hash") or "")
    if not status_hash or status_path.name != f"execution-status-{status_hash}.json":
        raise ValueError("execution status path is not bound to its status hash")

    success_ids = {str(item) for item in status.get("success_evidence_ids", []) if item}
    if not success_ids:
        raise ValueError("successful execution status has no response evidence ids")

    evidence = _find_response_evidence(evidence_dir, success_ids)
    payload: dict[str, object] = {
        "schema_version": "1",
        "session_id": session_id,
        "network_state": "HTTP_RESPONSE_OBSERVED",
        "network_execution_performed": True,
        "execution_status_hash": status_hash,
        "execution_status_path": str(status_path.resolve()),
        "response_evidence": [row.model_dump(mode="json") for row in evidence],
    }
    payload["provenance_hash"] = _sha256(payload)
    return FieldAssessmentNetworkProvenance.model_validate(payload)


def apply_network_provenance(
    *,
    status_path: Path,
    evidence_dir: Path,
    result_path: Path,
    report_path: Path,
    output_dir: Path,
) -> tuple[FieldAssessmentNetworkProvenance, Path]:
    provenance = build_network_provenance(
        status_path=status_path,
        evidence_dir=evidence_dir,
        result_path=result_path,
    )
    provenance_path = output_dir / f"network-provenance-{provenance.provenance_hash}.json"
    _write_json_immutable(provenance_path, provenance.model_dump(mode="json"))

    result = _load_yaml_mapping(result_path)
    result["network_execution_performed"] = True
    result["network_state"] = provenance.network_state
    result["network_provenance_hash"] = provenance.provenance_hash
    result["network_provenance_path"] = str(provenance_path.resolve())
    result_path.write_text(
        yaml.safe_dump(result, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    marker = "<!-- ASTP_M466B_RESPONSE_BACKED_NETWORK_PROVENANCE -->"
    report = report_path.read_text(encoding="utf-8")
    if marker not in report:
        lines = [
            "",
            marker,
            "## Execution provenance",
            "",
            "- Network execution performed: **YES**",
            f"- Network state: `{provenance.network_state}`",
            f"- Execution status hash: `{provenance.execution_status_hash}`",
            f"- Network provenance hash: `{provenance.provenance_hash}`",
        ]
        for row in provenance.response_evidence:
            lines.extend(
                [
                    f"- Response evidence: `{row.evidence_id}` — HTTP {row.status_code} — `{row.target}`",
                ]
            )
            if row.redirect_target:
                lines.append(
                    "  - Redirect: "
                    f"`{row.redirect_target}`; followed={str(bool(row.redirect_followed)).lower()}; "
                    "requires_new_permit="
                    f"{str(bool(row.redirect_requires_new_permit)).lower()}"
                )
        report_path.write_text(report.rstrip() + "\n" + "\n".join(lines) + "\n", encoding="utf-8")

    return provenance, provenance_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bind response-backed network provenance into a completed field assessment"
    )
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        provenance, path = apply_network_provenance(
            status_path=args.status,
            evidence_dir=args.evidence_dir,
            result_path=args.result,
            report_path=args.report,
            output_dir=args.output_dir,
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"FIELD_NETWORK_PROVENANCE_BLOCKED: {exc}")
        return 2
    print(
        json.dumps(
            {**provenance.model_dump(mode="json"), "provenance_path": str(path)},
            indent=2,
            sort_keys=True,
        )
    )
    print("FIELD_NETWORK_PROVENANCE: HTTP_RESPONSE_OBSERVED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
