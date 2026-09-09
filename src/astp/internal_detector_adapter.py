from __future__ import annotations

import json
from pathlib import Path

from astp.detector_execution import (
    DetectorAccounting,
    DetectorAdapterError,
    DetectorAdapterResult,
    DetectorArtifacts,
    DetectorExecutionRequest,
)
from astp.detector_run_permit import SignedDetectorRunPermit
from astp.differential_access import IdentityObservation, compare_identity_observations
from astp.oast import OastCallback, OastPayload, correlate_oast
from astp.proof_model import ProofStateV2
from astp.secret_exposure import analyze_exposed_content


class InternalDetectorAdapter:
    detector_ids = frozenset(
        {
            "astp.secret-exposure.v1",
            "astp.idor-differential.v1",
            "astp.ssrf-oast.v1",
        }
    )

    def execute(
        self,
        request: DetectorExecutionRequest,
        permit: SignedDetectorRunPermit,
        run_root: Path,
    ) -> DetectorAdapterResult:
        source = self._source(request)
        detector_id = request.detector.detector_id
        if detector_id == "astp.secret-exposure.v1":
            return self._secrets(source, permit, run_root)
        if detector_id == "astp.idor-differential.v1":
            return self._idor(source, permit, run_root)
        return self._oast(source, permit, run_root)

    @staticmethod
    def _source(request: DetectorExecutionRequest) -> dict:
        if request.input_artifact_path is None:
            raise DetectorAdapterError("input_artifact_missing")
        path = Path(request.input_artifact_path).resolve()
        if not path.is_file():
            raise DetectorAdapterError("input_artifact_missing")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DetectorAdapterError("input_artifact_invalid") from exc
        if not isinstance(value, dict):
            raise DetectorAdapterError("input_artifact_invalid")
        return value

    @staticmethod
    def _persist(run_root: Path, payload: dict) -> tuple[str, Path]:
        evidence_id = f"evidence-{run_root.name.removeprefix('detector-run-')}"
        path = run_root / "normalized-evidence.json"
        path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return evidence_id, path

    def _secrets(
        self, source: dict, permit: SignedDetectorRunPermit, run_root: Path
    ) -> DetectorAdapterResult:
        content = str(source.get("content", "")).encode()
        signals = analyze_exposed_content(
            content, content_type=str(source.get("content_type", "text/plain"))
        )
        safe = [signal.model_dump(mode="json") for signal in signals]
        evidence_id, path = self._persist(
            run_root,
            {"permit_id": permit.payload.permit_id, "signals": safe, "raw_content_stored": False},
        )
        return DetectorAdapterResult(
            accounting=DetectorAccounting(),
            artifacts=DetectorArtifacts(
                worker_receipt={"signal_count": len(signals), "secret_values_redacted": True},
                raw_output_path=str(path),
                evidence_ids=(evidence_id,),
            ),
            proof_state=ProofStateV2.REPRODUCED if signals else ProofStateV2.OBSERVED,
            requirement_satisfied=bool(signals),
            candidate_id=f"candidate-{evidence_id}",
            finding_id=f"finding-{evidence_id}" if signals else None,
        )

    def _idor(
        self, source: dict, permit: SignedDetectorRunPermit, run_root: Path
    ) -> DetectorAdapterResult:
        rows = source.get("observations", [])
        if not isinstance(rows, list) or len(rows) != 2:
            raise DetectorAdapterError("idor_observations_invalid")
        result = compare_identity_observations(
            IdentityObservation.model_validate(rows[0]), IdentityObservation.model_validate(rows[1])
        )
        evidence_id, path = self._persist(
            run_root,
            {
                "permit_id": permit.payload.permit_id,
                "state": result.state.value,
                "identity_hashes": result.identity_hashes,
                "sensitive_fields": result.sensitive_fields_exposed,
                "reason": result.reason,
            },
        )
        confirmed = result.state is ProofStateV2.CONFIRMED
        return DetectorAdapterResult(
            accounting=DetectorAccounting(),
            artifacts=DetectorArtifacts(
                worker_receipt={"identity_refs_redacted": True},
                raw_output_path=str(path),
                evidence_ids=(evidence_id,),
            ),
            proof_state=result.state,
            requirement_satisfied=confirmed,
            candidate_id=f"candidate-{evidence_id}",
            finding_id=f"finding-{evidence_id}" if confirmed else None,
        )

    def _oast(
        self, source: dict, permit: SignedDetectorRunPermit, run_root: Path
    ) -> DetectorAdapterResult:
        payload = OastPayload.model_validate(source.get("payload"))
        callback = OastCallback.model_validate(source.get("callback"))
        if payload.permit_id != permit.payload.permit_id:
            raise DetectorAdapterError("oast_permit_binding_mismatch")
        result = correlate_oast(payload, callback)
        evidence_id, path = self._persist(
            run_root,
            {
                "permit_id": permit.payload.permit_id,
                "payload_id": payload.payload_id,
                "callback_source_hash": callback.source_hash,
                "matched": result.matched,
                "state": result.state.value,
            },
        )
        return DetectorAdapterResult(
            accounting=DetectorAccounting(),
            artifacts=DetectorArtifacts(raw_output_path=str(path), evidence_ids=(evidence_id,)),
            proof_state=result.state,
            requirement_satisfied=result.matched,
            candidate_id=f"candidate-{evidence_id}",
            finding_id=f"finding-{evidence_id}" if result.matched else None,
        )
