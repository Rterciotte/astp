from __future__ import annotations

import json
import sqlite3
import subprocess
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict

from astp.detector_execution import (
    DetectorAccounting,
    DetectorAdapterError,
    DetectorAdapterResult,
    DetectorArtifacts,
    DetectorExecutionRequest,
)
from astp.detector_run_permit import SignedDetectorRunPermit
from astp.proof_model import ProofStateV2, proof_ceiling


class DockerDetectorRuntime(BaseModel):
    model_config = ConfigDict(frozen=True)

    image: str
    image_digest: str


class DockerDetectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    target_network: str
    proxy_image: str = "astp/counting-proxy:m52"
    proxy_image_digest: str
    runtimes: dict[str, DockerDetectorRuntime]
    timeout_seconds: int = 90


FIELD_IMAGES = {
    "nuclei.astp-lab-cve.v1": "astp/nuclei-worker:m52",
    "dalfox.reflected-bounded.v1": "astp/dalfox-worker:m52",
    "ffuf.discovery-bounded.v1": "astp/ffuf-worker:m52",
    "sqlmap.detect-bounded.v1": "astp/sqlmap-worker:m52",
    "playwright.dom-navigation-field.v1": "astp/playwright-field-worker:m52",
}


class DockerDetectorAdapter:
    """Fixed-contract Docker adapter; callers can never supply command arguments."""

    detector_ids = frozenset(FIELD_IMAGES)

    def __init__(self, config: DockerDetectorConfig, signing_key: str) -> None:
        self.config = config
        self.signing_key = signing_key

    @staticmethod
    def _run(argv: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)

    def _request_payload(
        self, request: DetectorExecutionRequest, permit: SignedDetectorRunPermit
    ) -> dict:
        base = {
            "request_id": request.opportunity.model_dump_json(),
            "permit_id": permit.payload.permit_id,
            "action_id": permit.payload.action_id,
            "engagement_id": request.campaign_id,
            "operation": request.detector.operation,
        }
        detector_id = request.detector.detector_id
        if detector_id == "ffuf.discovery-bounded.v1":
            return {
                **base,
                "origin": request.target.rstrip("/"),
                "max_words": min(4, permit.payload.max_requests),
                "max_requests": permit.payload.max_requests,
                "concurrency": permit.payload.max_concurrency,
                "rate_per_second": permit.payload.max_rps,
                "timeout_seconds": self.config.timeout_seconds,
            }
        payload = {
            **base,
            "target": request.target,
            "timeout_seconds": self.config.timeout_seconds,
        }
        if detector_id == "nuclei.astp-lab-cve.v1":
            payload.update(
                template_ids=["astp-lab-cve-2099-0001"],
                max_requests=permit.payload.max_requests,
                max_concurrency=permit.payload.max_concurrency,
                rate_per_second=permit.payload.max_rps,
            )
        elif detector_id == "dalfox.reflected-bounded.v1":
            payload.update(
                parameter=self._parameter(request.target),
                max_requests=permit.payload.max_requests,
                max_workers=permit.payload.max_concurrency,
                rate_per_second=permit.payload.max_rps,
            )
        elif detector_id == "sqlmap.detect-bounded.v1":
            payload.update(
                parameter=self._parameter(request.target),
                method="GET",
                level=1,
                risk=1,
                max_requests=permit.payload.max_requests,
            )
        else:
            payload.update(profile="dom-navigation")
        return payload

    @staticmethod
    def _parameter(target: str) -> str:
        parameters = tuple(parse_qs(urlsplit(target).query, keep_blank_values=True))
        if len(parameters) != 1:
            raise ValueError("detector target must bind exactly one parameter")
        return parameters[0]

    def execute(
        self,
        request: DetectorExecutionRequest,
        permit: SignedDetectorRunPermit,
        run_root: Path,
    ) -> DetectorAdapterResult:
        proxy_inspected = self._run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", self.config.proxy_image]
        )
        if (
            proxy_inspected.returncode
            or proxy_inspected.stdout.strip() != self.config.proxy_image_digest
        ):
            raise DetectorAdapterError("proxy_image_identity_drift", retryable=False)

        runtime = self.config.runtimes.get(request.detector.detector_id)
        expected_image = FIELD_IMAGES[request.detector.detector_id]
        if runtime is None or runtime.image != expected_image:
            raise DetectorAdapterError("runtime_binding", retryable=False)
        if runtime.image_digest != request.runtime_digest:
            raise DetectorAdapterError("runtime_digest_drift", retryable=False)
        inspected = self._run(["docker", "image", "inspect", "--format", "{{.Id}}", runtime.image])
        if inspected.returncode or inspected.stdout.strip() != runtime.image_digest:
            raise DetectorAdapterError("runtime_image_identity_drift", retryable=False)

        suffix = permit.payload.detector_run_id.removeprefix("detector-run-")
        worker_network = f"astp-worker-{suffix}"
        proxy_name = f"astp-proxy-{suffix}"
        request_path = run_root / "request.json"
        ledger_path = run_root / "proxy-ledger.db"
        request_path.write_text(
            json.dumps(self._request_payload(request, permit), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        authorization_path = run_root / "authorization.json"
        self._checked(["docker", "network", "create", "--internal", worker_network])
        try:
            self._checked(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--name",
                    proxy_name,
                    "--network",
                    worker_network,
                    "--network-alias",
                    "astp-counting-proxy",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--env",
                    f"ASTP_DETECTOR_RUN_KEY={self.signing_key}",
                    "--mount",
                    f"type=bind,src={authorization_path.resolve()},dst=/run/astp/permit.json,readonly",
                    "--mount",
                    f"type=bind,src={run_root.resolve()},dst=/var/lib/astp",
                    self.config.proxy_image,
                ]
            )
            self._checked(["docker", "network", "connect", self.config.target_network, proxy_name])
            time.sleep(0.25)
            worker_argv = [
                "docker",
                "run",
                "--rm",
                "--network",
                worker_network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=128m",
                "--env",
                "ASTP_PROXY_URL=http://astp-counting-proxy:8081",
                "--env",
                "ASTP_PERMIT_CONSUMED=true",
                "--env",
                f"ASTP_ALLOWED_TARGET={request.target}",
                "--env",
                f"ASTP_ALLOWED_ORIGIN={request.target.rstrip('/')}",
                "--mount",
                f"type=bind,src={request_path.resolve()},dst=/run/astp/request.json,readonly",
                runtime.image,
            ]
            try:
                completed = self._run(worker_argv, timeout=self.config.timeout_seconds + 20)
            except subprocess.TimeoutExpired as exc:
                accounting = self._accounting(ledger_path)
                (run_root / "proxy-ledger-summary.json").write_text(
                    accounting.model_dump_json(indent=2) + "\n", encoding="utf-8"
                )
                raise DetectorAdapterError(
                    "worker_timeout",
                    accounting=accounting,
                    network_started=True,
                    retryable=True,
                ) from exc
            accounting = self._accounting(ledger_path)
            (run_root / "proxy-ledger-summary.json").write_text(
                accounting.model_dump_json(indent=2) + "\n", encoding="utf-8"
            )
            receipt = self._receipt(completed.stdout)
            (run_root / "worker-stdout.txt").write_text(completed.stdout, encoding="utf-8")
            (run_root / "worker-stderr.txt").write_text(completed.stderr, encoding="utf-8")
            if completed.returncode != 0 or not receipt.get("accepted"):
                raise DetectorAdapterError(
                    "worker_failure",
                    accounting=accounting,
                    network_started=True,
                    retryable=accounting.forwarded == accounting.responses,
                )
            evidence_id = f"evidence-{suffix}"
            state, satisfied, finding_id = self._normalize(request, receipt, suffix)
            return DetectorAdapterResult(
                accounting=accounting,
                artifacts=DetectorArtifacts(
                    worker_receipt=receipt,
                    raw_output_path=str(run_root / "worker-stdout.txt"),
                    evidence_ids=(evidence_id,),
                ),
                proof_state=state,
                requirement_satisfied=satisfied,
                candidate_id=request.parent_candidate_id or f"candidate-{suffix}",
                finding_id=finding_id,
                network_started=True,
            )
        finally:
            self._run(["docker", "rm", "--force", proxy_name])
            self._run(["docker", "network", "rm", worker_network])

    def _checked(self, argv: list[str]) -> None:
        completed = self._run(argv)
        if completed.returncode:
            raise DetectorAdapterError("docker_control_failure", retryable=True)

    @staticmethod
    def _receipt(stdout: str) -> dict:
        for line in reversed(stdout.splitlines()):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
        return {}

    @staticmethod
    def _accounting(path: Path) -> DetectorAccounting:
        if not path.exists():
            return DetectorAccounting()
        with sqlite3.connect(path) as db:
            rows = dict(db.execute("SELECT state,count(*) FROM requests GROUP BY state"))
            request_bytes, response_bytes = db.execute(
                "SELECT COALESCE(sum(request_bytes),0),COALESCE(sum(response_bytes),0) FROM requests"
            ).fetchone()
        responses = rows.get("response_received", 0)
        failed = rows.get("failed_after_io", 0)
        blocked = rows.get("blocked_before_io", 0)
        forwarded = responses + failed
        return DetectorAccounting(
            attempted=forwarded + blocked,
            forwarded=forwarded,
            responses=responses,
            blocked_before_io=blocked,
            failed_after_io=failed,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
        )

    @staticmethod
    def _normalize(
        request: DetectorExecutionRequest, receipt: dict, suffix: str
    ) -> tuple[ProofStateV2, bool, str | None]:
        detector_id = request.detector.detector_id
        if detector_id == "nuclei.astp-lab-cve.v1" and receipt.get("stdout"):
            return ProofStateV2.REPRODUCED, True, None
        if detector_id == "sqlmap.detect-bounded.v1" and receipt.get("detected"):
            return ProofStateV2.REPRODUCED, True, f"finding-{suffix}"
        if detector_id == "playwright.dom-navigation-field.v1":
            dom = str(receipt.get("dom", ""))
            if request.parent_candidate_id and ("innerHTML" in dom or "ASTP_XSS" in dom):
                return ProofStateV2.CONFIRMED, True, f"finding-{suffix}"
            return ProofStateV2.REPRODUCED, True, None
        if detector_id == "dalfox.reflected-bounded.v1" and receipt.get("stdout"):
            return ProofStateV2.CANDIDATE, False, None
        return (
            proof_ceiling(request.detector.vulnerability_family, signal_only=False),
            request.proof_requirement.value == "observation",
            None,
        )
