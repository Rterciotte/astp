from __future__ import annotations

import json
import sqlite3
import subprocess
import time
from enum import StrEnum
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


class DockerLifecycleFaultPoint(StrEnum):
    BEFORE_WORKER_LAUNCH = "before_worker_launch"
    AFTER_WORKER_LAUNCH_BEFORE_FIRST_IO = "after_worker_launch_before_first_io"
    AFTER_FIRST_PROXY_FORWARD = "after_first_proxy_forward"
    WORKER_CRASH_AFTER_TARGET_RESPONSE = "worker_crash_after_target_response"
    AFTER_PROXY_RESULT_BEFORE_EVIDENCE_NORMALIZATION = (
        "after_proxy_result_before_evidence_normalization"
    )
    AFTER_EVIDENCE_NORMALIZATION_BEFORE_PERSISTENCE = (
        "after_evidence_normalization_before_persistence"
    )


class DockerDetectorAdapter:
    """Fixed-contract Docker adapter; callers can never supply command arguments."""

    detector_ids = frozenset(FIELD_IMAGES)

    def __init__(
        self,
        config: DockerDetectorConfig,
        signing_key: str,
        *,
        acceptance_fault: DockerLifecycleFaultPoint | None = None,
    ) -> None:
        self.config = config
        self.signing_key = signing_key
        self.acceptance_fault = acceptance_fault
        if acceptance_fault is not None and config.target_network != "astp-m2-local":
            raise ValueError("Docker lifecycle faults are restricted to the local acceptance lab")

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
            raise DetectorAdapterError(
                "proxy_image_identity_drift", retryable=False, blocked_before_io=True
            )

        runtime = self.config.runtimes.get(request.detector.detector_id)
        expected_image = FIELD_IMAGES[request.detector.detector_id]
        if runtime is None or runtime.image != expected_image:
            raise DetectorAdapterError("runtime_binding", retryable=False, blocked_before_io=True)
        if runtime.image_digest != request.runtime_digest:
            raise DetectorAdapterError(
                "runtime_digest_drift", retryable=False, blocked_before_io=True
            )
        inspected = self._run(["docker", "image", "inspect", "--format", "{{.Id}}", runtime.image])
        if inspected.returncode or inspected.stdout.strip() != runtime.image_digest:
            raise DetectorAdapterError(
                "runtime_image_identity_drift", retryable=False, blocked_before_io=True
            )

        suffix = permit.payload.detector_run_id.removeprefix("detector-run-")
        worker_network = f"astp-worker-{suffix}"
        proxy_name = f"astp-proxy-{suffix}"
        worker_name: str | None = None
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
                    *(
                        [
                            "--env",
                            "ASTP_ACCEPTANCE_MODE=local-only",
                            "--env",
                            "ASTP_ACCEPTANCE_PROXY_FAULT="
                            + (
                                "hold_after_target_response"
                                if self.acceptance_fault
                                is DockerLifecycleFaultPoint.WORKER_CRASH_AFTER_TARGET_RESPONSE
                                else self.acceptance_fault.value
                            ),
                        ]
                        if self.acceptance_fault
                        in {
                            DockerLifecycleFaultPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_IO,
                            DockerLifecycleFaultPoint.AFTER_FIRST_PROXY_FORWARD,
                            DockerLifecycleFaultPoint.WORKER_CRASH_AFTER_TARGET_RESPONSE,
                        }
                        else []
                    ),
                    "--mount",
                    f"type=bind,src={authorization_path.resolve()},dst=/run/astp/permit.json,readonly",
                    "--mount",
                    f"type=bind,src={run_root.resolve()},dst=/var/lib/astp",
                    self.config.proxy_image,
                ]
            )
            self._checked(["docker", "network", "connect", self.config.target_network, proxy_name])
            time.sleep(0.25)
            if self.acceptance_fault is DockerLifecycleFaultPoint.BEFORE_WORKER_LAUNCH:
                raise DetectorAdapterError(
                    "chaos_before_worker_launch",
                    accounting=DetectorAccounting(),
                    network_started=False,
                    retryable=True,
                    blocked_before_io=True,
                )
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
            (run_root / "worker-lifecycle.json").write_text(
                json.dumps(
                    {
                        "state": "launching",
                        "image": runtime.image,
                        "image_digest": runtime.image_digest,
                        "network": worker_network,
                        "proxy": "http://astp-counting-proxy:8081",
                        "direct_target_network_attached": False,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            try:
                if (
                    self.acceptance_fault
                    is DockerLifecycleFaultPoint.WORKER_CRASH_AFTER_TARGET_RESPONSE
                ):
                    worker_name = f"astp-worker-process-{suffix}"
                    self._checked(
                        [
                            "docker",
                            "run",
                            "--detach",
                            "--name",
                            worker_name,
                            *worker_argv[3:],
                        ]
                    )
                    deadline = time.monotonic() + self.config.timeout_seconds
                    while time.monotonic() < deadline:
                        if self._container_forwarded(proxy_name):
                            break
                        time.sleep(0.05)
                    else:
                        worker_logs = self._run(["docker", "logs", worker_name])
                        (run_root / "worker-stdout.txt").write_text(
                            worker_logs.stdout, encoding="utf-8"
                        )
                        (run_root / "worker-stderr.txt").write_text(
                            worker_logs.stderr, encoding="utf-8"
                        )
                        proxy_logs = self._run(["docker", "logs", proxy_name])
                        (run_root / "proxy-stdout.txt").write_text(
                            proxy_logs.stdout, encoding="utf-8"
                        )
                        (run_root / "proxy-stderr.txt").write_text(
                            proxy_logs.stderr, encoding="utf-8"
                        )
                        raise DetectorAdapterError(
                            "worker_crash_fault_did_not_reach_proxy",
                            accounting=self._accounting(ledger_path),
                            retryable=True,
                            blocked_before_io=True,
                        )
                    self._run(["docker", "rm", "--force", worker_name])
                    # On Docker Desktop, reading a bind-mounted WAL database from
                    # Windows while Linux is writing can corrupt the active I/O.
                    # Stop the sole writer before reopening its durable ledger on
                    # the host. The worker has already been killed at this point.
                    self._run(["docker", "rm", "--force", proxy_name])
                    accounting = self._accounting(ledger_path)
                    (run_root / "worker-lifecycle.json").write_text(
                        json.dumps(
                            {
                                "state": "killed",
                                "image": runtime.image,
                                "image_digest": runtime.image_digest,
                                "network": worker_network,
                                "proxy": "http://astp-counting-proxy:8081",
                                "direct_target_network_attached": False,
                            },
                            sort_keys=True,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    raise DetectorAdapterError(
                        "worker_crash",
                        accounting=accounting,
                        network_started=accounting.forwarded > 0,
                        retryable=False,
                    )
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
            (run_root / "worker-lifecycle.json").write_text(
                json.dumps(
                    {
                        "state": "exited",
                        "returncode": completed.returncode,
                        "image": runtime.image,
                        "image_digest": runtime.image_digest,
                        "network": worker_network,
                        "proxy": "http://astp-counting-proxy:8081",
                        "direct_target_network_attached": False,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
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
                    network_started=accounting.forwarded > 0,
                    retryable=accounting.forwarded == 0,
                )
            if accounting.unknown_outcomes:
                return DetectorAdapterResult(
                    accounting=accounting,
                    artifacts=DetectorArtifacts(
                        worker_receipt=receipt,
                        raw_output_path=str(run_root / "worker-stdout.txt"),
                    ),
                    proof_state=ProofStateV2.OBSERVED,
                    requirement_satisfied=False,
                    network_started=True,
                    response_uncertain=True,
                )
            if accounting.attempted == 0 and receipt.get("network_io_performed"):
                raise DetectorAdapterError(
                    "worker_io_unaccounted",
                    accounting=accounting,
                    network_started=False,
                    retryable=True,
                    blocked_before_io=True,
                )
            if (
                self.acceptance_fault
                is DockerLifecycleFaultPoint.AFTER_PROXY_RESULT_BEFORE_EVIDENCE_NORMALIZATION
            ):
                raise DetectorAdapterError(
                    "chaos_after_proxy_result",
                    accounting=accounting,
                    network_started=accounting.forwarded > 0,
                    retryable=False,
                )
            evidence_id = f"evidence-{suffix}"
            state, satisfied, finding_id = self._normalize(request, receipt, suffix)
            if (
                self.acceptance_fault
                is DockerLifecycleFaultPoint.AFTER_EVIDENCE_NORMALIZATION_BEFORE_PERSISTENCE
            ):
                (run_root / "normalized-intermediate.json").write_text(
                    json.dumps(
                        {
                            "evidence_id": evidence_id,
                            "proof_state": state.value,
                            "requirement_satisfied": satisfied,
                            "finding_id": finding_id,
                        },
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                raise DetectorAdapterError(
                    "chaos_after_evidence_normalization",
                    accounting=accounting,
                    network_started=accounting.forwarded > 0,
                    retryable=False,
                )
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
            if worker_name is not None:
                self._run(["docker", "rm", "--force", worker_name])
            self._run(["docker", "rm", "--force", proxy_name])
            self._run(["docker", "network", "rm", worker_network])

    def _checked(self, argv: list[str]) -> None:
        completed = self._run(argv)
        if completed.returncode:
            raise DetectorAdapterError("docker_control_failure", retryable=True)

    def _container_forwarded(self, proxy_name: str) -> bool:
        completed = self._run(
            [
                "docker",
                "exec",
                proxy_name,
                "python",
                "-c",
                (
                    "import sqlite3;"
                    "db=sqlite3.connect('/var/lib/astp/proxy-ledger.db');"
                    'print(db.execute("SELECT count(*) FROM requests WHERE state IN '
                    "('forwarding','response_received','failed_after_io')\").fetchone()[0])"
                ),
            ]
        )
        return completed.returncode == 0 and int(completed.stdout.strip() or "0") > 0

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
        unknown = rows.get("forwarding", 0)
        blocked = rows.get("blocked_before_io", 0)
        forwarded = responses + failed + unknown
        return DetectorAccounting(
            attempted=forwarded + blocked,
            forwarded=forwarded,
            responses=responses,
            blocked_before_io=blocked,
            failed_after_io=failed,
            unknown_outcomes=unknown,
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
