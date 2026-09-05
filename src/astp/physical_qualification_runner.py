from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from astp.evidence_store import register_evidence
from astp.local_qualification_lab import LocalQualificationLab
from astp.models import (
    Constraints,
    Engagement,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
    TestDefinition,
)
from astp.permit_broker import broker_queue_item_permit
from astp.permit_consumption_proof import consume_worker_request_permit
from astp.physical_probe_evaluator import record_physical_probe
from astp.physical_runtime_commands import compile_authorized_lab_run
from astp.qualification_journal import QualificationJournalEntry, render_jsonl
from astp.qualification_session import QualificationProbe
from astp.runtime_resource_envelope import default_resource_envelopes
from astp.work_queue import WorkQueueItem
from astp.worker_evidence_bridge import register_worker_receipt
from astp.worker_protocol import WorkerOperation, WorkerReceipt, WorkerRequest


@dataclass(frozen=True)
class RuntimeLabSpec:
    runtime_id: str
    image_tag: str
    provenance_name: str
    operation: WorkerOperation
    target_kind: str
    argument: str | None
    timeout_seconds: int


_RUNTIME_SPECS = {
    "security-tools": RuntimeLabSpec(
        "security-tools.isolated.v1",
        "astp/security-tools-worker:qualification",
        "security-tools.json",
        WorkerOperation.NMAP_DISCOVERY,
        "host",
        "tcp-connect-bounded",
        30,
    ),
    "playwright": RuntimeLabSpec(
        "playwright.isolated.v1",
        "astp/playwright-worker:qualification",
        "playwright.json",
        WorkerOperation.BROWSER_NAVIGATE,
        "url",
        None,
        45,
    ),
    "zap": RuntimeLabSpec(
        "zap.isolated.v1",
        "astp/zap-worker:qualification",
        "zap.json",
        WorkerOperation.ZAP_BASELINE,
        "url",
        "passive-baseline",
        120,
    ),
}


def _local_engagement(lab: LocalQualificationLab) -> Engagement:
    return Engagement(
        id=lab.engagement_id,
        name="ASTP authorized local runtime qualification",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value=lab.service_name)]),
        constraints=Constraints(max_requests_per_second=1.0),
    )


def _qualification_test(spec: RuntimeLabSpec | None = None) -> TestDefinition:
    spec = spec or _RUNTIME_SPECS["security-tools"]
    return TestDefinition(
        id=f"qualification-{spec.runtime_id}",
        title=f"Bounded {spec.runtime_id} local qualification",
        category="runtime-qualification",
        risk_class=RiskClass.SAFE_ACTIVE,
        evidence_required=["worker-receipt", "command-output"],
        description="One permit-gated bounded action against the isolated ASTP qualification lab.",
    )


def _load_image_id(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    image_id = str(data.get("image_id", "")).strip()
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise ValueError("runtime provenance does not contain a full image sha256")
    return image_id


def _ensure_lab_running(lab: LocalQualificationLab) -> None:
    completed = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", lab.service_name],
        capture_output=True,
        text=True,
        timeout=15,
        shell=False,
        check=False,
    )
    if completed.returncode != 0 or completed.stdout.strip().lower() != "true":
        raise RuntimeError("qualification lab is not running; run start-local-lab.ps1 first")


def _digest(stdout: str, stderr: str) -> str:
    return hashlib.sha256((stdout + "\n---stderr---\n" + stderr).encode()).hexdigest()


def run_runtime_lab_qualification(
    root: Path,
    *,
    runtime: str,
    signing_key: str,
    path: str = "/health",
    max_output_bytes: int = 131_072,
    qualification_probe: str | None = None,
) -> dict[str, object]:
    if runtime not in _RUNTIME_SPECS:
        raise ValueError(f"unsupported runtime: {runtime}")
    spec = _RUNTIME_SPECS[runtime]
    lab = LocalQualificationLab()
    _ensure_lab_running(lab)
    qroot = root / ".astp" / "qualification"
    tmp_dir, evidence_dir = qroot / "tmp", qroot / "evidence"
    worker_artifacts = evidence_dir / "worker-receipts"
    for directory in (tmp_dir, evidence_dir, worker_artifacts):
        directory.mkdir(parents=True, exist_ok=True)
    provenance_path = qroot / "images" / spec.provenance_name
    if not provenance_path.is_file():
        raise FileNotFoundError(
            f"{runtime} build provenance missing; run build-images.ps1 -Runtime {runtime}"
        )
    image_id = _load_image_id(provenance_path)

    engagement = _local_engagement(lab)
    test = _qualification_test(spec)
    if path not in lab.allowed_paths:
        raise ValueError("qualification path is outside the local lab allowlist")
    target = lab.service_name if spec.target_kind == "host" else lab.base_url() + path
    action_id = f"qualification-{runtime}-{spec.operation.value.replace('.', '-')}"
    queue = WorkQueueItem(
        queue_id=f"qualification-{runtime}-queue",
        engagement_id=engagement.id,
        test_id=test.id,
        plan_item_id=f"qualification-{runtime}-plan",
        target=target,
        method="CONNECT" if spec.target_kind == "host" else "GET",
        requires_new_permit=True,
    )
    broker = broker_queue_item_permit(
        queue,
        engagement,
        test,
        signing_key,
        key_id="local-qualification-v1",
        ttl_seconds=180,
        requested_rps=1.0,
    )
    request = WorkerRequest(
        request_id=f"qualification-{runtime}-request",
        permit_id=broker.permit.payload.permit_id,
        action_id=action_id,
        engagement_id=engagement.id,
        operation=spec.operation,
        target=target,
        timeout_seconds=spec.timeout_seconds,
        max_output_bytes=max_output_bytes,
        arguments=(spec.argument,) if spec.argument else (),
    )
    request_path = tmp_dir / f"{runtime}-authorized-lab-request.json"
    request_path.write_text(
        json.dumps(request.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    state_path = qroot / "permit-state.json"
    consumption = consume_worker_request_permit(
        broker.permit, request, engagement, test, signing_key, state_path=state_path
    )
    command = compile_authorized_lab_run(
        image_ref=spec.image_tag,
        request_path=str(request_path.resolve()),
        resources=default_resource_envelopes()[spec.runtime_id],
        lab=lab,
        worker_request=request,
        consumption=consumption,
        qualification_probe=qualification_probe,
    )
    run_dir = evidence_dir / "runs" / runtime / request.permit_id
    run_dir.mkdir(parents=True, exist_ok=False)
    command_path = run_dir / "command.json"
    command_path.write_text(
        json.dumps(
            {
                "argv": list(command.argv),
                "network_capable": command.network_capable,
                "permit_consumption_binding_hash": consumption.binding_hash(),
                "permit_id": consumption.permit_id,
                "action_id": consumption.action_id,
                "image_id": image_id,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    consumption_path = run_dir / "permit-consumption.json"
    consumption_path.write_text(
        json.dumps(consumption.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_path = qroot / "evidence-manifest.jsonl"
    register_evidence(
        manifest_path,
        consumption_path,
        evidence_type="runtime.qualification.permit-consumption.v1",
        permit_id=request.permit_id,
        action_id=request.action_id,
    )
    register_evidence(
        manifest_path,
        command_path,
        evidence_type="runtime.qualification.command.v1",
        permit_id=request.permit_id,
        action_id=request.action_id,
    )
    completed = subprocess.run(
        list(command.argv),
        capture_output=True,
        text=True,
        timeout=spec.timeout_seconds + 90,
        shell=False,
        check=False,
    )
    output_path = run_dir / "output.json"
    output_path.write_text(
        json.dumps(
            {
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "output_digest": _digest(completed.stdout, completed.stderr),
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{runtime} qualification worker failed: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )
    try:
        worker_output = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{runtime} worker did not emit valid JSON") from exc
    if worker_output.get("accepted") is not True or worker_output.get("target") != target:
        raise RuntimeError(f"{runtime} worker output binding mismatch")
    network_io_performed = bool(
        worker_output.get("network_io_performed", qualification_probe is None)
    )
    receipt = WorkerReceipt(
        request_id=request.request_id,
        permit_id=request.permit_id,
        action_id=request.action_id,
        operation=request.operation,
        exit_code=completed.returncode,
        output_sha256=_digest(completed.stdout, completed.stderr),
        output_truncated=bool(worker_output.get("output_truncated", False)),
        network_io_performed=network_io_performed,
        permit_consumed_before_io=True,
    )
    registered = register_worker_receipt(
        receipt, manifest_path=manifest_path, artifact_directory=worker_artifacts
    )
    register_evidence(
        manifest_path,
        output_path,
        evidence_type="runtime.qualification.output.v1",
        permit_id=request.permit_id,
        action_id=request.action_id,
    )
    record_physical_probe(
        root,
        runtime=runtime,
        probe=QualificationProbe.PERMIT_BEFORE_IO,
        passed=receipt.permit_consumed_before_io,
        authorized_lab=True,
        source_ref=consumption_path,
        details={"permit_id": request.permit_id, "action_id": request.action_id},
    )
    record_physical_probe(
        root,
        runtime=runtime,
        probe=QualificationProbe.RECEIPT_INGESTION,
        passed=True,
        authorized_lab=True,
        source_ref=Path(registered.manifest_entry.artifact_path),
        details={"evidence_id": registered.manifest_entry.evidence_id},
    )
    if receipt.output_truncated:
        record_physical_probe(
            root,
            runtime=runtime,
            probe=QualificationProbe.BOUNDED_OUTPUT,
            passed=True,
            authorized_lab=True,
            source_ref=output_path,
            details={"max_output_bytes": request.max_output_bytes},
        )
    journal_path = qroot / "qualification-journal.jsonl"
    entries = (
        QualificationJournalEntry(
            runtime_id=spec.runtime_id,
            stage="authorized-lab",
            event="permit-consumed-before-worker-launch",
            evidence_path=str(consumption_path),
            details={
                "permit_id": request.permit_id,
                "action_id": request.action_id,
                "binding_hash": consumption.binding_hash(),
            },
        ),
        QualificationJournalEntry(
            runtime_id=spec.runtime_id,
            stage="authorized-lab",
            event="bounded-network-worker-completed",
            evidence_path=str(output_path),
            details={"target": target, "docker_network": lab.docker_network, "image_id": image_id},
        ),
        QualificationJournalEntry(
            runtime_id=spec.runtime_id,
            stage="receipt-ingestion",
            event="worker-receipt-registered",
            evidence_path=registered.manifest_entry.artifact_path,
            details={"evidence_id": registered.manifest_entry.evidence_id},
        ),
    )
    with journal_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(render_jsonl(entries))
    network_execution = "PERFORMED" if receipt.network_io_performed else "NOT_PERFORMED_BY_PROBE"
    return {
        "runtime_id": spec.runtime_id,
        "image_id": image_id,
        "engagement_id": engagement.id,
        "target": target,
        "permit_id": request.permit_id,
        "action_id": request.action_id,
        "permit_consumed_before_io": True,
        "container_execution": "PERFORMED",
        "network_execution": network_execution,
        "network": lab.docker_network,
        "evidence_id": registered.manifest_entry.evidence_id,
        "output_truncated": receipt.output_truncated,
        "manifest_path": str(manifest_path),
        "journal_path": str(journal_path),
        "qualification_probe": qualification_probe,
    }


def run_security_tools_lab_qualification(root: Path, *, signing_key: str) -> dict[str, object]:
    return run_runtime_lab_qualification(root, runtime="security-tools", signing_key=signing_key)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run ASTP permit-gated local runtime qualification"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--runtime", choices=tuple(_RUNTIME_SPECS), default="security-tools")
    parser.add_argument("--path", choices=("/", "/health", "/large"), default="/health")
    parser.add_argument("--max-output-bytes", type=int, default=131_072)
    parser.add_argument("--qualification-probe", choices=("bounded-output-v1",))
    args = parser.parse_args()
    key = os.environ.get("ASTP_PERMIT_KEY", "")
    if not key:
        raise SystemExit("ASTP_PERMIT_KEY is required for permit-gated qualification")
    print(
        json.dumps(
            run_runtime_lab_qualification(
                args.root.resolve(),
                runtime=args.runtime,
                signing_key=key,
                path=args.path,
                max_output_bytes=args.max_output_bytes,
                qualification_probe=args.qualification_probe,
            ),
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
