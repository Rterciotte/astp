from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
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
from astp.physical_runtime_commands import compile_authorized_lab_run
from astp.qualification_journal import QualificationJournalEntry, render_jsonl
from astp.runtime_resource_envelope import default_resource_envelopes
from astp.work_queue import WorkQueueItem
from astp.worker_evidence_bridge import register_worker_receipt
from astp.worker_protocol import WorkerOperation, WorkerReceipt, WorkerRequest

RUNTIME_ID = "security-tools.isolated.v1"
IMAGE_TAG = "astp/security-tools-worker:qualification"
TEST_ID = "qualification-nmap-discovery"
ACTION_ID = "qualification-nmap-discovery"


def _local_engagement(lab: LocalQualificationLab) -> Engagement:
    return Engagement(
        id=lab.engagement_id,
        name="ASTP authorized local runtime qualification",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value=lab.service_name)],
        ),
        constraints=Constraints(max_requests_per_second=1.0),
    )


def _qualification_test() -> TestDefinition:
    return TestDefinition(
        id=TEST_ID,
        title="Bounded Nmap discovery against ASTP local qualification lab",
        category="runtime-qualification",
        risk_class=RiskClass.SAFE_ACTIVE,
        evidence_required=["worker-receipt", "command-output"],
        description="One bounded TCP connect discovery against the isolated local lab service.",
    )


def _load_image_id(provenance_path: Path) -> str:
    data = json.loads(provenance_path.read_text(encoding="utf-8-sig"))
    image_id = str(data.get("image_id", "")).strip()
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise ValueError("security-tools provenance does not contain a full image sha256")
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
        raise RuntimeError(
            "qualification lab is not running; run start-local-lab.ps1 before qualification"
        )


def _output_digest(stdout: str, stderr: str) -> str:
    return hashlib.sha256((stdout + "\n---stderr---\n" + stderr).encode("utf-8")).hexdigest()


def run_security_tools_lab_qualification(root: Path, *, signing_key: str) -> dict[str, object]:
    lab = LocalQualificationLab()
    _ensure_lab_running(lab)

    qualification_root = root / ".astp" / "qualification"
    tmp_dir = qualification_root / "tmp"
    evidence_dir = qualification_root / "evidence"
    worker_artifacts = evidence_dir / "worker-receipts"
    state_path = qualification_root / "permit-state.json"
    manifest_path = qualification_root / "evidence-manifest.jsonl"
    journal_path = qualification_root / "qualification-journal.jsonl"
    provenance_path = qualification_root / "images" / "security-tools.json"
    for path in (tmp_dir, evidence_dir, worker_artifacts):
        path.mkdir(parents=True, exist_ok=True)

    if not provenance_path.is_file():
        raise FileNotFoundError(
            "security-tools build provenance is missing; run build-images.ps1 -Runtime security-tools"
        )
    image_id = _load_image_id(provenance_path)

    engagement = _local_engagement(lab)
    test = _qualification_test()
    queue_item = WorkQueueItem(
        queue_id="qualification-queue-0001",
        engagement_id=engagement.id,
        test_id=test.id,
        plan_item_id="qualification-plan-0001",
        target=lab.service_name,
        method="CONNECT",
        requires_new_permit=True,
    )
    broker_receipt = broker_queue_item_permit(
        queue_item,
        engagement,
        test,
        signing_key,
        key_id="local-qualification-v1",
        ttl_seconds=120,
        requested_rps=1.0,
    )

    worker_request = WorkerRequest(
        request_id="qualification-security-tools-0001",
        permit_id=broker_receipt.permit.payload.permit_id,
        action_id=ACTION_ID,
        engagement_id=engagement.id,
        operation=WorkerOperation.NMAP_DISCOVERY,
        target=lab.service_name,
        timeout_seconds=30,
        max_output_bytes=131_072,
        arguments=("tcp-connect-bounded",),
    )
    request_path = tmp_dir / "security-tools-authorized-lab-request.json"
    request_path.write_text(
        json.dumps(worker_request.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    consumption = consume_worker_request_permit(
        broker_receipt.permit,
        worker_request,
        engagement,
        test,
        signing_key,
        state_path=state_path,
    )
    command = compile_authorized_lab_run(
        image_ref=IMAGE_TAG,
        request_path=str(request_path.resolve()),
        resources=default_resource_envelopes()[RUNTIME_ID],
        lab=lab,
        worker_request=worker_request,
        consumption=consumption,
    )
    if not command.network_capable:
        raise RuntimeError("authorized lab command did not become network-capable")

    command_path = evidence_dir / "security-tools-authorized-lab-command.json"
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

    completed = subprocess.run(
        list(command.argv),
        capture_output=True,
        text=True,
        timeout=60,
        shell=False,
        check=False,
    )
    output_path = evidence_dir / "security-tools-authorized-lab-output.json"
    output_path.write_text(
        json.dumps(
            {
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "output_digest": _output_digest(completed.stdout, completed.stderr),
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "security-tools qualification worker failed: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )

    try:
        worker_output = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError("security-tools worker did not emit valid JSON") from exc
    if worker_output.get("accepted") is not True:
        raise RuntimeError("security-tools worker did not accept the bounded qualification request")
    if worker_output.get("target") != lab.service_name:
        raise RuntimeError("security-tools worker output target mismatch")

    output_digest = _output_digest(completed.stdout, completed.stderr)
    receipt = WorkerReceipt(
        request_id=worker_request.request_id,
        permit_id=worker_request.permit_id,
        action_id=worker_request.action_id,
        operation=worker_request.operation,
        exit_code=completed.returncode,
        output_sha256=output_digest,
        output_truncated=bool(worker_output.get("output_truncated", False)),
        network_io_performed=True,
        permit_consumed_before_io=True,
    )
    registered = register_worker_receipt(
        receipt,
        manifest_path=manifest_path,
        artifact_directory=worker_artifacts,
    )
    register_evidence(
        manifest_path,
        command_path,
        evidence_type="runtime.qualification.command.v1",
        permit_id=worker_request.permit_id,
        action_id=worker_request.action_id,
    )
    register_evidence(
        manifest_path,
        output_path,
        evidence_type="runtime.qualification.output.v1",
        permit_id=worker_request.permit_id,
        action_id=worker_request.action_id,
    )

    journal_entries = (
        QualificationJournalEntry(
            runtime_id=RUNTIME_ID,
            stage="authorized-lab",
            event="permit-consumed-before-worker-launch",
            evidence_path=str(state_path),
            details={
                "permit_id": worker_request.permit_id,
                "action_id": worker_request.action_id,
                "binding_hash": consumption.binding_hash(),
            },
        ),
        QualificationJournalEntry(
            runtime_id=RUNTIME_ID,
            stage="authorized-lab",
            event="bounded-network-worker-completed",
            evidence_path=str(output_path),
            details={
                "target": worker_request.target,
                "docker_network": lab.docker_network,
                "image_id": image_id,
            },
        ),
        QualificationJournalEntry(
            runtime_id=RUNTIME_ID,
            stage="receipt-ingestion",
            event="worker-receipt-registered",
            evidence_path=registered.manifest_entry.artifact_path,
            details={"evidence_id": registered.manifest_entry.evidence_id},
        ),
    )
    with journal_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(render_jsonl(journal_entries))

    return {
        "runtime_id": RUNTIME_ID,
        "image_id": image_id,
        "engagement_id": engagement.id,
        "target": worker_request.target,
        "permit_id": worker_request.permit_id,
        "action_id": worker_request.action_id,
        "permit_consumed_before_io": True,
        "container_execution": "PERFORMED",
        "network_execution": "PERFORMED",
        "network": lab.docker_network,
        "evidence_id": registered.manifest_entry.evidence_id,
        "manifest_path": str(manifest_path),
        "journal_path": str(journal_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run ASTP's permit-gated local qualification worker"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()

    signing_key = os.environ.get("ASTP_PERMIT_KEY", "")
    if not signing_key:
        raise SystemExit("ASTP_PERMIT_KEY is required for permit-gated qualification")

    result = run_security_tools_lab_qualification(args.root.resolve(), signing_key=signing_key)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
