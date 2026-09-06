from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from astp.io import dump_yaml, load_model
from astp.models import Engagement, ProgramOperationalAttestation
from astp.operational_lease import MAX_ASSESSMENT_LEASE_SECONDS, build_operational_lease
from astp.program_field_assessment import FieldAssessmentPreparation


def create_lease_from_preparation(
    preparation_path: Path,
    *,
    ttl_seconds: int = MAX_ASSESSMENT_LEASE_SECONDS,
    now: datetime | None = None,
) -> Path:
    preparation = FieldAssessmentPreparation.model_validate_json(
        preparation_path.read_text(encoding="utf-8")
    )
    engagement = load_model(Path(preparation.engagement_path), Engagement)
    attestation = load_model(Path(preparation.attestation_path), ProgramOperationalAttestation)
    lease = build_operational_lease(
        engagement,
        attestation,
        assessment_id=preparation.assessment_id,
        preflight_report_hash=preparation.preflight_report_hash,
        valid_from=preparation.prepared_at,
        ttl_seconds=ttl_seconds,
    )
    current = now or datetime.now(UTC)
    if current >= lease.valid_until:
        raise ValueError("assessment operational lease window has already expired")
    output = preparation_path.parent / f"operational-lease-{lease.lease_hash}.yaml"
    rendered = dump_yaml(lease)
    if output.exists() and output.read_text(encoding="utf-8") != rendered:
        raise ValueError("immutable assessment operational lease collision")
    if not output.exists():
        output.write_text(rendered, encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create/recover a bounded operational lease for an existing field assessment"
    )
    parser.add_argument("--preparation", type=Path, required=True)
    parser.add_argument("--ttl-seconds", type=int, default=MAX_ASSESSMENT_LEASE_SECONDS)
    args = parser.parse_args()
    try:
        path = create_lease_from_preparation(args.preparation, ttl_seconds=args.ttl_seconds)
    except (OSError, ValueError) as exc:
        print(f"ASSESSMENT_OPERATIONAL_LEASE_BLOCKED: {exc}")
        return 2
    print(json.dumps({"operational_lease_path": str(path)}, indent=2, sort_keys=True))
    print("ASSESSMENT_OPERATIONAL_LEASE: READY")
    print("Network execution: NOT PERFORMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
