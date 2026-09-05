from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from astp.capability_action import CapabilityAction, CapabilityOperation
from astp.capability_grant import SignedCapabilityGrant
from astp.capability_observation import observe_dns, observe_tls
from astp.models import Engagement, TestDefinition
from astp.permits import SignedExecutionPermit


def dispatch_capability_observation(
    grant: SignedCapabilityGrant,
    permit: SignedExecutionPermit,
    action: CapabilityAction,
    engagement: Engagement,
    test: TestDefinition,
    keys: str | bytes | Mapping[str, str | bytes],
    *,
    state_path: Path,
    evidence_path: Path,
    manifest_path: Path,
):
    if action.operation in {
        CapabilityOperation.DNS_A,
        CapabilityOperation.DNS_AAAA,
        CapabilityOperation.DNS_CNAME,
    }:
        return observe_dns(
            grant,
            permit,
            action,
            engagement,
            test,
            keys,
            state_path=state_path,
            evidence_path=evidence_path,
            manifest_path=manifest_path,
        )
    if action.operation == CapabilityOperation.TLS_HANDSHAKE:
        return observe_tls(
            grant,
            permit,
            action,
            engagement,
            test,
            keys,
            state_path=state_path,
            evidence_path=evidence_path,
            manifest_path=manifest_path,
        )
    raise ValueError(f"unsupported capability operation: {action.operation.value}")
