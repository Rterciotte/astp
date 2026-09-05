from __future__ import annotations

from urllib.parse import urlparse

from pydantic import BaseModel, Field

from astp.capability_action import CapabilityAction, CapabilityOperation


class SafeSurfacePlan(BaseModel):
    target: str
    actions: list[CapabilityAction] = Field(default_factory=list)
    network_execution_performed: bool = False


def plan_safe_surface_observations(target: str) -> SafeSurfacePlan:
    """Build a conservative initial observation set without granting execution rights."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("target must contain a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    actions = [
        CapabilityAction(
            capability_id="dns.lookup.v1",
            operation=CapabilityOperation.DNS_A,
            target=hostname,
        ),
        CapabilityAction(
            capability_id="dns.lookup.v1",
            operation=CapabilityOperation.DNS_AAAA,
            target=hostname,
        ),
    ]
    if parsed.scheme == "https":
        actions.append(
            CapabilityAction(
                capability_id="tls.handshake.v1",
                operation=CapabilityOperation.TLS_HANDSHAKE,
                target=hostname,
                port=port,
            )
        )
    actions.append(
        CapabilityAction(
            capability_id="http.observation.v1",
            operation=CapabilityOperation.HTTP_HEAD,
            target=target,
        )
    )
    return SafeSurfacePlan(target=target, actions=actions)
