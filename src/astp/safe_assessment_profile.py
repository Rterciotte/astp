from __future__ import annotations

from pydantic import BaseModel, Field


class SafeAssessmentProfile(BaseModel):
    """Autonomous ceiling for the first end-to-end field mode.

    This profile intentionally excludes exploit payloads, credential attacks,
    state-changing methods, brute force, and intrusive validation.
    """

    name: str = "safe-observation-v1"
    allowed_capabilities: list[str] = Field(
        default_factory=lambda: ["http.observation.v1", "dns.lookup.v1", "tls.handshake.v1"]
    )
    allowed_http_methods: list[str] = Field(default_factory=lambda: ["GET", "HEAD"])
    state_changing_allowed: bool = False
    credential_attacks_allowed: bool = False
    brute_force_allowed: bool = False
    exploit_payloads_allowed: bool = False
    intrusive_validation_allowed: bool = False
    fresh_permit_per_action: bool = True
