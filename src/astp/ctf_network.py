from __future__ import annotations

from astp.action import canonical_http_target
from astp.ctf_mode import ChallengeDefinition, CtfNetworkPolicy


def ensure_ctf_http_target_authorized(challenge: ChallengeDefinition, target: str) -> str:
    if not challenge.allow_automation:
        raise ValueError("challenge rules do not allow automation")
    if challenge.network_policy != CtfNetworkPolicy.DECLARED_ENDPOINTS_ONLY:
        raise ValueError("challenge network policy does not allow endpoint execution")

    canonical_target = canonical_http_target(target)
    declared: set[str] = set()
    for endpoint in challenge.authorized_endpoints:
        try:
            declared.add(canonical_http_target(endpoint))
        except ValueError as exc:
            raise ValueError(f"invalid declared challenge endpoint: {endpoint}") from exc
    if canonical_target not in declared:
        raise ValueError("target is not an exact declared challenge endpoint")
    return canonical_target
