from __future__ import annotations

from datetime import UTC, datetime

from astp.findings import FindingSet, ProofState
from astp.models import Engagement


def render_markdown_report(
    engagement: Engagement,
    findings: FindingSet,
    *,
    now: datetime | None = None,
) -> str:
    generated = now or datetime.now(UTC)
    lines = [
        f"# ASTP Security Assessment — {engagement.name}",
        "",
        f"Generated: {generated.isoformat()}",
        f"Engagement ID: `{engagement.id}`",
        "",
        "## Executive summary",
        "",
        f"ASTP correlated {len(findings.findings)} finding(s). ",
        (
            "Only evidence-backed proof states are reported; no proof state is inferred beyond "
            "supplied evidence."
        ),
        "",
        "## Findings",
        "",
    ]
    if not findings.findings:
        lines.append("No correlated findings were supplied.")
    for finding in findings.findings:
        lines.extend(
            [
                f"### {finding.id} — {finding.vulnerability}",
                "",
                f"- Asset: `{finding.asset}`",
                f"- Endpoint: `{finding.endpoint or 'n/a'}`",
                f"- Role: `{finding.role or 'n/a'}`",
                f"- Proof state: **{finding.proof_state.value.upper()}**",
                f"- CWE: {', '.join(finding.cwe) or 'not mapped'}",
                f"- OWASP: {', '.join(finding.owasp) or 'not mapped'}",
                "",
                "Evidence signals:",
                "",
            ]
        )
        if finding.signals:
            for signal in finding.signals:
                lines.append(
                    f"- `{signal.evidence_id}` via `{signal.sensor}`: {signal.observation} "
                    f"(confidence {signal.confidence:.2f})"
                )
        else:
            lines.append("- No signals attached.")
        lines.extend(
            [
                "",
                "Remediation:",
                "",
                finding.remediation or "No remediation text supplied.",
                "",
            ]
        )
    lines.extend(
        [
            "## Retest plan",
            "",
            (
                "Each retest action must pass current policy evaluation and receive a fresh "
                "execution permit."
            ),
            "",
        ]
    )
    for finding in findings.findings:
        if finding.proof_state in {ProofState.VERIFIED, ProofState.IMPACT_CONFIRMED}:
            lines.append(
                f"- [ ] Retest `{finding.id}` on `{finding.asset}` using bounded evidence "
                "collection."
            )
    return "\n".join(lines).rstrip() + "\n"
