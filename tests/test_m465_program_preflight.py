from __future__ import annotations

from datetime import UTC, datetime

from astp.browser_intake import BrowserCapture, BrowserOperationalSignal
from astp.models import OperationalStatus
from astp.program_intake import import_program_text
from astp.program_preflight import (
    PolicyDriftStatus,
    _capture_status,
    classify_policy_drift,
    evaluate_preflight_gate,
    program_security_fingerprint,
)

POLICY = """
# Escopo
*.smartfit.com.br

5. Testes são proibidos enquanto o programa estiver offline.
5.37. Uso de ferramentas automatizadas que podem gerar tráfego significativo.
"""


def _program(text: str = POLICY):
    return import_program_text(
        text,
        name="Smart Fit",
        platform="bughunt",
        source_type="authenticated_browser",
        source_url="https://bughunt.example/program/detail/1",
        captured_at=datetime.now(UTC),
        program_id="smartfit",
    )


def test_browser_capture_accepts_structured_operational_status_hint() -> None:
    capture = BrowserCapture(
        url="https://bughunt.example/program/detail/1",
        text="Program detail",
        operational_status_hint="online",
        operational_status_evidence="span.status: Online",
    )
    assert capture.operational_status_hint == "online"
    assert capture.operational_status_evidence == "span.status: Online"


def test_policy_fingerprint_ignores_source_hash_only_change() -> None:
    previous = _program()
    current = previous.model_copy(deep=True)
    current.source.content_sha256 = "a" * 64
    status, old_fingerprint, new_fingerprint = classify_policy_drift(previous, current)
    assert status == PolicyDriftStatus.NON_SECURITY_TEXT_ONLY
    assert old_fingerprint == new_fingerprint == program_security_fingerprint(previous)


def test_security_relevant_scope_change_is_drift() -> None:
    previous = _program()
    current = _program(POLICY.replace("*.smartfit.com.br", "*.smartfit.com"))
    status, old_fingerprint, new_fingerprint = classify_policy_drift(previous, current)
    assert status == PolicyDriftStatus.SECURITY_RELEVANT
    assert old_fingerprint != new_fingerprint


def test_gate_allows_only_fresh_ready_online_ready_engine() -> None:
    result = evaluate_preflight_gate(
        source_capture_fresh=True,
        policy_ready=True,
        policy_drift=PolicyDriftStatus.NONE,
        requires_online=True,
        operational_status=OperationalStatus.ONLINE,
        full_pentest_ready=True,
    )
    assert result.execution_eligible is True
    assert result.blocking_reasons == ()


def test_gate_blocks_unknown_online_status() -> None:
    result = evaluate_preflight_gate(
        source_capture_fresh=True,
        policy_ready=True,
        policy_drift=PolicyDriftStatus.NONE,
        requires_online=True,
        operational_status=OperationalStatus.UNKNOWN,
        full_pentest_ready=True,
    )
    assert result.execution_eligible is False
    assert "current program online/offline status is not proven" in result.blocking_reasons


def test_gate_blocks_security_policy_drift() -> None:
    result = evaluate_preflight_gate(
        source_capture_fresh=True,
        policy_ready=True,
        policy_drift=PolicyDriftStatus.SECURITY_RELEVANT,
        requires_online=True,
        operational_status=OperationalStatus.ONLINE,
        full_pentest_ready=True,
    )
    assert result.execution_eligible is False
    assert "security-relevant policy drift requires review" in result.blocking_reasons


def test_gate_blocks_stale_source_and_readiness_failure() -> None:
    result = evaluate_preflight_gate(
        source_capture_fresh=False,
        policy_ready=True,
        policy_drift=PolicyDriftStatus.NONE,
        requires_online=False,
        operational_status=OperationalStatus.UNKNOWN,
        full_pentest_ready=False,
    )
    assert result.execution_eligible is False
    assert "program source capture is stale" in result.blocking_reasons
    assert "ASTP full-pentest readiness gate is not satisfied" in result.blocking_reasons


def test_bughunt_enabled_submission_affordance_proves_online() -> None:
    capture = BrowserCapture(
        url="https://admin.bughunt.com.br/program/detail?abc",
        text="Grupo Smart Fit\nPublicado há 6 meses\nSubmeter Relatório",
        operational_signals=[
            BrowserOperationalSignal(
                kind="submission_control",
                evidence="button.btn-primary: Submeter Relatório",
                visible=True,
                enabled=True,
            ),
            BrowserOperationalSignal(
                kind="published_marker",
                evidence="Publicado há 6 meses",
                visible=True,
            ),
        ],
    )
    status, source, evidence = _capture_status(capture, platform="bughunt")
    assert status == OperationalStatus.ONLINE
    assert source == "authenticated_browser_bughunt_operational_affordance"
    assert evidence is not None and "Submeter Relatório" in evidence


def test_bughunt_disabled_submission_control_does_not_prove_online() -> None:
    capture = BrowserCapture(
        url="https://admin.bughunt.com.br/program/detail?abc",
        text="Grupo Smart Fit\nPublicado há 6 meses\nSubmeter Relatório",
        operational_signals=[
            BrowserOperationalSignal(
                kind="submission_control",
                evidence="button.disabled: Submeter Relatório",
                visible=True,
                enabled=False,
            ),
            BrowserOperationalSignal(
                kind="published_marker",
                evidence="Publicado há 6 meses",
                visible=True,
            ),
        ],
    )
    status, source, evidence = _capture_status(capture, platform="bughunt")
    assert status == OperationalStatus.UNKNOWN
    assert source is None
    assert evidence is None


def test_explicit_offline_signal_overrides_bughunt_submission_affordance() -> None:
    capture = BrowserCapture(
        url="https://admin.bughunt.com.br/program/detail?abc",
        text="Grupo Smart Fit\nPrograma offline\nSubmeter Relatório",
        operational_signals=[
            BrowserOperationalSignal(
                kind="blocking_banner",
                status="offline",
                evidence="div.alert: Programa offline",
                visible=True,
            ),
            BrowserOperationalSignal(
                kind="submission_control",
                evidence="button.btn-primary: Submeter Relatório",
                visible=True,
                enabled=True,
            ),
            BrowserOperationalSignal(
                kind="published_marker",
                evidence="Publicado há 6 meses",
                visible=True,
            ),
        ],
    )
    status, source, evidence = _capture_status(capture, platform="bughunt")
    assert status == OperationalStatus.OFFLINE
    assert source == "authenticated_browser_explicit_status"
    assert evidence == "div.alert: Programa offline"
