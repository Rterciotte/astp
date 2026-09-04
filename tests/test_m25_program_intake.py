from datetime import UTC, datetime
from pathlib import Path

import pytest

from astp.browser_intake import (
    BrowserCapture,
    _capture_handler,
    capture_digest,
    capture_to_text,
    load_capture,
    write_capture,
)
from astp.models import ScopeKind
from astp.program_intake import compile_program, import_program_text

SMARTFIT = """
###### Programa Público
### 1.1. EXCLUSÃO DE ENDPOINTS / ATIVOS
- https://universidade.smartfit.com.br/
- https://universidad.smartfit.com/
- Qualquer sistema, domínio, subdomínio, API ou serviço relacionado às plataformas de
  Universidade Smart Fit
- Qualquer sistema, domínio, subdomínio, API ou serviço pertencente ou operado pela empresa ASAP
- Sistemas e serviços relacionados aos totens utilizados nas academias Smart Fit
- Recomendamos o User Agent: Bughunt - Security Research.
- É proibido realizar ataques quando o programa estiver offline.
- Interaja apenas com as contas que você possui ou com permissão explícita.
- Ataques de brute-force em formulários de autenticação são proibidos.
- Engenharia social é proibida.
- Negação de serviço (DoS) é proibida.
- Uso de ferramentas automatizadas que podem gerar tráfego significativo é proibido.
## Escopo
- *.smartfit.com.br
- https://smartfit.com
- *.smartfit.com
"""


def test_smartfit_intake_extracts_allow_deny_and_review_issues() -> None:
    program = import_program_text(SMARTFIT, name="Smart Fit", platform="bughunt")

    allowed = {(item.kind, item.value) for item in program.allowed_scope()}
    denied = {(item.kind, item.value) for item in program.denied_scope()}
    issue_codes = {issue.code for issue in program.issues}

    assert (ScopeKind.WILDCARD_DOMAIN, "*.smartfit.com.br") in allowed
    assert (ScopeKind.DOMAIN, "smartfit.com") in allowed
    assert (ScopeKind.DOMAIN, "universidade.smartfit.com.br") in denied
    assert "qualitative_rate_limit" in issue_codes
    assert "broad_asset_exclusion" in issue_codes
    assert "physical_or_totem_asset_exclusion" in issue_codes
    assert program.recommended_user_agent == "Bughunt - Security Research"


def test_compile_blocks_unresolved_broad_exclusions() -> None:
    program = import_program_text(SMARTFIT, name="Smart Fit", platform="bughunt")
    with pytest.raises(ValueError, match="unresolved review issues"):
        compile_program(program, max_requests_per_second=1)


def test_compile_requires_explicit_rate_for_qualitative_limit() -> None:
    program = import_program_text(
        """
        ## Escopo
        - *.example.com
        - Uso de ferramentas automatizadas que podem gerar tráfego significativo é proibido.
        """,
        name="Example",
        platform="manual",
    )
    with pytest.raises(ValueError, match="qualitative traffic restriction"):
        compile_program(program)
    engagement = compile_program(program, max_requests_per_second=1)
    assert engagement.constraints.max_requests_per_second == 1


def test_browser_capture_round_trip_and_digest(tmp_path: Path) -> None:
    capture = BrowserCapture(
        url="https://admin.example.test/program/1",
        title="Program",
        text="## Escopo\n*.example.com",
        tables=[[["Scope"], ["*.example.com"]]],
        links=[{"text": "Rules", "href": "https://example.test/rules"}],
        captured_at=datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
    )
    path = tmp_path / "capture.json"
    receipt = write_capture(capture, path)
    loaded = load_capture(path)

    assert loaded == capture
    assert receipt.sha256 == capture_digest(capture)
    assert "*.example.com" in capture_to_text(loaded)


def test_browser_capture_schema_contains_no_session_secret_fields() -> None:
    fields = set(BrowserCapture.model_fields)
    assert "cookies" not in fields
    assert "authorization" not in fields
    assert "local_storage" not in fields
    assert "session_storage" not in fields
    assert "password" not in fields


def test_browser_capture_handler_binds_output_and_token(tmp_path: Path) -> None:
    output = tmp_path / "capture.json"
    handler = _capture_handler(output, "one-time-token")
    assert handler.output_path == output
    assert handler.intake_token == "one-time-token"
