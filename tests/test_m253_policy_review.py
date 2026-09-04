from datetime import UTC, datetime
from pathlib import Path

import pytest

from astp.browser_intake import BrowserCapture
from astp.io import load_model
from astp.models import ScopeKind, ScopeRule
from astp.program_catalog import (
    BugBountyWorkspace,
    ProgramSyncStatus,
    discover_programs,
    merge_discovery,
    save_workspace,
    sync_program_capture,
)
from astp.program_intake import (
    compile_program,
    import_program_text,
    resolve_issue_with_denies,
    resolve_rate_issue,
)
from astp.program_models import BugBountyProgram

REALISTIC_SMARTFIT = """
Programa Público
1.1. EXCLUSÃO DE ENDPOINTS / ATIVOS
https://universidade.smartfit.com.br/
https://universidad.smartfit.com/
Qualquer sistema, domínio, subdomínio, API ou serviço relacionado às plataformas de
Universidade Smart Fit, independentemente do país
Qualquer sistema, domínio, subdomínio, API ou serviço pertencente ou operado pela empresa ASAP
Sistemas, aplicações, APIs, equipamentos e serviços relacionados aos totens utilizados nas
academias Smart Fit
Caso algum dos ativos acima seja identificado durante os testes realizados em sistemas dentro do
escopo, não prossiga com qualquer tentativa de exploração, validação adicional ou aprofundamento
do teste nesse ativo.
2.4. Interaja apenas com as contas que você possui ou com permissão explícita do titular da conta.
2.5. Recomendamos que os analistas usem o User Agent: Bughunt - Security Research.
2.6. É explicitamente proibido realizar ataques no escopo quando o programa estiver offline.
3.1. Relatórios fora do escopo não serão pagos. Embora aceitos para análise, recomendamos
evitar testes fora do escopo.
5.14. Ataques de brute-force em formulários de autenticação;
5.17. Qualquer atividade que possa levar à interrupção do nosso serviço (ex. DoS);
5.20. Engenharia social (incluindo phishing) na nossa equipe ou terceiros;
5.32. Negação de serviço;
5.37. Uso de ferramentas automatizadas que podem gerar tráfego significativo e possivelmente
prejudicar o funcionamento de nossa aplicação.
Escopo
*.smartfit.com.br
https://smartfit.com
*.smartfit.com
"""


def test_portuguese_dos_contraction_does_not_create_false_positive() -> None:
    program = import_program_text(REALISTIC_SMARTFIT, name="Smart Fit", platform="bughunt")
    no_dos = [constraint for constraint in program.constraints if constraint.code == "no_dos"]

    assert len(no_dos) == 1
    assert len(no_dos[0].provenance) == 2
    texts = {item.source_text for item in no_dos[0].provenance}
    assert any("5.17." in text for text in texts)
    assert any("5.32." in text for text in texts)
    assert not any("ativos acima" in text for text in texts)
    assert not any("Relatórios fora do escopo" in text for text in texts)


def test_numbered_rule_provenance_does_not_stay_stuck_on_section_1_1() -> None:
    program = import_program_text(REALISTIC_SMARTFIT, name="Smart Fit", platform="bughunt")
    social = next(item for item in program.constraints if item.code == "no_social_engineering")

    assert social.provenance[0].section == "5.x numbered rules"


def test_capture_timestamp_is_propagated_to_extracted_provenance() -> None:
    captured_at = datetime(2026, 9, 4, 15, 43, 35, tzinfo=UTC)
    program = import_program_text(
        REALISTIC_SMARTFIT,
        name="Smart Fit",
        platform="bughunt",
        captured_at=captured_at,
    )

    assert program.source.captured_at == captured_at
    assert all(entry.provenance.captured_at == captured_at for entry in program.scope)
    assert all(
        provenance.captured_at == captured_at
        for constraint in program.constraints
        for provenance in constraint.provenance
    )


def test_explicit_finding_exclusions_are_normalized_without_inventing_missing_ones() -> None:
    text = """
    5. ITENS NÃO ACEITOS
    Clickjacking em páginas sem ações sensíveis
    Auto-XSS
    Relatórios de scanner sem validação
    Escopo
    *.example.com
    """
    program = import_program_text(text, name="Example", platform="bughunt")

    assert set(program.excluded_finding_types) == {
        "clickjacking",
        "self_xss",
        "unvalidated_scanner_report",
    }


def test_rate_review_is_recorded_as_operator_decision() -> None:
    program = import_program_text(REALISTIC_SMARTFIT, name="Smart Fit", platform="bughunt")
    resolve_rate_issue(program, 1.0)

    rate_issue = next(issue for issue in program.issues if issue.code == "qualitative_rate_limit")
    assert rate_issue.resolved
    assert rate_issue.resolution is not None
    assert rate_issue.resolution.resolution_type == "operator_constraint"
    assert rate_issue.resolution.operator_value == 1.0
    assert program.reviewed_max_requests_per_second == 1.0


def test_broad_issue_cannot_be_resolved_by_incomplete_host_mapping() -> None:
    program = import_program_text(REALISTIC_SMARTFIT, name="Smart Fit", platform="bughunt")
    index = next(
        index
        for index, issue in enumerate(program.issues, start=1)
        if issue.code == "broad_asset_exclusion"
    )

    with pytest.raises(ValueError, match="semantic exclusions cannot be resolved by host mappings"):
        resolve_issue_with_denies(
            program,
            issue_index=index,
            deny_rules=[ScopeRule(kind=ScopeKind.WILDCARD_DOMAIN, value="*.university.example")],
        )

    assert not program.issues[index - 1].resolved


def test_compile_remains_blocked_while_broad_semantic_exclusions_are_unresolved() -> None:
    program = import_program_text(REALISTIC_SMARTFIT, name="Smart Fit", platform="bughunt")
    resolve_rate_issue(program, 1.0)

    with pytest.raises(ValueError, match="unresolved review issues"):
        compile_program(program)


def _listing_capture() -> BrowserCapture:
    return BrowserCapture(
        url="https://admin.bughunt.test/programs",
        title="Programs",
        text="Programas Timeline!\nMostrando 1 de 1 resultados.\nPublicado há 1 dia",
        links=[
            {
                "text": "Example Program",
                "href": "https://admin.bughunt.test/program/detail?example",
                "context": "Example Program",
            }
        ],
    )


def _detail_capture(captured_at: datetime) -> BrowserCapture:
    return BrowserCapture(
        url="https://admin.bughunt.test/program/detail?example",
        title="Example Program",
        text=(
            "Política do Programa\nPrograma Público\nLista de escopo do programa\n"
            "Escopo\n*.example.com\nRecompensas com valores financeiros"
        ),
        captured_at=captured_at,
    )


def test_catalog_candidate_id_becomes_normalized_program_id(tmp_path: Path) -> None:
    listing = _listing_capture()
    result = discover_programs(listing, platform="bughunt")
    workspace = BugBountyWorkspace(platform="bughunt", source_url=listing.url)
    merge_discovery(workspace, result)
    catalog = tmp_path / ".astp" / "program-catalog.yaml"
    save_workspace(workspace, catalog)
    candidate = workspace.programs[0].candidate
    captured_at = datetime(2026, 9, 4, 15, 43, 35, tzinfo=UTC)

    program = sync_program_capture(
        workspace,
        candidate_id=candidate.id,
        capture=_detail_capture(captured_at),
        catalog_path=catalog,
        captures_dir=tmp_path / ".astp" / "captures",
        programs_dir=tmp_path / "programs",
    )

    assert program.id == candidate.id
    assert program.source.captured_at == captured_at
    item = workspace.programs[0]
    assert item.sync_status == ProgramSyncStatus.READY
    loaded = load_model(Path(item.normalized_path), BugBountyProgram)
    assert loaded.id == candidate.id
