from pathlib import Path

from astp.browser_intake import BrowserCapture, capture_to_text
from astp.io import dump_yaml, load_model
from astp.models import ScopeKind
from astp.program_catalog import (
    BugBountyWorkspace,
    ProgramPageType,
    ProgramSyncStatus,
    classify_program_page,
    discover_programs,
    merge_discovery,
    save_workspace,
    set_active_programs,
    sync_program_capture,
)
from astp.program_intake import import_program_text


def listing_capture() -> BrowserCapture:
    return BrowserCapture(
        url="https://admin.bughunt.test/programs",
        title="Programs",
        text=(
            "Programas Timeline!\nMostrando 10 de 7 resultados.\n"
            "Grupo Smart Fit - Bug Bounty Público\nPublicado há 6 meses\n"
            "OLX Brasil Bug Bounty\nPublicado há 5 anos"
        ),
        links=[
            {
                "text": "Grupo Smart Fit - Bug Bounty Público",
                "href": "https://admin.bughunt.test/program/detail?smartfit",
                "context": "Grupo Smart Fit - Bug Bounty Público\nRelatórios 278\nEscopo 5",
            },
            {
                "text": "OLX Brasil Bug Bounty",
                "href": "https://admin.bughunt.test/program/detail?olx",
                "context": "OLX Brasil Bug Bounty\nRelatórios 572\nEscopo 13",
            },
            {
                "text": "Ranking",
                "href": "https://admin.bughunt.test/ranking",
                "context": "Ranking",
            },
        ],
    )


def smartfit_detail_capture() -> BrowserCapture:
    return BrowserCapture(
        url="https://admin.bughunt.test/program/detail?smartfit",
        title="Grupo Smart Fit",
        text="""Política do Programa
Programa Público
EXCLUSÃO DE ENDPOINTS / ATIVOS
https://universidade.smartfit.com.br/
https://universidad.smartfit.com/
Qualquer sistema, domínio, subdomínio, API ou serviço relacionado às plataformas de
Universidade Smart Fit
Sistemas, aplicações, APIs, equipamentos e serviços relacionados aos totens utilizados nas
academias Smart Fit
Uso de ferramentas automatizadas que podem gerar tráfego significativo é proibido.
Escopo
Lista de escopo do programa!
*.smartfit.com.br
https://smartfit.com
*.smartfit.com
Recompensas
Recompensas com valores financeiros
""",
        tables=[
            [["Escopo", "Tipo"], ["*.smartfit.com.br", "Domínio"]],
        ],
        links=[
            {"text": "Home", "href": "https://admin.bughunt.test/dashboard"},
        ],
    )


def test_listing_is_classified_and_candidates_are_discovered() -> None:
    capture = listing_capture()
    result = discover_programs(capture, platform="bughunt")
    assert result.page_type == ProgramPageType.PROGRAM_LISTING
    assert [item.name for item in result.candidates] == [
        "Grupo Smart Fit - Bug Bounty Público",
        "OLX Brasil Bug Bounty",
    ]


def test_plain_text_detail_is_classified_and_scope_is_extracted() -> None:
    capture = smartfit_detail_capture()
    assert classify_program_page(capture) == ProgramPageType.PROGRAM_DETAIL
    program = import_program_text(
        capture_to_text(capture),
        name="Grupo Smart Fit - Bug Bounty Público",
        platform="bughunt",
        source_type="authenticated_browser",
        source_url=capture.url,
    )
    allowed = {(rule.kind, rule.value) for rule in program.allowed_scope()}
    denied = {(rule.kind, rule.value) for rule in program.denied_scope()}
    assert (ScopeKind.WILDCARD_DOMAIN, "*.smartfit.com.br") in allowed
    assert (ScopeKind.DOMAIN, "smartfit.com") in allowed
    assert (ScopeKind.DOMAIN, "universidade.smartfit.com.br") in denied
    assert "qualitative_rate_limit" in {issue.code for issue in program.issues}


def test_catalog_sync_writes_capture_and_normalized_program(tmp_path: Path) -> None:
    listing = listing_capture()
    result = discover_programs(listing, platform="bughunt")
    workspace = BugBountyWorkspace(platform="bughunt", source_url=listing.url)
    merge_discovery(workspace, result)
    catalog = tmp_path / ".astp" / "program-catalog.yaml"
    save_workspace(workspace, catalog)

    candidate = workspace.programs[0].candidate
    program = sync_program_capture(
        workspace,
        candidate_id=candidate.id,
        capture=smartfit_detail_capture(),
        catalog_path=catalog,
        captures_dir=tmp_path / ".astp" / "captures",
        programs_dir=tmp_path / "programs",
    )

    loaded = load_model(catalog, BugBountyWorkspace)
    item = next(entry for entry in loaded.programs if entry.candidate.id == candidate.id)
    assert item.sync_status == ProgramSyncStatus.NEEDS_REVIEW
    assert Path(item.capture_path).exists()
    assert Path(item.normalized_path).exists()
    assert len(program.allowed_scope()) >= 2


def test_multiple_programs_can_be_selected_active() -> None:
    result = discover_programs(listing_capture(), platform="bughunt")
    workspace = BugBountyWorkspace(platform="bughunt", source_url="https://admin.bughunt.test")
    merge_discovery(workspace, result)
    selected = {workspace.programs[0].candidate.id, workspace.programs[1].candidate.id}
    set_active_programs(workspace, selected)
    assert {item.candidate.id for item in workspace.active_programs()} == selected


def test_dump_yaml_creates_parent_directories(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "programs" / "catalog.yaml"
    dump_yaml({"ok": True}, output)
    assert output.exists()
