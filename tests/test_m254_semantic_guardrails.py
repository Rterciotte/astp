from datetime import UTC

from astp.authorization import AuthorizationRequest, authorize_test
from astp.models import (
    Decision,
    RiskClass,
    SemanticExclusionKind,
)
from astp.models import (
    TestDefinition as ASTPTestDefinition,
)
from astp.program_intake import (
    compile_program,
    import_program_text,
    resolve_issue_with_semantic_exclusion,
    resolve_rate_issue,
)

SMARTFIT = """
Programa Público
1.1. EXCLUSÃO DE ENDPOINTS / ATIVOS
Qualquer sistema relacionado à Universidade Smart Fit, independentemente do país
Qualquer sistema, domínio, subdomínio, API ou serviço pertencente ou operado pela empresa ASAP
Sistemas, aplicações, APIs, equipamentos e serviços relacionados aos totens utilizados nas
academias Smart Fit
5.37. Uso de ferramentas automatizadas que podem gerar tráfego significativo e possivelmente
prejudicar o funcionamento de nossa aplicação.
Escopo
*.smartfit.com.br
"""


def _reviewed_program():
    program = import_program_text(SMARTFIT, name="Smart Fit", platform="bughunt")
    resolve_rate_issue(program, 1.0)
    university_index = next(
        i
        for i, issue in enumerate(program.issues, 1)
        if "Universidade Smart Fit" in (issue.source_text or "")
    )
    asap_index = next(
        i for i, issue in enumerate(program.issues, 1) if "ASAP" in (issue.source_text or "")
    )
    totem_index = next(
        i
        for i, issue in enumerate(program.issues, 1)
        if issue.code == "physical_or_totem_asset_exclusion"
    )
    resolve_issue_with_semantic_exclusion(
        program,
        issue_index=university_index,
        kind=SemanticExclusionKind.PRODUCT_FAMILY,
        value="Universidade Smart Fit",
    )
    resolve_issue_with_semantic_exclusion(
        program,
        issue_index=asap_index,
        kind=SemanticExclusionKind.ORGANIZATION_FAMILY,
        value="ASAP",
    )
    resolve_issue_with_semantic_exclusion(
        program,
        issue_index=totem_index,
        kind=SemanticExclusionKind.ASSET_FAMILY,
        value="Smart Fit gym totem systems",
    )
    return program


def test_semantic_review_can_make_program_ready_without_inventing_hosts() -> None:
    program = _reviewed_program()

    assert not program.unresolved_issues
    assert len(program.semantic_exclusions) == 3
    engagement = compile_program(program)
    assert engagement.constraints.max_requests_per_second == 1.0
    assert len(engagement.constraints.semantic_exclusions) == 3


def test_semantic_guardrail_requires_explicit_target_clearance() -> None:
    engagement = compile_program(_reviewed_program())
    test = ASTPTestDefinition(
        id="observation",
        title="Observation",
        category="discovery",
        risk_class=RiskClass.SAFE_ACTIVE,
    )

    result = authorize_test(
        engagement,
        test,
        AuthorizationRequest(target="https://www.smartfit.com.br/"),
    )

    assert result.decision == Decision.INSUFFICIENT_CONTEXT
    assert any(check.name == "semantic_exclusions" for check in result.checks)


def test_semantic_guardrail_denies_known_match() -> None:
    engagement = compile_program(_reviewed_program())
    test = ASTPTestDefinition(
        id="observation",
        title="Observation",
        category="discovery",
        risk_class=RiskClass.SAFE_ACTIVE,
    )
    excluded = engagement.constraints.semantic_exclusions[0]

    result = authorize_test(
        engagement,
        test,
        AuthorizationRequest(
            target="https://www.smartfit.com.br/",
            semantic_exclusion_matches={excluded.id},
        ),
    )

    assert result.decision == Decision.DENY


def test_semantic_guardrail_allows_scope_evaluation_only_after_all_clear() -> None:
    engagement = compile_program(_reviewed_program())
    test = ASTPTestDefinition(
        id="observation",
        title="Observation",
        category="discovery",
        risk_class=RiskClass.SAFE_ACTIVE,
    )
    clear_ids = {rule.id for rule in engagement.constraints.semantic_exclusions}

    result = authorize_test(
        engagement,
        test,
        AuthorizationRequest(
            target="https://www.smartfit.com.br/",
            semantic_exclusion_clears=clear_ids,
        ),
    )

    assert result.decision == Decision.ALLOW


def test_resync_preserves_review_only_when_source_issue_is_unchanged(tmp_path) -> None:
    from datetime import datetime

    from astp.browser_intake import BrowserCapture
    from astp.program_catalog import (
        BugBountyWorkspace,
        discover_programs,
        merge_discovery,
        sync_program_capture,
    )

    listing = BrowserCapture(
        url="https://admin.bughunt.test/programs",
        title="Programs",
        text="Programas Timeline!\nMostrando 1 de 1 resultados.",
        links=[
            {
                "text": "Smart Fit",
                "href": "https://admin.bughunt.test/program/detail?smartfit",
                "context": "Smart Fit",
            }
        ],
    )
    workspace = BugBountyWorkspace(platform="bughunt", source_url=listing.url)
    merge_discovery(workspace, discover_programs(listing, platform="bughunt"))
    candidate = workspace.programs[0].candidate
    catalog = tmp_path / ".astp" / "program-catalog.yaml"
    captures = tmp_path / ".astp" / "captures"
    programs = tmp_path / "programs"

    capture = BrowserCapture(
        url=candidate.detail_url,
        title="Smart Fit",
        text="Política do Programa\nLista de escopo do programa\n" + SMARTFIT,
        captured_at=datetime(2026, 9, 4, 16, 0, tzinfo=UTC),
    )
    first = sync_program_capture(
        workspace,
        candidate_id=candidate.id,
        capture=capture,
        catalog_path=catalog,
        captures_dir=captures,
        programs_dir=programs,
    )
    rate_index = next(
        i for i, issue in enumerate(first.issues, 1) if issue.code == "qualitative_rate_limit"
    )
    resolve_rate_issue(first, 1.0)
    broad_index = next(
        i
        for i, issue in enumerate(first.issues, 1)
        if "Universidade Smart Fit" in (issue.source_text or "")
    )
    resolve_issue_with_semantic_exclusion(
        first,
        issue_index=broad_index,
        kind=SemanticExclusionKind.PRODUCT_FAMILY,
        value="Universidade Smart Fit",
    )
    from astp.io import dump_yaml

    dump_yaml(first, programs / f"{candidate.id}.yaml")

    second = sync_program_capture(
        workspace,
        candidate_id=candidate.id,
        capture=capture,
        catalog_path=catalog,
        captures_dir=captures,
        programs_dir=programs,
    )

    assert second.reviewed_max_requests_per_second == 1.0
    assert second.issues[rate_index - 1].resolved
    assert any(
        issue.resolved
        for issue in second.issues
        if "Universidade Smart Fit" in (issue.source_text or "")
    )
    assert len(second.semantic_exclusions) == 1


def test_planner_target_semantic_assessment_is_exact_target_bound() -> None:
    from datetime import datetime

    from astp.planner import PlanItemStatus, TargetSemanticAssessment, build_observation_plan
    from astp.target_discovery import CandidateKind, CandidateSafety, TargetCandidate
    from astp.target_registry import RegistryEntry, TargetRegistry

    engagement = compile_program(_reviewed_program())
    now = datetime.now(UTC)
    targets = ["https://smartfit.com.br/", "https://other.smartfit.com.br/"]
    entries = []
    for index, target in enumerate(targets):
        candidate = TargetCandidate(
            id=f"candidate-{index}",
            canonical_target=target,
            display_target=target,
            kind=CandidateKind.LINK,
            safety=CandidateSafety.READY_FOR_POLICY,
            in_scope=True,
            same_origin=True,
            requires_new_permit=True,
            requires_semantic_assessment=True,
            executable=False,
            reason="test",
            provenance=(),
            discovered_at=now,
        )
        entries.append(
            RegistryEntry(
                canonical_target=target,
                candidate_ids=[candidate.id],
                provenance=[],
                latest_candidate=candidate,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
    registry = TargetRegistry(engagement_id=engagement.id, updated_at=now, entries=entries)
    test = ASTPTestDefinition(
        id="observation",
        title="Observation",
        category="discovery",
        risk_class=RiskClass.SAFE_ACTIVE,
    )
    all_clear = {rule.id for rule in engagement.constraints.semantic_exclusions}

    plan = build_observation_plan(
        registry,
        engagement,
        test,
        semantic_target_assessments={
            targets[0]: TargetSemanticAssessment(semantic_exclusion_clears=all_clear)
        },
        now=now,
    )

    assert plan.items[0].status == PlanItemStatus.AUTHORIZABLE
    assert plan.items[0].semantic_exclusion_clears == all_clear
    assert plan.items[1].status == PlanItemStatus.BLOCKED_CONTEXT
    assert plan.items[1].semantic_exclusion_clears == set()


def test_planner_target_semantic_match_never_becomes_authorizable() -> None:
    from datetime import datetime

    from astp.planner import PlanItemStatus, TargetSemanticAssessment, build_observation_plan
    from astp.target_discovery import CandidateKind, CandidateSafety, TargetCandidate
    from astp.target_registry import RegistryEntry, TargetRegistry

    engagement = compile_program(_reviewed_program())
    now = datetime.now(UTC)
    target = "https://smartfit.com.br/"
    candidate = TargetCandidate(
        id="candidate-match",
        canonical_target=target,
        display_target=target,
        kind=CandidateKind.LINK,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        same_origin=True,
        requires_new_permit=True,
        requires_semantic_assessment=True,
        executable=False,
        reason="test",
        provenance=(),
        discovered_at=now,
    )
    registry = TargetRegistry(
        engagement_id=engagement.id,
        updated_at=now,
        entries=[
            RegistryEntry(
                canonical_target=target,
                candidate_ids=[candidate.id],
                provenance=[],
                latest_candidate=candidate,
                first_seen_at=now,
                last_seen_at=now,
            )
        ],
    )
    test = ASTPTestDefinition(
        id="observation",
        title="Observation",
        category="discovery",
        risk_class=RiskClass.SAFE_ACTIVE,
    )
    matched = engagement.constraints.semantic_exclusions[0].id

    plan = build_observation_plan(
        registry,
        engagement,
        test,
        semantic_target_assessments={
            target: TargetSemanticAssessment(semantic_exclusion_matches={matched})
        },
        now=now,
    )

    assert plan.items[0].status == PlanItemStatus.BLOCKED_POLICY
    assert plan.items[0].semantic_exclusion_matches == {matched}


def test_planner_rejects_global_and_target_semantic_review_mix() -> None:
    from astp.planner import TargetSemanticAssessment, build_observation_plan
    from astp.target_registry import empty_registry

    engagement = compile_program(_reviewed_program())
    test = ASTPTestDefinition(
        id="observation",
        title="Observation",
        category="discovery",
        risk_class=RiskClass.SAFE_ACTIVE,
    )

    try:
        build_observation_plan(
            empty_registry(engagement.id),
            engagement,
            test,
            semantic_exclusion_clears=set(),
            semantic_target_assessments={"https://example.test/": TargetSemanticAssessment()},
        )
    except ValueError as exc:
        assert "cannot be combined" in str(exc)
    else:
        raise AssertionError("expected ValueError")
