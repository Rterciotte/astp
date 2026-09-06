from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from astp import nightly_campaign as campaign_module
from astp.models import Engagement, ScopeKind, ScopePolicy, ScopeRule
from astp.nightly_campaign import NightlyProgramResult, build_scope_seed_registry


def _workspace(*program_ids: str):
    return SimpleNamespace(
        platform="bughunt",
        programs=[
            SimpleNamespace(
                candidate=SimpleNamespace(
                    id=program_id,
                    name=f"Program {program_id}",
                )
            )
            for program_id in program_ids
        ],
    )


def _stub_campaign_io(monkeypatch, workspace) -> None:
    monkeypatch.setattr(
        campaign_module,
        "load_model",
        lambda path, model: workspace,
    )
    monkeypatch.setattr(
        campaign_module,
        "dump_yaml",
        lambda value, path: None,
    )
    monkeypatch.setattr(
        campaign_module,
        "_write_campaign_markdown",
        lambda summary, path: None,
    )


def _completed_result(item) -> NightlyProgramResult:
    return NightlyProgramResult(
        program_id=item.candidate.id,
        program_name=item.candidate.name,
        status="completed",
        reason="completed",
    )


def test_scope_seed_registry_uses_only_explicit_http_seedable_scope() -> None:
    engagement = Engagement(
        id="eng-nightly",
        name="Nightly",
        scope=ScopePolicy(
            allowed=[
                ScopeRule(kind=ScopeKind.DOMAIN, value="example.com"),
                ScopeRule(
                    kind=ScopeKind.WILDCARD_DOMAIN,
                    value="*.example.net",
                ),
                ScopeRule(
                    kind=ScopeKind.URL_PREFIX,
                    value="https://app.example.org/api",
                ),
                ScopeRule(
                    kind=ScopeKind.CIDR,
                    value="203.0.113.0/24",
                ),
            ]
        ),
    )

    registry = build_scope_seed_registry(
        engagement,
        now=datetime(2026, 9, 6, 22, 0, tzinfo=UTC),
    )

    assert [row.canonical_target for row in registry.entries] == [
        "https://app.example.org/api",
        "https://example.com/",
        "https://example.net/",
    ]
    assert all(row.latest_candidate.requires_new_permit for row in registry.entries)
    assert all(row.latest_candidate.executable is False for row in registry.entries)


def test_scope_seed_registry_does_not_guess_from_cidr() -> None:
    engagement = Engagement(
        id="eng-cidr",
        name="CIDR only",
        scope=ScopePolicy(
            allowed=[
                ScopeRule(
                    kind=ScopeKind.CIDR,
                    value="203.0.113.0/24",
                )
            ]
        ),
    )

    registry = build_scope_seed_registry(engagement)

    assert registry.entries == []


def test_nightly_campaign_isolates_expected_program_failure(
    tmp_path,
    monkeypatch,
) -> None:
    workspace = _workspace("program-one", "program-two")
    _stub_campaign_io(monkeypatch, workspace)

    calls: list[str] = []

    def fake_run_program(**kwargs):
        item = kwargs["item"]
        calls.append(item.candidate.id)
        if item.candidate.id == "program-one":
            raise AttributeError("offline consumer mismatch")
        return _completed_result(item)

    monkeypatch.setattr(
        campaign_module,
        "_run_program",
        fake_run_program,
    )

    summary = campaign_module.run_nightly_campaign(
        catalog_path=tmp_path / "catalog.yaml",
        output_directory=tmp_path / "campaigns",
        execute=False,
    )

    assert calls == ["program-one", "program-two"]
    assert len(summary.program_results) == 2

    failed = summary.program_results[0]
    assert failed.program_id == "program-one"
    assert failed.status == "failed"
    assert "AttributeError" in failed.reason
    assert "offline consumer mismatch" in failed.reason

    completed = summary.program_results[1]
    assert completed.program_id == "program-two"
    assert completed.status == "completed"


def test_nightly_campaign_program_ids_process_only_selected_program(
    tmp_path,
    monkeypatch,
) -> None:
    workspace = _workspace("program-one", "program-two", "program-three")
    _stub_campaign_io(monkeypatch, workspace)

    calls: list[str] = []

    def fake_run_program(**kwargs):
        item = kwargs["item"]
        calls.append(item.candidate.id)
        return _completed_result(item)

    monkeypatch.setattr(campaign_module, "_run_program", fake_run_program)

    summary = campaign_module.run_nightly_campaign(
        catalog_path=tmp_path / "catalog.yaml",
        output_directory=tmp_path / "campaigns",
        execute=False,
        program_ids=["program-two"],
    )

    assert calls == ["program-two"]
    assert [row.program_id for row in summary.program_results] == ["program-two"]


def test_nightly_campaign_program_ids_preserve_requested_order(
    tmp_path,
    monkeypatch,
) -> None:
    workspace = _workspace("program-one", "program-two", "program-three")
    _stub_campaign_io(monkeypatch, workspace)

    calls: list[str] = []

    def fake_run_program(**kwargs):
        item = kwargs["item"]
        calls.append(item.candidate.id)
        return _completed_result(item)

    monkeypatch.setattr(campaign_module, "_run_program", fake_run_program)

    summary = campaign_module.run_nightly_campaign(
        catalog_path=tmp_path / "catalog.yaml",
        output_directory=tmp_path / "campaigns",
        execute=False,
        program_ids=["program-three", "program-one"],
    )

    assert calls == ["program-three", "program-one"]
    assert [row.program_id for row in summary.program_results] == [
        "program-three",
        "program-one",
    ]


def test_nightly_campaign_program_ids_deduplicate_without_reexecution(
    tmp_path,
    monkeypatch,
) -> None:
    workspace = _workspace("program-one", "program-two")
    _stub_campaign_io(monkeypatch, workspace)

    calls: list[str] = []

    def fake_run_program(**kwargs):
        item = kwargs["item"]
        calls.append(item.candidate.id)
        return _completed_result(item)

    monkeypatch.setattr(campaign_module, "_run_program", fake_run_program)

    summary = campaign_module.run_nightly_campaign(
        catalog_path=tmp_path / "catalog.yaml",
        output_directory=tmp_path / "campaigns",
        execute=False,
        program_ids=["program-two", "program-two", "program-one"],
    )

    assert calls == ["program-two", "program-one"]
    assert [row.program_id for row in summary.program_results] == [
        "program-two",
        "program-one",
    ]


def test_nightly_campaign_unknown_program_id_fails_before_program_processing(
    tmp_path,
    monkeypatch,
) -> None:
    workspace = _workspace("program-one", "program-two")
    _stub_campaign_io(monkeypatch, workspace)

    calls: list[str] = []

    def fake_run_program(**kwargs):
        item = kwargs["item"]
        calls.append(item.candidate.id)
        return _completed_result(item)

    monkeypatch.setattr(campaign_module, "_run_program", fake_run_program)

    with pytest.raises(ValueError, match=r"unknown program ID\(s\): missing-program"):
        campaign_module.run_nightly_campaign(
            catalog_path=tmp_path / "catalog.yaml",
            output_directory=tmp_path / "campaigns",
            execute=False,
            program_ids=["missing-program"],
        )

    assert calls == []


def test_nightly_campaign_without_program_ids_preserves_catalog_behavior(
    tmp_path,
    monkeypatch,
) -> None:
    workspace = _workspace("program-one", "program-two", "program-three")
    _stub_campaign_io(monkeypatch, workspace)

    calls: list[str] = []

    def fake_run_program(**kwargs):
        item = kwargs["item"]
        calls.append(item.candidate.id)
        return _completed_result(item)

    monkeypatch.setattr(campaign_module, "_run_program", fake_run_program)

    summary = campaign_module.run_nightly_campaign(
        catalog_path=tmp_path / "catalog.yaml",
        output_directory=tmp_path / "campaigns",
        execute=False,
    )

    assert calls == ["program-one", "program-two", "program-three"]
    assert [row.program_id for row in summary.program_results] == [
        "program-one",
        "program-two",
        "program-three",
    ]
