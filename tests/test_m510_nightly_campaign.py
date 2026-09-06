from datetime import UTC, datetime
from types import SimpleNamespace

from astp import nightly_campaign as campaign_module
from astp.models import Engagement, ScopeKind, ScopePolicy, ScopeRule
from astp.nightly_campaign import NightlyProgramResult, build_scope_seed_registry


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
    first = SimpleNamespace(
        candidate=SimpleNamespace(
            id="program-one",
            name="Program One",
        )
    )
    second = SimpleNamespace(
        candidate=SimpleNamespace(
            id="program-two",
            name="Program Two",
        )
    )
    workspace = SimpleNamespace(
        platform="bughunt",
        programs=[first, second],
    )

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

    calls: list[str] = []

    def fake_run_program(**kwargs):
        item = kwargs["item"]
        calls.append(item.candidate.id)
        if item.candidate.id == "program-one":
            raise AttributeError("offline consumer mismatch")
        return NightlyProgramResult(
            program_id=item.candidate.id,
            program_name=item.candidate.name,
            status="completed",
            reason="completed",
        )

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
