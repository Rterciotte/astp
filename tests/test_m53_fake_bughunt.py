import pytest

from astp.cli import _local_bughunt_detector_requests
from astp.platform_adapters import LocalBughuntAdapter


def test_fake_bughunt_discovers_exactly_eight_authenticated_programs() -> None:
    adapter = LocalBughuntAdapter.authenticated_fixture()
    assert [row.program_id for row in adapter.discover_programs()] == list("ABCDEFGH")
    assert adapter.supports_authenticated_browser_session()
    assert not hasattr(adapter.session, "username")
    assert not hasattr(adapter.session, "password")


def test_spa_readiness_rejects_transitional_dom_then_accepts_semantic_detail() -> None:
    adapter = LocalBughuntAdapter.authenticated_fixture()
    for program_id in ("A", "B", "C", "D", "E"):
        with pytest.raises(TimeoutError):
            adapter.fetch_program_detail(program_id)
        assert adapter.fetch_program_detail(program_id).program_id == program_id


def test_detail_failure_and_timeout_do_not_prevent_next_program() -> None:
    adapter = LocalBughuntAdapter.authenticated_fixture()
    with pytest.raises(ConnectionError):
        adapter.fetch_program_detail("F")
    with pytest.raises(TimeoutError):
        adapter.fetch_program_detail("G")
    assert adapter.fetch_program_detail("H").program_id == "H"


def test_expired_session_enters_waiting_prerequisite_without_login_guess() -> None:
    adapter = LocalBughuntAdapter.authenticated_fixture()
    adapter.expire_session()
    with pytest.raises(PermissionError, match="WAITING_PREREQUISITE"):
        adapter.discover_programs()


def test_operational_refresh_and_revision_drift_are_deterministic() -> None:
    adapter = LocalBughuntAdapter.authenticated_fixture()
    assert adapter.get_operational_status("E") is False
    assert adapter.refresh_program("E").operational is True
    assert adapter.get_revision("F") == "1"
    assert adapter.refresh_program("F").revision == "2"


def test_one_command_planner_derives_requests_without_program_b_scanners() -> None:
    adapter = LocalBughuntAdapter.authenticated_fixture()
    requests = _local_bughunt_detector_requests("campaign", adapter)

    assert {request.program_id for request in requests} == set("ACDEFGH")
    assert all(request.campaign_id == "campaign" for request in requests)
    assert all(request.opportunity.policy_decision.allowed for request in requests)
    assert (
        next(request for request in requests if request.program_id == "D").detector.engine == "ffuf"
    )
    assert (
        next(request for request in requests if request.program_id == "F").program_revision == "2"
    )
