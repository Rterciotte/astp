import pytest

from astp.session_ledger import initialize_session_ledger, record_completion, reserve_action


def test_session_ledger_reserves_atomically(tmp_path):
    path = tmp_path / "ledger.db"
    initialize_session_ledger(path, "s")
    counters = reserve_action(path, "s", max_actions=1, max_requests=1)
    assert counters.actions_reserved == 1
    assert counters.requests_reserved == 1
    with pytest.raises(ValueError, match="action budget exhausted"):
        reserve_action(path, "s", max_actions=1, max_requests=1)
    counters = record_completion(path, "s")
    assert counters.completed == 1
