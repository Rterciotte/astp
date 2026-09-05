import pytest

from astp.origin_budget import OriginBudget, OriginBudgetState, check_and_record_origin


def test_origin_budget_is_per_origin():
    budget = OriginBudget(max_actions_per_origin=1)
    state = check_and_record_origin(budget, OriginBudgetState(), "https://example.com/a")
    with pytest.raises(ValueError, match="origin action budget exhausted"):
        check_and_record_origin(budget, state, "https://example.com/b")
    other = check_and_record_origin(budget, state, "https://api.example.com/")
    assert len(other.counts) == 2
