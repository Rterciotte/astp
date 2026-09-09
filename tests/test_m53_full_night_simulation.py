from astp.m53_simulation import run_accelerated_full_night


def test_m53_multi_program_full_night_simulation():
    result = run_accelerated_full_night()
    assert result.passed and result.graceful_drain
    by_id = {item.program_id: item for item in result.programs}
    assert by_id["B"].state == "blocked"
    assert by_id["C"].state == "blocked"
    assert by_id["E"].lease_renewals == 2
    assert by_id["F"].revision_changes == 1
    assert by_id["G"].retries == 1
    assert by_id["H"].rate_backoffs == 1
    assert result.fairness_order[:6] == result.fairness_order[6:]
