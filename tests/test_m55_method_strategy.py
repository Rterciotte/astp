from astp.method_strategy import choose_observation_method


def test_method_strategy_is_head_first():
    assert choose_observation_method().method == "HEAD"
    assert choose_observation_method(body_required=True).method == "GET"
