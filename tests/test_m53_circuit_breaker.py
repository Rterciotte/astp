from astp.circuit_breaker import CircuitState, FailureCircuitBreaker, record_circuit_result


def test_circuit_breaker_opens_after_consecutive_failures():
    breaker = FailureCircuitBreaker(max_consecutive_failures=2)
    breaker = record_circuit_result(breaker, failed=True)
    assert breaker.state == CircuitState.CLOSED
    breaker = record_circuit_result(breaker, failed=True)
    assert breaker.state == CircuitState.OPEN
    breaker = record_circuit_result(breaker, failed=False)
    assert breaker.state == CircuitState.CLOSED
