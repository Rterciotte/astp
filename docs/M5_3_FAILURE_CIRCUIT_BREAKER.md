# M5.3 — Failure Circuit Breaker

Consecutive broker/worker failures are counted. Reaching the configured threshold opens the circuit and stops further queue processing until a new session is deliberately prepared.
