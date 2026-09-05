# M5.6 — Bounded Observation Session Runner

`astp run-observation-session` is the first CLI command that can execute multiple authorized observation actions in one invocation. Safety properties:

- explicit `--execute` opt-in;
- sequential execution only;
- GET/HEAD worker only;
- one fresh Permit Broker authorization and permit per action;
- fresh program status required when the program requires ONLINE status;
- policy-drift hard stop;
- atomic action/request budgets;
- per-origin cap;
- failure circuit breaker;
- existing durable target RPS enforcement;
- one evidence object per completed request;
- hash-linked execution trace;
- redirects remain evidence/candidates and are never automatically followed.
