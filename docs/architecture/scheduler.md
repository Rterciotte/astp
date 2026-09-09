# Orchestrator scheduler

Opportunities are ranked deterministically using family frequency, supporting-signal confidence, request cost, remaining budget/time and previous negative runs. Weighted round robin prevents program starvation. Policy-blocked opportunities never enter execution. Retry is limited to transient classes with bounded exponential backoff; policy/scope/budget denials are not retried.
