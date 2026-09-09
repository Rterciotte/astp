# Autonomous orchestrator (M53)

The orchestrator is durable coordination, not an authorization authority. Its SQLite WAL store records campaigns, programs, actions, idempotency keys, events, accounting and checkpoints. Valid state transitions prevent impossible jumps. A crash after permit issuance can become `unknown_outcome`; it is never replayed blindly.

The current M53 surface provides a zero-network dry-run/state/recovery/report path. Physical unattended detector execution is intentionally disabled until M52 external runtimes are digest-qualified and field-ready.
