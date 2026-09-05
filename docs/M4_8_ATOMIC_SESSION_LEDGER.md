# M4.8 — Atomic Session Ledger

`session_ledger.py` stores per-session action/request reservations and completion/error counters in SQLite WAL mode. `reserve_action()` uses `BEGIN IMMEDIATE` before checking and incrementing limits, preventing concurrent oversubscription.
