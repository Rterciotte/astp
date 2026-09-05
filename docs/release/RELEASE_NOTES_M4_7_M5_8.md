# ASTP M4.7–M5.8 Release Notes

This block closes the first bounded autonomous **observation** loop while preserving the invariant:

`Planner -> Policy -> fresh Permit -> Worker -> Evidence`

It does not add exploit adapters, credential attacks, mutation, scanner bypasses, or state-changing automation.

## M4.7 — Controlled Autonomous Observation Loop

Adds `controlled_loop.py` and the explicit `astp run-observation-session` boundary. A session may process an already-authorizable work queue sequentially, but only when the operator passes `--execute`. Every queue item is separately re-authorized by the Permit Broker and receives a fresh exact-action permit before the existing GET/HEAD observation worker is called.

## M4.8 — Atomic Session Ledger

Adds a WAL-backed SQLite ledger for action/request reservations and completion/error counters. Reservations use `BEGIN IMMEDIATE` so concurrent callers cannot oversubscribe the same configured session budget.

## M4.9 — Evidence Feedback Pipeline

Adds evidence-to-target-registry feedback. Stored evidence may generate redirect/link candidates and merge their provenance into the target registry without making a request. Newly discovered targets remain non-executable and still require planning, policy evaluation, and a fresh permit.

## M5.0 — Policy Drift Guard

Captures the same engagement/test policy digest used by permits. A controlled session stops if the current policy no longer matches the snapshot under which the session was prepared.

## M5.1 — Operational Freshness Guard

Rechecks program ONLINE status, source revision, and attestation age before each controlled queue action. Missing, stale, offline, unknown, or revision-mismatched status blocks the next action.

## M5.2 — Per-Origin Action Budget

Adds an independent action cap per canonical origin so one host cannot consume the entire session budget simply because the queue contains many paths from that origin.

## M5.3 — Failure Circuit Breaker

Consecutive worker/broker failures open a session circuit breaker and stop further actions instead of repeatedly hitting a failing target or unsafe context.

## M5.4 — Bounded Crawl Frontier

Adds a durable-shaped frontier model with explicit visit states and discovery depth. The frontier is built from already-discovered registry entries; it does not crawl by itself.

## M5.5 — Safe HTTP Method Strategy

Adds a deterministic HEAD-first observation strategy. GET is selected only when body evidence is explicitly required. This is a planning primitive, not an authorization bypass.

## M5.6 — Bounded Observation Session Runner

Adds the first real bounded multi-action observation runner. It remains sequential, GET/HEAD only, rate-limited by the engagement, budgeted, policy-drift guarded, online-status guarded, fresh-permit-per-action, and evidence producing. It requires an explicit `--execute` flag.

## M5.7 — Session Execution Summary

Summarizes durable ledger counters and hash-linked execution trace events into a portable YAML session report.

## M5.8 — Safe Resume Guard

Interrupted sessions never blindly resume permits or RUNNING/COMPLETED items. Only QUEUED or FAILED planner items are eligible to be re-planned; any future resumed network action still needs fresh context and a new permit.

## Version

`0.45.0`
