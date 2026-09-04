# Milestone 2 — HTTP Observation Worker

Milestone 2 introduces ASTP's first network-capable worker. It is intentionally narrow: one
permit-gated HTTP `GET` or `HEAD` request, with bounded response capture and redacted evidence.
It does not crawl, fuzz, authenticate, mutate state, execute payloads, or invoke scanners.

## Security invariant

```text
Planner / operator
    -> policy evaluation
    -> signed execution permit
    -> lifecycle verification + atomic consumption
    -> HTTP observation worker
    -> bounded/redacted evidence
    -> hash-linked audit
```

The worker never accepts a caller assertion that an action is authorized. It verifies and consumes
the signed permit under a cross-platform lifecycle file lock before opening the network connection. A failed network request therefore still
requires a newly issued permit for a retry.

## Request restrictions

The worker accepts only `http://` and `https://` targets and only the methods `GET` and `HEAD`.
URLs containing embedded username/password credentials are rejected. The requested target, method,
identity, policy digest, signature, validity window, and rate ceiling must match the permit.

Milestone 2 never follows redirects. A 3xx response is captured as evidence, the resolved redirect
target is classified as in-scope or out-of-scope, and `followed` remains false. This is stricter than
a same-origin redirect policy and prevents redirect-driven scope escape while the execution model is
still young.

## Bounds

Default timeout: 10 seconds. Maximum timeout: 30 seconds.

Default response body capture: 262,144 bytes (256 KiB). Maximum: 1,048,576 bytes (1 MiB).

`HEAD` captures no response body. `GET` reads at most the configured cap plus one byte, allowing the
worker to mark evidence as truncated without unbounded buffering.

## Evidence minimization and redaction

The worker does not persist raw response bodies. It stores:

- status and response metadata;
- a SHA-256 hash of the captured response bytes;
- bounded textual preview for text/JSON/XML/JavaScript content;
- whether the body was truncated;
- redirect metadata, when present;
- a canonical SHA-256 hash over the complete evidence record.

Known sensitive response headers such as `Set-Cookie`, `Authorization`, `Cookie`, API-key headers,
and auth-token headers are replaced with `[REDACTED]`. Common secret-bearing query parameters are
also redacted from the evidence target. A conservative inline redactor removes common Bearer-token
and token/password/API-key patterns from stored previews and non-sensitive header values.

Redaction is a risk-reduction mechanism, not a guarantee that arbitrary application secrets can
never appear in evidence. Future evidence-store milestones should support configurable redaction
policies and encrypted raw artifacts when an engagement explicitly requires them.

## Evidence verification

`astp verify-evidence` recomputes the canonical SHA-256 hash of a stored evidence JSON file. Any
change to a hashed field causes verification to fail.

## Local lifecycle and audit

By default:

```text
.astp/permit-state.json
.astp/audit.jsonl
.astp/evidence/<permit-id>.json
```

All are excluded from Git. Relevant audit events include:

```text
permit.issued
observation.started
observation.completed
observation.failed
observation.rejected
```

Audit append operations are also protected by a file lock so concurrent local workers cannot
legitimately create duplicate sequence numbers. The existing hash-linked audit verifier remains
available through `astp verify-audit`.

## Non-goals for Milestone 2

Milestone 2 deliberately does not implement automatic redirect following, authentication headers,
cookies, arbitrary request headers, request bodies, POST/PUT/PATCH/DELETE, crawling, fuzzing,
scanner adapters, JavaScript execution, browser automation, exploit verification, or LLM-driven
network actions.

## Next hardening step

The next worker iteration should add canonical action identities, a durable per-target rate limiter
across permits, richer evidence schemas/IDs, and explicit same-origin redirect permits if redirects
become necessary. Distributed workers still require asymmetric permit signatures and transactional
shared lifecycle state before they are trusted outside a single local execution boundary.
