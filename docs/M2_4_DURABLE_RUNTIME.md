# Milestone 2.4 — Durable Runtime and Worker Contracts

M2.4 moves the default HTTP observation admission path from independent JSON lifecycle/rate files to
one local SQLite runtime database. The goal is not more network capability. The goal is a stronger
execution boundary.

## Atomic admission

The previous local path performed two separate durable operations:

```text
consume permit -> acquire rate slot -> open network connection
```

That meant a rate-limit rejection could happen after the permit had already been consumed. M2.4
introduces the default transactional path:

```text
verify signed permit
        ↓
BEGIN IMMEDIATE
        ↓
check revoked/consumed state
        ↓
check target rate window
        ↓
reserve rate slot + mark permit consumed
        ↓
COMMIT
        ↓
open bounded network connection
```

A rate rejection rolls the transaction back. The permit remains available until it expires, is
revoked, or is successfully admitted later.

## SQLite runtime

Default database:

```text
.astp/runtime.db
```

SQLite is a local development boundary, not the final distributed state service. The database uses
WAL mode, foreign-key enforcement, a busy timeout, and `BEGIN IMMEDIATE` for worker admission.

Runtime tables currently contain:

- runtime schema metadata;
- permit lifecycle state;
- per-target rate events.

The database intentionally does not contain permit signing secrets.

## Worker capability contract

The HTTP observation worker declares `http.observation.v1`:

- schemes: `http`, `https`;
- methods: `GET`, `HEAD`;
- redirects: never followed;
- state changing: false;
- timeout ceiling: 30 seconds;
- body capture ceiling: 1 MiB.

Capability compatibility is checked before admission. A future worker or adapter must declare its
own capability instead of inheriting the HTTP worker's permissions implicitly.

## Contracts

`src/astp/contracts.py` introduces explicit protocol boundaries for:

- worker admission storage;
- evidence registration;
- observation worker dependencies;
- observation transport.

These contracts are intentionally small so future SQLite, PostgreSQL, S3/MinIO, container-worker,
and remote-verifier implementations can be substituted without giving scanners direct access to
policy or signing authority.

## Revocation and status

Runtime commands:

```powershell
astp runtime-permit-status PERMIT_ID
astp revoke-runtime-permit PERMIT_ID --reason "scope changed"
```

Both accept `--runtime-db` when a non-default database is required.

The older JSON lifecycle commands remain available for compatibility with permits consumed through
the legacy APIs. New HTTP observations launched through the CLI use the SQLite runtime by default.

## Failure semantics

Once admission commits, the permit is consumed even if DNS, TLS, connection, timeout, or evidence
writing later fails. This preserves the safety rule that one admitted external action consumes one
permit. Transport failures still produce structured failure evidence when possible.

The atomicity guarantee is specifically about **admission**: rate rejection, replay state, and permit
consumption cannot disagree because of separate state files.

## Current limits

M2.4 is still single-host development infrastructure. It does not provide:

- distributed consensus;
- remote worker identity;
- asymmetric permit signatures;
- transactional coupling between SQLite admission and external object storage;
- crash recovery that retries an already-admitted network action;
- state-changing or intrusive execution.

Before distributed workers, migrate the runtime state to a separately protected transactional
service and replace HMAC signing with asymmetric signatures.
