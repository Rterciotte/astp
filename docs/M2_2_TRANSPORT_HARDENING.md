# Milestone 2.2 — Transport and failure-evidence hardening

M2.2 keeps the worker observation-only (`GET`/`HEAD`) and strengthens the boundary between permit
verification and network transport.

## Added

- `ObservationTransport` protocol so the policy/worker layer does not depend directly on urllib.
- `UrllibObservationTransport` as the current standard-library implementation.
- explicit pre-request DNS resolution metadata: hostname, port, and deduplicated resolved addresses;
- transport failure taxonomy: `dns`, `tls`, `timeout`, `connection`, and `io`;
- structured failure evidence registered in the same hash-linked evidence manifest;
- DNS/connection provenance in successful observation evidence;
- injected transports for deterministic worker tests without external network dependencies.

## Redirect boundary

Redirects remain **never-follow** in M2.2. A redirect target is recorded and evaluated against scope,
but no second request is made. This avoids accidental scope expansion while redirect authorization is
still being designed.

## DNS boundary

Resolved addresses are evidence, not authorization. Authorizing a hostname does not silently add its
resolved IPs to engagement scope. Conversely, the resolver metadata must not be interpreted as a
permit for direct requests to those IPs.

The current urllib adapter resolves before opening the request for provenance, but the operating
system/HTTP stack can resolve again when connecting. Therefore M2.2 does **not** claim cryptographic
DNS pinning or complete DNS-rebinding resistance. A later transport should bind the authorized
hostname, verified resolution, connection endpoint, TLS SNI, and certificate evidence as one
transaction.

## Failure evidence

Once a permit has been consumed, a DNS/TLS/timeout/connection/I/O failure still produces a structured
artifact. This is intentional: a failed authorized observation is part of the test history and should
be auditable rather than disappear as an exception only.

Failure evidence contains no exception text from the remote/network stack. It records only the
bounded failure category and redacted target to reduce accidental leakage.

## Still intentionally absent

- redirect following;
- POST/PUT/PATCH/DELETE;
- exploit payloads;
- scanner orchestration;
- credential attacks;
- automatic retry loops;
- raw unredacted response storage;
- DNS pinning;
- browser execution.

These exclusions keep the first network worker narrow while its policy and evidence contracts mature.
