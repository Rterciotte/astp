# Milestone 2.3 — Worker boundary completion

M2.3 keeps ASTP's network capability deliberately narrow: one permit-gated `GET` or `HEAD`
observation. The milestone closes several trust-boundary gaps before browser or scanner workers are
introduced.

## Connection-bound DNS/TLS provenance

`PinnedObservationTransport` resolves the authorized hostname once and then opens the TCP connection
only to an address from that exact resolution result. HTTPS keeps the original hostname for TLS SNI
and certificate validation. Successful evidence records:

- the hostname and port;
- every address returned by the bounded resolution;
- the address actually used for the connection;
- TLS protocol and cipher when HTTPS is used;
- SHA-256 of the peer certificate when available.

This reduces the DNS-rebinding ambiguity documented in M2.2. It does not turn resolved IP addresses
into independently authorized scope. Authorization remains bound to the hostname/URL in the permit.

## Redirect boundary

Redirects are still never followed automatically. M2.3 records whether the redirect is same-origin
and whether the target is in engagement scope, but **every redirect target is a new action and
requires a new execution permit**. Same-origin is descriptive metadata, never implicit permission.

## Engagement-level redaction profiles

`constraints.redaction` can add engagement-specific sensitive names:

```yaml
constraints:
  redaction:
    sensitive_headers:
      - x-customer-secret
    sensitive_query_parameters:
      - customer_ref
    sensitive_body_fields:
      - internal_code
```

ASTP still applies its built-in secret redaction set. Engagement values only extend that baseline.
JSON body previews can redact named fields recursively. Raw response bodies are still not persisted.

## Portable evidence bundles

`astp export-evidence-bundle` first verifies the complete evidence manifest and artifact hashes. It
then creates a ZIP containing:

- a snapshot of the evidence manifest;
- every referenced evidence artifact;
- `receipt.json`, binding the manifest and artifacts by SHA-256.

`astp verify-evidence-bundle` verifies the receipt, manifest snapshot, member paths, and every artifact
hash without trusting the original evidence directory.

Example:

```powershell
astp export-evidence-bundle .\.astp\evidence-manifest.jsonl `
  --output .\.astp\evidence-bundle.zip

astp verify-evidence-bundle .\.astp\evidence-bundle.zip
```

## Security properties that remain unchanged

M2.3 does not add exploit payloads, mutation requests, credential attacks, scanner orchestration,
automatic retries, browser execution, or autonomous offensive action. POST/PUT/PATCH/DELETE remain
outside the observation worker.

The invariant remains:

```text
Planner -> Policy evaluation -> Execution permit -> Worker -> Evidence
```

No worker may interpret DNS results, redirects, or previously collected evidence as permission to
expand scope.
