# ASTP M40.4a — Immutable qualification evidence patch

This corrective patch closes two integrity gaps found during the first real multi-runtime local qualification runs.

## Corrections

- Runtime command/output artifacts are now stored under an immutable per-permit run directory. A later qualification run cannot overwrite an artifact already referenced by the evidence manifest.
- Physical probes are persisted as immutable evidence, rather than existing only as PowerShell stdout.
- Probe source artifacts are copied to unique immutable paths and registered in the evidence manifest before the probe record itself is registered.
- Qualification status verifies the complete evidence manifest, including artifact hashes, before a runtime can report `qualified=true`.
- Image digest, read-only-root, no-new-privileges, shell rejection, network-without-permit rejection, signing-key absence, permit-before-I/O, bounded-output, and receipt-ingestion can all be represented as durable probe evidence.
- Bounded-output probing is available for all three physical runtimes. Security-tools now honors `WorkerRequest.max_output_bytes` just like Playwright and ZAP.

## Important

Old overwritten M38.5-M40.4 artifacts are intentionally not retroactively treated as immutable evidence. Re-run the qualification scripts after applying this patch so a new internally consistent evidence chain is created for the current image IDs.

`qualified=true` remains impossible if any required probe is missing or if the evidence manifest/artifact verification fails.
