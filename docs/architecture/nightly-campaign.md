# ASTP nightly campaign MVP

This overlay adds the first bounded autonomous Bug Bounty campaign mode for ASTP 1.0.x.

## Scope of the MVP

The MVP is intentionally conservative:

- BugHunt is the first authenticated program-source adapter.
- Program listing and detail pages are read through the user's already-authenticated Chrome session.
- ASTP never stores BugHunt credentials.
- Every program detail is normalized by the existing program-intake pipeline.
- A program with unresolved blocking policy issues is skipped with zero target requests.
- Semantic deny guardrails are never auto-cleared. Target reviews are exact-target, source-revision-bound artifacts.
- HTTP execution remains limited to the existing read-only GET observation path.
- Every target request still receives one fresh exact ASTP permit.
- Evidence feedback may add in-scope links for a later bounded round.
- Evidence manifest and audit-chain integrity are checked before the stored-evidence report pipeline runs.
- Each program has an isolated campaign directory, permit state, audit log, manifest, runtime DB, trace and report.

## Browser-side authenticated discovery

Load `browser/bughunt-nightly-companion` as an unpacked Chrome extension.

The extension only has BugHunt plus ASTP loopback host permissions. It:

1. captures the authenticated program listing;
2. sends it to `/v1/discover-programs`;
3. walks each returned BugHunt detail URL in the same logged-in tab;
4. captures each detail page;
5. sends it to `/v1/program-detail`;
6. returns the tab to the original listing URL.

The extension does not read or store BugHunt passwords.

## Running tonight

Terminal 1:

```powershell
python -m astp.cli browser-intake-server `
  --platform bughunt `
  --catalog .astp\program-catalog.yaml `
  --captures-dir .astp\program-captures `
  --programs-dir programs
```

Paste the one-time intake token into the extension, open the authenticated BugHunt program listing and click **Sincronizar todos os programas**.

After synchronization finishes, stop the intake server and review:

```powershell
python -m astp.cli programs
```

Dry run first:

```powershell
python -m astp.cli nightly-campaign `
  --catalog .astp\program-catalog.yaml `
  --output-dir .astp\campaigns
```

If a ready program contains semantic deny guardrails, the dry run creates
`<program-id>/semantic-review-template.yaml`. The template is bound to the synchronized
program `source_content_sha256` and lists the exact seed targets. An operator must review
each target against every guardrail and record each guardrail ID under either
`semantic_exclusion_clears` or `semantic_exclusion_matches`, together with `reviewed_at`.
Missing decisions remain blocked; a match is denied; stale, unknown or contradictory
reviews fail closed. The review is never inferred from hostname keywords.

Rerun the selected program with the reviewed file:

```powershell
python -m astp.cli nightly-campaign `
  --catalog .astp\program-catalog.yaml `
  --output-dir .astp\campaigns `
  --program-id <program-id> `
  --semantic-review-file .astp\reviews\<program-id>.yaml
```

The planner binds the exact target clearance set into the work queue. The permit broker
re-authorizes from that queue-bound review and rejects later clearance overrides. Newly
discovered targets are not allowed to inherit a seed target's review; they appear in the
refreshed semantic review template and require their own explicit review before a later run.

Only after the dry run shows the expected programs and blocks ambiguous policies, enable execution:

```powershell
python -m astp.cli nightly-campaign `
  --catalog .astp\program-catalog.yaml `
  --output-dir .astp\campaigns `
  --max-actions-per-program 10 `
  --max-requests-per-program 10 `
  --max-rounds 2 `
  --execute
```

`ASTP_PERMIT_KEY` or `ASTP_PERMIT_KEYS` must already be configured exactly as for the stable ASTP permit workflow.

## Expected morning output

Each run creates:

```text
.astp/campaigns/nightly-YYYYMMDDTHHMMSSZ/
  campaign.yaml
  campaign.md
  <program-id>/
    engagement.yaml
    test.yaml
    target-registry.yaml
    plan-round-1.yaml
    queue-round-1.yaml
    evidence/
    evidence-manifest.jsonl
    audit.jsonl
    execution-trace.jsonl
    assessment/
      report.md
      assessment-result.json
```

A program can be `completed`, `planned`, `blocked`, `failed`, `no_targets` or `no_authorizable_actions`.

## Multi-site path

The campaign runner is deliberately platform-neutral once a `BugBountyWorkspace` has normalized program records. Future sites should add authenticated source adapters that feed the same `discover-programs` / `program-detail` contract rather than duplicating the execution pipeline.
## M52/M53 detector and orchestrator boundary

Stored HTTP evidence now feeds the M52 secret/exposure analyzer alongside fingerprint, protocol and posture consumers. Secret values are represented only by redacted previews and hashes; pattern matches remain candidates rather than confirmed findings.

The M53 orchestrator currently supports durable zero-network planning, state transitions, idempotency, recovery guards, status, reporting and manifest verification. Physical orchestrated detector execution remains blocked until the corresponding M52 runtime has immutable build provenance and field qualification.
