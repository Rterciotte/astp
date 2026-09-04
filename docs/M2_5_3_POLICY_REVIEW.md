# M2.5.3 — Policy Review & Parser Correctness

M2.5.3 hardens authenticated bug bounty policy normalization before any executable
engagement is created.

## Correctness fixes

- Portuguese `dos` is no longer treated as the DoS acronym. Only explicit denial-of-service
  language creates the `no_dos` constraint.
- Repeated constraints are deduplicated while every supporting source sentence is retained in
  `provenance[]`.
- Numbered rules no longer inherit an unrelated earlier section. When no matching heading is
  available, provenance uses a neutral `N.x numbered rules` section reference rather than lying
  about the source section.
- Browser capture timestamps are propagated to extracted scope and constraint provenance.
- Explicit excluded-finding rules are normalized when the source actually supports them,
  including exclusion-list sections such as `ITENS NÃO ACEITOS`.
- The stable catalog candidate ID is now also the normalized `BugBountyProgram.id`.

## ACTIVE versus READY

Program selection and execution readiness are distinct states:

- `ACTIVE` means the operator selected the program as a workspace target.
- `READY` means the normalized policy has no unresolved blocking review issue.
- `NEEDS_REVIEW` means execution compilation remains blocked.

Legacy catalog entries with `SYNCED` are displayed as `READY`; a new synchronization writes the
new explicit `READY` state.

## Review command

Inspect a program without changing it:

```powershell
astp review-program <PROGRAM_ID>
```

Resolve a qualitative traffic restriction with an operator-selected rate:

```powershell
astp review-program <PROGRAM_ID> --rps 1
```

The number is stored as an **operator decision**. ASTP never represents it as a rate published by
the bug bounty program.

Broad semantic exclusions cannot be dismissed. They require explicit reviewed deny mappings:

```powershell
astp review-program <PROGRAM_ID> `
  --issue 1 `
  --deny "wildcard_domain=*.example.com" `
  --note "Reviewed mapping from authoritative program documentation"
```

If the operator cannot map the broad family safely, leave the issue unresolved. Compilation then
remains blocked.

## Migration from M2.5.2

Existing M2.5.2 normalized YAML remains loadable. Constraint provenance in the old singular form is
accepted automatically. To receive parser correctness fixes, run authenticated discovery/sync again
so the normalized program files are regenerated from their captured policy source.
