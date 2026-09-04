# M2.5.1 — Authenticated Program Discovery & Catalog

M2.5.1 upgrades the authenticated browser intake from a single-page capture into a program
catalog workflow.

## Primary workflow

1. The user signs into a bug bounty platform in their normal browser.
2. The user opens a program-listing page and clicks **Discover & sync all programs**.
3. The ASTP Browser Companion captures only the active page DOM representation and sends it to
   the local ASTP loopback intake service.
4. ASTP classifies the page and extracts same-origin program-detail candidates.
5. The companion requests access only to the current platform origin, opens each discovered
   detail page sequentially in the already-authenticated browser session, captures the DOM, and
   closes the temporary tab.
6. ASTP normalizes every detail capture into `BugBountyProgram`, preserves provenance, stores the
   raw capture, and updates `.astp/program-catalog.yaml`.
7. The user chooses one or more catalog programs as active workspace programs.

The companion does not export cookies, authorization headers, localStorage, sessionStorage, or
password fields to ASTP.

## Control plane versus testing plane

Authenticated platform navigation is a control-plane operation. It discovers program policy and
scope. It does not authorize or perform security testing against target assets.

Target testing still follows the invariant:

`Planner -> Policy evaluation -> Execution permit -> Adapter/worker -> Evidence`

A catalog entry or active-program selection is never an execution permit.

## Program isolation

Each catalog entry has its own candidate id, source URL, normalized policy, capture, synchronization
state, and active flag. Future multi-program scheduling must carry `program_id`, `engagement_id`,
`policy_digest`, and `permit_id` per action so authorization can never cross program boundaries.

## Commands

Start intake:

```powershell
astp browser-intake-server --platform bughunt
```

Then open the authenticated platform program listing and use the Browser Companion's
**Discover & sync all programs on this platform page** action.

Inspect the catalog:

```powershell
astp programs
```

Select one or more active programs interactively:

```powershell
astp select-programs
```

Or select explicit ids:

```powershell
astp select-programs --id PROGRAM_A --id PROGRAM_B
```

The catalog defaults to `.astp/program-catalog.yaml`. Raw detail captures default to
`.astp/program-captures/`, while normalized programs default to `programs/`.

## Conservative behavior

- Only same-origin detail URLs discovered from the listing are synchronized automatically.
- Detail pages are visited sequentially rather than concurrently.
- Pages that do not classify as program details fail synchronization rather than being treated as
  policy input.
- Broad or qualitative policy rules still produce `NEEDS_REVIEW` rather than implicit permission.
- Output parent directories are created automatically.
