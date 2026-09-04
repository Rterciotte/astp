# M2.5 — Bug Bounty Program Intake

M2.5 introduces a first-class `BugBountyProgram` model above `Engagement`.
The primary intake path is an explicit capture of the page currently open in the
researcher's authenticated browser. ASTP does not need the site's username, password,
cookies, authorization headers, or browser storage.

## Invariant

```text
Authenticated browser page
        ↓ explicit user gesture
ASTP Browser Companion
        ↓ loopback + one-time intake token
BrowserCapture
        ↓ deterministic normalization
BugBountyProgram
        ↓ review unresolved rules
Engagement
```

An ambiguous or broad rule never silently becomes permission. `compile-program` refuses
to create an executable engagement while blocking review issues remain.

## Browser capture

Run:

```powershell
astp browser-intake-server --output .\.astp\browser-capture.json
```

The command binds only to `127.0.0.1` and prints a one-time intake token. Load the
`browser-companion/` directory as an unpacked Chromium extension, open the authenticated
program page, click the extension, paste the token, then choose **Import current page into
ASTP**.

The companion requests only `activeTab` and `scripting`. It intentionally does not request
cookie access. The capture schema includes URL, title, visible text, tables, links and a
timestamp. It has no cookie, authorization, local-storage, session-storage or password
fields.

## Normalize the capture

```powershell
astp import-program `
    .\.astp\browser-capture.json `
    --browser-capture `
    --name "Smart Fit" `
    --platform bughunt `
    --output .\programs\smartfit.yaml
```

M2.5 preserves rule provenance including source URL, source type, section and source text.
A SHA-256 snapshot digest is stored with the normalized program.

## Compile only after review

```powershell
astp compile-program `
    .\programs\smartfit.yaml `
    --rps 1 `
    --output .\engagements\smartfit.yaml
```

`--rps` is an explicit researcher decision when a program expresses only a qualitative
traffic restriction. ASTP does not invent a numeric limit.

Broad exclusions such as "all systems operated by company X" remain `NEEDS_REVIEW` until
they are mapped or otherwise resolved in the normalized program.

## Fallback sources

Markdown, text and HTML files remain supported for portability and testing:

```powershell
astp import-program rules.md --name "Example" --platform manual -o program.yaml
```

These are fallback paths. Authenticated browser capture is the preferred product workflow.

## Non-goals

M2.5 does not automate login, store third-party credentials, extract browser cookies,
execute tests from the companion extension, or bypass a program platform's access controls.
The companion is an intake surface only; execution remains inside ASTP's permit-gated worker
architecture.
