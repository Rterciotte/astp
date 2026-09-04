# ASTP Browser Companion

The Browser Companion is the preferred bug bounty program-intake path when the program platform
requires authentication.

## Security model

The user authenticates normally in Chrome/Edge/Chromium. ASTP does not receive the account
password or browser session secrets. The extension has no cookie permission and does not export
cookies, authorization headers, localStorage, sessionStorage, or password fields.

For program discovery, the user explicitly grants access to the current platform origin. This lets
the companion open program-detail pages using the browser's existing authenticated session. Access
is not silently granted to unrelated origins.

The local Python intake service binds to `127.0.0.1` and requires the intake token printed by
`astp browser-intake-server`.

## Actions

**Discover & sync all programs on this platform page**

- captures the current listing page;
- asks ASTP which same-origin links are program details;
- opens each detail page sequentially in an inactive temporary tab;
- captures the detail DOM;
- sends the capture to ASTP;
- closes the temporary tab;
- updates the local program catalog.

**Import current page only** retains the M2.5.0 single-page diagnostic/import workflow.

## Installing locally

In Chrome or Edge, enable Developer mode and load the `browser-companion/` directory as an
unpacked extension. After code updates, press **Reload** on the extension before testing again.
