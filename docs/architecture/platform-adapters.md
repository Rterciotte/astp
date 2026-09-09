# Platform adapters

`PlatformAdapter` separates orchestration from BugHunt-specific HTML. It models discovery, detail refresh, operational status, revision and attached-session support. Authentication remains in an operator-authorized browser context; credentials are not stored by ASTP.

BugHunt readiness is semantic: an expected detail route, exclusive detail markers, minimum content and absence of listing markers. Browser `tab.status == complete` alone is insufficient.
