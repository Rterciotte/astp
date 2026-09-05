# ASTP M28.5-M30.4 release notes

This block adds executable-runtime candidate bridges and the first resumable assessment-session/bundle primitives.

Key safety properties remain unchanged: every network-capable action requires an exact fresh permit; browser redirects require reauthorization; external commands are compiled from allowlisted operations; the coordinator never receives direct network authority; bundled runtimes are not considered operational until field-qualified.

The project version for this overlay is 0.291.0.
