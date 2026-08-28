# Scope Compiler v0.1

The Scope Compiler converts human-readable authorization text into ASTP's deterministic
`Engagement` model. It does not execute tests and it does not treat ambiguity as permission.

## Security invariant

**No explicit authorization = no inferred authorization.**

The compiler can emit two states:

- `CLEAN`: all extracted scope statements were explicit enough for the deterministic parser.
- `NEEDS_REVIEW`: at least one ambiguous, conflicting, invalid, or unclassified statement exists.

When `NEEDS_REVIEW` is returned, the CLI exits with status code `2`. A YAML file may still be
written so a human can inspect it, but later execution layers must not treat unresolved text as
new authorization.

## Supported in v0.1

- domains and wildcard domains;
- URL prefixes;
- IPv4 CIDR expressions;
- explicit `in scope` / `out of scope` wording;
- common `in scope except ...` wording;
- requests-per-second limits;
- explicit DoS prohibition;
- explicit social-engineering prohibition;
- explicit production/customer/user data protection wording;
- basic ambiguity detection;
- traceability from each extracted rule to the source sentence.

## Deliberate limitations

v0.1 is not a natural-language understanding system. It intentionally refuses to infer complex
legal or program language. Lists, tables, platform-specific markup, nested exceptions, time
windows, port ranges, account-specific rules, geographic restrictions, and many synonyms will be
added incrementally.

An LLM-assisted interpreter may be added later, but its output will be proposals. Deterministic
validation and conservative policy rules remain authoritative.

## CLI

```powershell
astp compile-scope .\examples\scope-briefing.txt `
    --id example-bounty `
    --name "Example Bug Bounty" `
    --output .\examples\compiled-engagement.yaml
```

A clean input exits `0`. An input needing human review exits `2`.
