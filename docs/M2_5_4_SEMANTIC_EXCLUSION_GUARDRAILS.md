# M2.5.4 — Semantic Exclusion Guardrails

M2.5.4 closes a safety gap discovered during the authenticated Smart Fit field trial. A broad
policy exclusion must not become resolved merely because an operator supplied one hostname.

## Review model

`review-program --issue N --semantic-deny KIND=VALUE` records one of:

- `product_family`
- `organization_family`
- `asset_family`

The original policy text is retained and a stable `semex-*` rule ID is generated.

## Enforcement

Semantic exclusions are copied into the compiled `Engagement.constraints`. Before ordinary
scope evaluation, authorization checks every semantic exclusion. A target must be explicitly
classified against each rule.

- `--semantic-match semex-...` -> `DENY`
- missing assessment -> `INSUFFICIENT_CONTEXT`
- contradictory clear/match -> `INSUFFICIENT_CONTEXT`
- all exclusions explicitly cleared -> continue with normal scope/policy checks

Permit issuance uses the same authorization path, so a permit cannot bypass this gate.

Concrete `--deny KIND=VALUE` mappings are still useful as explicit deny rules, but they can no
longer resolve broad semantic exclusion issues by themselves.
