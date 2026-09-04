# Permit lifecycle hardening — Milestone 1.4

Milestone 1.4 turns an execution permit from a signed document into a short-lived capability with
local lifecycle state. Network execution is still disabled.

## Lifecycle

A permit begins as `AVAILABLE`. It can then become exactly one of:

- `CONSUMED`: successfully verified and claimed once;
- `REVOKED`: explicitly invalidated before consumption.

A consumed permit cannot be consumed again. A revoked permit cannot be consumed. Invalid permits
are never marked consumed.

The local development state defaults to:

```text
.astp/permit-state.json
```

State writes use a temporary file plus `os.replace()` so a completed update is atomic on the local
filesystem. This is a development implementation, not a distributed lock. A multi-worker system
will move consumption and revocation to transactional shared storage.

## Audit chain

Lifecycle events default to:

```text
.astp/audit.jsonl
```

Each record stores `sequence`, `previous_hash`, and `record_hash`. The record hash is SHA-256 over a
canonical representation of that event. `astp verify-audit` detects record edits, broken links, and
sequence changes.

This is tamper-evident, not tamper-proof. An attacker who can replace the whole file can construct a
new chain. A production audit trail should be shipped to append-only/WORM or independently anchored
storage.

## Key rotation

Milestone 1.3 used one `ASTP_PERMIT_KEY`. That remains supported.

Milestone 1.4 adds a key ID to every newly issued permit. A verifier can keep multiple keys so old
permits remain verifiable during rotation while issuance uses only the active key.

Legacy-compatible setup:

```powershell
$env:ASTP_PERMIT_KEY = "your-existing-secret"
$env:ASTP_PERMIT_ACTIVE_KEY_ID = "local-v1"
```

Rotating setup:

```powershell
$env:ASTP_PERMIT_KEYS = '{"local-v1":"OLD_SECRET","local-v2":"NEW_SECRET"}'
$env:ASTP_PERMIT_ACTIVE_KEY_ID = "local-v2"
```

New permits are signed with `local-v2`. A permit carrying `key_id: local-v1` can still verify while
`local-v1` remains in `ASTP_PERMIT_KEYS`. Remove an old key only after every permit signed by it has
expired or been revoked.

Do not commit either environment variable or a serialized keyring to Git.

## Signer/verifier boundary

The contract is now asymmetric at the API level even though HMAC itself is symmetric:

```text
issuer -> one active key -> signs permit with key_id
worker/verifier -> verification keyring -> selects key by key_id
```

This prepares the worker boundary for a later migration to an actual asymmetric signature. With
HMAC, any verifier that possesses a secret can also sign. Therefore distributed workers must not be
given this HMAC keyring in production.

The planned production model is:

```text
Policy Engine: private signing key
Workers:       public verification keys only
```

## CLI lifecycle

After issuing a permit, claim it once without executing a network action:

```powershell
astp consume-permit `
    .\examples\execution-permit.yaml `
    .\examples\engagement-granular.yaml `
    .\examples\test-idor.yaml `
    --target https://api.example.com/v1/users/123 `
    --http-method GET `
    --identity researcher `
    --rps 1
```

Running the same command again must fail because the permit has already been consumed.

A permit can instead be revoked before consumption:

```powershell
astp revoke-permit PERMIT_ID --reason "scope changed"
```

Check lifecycle state:

```powershell
astp permit-status PERMIT_ID
```

Validate the audit chain:

```powershell
astp verify-audit .\.astp\audit.jsonl
```

## Invariant

Lifecycle state does not authorize an action. It is an additional gate after cryptographic and
policy verification:

```text
Policy ALLOW
    -> signed permit
    -> signature/current-policy/action verification
    -> revocation/replay gate
    -> atomic consumption
    -> future worker execution
```
