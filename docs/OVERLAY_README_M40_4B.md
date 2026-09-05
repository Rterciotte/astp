# ASTP M40.4b — Deterministic bounded-output qualification

This patch closes the two remaining physical qualification gaps for
`security-tools.isolated.v1` and `zap.isolated.v1` without increasing scanner
traffic or weakening the canonical `WorkerRequest.max_output_bytes >= 1024`
contract.

## Design

For security-tools and ZAP only, the local qualification runner can inject the
exact marker `ASTP_QUALIFICATION_PROBE=bounded-output-v1` into a permit-gated,
authorized-local-lab container launch. The real worker then produces a fixed
4096-byte internal payload and passes it through the same `_bounded()` limiter
used for normal tool output.

The qualification path:

```text
policy -> broker -> signed permit -> permit consumption
       -> isolated physical worker
       -> deterministic internal 4096-byte payload
       -> real worker output limiter (1024-byte request limit)
       -> output_truncated=true
       -> immutable evidence + physical probe record
```

The probe performs no Nmap/ZAP network I/O. The container remains bound to the
fixed authorized qualification network and exact local-lab target context.
Playwright keeps using the real `/large` HTTP fixture because it already proves
bounded output through its normal browser path.

## Safety invariants

- No lowering of the canonical 1024-byte minimum.
- No arbitrary payload size, content, shell command, URL, or tool argument.
- Only the exact `bounded-output-v1` marker is accepted by the command compiler.
- The marker is exposed only by the local physical-qualification runner.
- Normal Nmap/ZAP behavior is unchanged when the marker is absent.
- A fresh execution permit is still required and consumed before worker launch.
- Evidence remains immutable per execution.

## Required operator sequence

Because the security-tools and ZAP worker sources changed, rebuild those two
qualification images before running the bounded-output probes:

```powershell
.\scripts\runtime-qualification\build-images.ps1 -Runtime security-tools
.\scripts\runtime-qualification\build-images.ps1 -Runtime zap

.\scripts\runtime-qualification\run-bounded-output-probe.ps1 -Runtime security-tools
.\scripts\runtime-qualification\run-bounded-output-probe.ps1 -Runtime zap

.\scripts\runtime-qualification\qualification-status.ps1 -Runtime all
```

Do not archive the current qualification cycle. Existing valid Playwright and
authorized-lab evidence should remain in place.
