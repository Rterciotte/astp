# M36.5-M38.4a authorized local-lab run

Prerequisites:

- the three runtime images have passed offline negative probes;
- `astp-qualification-lab` is running on `astp-qualification-net`;
- `ASTP_PERMIT_KEY` is present in the current PowerShell session;
- `scripts/validate.ps1` passes after applying this patch.

Run:

```powershell
.\scripts\runtime-qualification\run-authorized-lab-qualification.ps1 -Runtime security-tools
```

Expected terminal markers:

```text
AUTHORIZED LOCAL QUALIFICATION PASSED
Container execution: PERFORMED
Network execution: PERFORMED
Target class: AUTHORIZED LOCAL LAB
```

The worker is not launched with the lab network until policy evaluation returns ALLOW, a signed permit is issued through the permit broker, and lifecycle consumption succeeds exactly once.

Local evidence is written below `.astp/qualification/` and remains local runtime state rather than source-controlled project content.
