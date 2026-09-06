# ASTP M36.5–M38.4 overlay

Incremental overlay for ASTP 0.371.0.

Apply it over the repository after M34.5–M36.4. Run the normal project validation and the offline focused field harness first. Physical Docker builds are intentionally separate because they can be slow and memory-intensive.

See `docs/OVERLAY_README_M36_5_M38_4.md` and `scripts/runtime-qualification/README.md`.

### M38.5-M40.4

ASTP now supports evidence-producing, permit-gated local qualification runs for all three physical worker candidates (security-tools, Playwright, and ZAP), while preserving exact target binding, serial low-resource execution, and no-self-certification semantics. See `docs/OVERLAY_README_M38_5_M40_4.md`.

### M40.5-M42.4 adaptive verification E2E

ASTP now has an offline regression model for qualified-runtime admission and the adaptive chain `evidence -> signal -> hypothesis -> bounded verification -> proof update -> REPLAN`, while preserving a hard no-approval block for state-changing verification. This is not production/program readiness and performs no network execution by itself.
