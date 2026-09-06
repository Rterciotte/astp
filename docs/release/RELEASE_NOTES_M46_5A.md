# M46.5a — BugHunt operational attestation fix

Version: 0.461.1

This patch closes the first live Smart Fit pre-flight gap found in M46.5.

The authenticated browser companion now captures bounded operational signals instead of relying only on literal ONLINE/OFFLINE badges:

- explicit structured ONLINE/OFFLINE status remains authoritative;
- short visible offline/paused/closed banners are captured as blocking evidence;
- on BugHunt program-detail pages the visible/enabled `Submeter Relatório` control is captured as a provider-specific operational affordance;
- the BugHunt publication marker is captured as corroborating evidence;
- long policy prose is never interpreted as current operational state.

The pre-flight resolver accepts the BugHunt positive affordance only when both the enabled visible submission control and publication marker are present and no explicit offline signal exists. Explicit OFFLINE evidence always wins.

Pre-flight reports now expose `operational_status_source` and `operational_status_evidence`, and the resulting attestation records the exact evidence used.

This patch does not weaken the fail-closed gate. Missing, disabled, contradictory, or insufficient signals remain `UNKNOWN` and execution remains blocked.
