# ASTP CTF Mode — roadmap

ASTP can grow a dedicated CTF/lab mode for systems that are explicitly supplied as challenge
artifacts or targets. This mode should reuse ASTP's scope, permit, isolation, evidence, and audit
boundaries rather than becoming an unrestricted autonomous shell agent.

## Goal

Given a challenge statement plus authorized artifacts/endpoints, build a hypothesis graph, choose
safe analysis tools, execute bounded experiments in an isolated worker, recognize candidate flags,
validate them against the declared format, and produce a reproducible solve trace/write-up.

## Planned solver families

- web and API challenge reasoning;
- reverse engineering and static/dynamic binary analysis;
- binary exploitation inside challenge sandboxes;
- cryptography and encoding analysis;
- digital forensics, PCAP, disk/memory, and steganography;
- OSINT when the event rules explicitly allow it;
- cloud, mobile, hardware, and miscellaneous challenge adapters later.

## Challenge contract

A future `ChallengeDefinition` should declare category, provided files, authorized endpoints,
expected flag format, event rules, time/resource budget, network policy, and whether AI assistance is
allowed. If the rules prohibit AI or automation, ASTP must refuse autonomous solving for that event.

## Solver architecture

```text
Challenge intake
  -> rule/scope compiler
  -> artifact classifier
  -> hypothesis graph
  -> planner
  -> bounded permit
  -> isolated solver adapter
  -> observation/result parser
  -> flag candidate verifier
  -> evidence + solve trace
  -> next hypothesis
```

The planner should learn from failed hypotheses instead of blindly running every tool. Tool adapters
should expose structured capabilities and evidence, not raw unrestricted shell access.

## Evaluation

CTF capability should be measured on reproducible public/retired challenge sets and local synthetic
labs, tracking solve rate, time-to-flag, tool cost, false flag rate, number of hypotheses, and
reproducibility. Difficulty and category coverage should be reported separately.

## Important boundary

CTF mode is for challenge environments and other explicitly authorized labs. Competition rules take
precedence: some events allow automation/AI and others explicitly prohibit it.
