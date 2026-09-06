# ASTP CTF Mode — implementation roadmap

CTF mode is now in implementation. M47.1 provides the first control-plane layer: structured challenge rules plus local artifact inventory. It deliberately does **not** execute a solver or contact challenge endpoints.

## Current implementation — M47.1

`python -m astp.cli ctf-intake` accepts a `ChallengeDefinition` containing:

- challenge ID, title, and category;
- relative local artifact paths;
- optional explicitly authorized endpoints;
- expected flag pattern;
- whether AI assistance is allowed;
- whether automation is allowed;
- network policy: `disabled` or `declared_endpoints_only`.

The intake hashes local artifacts and records blockers. Artifact paths cannot escape the challenge directory. If rules prohibit AI or automation, autonomous solving is not eligible. No network action occurs.

```text
Challenge YAML
   -> rule validation
   -> local artifact inventory + SHA-256
   -> eligibility/blockers
   -> NO solver / NO network (M47.1)
```

## Goal

Given a challenge statement plus authorized artifacts/endpoints, build a hypothesis graph, choose safe analysis tools, execute bounded experiments in an isolated worker, recognize candidate flags, validate them against the declared format, and produce a reproducible solve trace/write-up.

## Planned solver families

- web and API challenge reasoning;
- reverse engineering and static/dynamic binary analysis;
- binary exploitation inside challenge sandboxes;
- cryptography and encoding analysis;
- digital forensics, PCAP, disk/memory, and steganography;
- OSINT when the event rules explicitly allow it;
- cloud, mobile, hardware, and miscellaneous challenge adapters later.

## Remaining architecture

```text
Implemented:
Challenge intake
  -> rule/eligibility gate
  -> local artifact inventory

Next:
  -> artifact classifier
  -> CTF hypothesis graph
  -> solver planner
  -> bounded capability/permit
  -> isolated solver adapter
  -> observation/result parser
  -> flag candidate verifier
  -> evidence + solve trace
  -> next hypothesis
  -> reproducible write-up
```

The planner must learn from failed hypotheses instead of blindly running every tool. Tool adapters must expose structured capabilities and evidence, not raw unrestricted shell access.

## Network boundary

`declared_endpoints_only` is a declaration in the challenge contract, not an execution permit. Future network-capable CTF workers must still bind actions to exact authorized endpoints and ASTP's permit/lifecycle boundary. M47.1 never opens a network connection.

## Evaluation

CTF capability should be measured on reproducible public/retired challenge sets and local synthetic labs, tracking solve rate, time-to-flag, tool cost, false flag rate, number of hypotheses, and reproducibility. Difficulty and category coverage should be reported separately.

## Important boundary

CTF mode is for challenge environments and other explicitly authorized labs. Competition rules take precedence: some events allow automation/AI and others explicitly prohibit it.
