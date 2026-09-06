# ASTP 1.0 stable release checklist

Use this checklist for M50.0 / `1.0.0`.

## Repository validation

Run:

- `ruff check . --fix`
- `black .`
- `ruff check .`
- `pytest`
- `.\scripts\validate.ps1`

Then verify:

- `python -m astp.cli doctor`
- `python -m astp.cli release-info`
- `python -m astp.cli release-readiness --help`
- `python -m astp.cli bug-bounty-v1-acceptance --help`
- `python -m astp.cli ctf-acceptance --help`

## Qualification evidence

Stable qualification requires:

- M48.0 Bug Bounty v1 acceptance from the stored authorized assessment chain;
- balanced network-action / consumed-permit accounting;
- M48.6 CTF acceptance with every declared case passing;
- 100% solve-trace reproducibility;
- no assessment-target network execution during release qualification;
- M50.0 release-readiness PASS.

## Stable invariants

- authorization precedes execution;
- every target network action requires an exact fresh permit;
- consumed permits cannot be replayed;
- stored-evidence analysis does not retrieve targets;
- integrity is checked before downstream evidence use;
- findings cannot exceed their evidence-backed proof state;
- CTF network observations remain scope- and permit-gated.

## Pre-release review

Before tagging `v1.0.0`:

- working tree is clean after the GA commit;
- `.astp/` runtime artifacts are not staged;
- `OVERLAY.txt` is not staged;
- credentials, cookies, tokens, secret material and private captures are not staged;
- `pyproject.toml` and `src/astp/__init__.py` report `1.0.0`;
- `release-info` reports `M50.0` and `stable`;
- `docs/release/M50.0.md` exists;
- the exact GA commit passes validation and release-readiness.
