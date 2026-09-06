# ASTP 1.0 RC release checklist

Use this checklist for M49.0 / `1.0.0rc1`.

## Repository validation

```powershell
ruff check . --fix
black .
ruff check .
pytest
.\scripts\validate.ps1
```

Then verify the CLI surface:

```powershell
python -m astp.cli doctor
python -m astp.cli release-info
python -m astp.cli release-readiness --help
python -m astp.cli bug-bounty-v1-acceptance --help
python -m astp.cli ctf-acceptance --help
```

## Qualification evidence

M49.0 requires two stored acceptance artifacts:

- an M48.0 Bug Bounty v1 acceptance YAML with `accepted: true`, at least one authorized field network action, and equal network-action/permit-consumption counts;
- an M48.6 CTF acceptance YAML with `accepted: true`, at least one case, 100% trace reproducibility, and `network_performed: false`.

Run the final offline gate:

```powershell
python -m astp.cli release-readiness `
    .\bug-bounty-v1-acceptance-m48.0.yaml `
    .\ctf-acceptance-m48.6.yaml `
    --output .\astp-1.0rc1-readiness.yaml
```

Expected result:

```text
ASTP 1.0 RC readiness: PASS
Network execution: NOT PERFORMED
```

## Pre-commit review

- `.astp/` runtime/evidence artifacts are not staged.
- `OVERLAY.txt` is not staged.
- no credentials, tokens, cookies, raw authenticated secrets, or private program captures are staged.
- README command reference reflects the current CLI.
- `pyproject.toml` and `src/astp/__init__.py` both report `1.0.0rc1`.
- `docs/release/M49.0.md` is present.

## Commit suggestion

```powershell
git add README.md pyproject.toml docs examples src tests
git status
git diff --cached --stat
git commit -m "release: prepare ASTP 1.0 RC"
git push
git status
```
