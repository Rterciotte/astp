# ASTP M46.7d overlay

Response Body Artifact Persistence.

Copy this overlay onto the repository root, then run the standard ASTP validation sequence. This overlay contains complete replacements for `src/astp/observation.py` and `src/astp/cli.py`, plus focused tests and release notes.

No network action is performed by installing or validating this overlay. Raw body persistence remains opt-in through `--persist-body`.
