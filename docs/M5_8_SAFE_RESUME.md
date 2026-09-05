# M5.8 — Safe Resume Guard

A restart does not resurrect an old permit or blindly continue a RUNNING/COMPLETED item. `resume-session-check` marks only QUEUED and FAILED planner items as candidates for re-planning. Re-planning still requires current policy/context and a new permit.
