# Milestone 3.1 — Multi-Program Work Queue

M3.1 provides a fair round-robin control-plane queue across multiple observation plans. It is deliberately **not** an execution scheduler yet.

Only `authorizable` plan items enter the queue. Every queue item still requires an independently signed execution permit. This preserves program isolation and prevents one program's policy from authorizing another program's action.

```powershell
astp build-work-queue .\.astp\smartfit-plan.yaml .\.astp\other-plan.yaml `
  --max-active-programs 2 --max-items 20 --output .\.astp\work-queue.yaml
```
