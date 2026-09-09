# Proof model

M52 uses `observed`, `suspected`, `candidate`, `reproduced`, `confirmed`, `impact_demonstrated`, and `blocked`. Reflection is not confirmed XSS; response difference is not IDOR; error text is not SQLi; fingerprint is not a CVE; a pattern is not necessarily a valid secret; and an SSRF-shaped parameter is not SSRF without controlled response or exactly correlated OAST evidence.

Stop-on-proof prevents unnecessary exploitation after reportable proof is obtained.
