# External tools

Physical field workers use the mandatory [ASTP counting proxy](counting-proxy.md); direct worker-to-target networking is not an accepted field topology.

ASTP generates shell-free argv from typed jobs. Arbitrary arguments are rejected. Nuclei accepts classified template IDs; ffuf accepts only a small ASTP-generated wordlist; sqlmap exposes detection-only level/risk 1 and no dump, shell, filesystem, persistence or post-exploitation switches.

Versions and image digests must be installed and qualified separately. A contract or Dockerfile is not field readiness.
