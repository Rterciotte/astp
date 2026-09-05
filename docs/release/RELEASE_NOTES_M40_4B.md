# Release notes — M40.4b

Version: 0.391.2

M40.4b adds deterministic, qualification-only bounded-output stimulation for
the physical security-tools and ZAP workers. It fixes the case where normal
Nmap discovery or ZAP baseline output is smaller than the canonical 1024-byte
minimum and therefore cannot naturally demonstrate truncation.

The patch does not make Nmap/ZAP noisier and does not reduce the WorkerRequest
minimum. The physical worker uses a fixed internal 4096-byte payload, the real
worker limiter, and immutable qualification evidence. The probe is restricted
to the exact `bounded-output-v1` qualification marker.
