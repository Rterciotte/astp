# Next steps after M38.4

M38.5–M40.4 should connect the fixed local Docker lab to the existing signed execution-permit lifecycle without introducing a second authorization system. The bridge should consume one exact ASTP permit before enabling the internal Docker network, persist a permit-bound worker receipt, ingest that receipt into Evidence Store, and then qualify the security-tools worker first. Playwright follows serially; ZAP should remain optional if the host resource envelope is insufficient.

Only after real permit-bound evidence exists should a runtime's `field_qualified` state become true.
