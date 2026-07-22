# Tasks — SIEM-1 mount /events
- [x] Mount /events on the served TLS mux in serve() (operator-gated).
- [x] Served-mux test: operator cert reaches every operator-read route (no 404); agent cert on /events → 403.
- [x] Verify the test catches the missing mount (revert → fail).
- [x] make all clean; docs D145; sync; archive; commit; push; memory.
