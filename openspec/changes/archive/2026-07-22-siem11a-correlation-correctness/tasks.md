# Tasks — SIEM-11a correlation correctness
- [x] count(DISTINCT NULLIF(agent_id,'')) so a legacy empty host is not counted.
- [x] /incidents 400s a malformed window/min_risk/min_alerts/min_hosts (intParam fail-loud).
- [x] /overdue 400s a malformed threshold.
- [x] Test: one real host + legacy '' alerts → HostCount 1, excluded at MinHosts=2.
- [x] Test (served mux): bad params → 400, valid → 200.
- [x] Mutations: revert NULLIF (false lateral movement); swallow bad window (no 400).
- [x] make all clean; docs D154; sync; archive; commit; push; memory.
