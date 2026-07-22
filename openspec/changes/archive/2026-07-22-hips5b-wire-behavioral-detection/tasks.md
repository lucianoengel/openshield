# Tasks — HIPS-5b wire behavioral detection
- [x] buildInput runs behavioral.Analyze for process events → event.behavioral {score,lolbin,lineage,encoded}.
- [x] default.rego: behavioral_alert at score>=0.5; ALERT/ALLOW restructured around a single alert flag.
- [x] Test: suspicious nginx→bash ALERTs; benign ls ALLOWs; clean file event ALLOWs (no misfire).
- [x] Mutation: behavioral.Analyze("","",nil) → suspicious process no longer alerts.
- [x] make all clean; docs D151; sync; archive; commit; push; memory.
