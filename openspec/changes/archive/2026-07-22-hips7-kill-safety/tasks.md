# Tasks — HIPS-7 KILL safety
- [x] Critical-process allowlist (comm) + openshield-prefix; refuse before kill.
- [x] pidfd-based platformKill on Linux (instance-atomic; ESRCH on reused/gone pid); darwin/other stubs.
- [x] procComm (/proc/<pid>/comm) resolver; injectable for tests.
- [x] Bound argc in ParseExecve (maxArgc=1024) against O(argc·len) CPU-DoS.
- [x] Tests: critical comms refused (kill not invoked), ordinary killed; argc=2e9 returns promptly.
- [x] Mutations: remove critical guard (systemd killed); remove argc bound (parse hangs).
- [x] make all clean (incl. GOOS=darwin/windows cross-build); docs D158; sync; archive; commit; push; memory.
