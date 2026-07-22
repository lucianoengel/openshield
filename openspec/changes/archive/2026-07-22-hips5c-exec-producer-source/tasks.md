# Tasks — HIPS-5c exec producer source
- [x] execaudit.Scanner: pair SYSCALL+EXECVE by audit id → Event; drop+count malformed; bounded pending buffer.
- [x] engine execSource helper + OPENSHIELD_EXEC_AUDIT_LOG wiring (wg-tracked, ctx-racing send).
- [x] Test: interleaved pairs matched by id; malformed dropped+counted; 20k unpaired flood bounded (0 emitted).
- [x] Test: engine source feeds a ProcessSubject event onto the channel.
- [x] make all clean; docs D152; sync; archive; commit; push; memory.
