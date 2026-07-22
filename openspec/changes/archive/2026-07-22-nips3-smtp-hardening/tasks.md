# Tasks — NIPS-3-SMTP hardening
- [x] Bounded reader: io.LimitReader(conn, maxBody+1) around the session read (OOM fix).
- [x] Per-line idle deadline (IdleTimeout, default 30s) before each read (slowloris fix).
- [x] Accept semaphore (MaxConns, default 128); refuse+count beyond the cap (Refused()).
- [x] Tests: no-newline bounded/dropped; idle conn timed out; concurrency capped (Refused()>0).
- [x] Mutations: remove deadline → idle hangs; remove semaphore → Refused()=0.
- [x] make all clean; docs D148; sync; archive; commit; push; memory.
