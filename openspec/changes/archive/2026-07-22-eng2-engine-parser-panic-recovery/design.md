# Design — contain parser panics

## Re-derive the boundary, don't just annotate it

D35 kept the RCE-prone CONTENT parsing (PDF/OOXML/regex on bodies) in the seccomp-confined worker;
that is unchanged. What changed is that the engine now hosts METADATA parsers for network/exec
sources it listens on. Those parsers are small and defensive, but "defensive" is not "cannot panic":
a slice index, a malformed length, an unexpected shape can panic on crafted bytes. Since the engine
is the process that observes the whole host/fleet, a single crafted datagram crashing it is a
denial-of-service. So each in-process parse loop contains a panic to the one input that caused it —
the same discipline the drop-and-count already applies to a parse ERROR, extended to a parse PANIC.

## Recover per unit, at the loop

Recovery must be in the goroutine that panics, so it goes at the per-item boundary of each loop: one
datagram (DNS), one record (exec), one session (SMTP), one event (the engine loop). A recovered
panic is counted as a drop (observable, D28) and the loop continues. The engine-loop recover is
belt-and-suspenders: even a panic that somehow reaches a stage is contained to that event.

## Proven

A panicking sink stands in for a parser that panics on crafted input: the DNS listener survives a
datagram that panics its sink and still delivers the next; the exec scanner survives a record that
panics its sink and delivers the next. The mutation removing the DNS recover lets the panic crash
the process — the test dies — proving the recover is load-bearing.
