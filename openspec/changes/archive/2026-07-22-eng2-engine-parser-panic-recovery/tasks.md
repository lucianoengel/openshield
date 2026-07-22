# Tasks — ENG-2 parser panic recovery
- [x] DNS Serve: recover per datagram (handleDatagram); drop+count on panic.
- [x] exec Scan: recover per record (handleLine); drop+count on panic.
- [x] SMTP handle: recover per session; drop+count on panic.
- [x] engine loop: processOne recovers around eng.Process per event.
- [x] Tests: DNS + exec survive a panicking sink and deliver the next input.
- [x] Mutation: remove the DNS recover → the crafted datagram crashes the process (test dies).
- [x] make all clean; docs D156; sync; archive; commit; push; memory.
