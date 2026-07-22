# Design — classify skips content-free events

## Gate on the target type, not the path alone

The original guard was `path == "" → error`. The fix distinguishes WHY the path is empty: a
network/process/usb event has no filesystem target at all (`GetFilesystem() == nil`) — it is
content-free by nature, so classification is legitimately empty. A file event WITH a filesystem
target but an empty resolved path is a real bug and must still error. Gating on the target type
separates the two cases cleanly; gating on the path alone conflated them.

## Empty classification, not a skipped stage

The content-free event still passes through the classify stage — it just yields an empty
`LocalClassification` rather than calling the worker. Keeping it in the stage (rather than
special-casing the dispatcher) means the policy always sees a `Classification` object (empty
hits) and `buildInput` needs no nil-handling change. The policy decides on the event metadata
`buildInput` already exposes.

## Regression discipline

The bug survived D133 because that increment's test asserted only that the Event reached the
channel, never that `Process` accepted it. The fix's test runs a DNS event through the REAL
`eng.Process` and asserts a Decision is produced and audited, with the worker NOT called (a
fakeWorker that errors if invoked). A second test pins the guard: a file event with an empty
path must still error, so the content-free skip cannot swallow a broken file event. Both are
mutation-tested.
