# Design

## Why the assertion is "the spool is empty" and not "rows went up"

The agent keeps producing after the broker returns, so a row-count increase is satisfied by an agent
that discarded every spooled record and resumed. That is precisely the failure being tested for, so the
obvious assertion cannot see it.

`Queue.Drain` gives a better one for free:

```go
if err := fn(rec); err != nil {
    return delivered, err          // keep this record AND the rest
}
if err := os.Remove(q.path(seq)); ...
```

A record is removed only after its send succeeds, and the first failure stops the walk. So **an empty
spool is proof every record in it was delivered** — and it is proof that does not encode the on-disk
format, which a count-the-files-and-compare assertion would.

## Delivered and stored are different milestones

The first version of this test read the row count at the instant the spool emptied and reported *"the
spool emptied but 0 rows appeared for 2 held records"*. That is the wording of the catastrophic bug —
`Drain` removing records it never delivered — and it was a race in the test.

An empty spool means the **broker** accepted the records. The row appears only after the control plane
consumes them off JetStream and writes them. Two milestones, the second lagging the first. The fix is an
`Eventually`, and the reason it is worth a comment is that the wrong reading is the alarming one: the
count cannot distinguish "not yet stored" from "thrown away".

## Why the broker has to come back on the same port

`OPENSHIELD_NATS_URL` is read once at agent startup. A broker that returns on a kernel-assigned port is
a different broker as far as the agent is concerned, and the reconnect the scenario exists to exercise
would never be attempted against a live listener — the test would pass or fail for reasons having
nothing to do with draining.

`StopBroker` runs `podman stop` on a `--rm` container, so podman removes it and it cannot be restarted.
`restoreBroker` therefore starts a **new** container rebinding the original host port, retrying the bind
briefly because the stopped container does not always release the port by the time `podman stop`
returns. That retry is about a teardown race, not about the property under test, which is why it is a
loop rather than a failure.

## Why the JetStream store had to move into a volume

Without it the restored broker has empty JetStream state, and the first run of this test failed with
`flush stopped after 0 (still unreachable?): nats: no response from stream`, forever.

That was not a flake — it is a real product defect (PLAT-10), and it had to be separated from the
property under test before either could be measured. A restart that keeps its store recovers fully
(measured 2 → 120 rows); a broker with a fresh store never recovers. Two behaviours, one helper: so the
helper became two, `RestoreBroker` and `RestoreBrokerEmpty`, and the recovery scenario uses the first.

Naming the second helper now, rather than when PLAT-10 is fixed, is deliberate — it keeps the defect
reproducible in one call instead of rediscoverable.

## What a mutation had to prove

`Flush` returning `0, nil` — the plausible regression, a flush that silently does nothing. The scenario
fails on the spool never emptying (138s, the full drain deadline). Restored, it passes in 19s. Checked
that the mutant compiled before believing the result (D359).
