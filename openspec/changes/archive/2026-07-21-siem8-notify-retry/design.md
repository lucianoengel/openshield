# Design — SIEM-8 notify retry

## A decorator, not a change to Notifier

Retry wraps the `Notifier` interface rather than being baked into `Webhook`, so it composes with
any sink (webhook today, others later) and the retry policy is one place, tested once. The server
wraps its webhook at construction; nothing else changes.

## Permanent vs transient

Retrying every failure the same number of times wastes the budget on errors that cannot succeed
(a 400, a malformed payload). So a failure carries its retryability: `notify.Permanent(err)`
marks a non-retryable error, and `Retrying` returns immediately when it sees one. The `Webhook`
classifies: a 4xx (except 429 Too Many Requests) and a marshal/bad-URL error are permanent; a
5xx, a 429, and transport errors (timeout, refused) are transient. The classification is proven
end-to-end by counting how many requests a receiver returning each status actually gets.

## Testability: an injected sleep seam

Real backoff would make the tests slow and timing-dependent. `Retrying.sleep` is an unexported
seam defaulting to a context-aware `time.Timer` wait; the internal tests inject an instant sleep
(that still honors cancellation), so the retry logic — succeed-after-N, exhaust-the-budget,
skip-permanent, honor-cancellation — is exercised deterministically. The cancellation test uses a
1-hour base delay with the REAL `sleepCtx` and an already-cancelled context to prove backoff
returns promptly rather than sleeping out the window.

## Mutation proof

Three guards pin the behavior: the retry loop (bound it to one iteration → succeed-after-transient
and exhaust-budget fail), the permanent short-circuit (remove it → a permanent error is retried to
the budget), and the cancellation check in backoff (ignore the sleep error → a cancelled context
runs all attempts). Each mutation fails a distinct test.
