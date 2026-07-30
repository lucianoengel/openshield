# Design

## No SDK, and the reason is the dependency tree

`go.mod` has **12 direct dependencies** and has clearly been defended. `aws-sdk-go-v2` brings dozens of
modules to call two REST endpoints — `ListObjectsV2` and a ranged `GetObject`. Both are plain HTTP with an
XML response; the only non-trivial part is SigV4, which is HMAC-SHA256 over a canonical request and is
covered by the standard library.

The trade is stated rather than assumed: hand-rolled SigV4 is fiddly and easy to get subtly wrong. The
failure mode is benign — a wrong signature is a 403, not a security hole, because we are the client
authenticating ourselves — and it is caught immediately by a test against a real server. That is the
argument for MinIO below.

Being S3-*compatible* rather than S3-*specific* is a side benefit worth having: MinIO, Ceph, Wasabi,
Backblaze and R2 all speak this API, so one connector covers self-hosted object storage too — which for a
self-hostable product is arguably the more relevant target than AWS.

## The content boundary is the same one SMTP already solved

`cmd/openshield-engine/smtpsource.go` is the worked example and this follows it exactly:

```go
store.Put(ev.GetEventId(), body)   // BEFORE the send
events <- ev
```

The ordering is load-bearing and its comment says why: the pipeline can begin classifying the moment the
event is received, so storing afterwards races a resolver lookup that returns nothing — and **"no content"
is indistinguishable from "clean content" downstream, which is a scan that silently did not happen**. The
same trap applies here and the same ordering avoids it.

So: the connector holds bytes and never parses them; the worker parses and never holds credentials or the
network (D13/D72). The Event carries `bucket/key` metadata and no content (D10/D29).

## Bounded everywhere, and the bounds are reported

A bucket can hold ten million objects and a single object can be a terabyte. Three ceilings:

- **objects per sweep** — an enumeration that never ends is a connector that never yields.
- **bytes per object** — a ranged GET, so the ceiling costs no bandwidth beyond it.
- **concurrent fetches** — a discovery sweep must not saturate the link the endpoint also uses.

**A truncated sweep is REPORTED, not silent.** If the object ceiling is hit, the connector says how many it
did not look at. A partial sweep that reads as a clean one is exactly the D31 failure, and it is worse here
than elsewhere because the output of this feature is a reassuring absence — "no sensitive data found" is the
answer nobody re-checks.

## Testing against MinIO, not a mock

A mocked S3 would agree with whatever the signing code believes, which is the project's signature failure —
a test that passes because it shares the code's wrong premise. MinIO is S3-compatible, runs in podman like
the rest of the harness's infrastructure, and exercises the real SigV4 path, the real XML parsing and real
pagination.

The scenario seeds a bucket with a benign object and one containing a seeded CPF **past the prefix ceiling
as well as within it**, and asserts: the within-ceiling one is detected, the past-ceiling one is not, and the
Event carries no content. The second assertion is the honest one — it pins the documented limit rather than
letting the ceiling be believed to be unlimited.

## The fitness verdict is an output of this work

The question is whether a **pull/enumerate** producer fits the frozen core. Concretely:

1. Does it fit the `Next(ctx) (*corev1.Event, error)` producer seam? A sweep yields objects one at a time,
   so probably yes — but "probably" is why it gets tried rather than asserted.
2. Does `FilesystemSubject.resolved_path` carry `s3://bucket/key` well enough for policy, or does policy
   end up string-parsing a URI to express "this bucket"?

(2) is the interesting one and is where a core change would be forced. The verdict gets recorded beside the
T-004 verdict either way, because a fitness test whose result is only written down when it passes is not a
test.
