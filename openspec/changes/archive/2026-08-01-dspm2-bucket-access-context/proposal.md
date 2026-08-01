# "Where is my sensitive data" did not rank anything

## Why

DSPM-1 shipped a sweep that finds sensitive data at rest. On its own it produces a list, not a queue: a
bucket of customer records the whole internet can read and a bucket only one service role can read yield
identical findings, and the operator handed both has to go and check each one by hand — which is the work
the discovery was supposed to have done.

And there was a second, quieter defect underneath it. `ObjectSubject` had existed since the sweep shipped
and `GetObject` had exactly **one** caller in the entire tree — a test. Bucket, key and store never reached
Rego at all, so the rule `sweep.go`'s own doc comment used to justify the structured subject —
"every policy that wants `bucket = finance-exports`" — could not be written. This is the D313 shape again:
a producer minting a subject nothing consumes.

## What changes

**The bucket's access context is probed once per sweep and rides every object discovered in it**: bucket
ACL, bucket policy, block-public-access settings and default encryption.

- **Three-valued, always.** PUBLIC, PRIVATE and *not established* are different answers. A credential
  permitted to list objects but not to read `?acl` yields UNKNOWN, never "private", and every probe that
  could not run is named with its cause. A reassurance produced by having looked at nothing is this
  feature's most expensive failure (D31).
- **A proven exposure survives an incomplete picture**; a negative one does not. If the policy proves the
  bucket is open, an unreadable ACL does not make it less open — but "nothing found" from a probe set with
  a hole in it is exactly the reassurance this refuses to give.
- **Only the two block-public-access settings that affect EXISTING access are treated as protective.**
  `IgnorePublicAcls` and `RestrictPublicBuckets` neuter live grants; `BlockPublicAcls` and
  `BlockPublicPolicy` only reject future calls. Treating all four as protective files a live exposure as
  safe; treating none as protective reports closed buckets until the operator stops reading findings.
- **A neutered grant is still reported as present**, because it is one deleted setting away from being live.
- **ObjectSubject reaches the policy**, exposure included, as an enum NAME so a rule reads
  `exposure == "OBJECT_EXPOSURE_PUBLIC"` and cannot mistake "nobody could tell" for the safe end of a scale.

## What this is not

Bucket-level ACL and policy only. Per-object ACLs are not read, and an IAM identity-based policy granting
access to a principal is invisible from the data plane entirely — no amount of asking the bucket reveals it.
The bucket-policy publicness rule is a conservative approximation of S3's own, deliberately erring toward
reporting exposure: it does not evaluate condition-operator semantics and does not resolve IAM policy
variables.

No discovery event is tagged with an exfil channel. Nothing moved; somebody looked.
