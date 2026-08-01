# Design notes

## The block-public-access table was checked, not reasoned about

The interaction between a public grant and the four Block Public Access settings is the load-bearing logic
here and the easy thing to get wrong. It was verified against the AWS documentation before any Go was
written, and the documentation contradicted the intuitive reading in one place that matters:

| Setting | Effect on access that ALREADY exists |
|---|---|
| `IgnorePublicAcls` | **Neuters** — "causes Amazon S3 to ignore all public ACLs on a bucket and any objects that it contains" |
| `RestrictPublicBuckets` | **Neuters** — restricts a bucket with a public policy to service principals and the owning account |
| `BlockPublicAcls` | None — rejects new public-ACL calls; "existing policies and ACLs … aren't modified" |
| `BlockPublicPolicy` | None — rejects `PutBucketPolicy`; "doesn't affect existing … bucket policies" |

Neutering is applied **per source**: an ignored ACL says nothing about a public policy, and a restricted
public bucket says nothing about an ACL. Collapsing them into one flag applied to the total is the version
that quietly clears a bucket which is still open.

One consequence works in our favour. On real AWS, `GetBucketAcl` "always returns the effective permissions",
so a grant already suppressed by `IgnorePublicAcls` never appears; on MinIO, Ceph and the rest it does.
Applying the rule ourselves is therefore idempotent on AWS and load-bearing everywhere else.

## The bucket-policy rule is the opposite way round from the obvious one

S3 assumes a policy is **public** and requires it to qualify as non-public, by granting access only to
*fixed* values of a specific set of condition keys. A wildcard inside a condition does not save it: AWS's own
worked example marks `{"StringLike": {"aws:SourceVpc": "vpc-*"}}` public, while the same key pinned to
`vpc-91237329` is not.

"It has a Condition, therefore it is restricted" is the intuitive reading, it is what this would have
shipped, and it is wrong in the unsafe direction — it would have cleared every public bucket that happened
to carry any condition at all.

## Why the exposure is not an exfil channel

The clipboard, print and USB arms of the policy input each assign an `exfil_channel` because each **is** a
movement of data off the endpoint. A discovery sweep is not. Tagging it `cloud_sync` would have been the
tidy-looking move and would have silently widened every already-written "nothing sensitive to cloud sync"
rule to fire on data that has been sitting still for two years — changing what an operator's existing policy
means without them touching it.

## Contradiction found while testing, recorded rather than reconciled

The integration scenario's first form asserted `exposure == PUBLIC AND a classifier hit`, which is the rule
an operator actually wants. It could not discriminate: a custom policy **composes** with the observe-only
default under most-restrictive-wins (ADR-5), and that default already ALERTs on a CPF wherever it finds one,
so both buckets returned ALERT and the negative control proved nothing.

That is a property of the composition, not a defect, and it is worth stating plainly because it constrains
every future test of a custom rule: **a custom rule can only be observed to have fired when its outcome
differs from what the default would have decided by itself.** The scenario now discriminates on a benign
object, on which the default has no opinion.

## Deliberately deferred

- **Per-object ACLs.** An object can be public inside a private bucket. Probing per object multiplies the
  request count by the object count, which is a sweep an operator turns off; the bucket-level answer is the
  one that covers the overwhelming majority of real exposures.
- **IAM identity-based policies.** Invisible from the data plane. No amount of asking the bucket reveals
  that a role elsewhere has `s3:GetObject` on it.
- **Access-log and last-accessed context** ("who actually reads this"), which needs the store's own audit
  trail rather than its configuration.
