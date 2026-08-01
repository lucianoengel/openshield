# object-discovery Specification

## ADDED Requirements

### Requirement: A discovered object carries the access context of the bucket it sits in

A sweep SHALL establish who can read the bucket — from its ACL, its bucket policy, its block-public-access
settings and its default encryption — and SHALL carry that determination on every Event it emits from that
bucket.

Discovery alone ranks nothing. A bucket of customer records the whole internet can read and one only a
service role can read produce identical findings, and the operator handed both must check each by hand,
which is the work the sweep was supposed to have done.

The probe SHALL run once per sweep rather than once per object. The access context is a property of the
bucket, and re-probing per object multiplies four requests by the object count to learn the same four facts.

#### Scenario: A world-readable bucket is reported as such
- **WHEN** a sweep runs over a bucket whose policy grants read access to everyone
- **THEN** every object discovered in it carries an exposure of PUBLIC, and the sweep's report states it

#### Scenario: A closed bucket is reported as private
- **WHEN** the same sweep runs over a bucket with no public grant
- **THEN** its objects carry an exposure of PRIVATE

### Requirement: An exposure that could not be established is never reported as private

The exposure SHALL be three-valued: readable by everyone, readable by nobody outside the account, and NOT
ESTABLISHED. A probe that could not run SHALL leave the exposure undetermined and SHALL be recorded by name
together with the reason it did not run.

A discovery credential routinely lists objects without being permitted to read the bucket's ACL or policy.
Reporting that silence as "private" produces the one answer nobody re-checks, from having looked at nothing —
the D31 failure in its most expensive form, on the feature whose whole output is a reassuring absence.

A determination that a grant IS present SHALL survive an incomplete picture; a determination that none is
present SHALL NOT. If the policy proves the bucket open, an unreadable ACL does not make it less open.

#### Scenario: A refused probe yields "not established"
- **WHEN** the credential is not permitted to read the bucket ACL and nothing else indicates exposure
- **THEN** the exposure is reported as not established, and the ACL probe is named as unchecked with its cause

#### Scenario: A proven exposure survives an unreadable probe
- **WHEN** the bucket policy proves the bucket is public and the ACL cannot be read
- **THEN** the exposure is PUBLIC and the incomplete picture is still recorded

### Requirement: Only block-public-access settings that affect existing access are treated as protective

A block-public-access setting SHALL reduce a reported exposure only where it suppresses access that ALREADY
exists, and SHALL be applied to the source it governs rather than to the total. Where a live grant is
suppressed, that fact SHALL be reported rather than the grant being erased.

Of the four settings, `IgnorePublicAcls` and `RestrictPublicBuckets` suppress existing access; `BlockPublicAcls`
and `BlockPublicPolicy` only reject future calls. Treating all four as protective files a live exposure as
safe. Treating none as protective reports buckets that are already closed, until the operator stops reading
the findings. An ignored ACL says nothing about a public policy, so applying one flag to the total quietly
clears a bucket that is still open.

A store that never implemented block-public-access SHALL NOT have its findings downgraded on that account.

#### Scenario: A setting that suppresses existing access reduces the exposure
- **WHEN** a bucket has a public ACL grant and IgnorePublicAcls is set
- **THEN** the exposure is private, and the suppressed grant is reported as present

#### Scenario: A setting that only rejects future calls does not
- **WHEN** a bucket has a public ACL grant and only BlockPublicAcls is set
- **THEN** the exposure remains public

#### Scenario: A store without the feature does not blank the finding
- **WHEN** the store does not implement block-public-access and a public grant exists
- **THEN** the exposure remains public and no probe is recorded as unchecked

### Requirement: A discovered object's identity and exposure reach the policy

The bucket, key, store and access context of a discovered object SHALL be available to policy evaluation.
The exposure SHALL be exposed as a name rather than an ordinal, so that "could not be established" cannot be
read as the safe end of a scale.

A discovery event SHALL NOT be assigned an exfiltration channel. Nothing moved; somebody looked. Assigning
one would widen every already-written rule about that channel to fire on data at rest, changing what an
operator's existing policy means without them editing it.

#### Scenario: The same object is ranked differently by where it sits
- **WHEN** identical content is discovered in a world-readable bucket and in a closed one
- **THEN** a policy reading the exposure can raise a finding for the first and not the second

#### Scenario: A discovery is not tagged as an exfiltration
- **WHEN** an object is discovered by a sweep
- **THEN** no exfiltration channel is set on its policy input
