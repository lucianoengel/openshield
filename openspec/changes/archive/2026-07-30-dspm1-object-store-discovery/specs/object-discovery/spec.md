## ADDED Requirements

### Requirement: Sensitive data AT REST in an object store is discoverable

There SHALL be a connector that enumerates objects in an S3-compatible store, reads a bounded prefix of
each, and emits one Event per object into the same pipeline every other producer feeds.

Until this, the product classified only data in motion past an interposition point, so it could not answer
"where is my sensitive data" — the first question asked of a Data Security Platform, and the one its name
promises.

#### Scenario: An object containing sensitive content is found
- **WHEN** a sweep runs over a bucket holding an object with detectable sensitive content
- **THEN** that object is classified and a decision is recorded against it, identified by bucket and key

#### Scenario: A benign object does not produce a finding
- **WHEN** the same sweep reads an object with nothing detectable in it
- **THEN** no sensitive-content finding is raised for it

### Requirement: The connector holds bytes and never parses them

Object content SHALL reach the sandboxed worker and nothing else. The connector SHALL NOT classify, and the
Event SHALL carry object metadata only — never content, and never a digest of it.

This is the same boundary the SMTP connector holds (D13/D72, D10/D29). The process that talks to the network
and holds credentials must not be the process that parses attacker-influenced bytes, and object content is
attacker-influenced whenever anyone can write to the bucket.

Content SHALL be stored for the resolver BEFORE the Event is dispatched. Storing afterwards races the
pipeline, and a resolver lookup that returns nothing is indistinguishable downstream from content that was
clean — a scan that silently did not happen.

#### Scenario: No content rides the Event
- **WHEN** an object with sensitive content is discovered
- **THEN** the Event carries bucket and key and no object bytes

#### Scenario: Content is available to the worker when the pipeline reaches it
- **WHEN** the Event is dispatched
- **THEN** the content is already resolvable, not stored afterwards

### Requirement: A sweep is bounded, and what it skipped is reported

A sweep SHALL bound the number of objects examined, the bytes read per object, and its concurrency. When a
bound truncates the sweep, the connector SHALL report how much was not examined.

A bucket can hold ten million objects and one object can be a terabyte; without bounds the connector never
yields and saturates the link. But the reporting matters more than the bounds here than almost anywhere
else in the product, because this feature's output is a REASSURING ABSENCE. "No sensitive data found" is the
answer nobody re-checks, and a partial sweep that reads as a complete one is the D31 failure in its most
expensive form.

Content past the per-object ceiling is NOT examined, and that limit SHALL be stated rather than implied.

#### Scenario: A truncated sweep says so
- **WHEN** a sweep stops at its object ceiling
- **THEN** it reports how many objects it did not examine

#### Scenario: The per-object ceiling is a real limit
- **WHEN** an object holds sensitive content only beyond the byte ceiling
- **THEN** it is not detected, and this is the documented behaviour rather than a defect

### Requirement: Discovery is distinguishable from access

A discovered object SHALL be emitted with an event kind that means "this data exists here", distinct from
the kinds meaning "someone touched this".

Reusing a file-access kind would misrepresent what happened — a scanner read it, nobody opened it — and the
distinction is one policy and correlation need, because the two justify different responses.

#### Scenario: A discovery is not reported as an access
- **WHEN** an object is discovered by a sweep
- **THEN** its Event kind identifies it as a discovery
