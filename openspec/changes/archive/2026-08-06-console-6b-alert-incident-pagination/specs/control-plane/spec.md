# control-plane

## ADDED Requirements

### Requirement: Every capped operator list read MUST be walkable to its end

The alert queue, the filtered alert search and the incident list SHALL each report whether rows beyond
the returned page exist and SHALL each provide the means to continue from the end of the page.

Pagination on one route does not make the console honest. An analyst reading a capped alert queue that
presents itself as a bare complete list concludes the fleet raised exactly that many alerts, and an
operator reading a capped incident list concludes there is nothing past it. That is a wrong answer that
looks authoritative — the same defect as the unpaginated event search, on the surfaces a console spends
most of its time on.

#### Scenario: The alert queue can be walked past its cap
- **WHEN** more alerts match a read than the page holds
- **THEN** the response reports that more exist and carries a cursor that reaches them

#### Scenario: The incident list can be walked past its cap
- **WHEN** more incidents exist than the page holds
- **THEN** the response reports that more exist and carries a cursor that reaches them

#### Scenario: A walk reaches every matching row exactly once
- **WHEN** an operator walks a filtered read to its end
- **THEN** every matching row is returned exactly once across the pages

### Requirement: A walk's ordering MUST be unique, so rows sharing a timestamp are not lost

The ordering a continuation cursor resumes from SHALL be unique across rows, so that rows sharing the
same timestamp are each reached exactly once.

A boundary expressed only on a timestamp cannot distinguish the rows that share it. The walk resumes
strictly past the timestamp, and every tied row after the first becomes permanently unreachable for the
rest of that walk — silently, with the page still reporting itself well-formed. Alerts sharing a
detection instant are not an edge case here: one detector pass writes several alerts for one subject.

#### Scenario: Rows sharing a detection time are all reached
- **WHEN** several alerts share the same detection timestamp and are walked one page at a time
- **THEN** each of them is returned exactly once, rather than the walk skipping past the whole group

### Requirement: A continuation cursor MUST NOT be honoured by a surface it was not minted for

A continuation cursor SHALL identify the read it was minted for, and a cursor presented to a different
read SHALL be refused.

Positions on different tables encode the same shape — a timestamp and a row id — so an alert cursor
presented to the incident list would decode successfully and serve a page that is wrong but entirely
plausible. That is a corruption of row identity dressed as a normal result, and the client holding the
opaque value has nothing to tell it which surface the value came from.

This says which walk a position belongs to. It says nothing about who may walk it: authority is still
re-derived from the caller's credential on every page, and the cursor still encodes no identity, role or
scope.

#### Scenario: A cursor from another read is refused
- **WHEN** a cursor minted by one read is presented to a different read
- **THEN** the request is refused, exactly as an unreadable cursor is

### Requirement: A read whose order is recomputed per call MUST NOT offer continuation

A read that computes its result set fresh on every call, with no persistent per-row ordering, SHALL NOT
offer a continuation cursor, and SHALL refuse a continuation cursor presented to it.

"The row after this one" is not defined across a result set that is re-aggregated per request, so a
cursor into it would be a position in something that no longer exists. Offering one would be worse than
offering nothing: the client would walk it and believe the walk meant something. Accepting one and
answering the first page is the same wrong answer arriving by a different route — and where the same
route's other rules refuse it, one URL would have two behaviours for one parameter.

#### Scenario: The recomputed incident rule offers no cursor
- **WHEN** the incident list is read under a rule whose result set is aggregated fresh per call
- **THEN** no continuation cursor is offered

#### Scenario: A cursor presented to the recomputed rule is refused
- **WHEN** a continuation cursor is presented to a read whose result set is aggregated fresh per call
- **THEN** the request is refused, rather than answered with the first page

### Requirement: One route MUST answer in one envelope

A read route SHALL return the same response envelope for every rule it serves, whether or not that
rule is walkable.

A route that answers an object under one rule and a bare list under another gives a client no single
shape to decode. The client reads the field it expects, finds nothing, and renders an empty result while
rows exist — a wrong answer that looks complete, on the surface pagination exists to make honest. A
typed client fails loudly on the mismatch; a browser does not.

A rule with no walk order still answers in the envelope. It reports that no further rows exist, which is
true because it applies no cap, and it carries no continuation field at all.

#### Scenario: Both incident rules answer in the same envelope
- **WHEN** the incident list is read under the walkable rule and under the per-call aggregated rule
- **THEN** both responses carry the rows under the same field, and neither requires a different decoder

### Requirement: A saved search MUST NOT capture a continuation cursor

A stored search SHALL NOT carry a continuation cursor. Saving one SHALL be refused, and a stored search
that carries one SHALL fail loudly when it is run rather than being executed.

A cursor is a position in one walk at one instant, and cursors do not expire. A saved search that
captured one applies that boundary on every future run: the hunt permanently excludes everything newer
than the moment it was saved, goes on returning rows, and presents a truncated result as the answer.
Nothing about it looks wrong, so nobody has a reason to look — which is the worst available outcome for
a hunt, and the exact failure a saved search exists to prevent.

Refusing at save is what puts the message in front of the analyst who wrote it. Refusing at run is what
covers the searches already stored, which are the ones that have already been frozen; stripping the
cursor and running the search anyway is not sufficient, because it repairs one result while leaving the
stored query wrong on every other path that reads it.

#### Scenario: A search carrying a cursor is refused when it is saved
- **WHEN** a search whose query carries a continuation cursor is saved
- **THEN** it is refused with the reason, and it is not stored

#### Scenario: A stored search carrying a cursor fails loudly when run
- **WHEN** a stored search whose query carries a continuation cursor is run
- **THEN** it fails with the reason, rather than returning the rows its captured boundary selects

### Requirement: A refused read MUST NOT have taken effect

A read that is refused for a malformed parameter SHALL have written nothing and raised nothing.

The incident list is a read that writes: it materializes the current correlation before returning it,
which can create an incident and page a human. Validating parameters after that write meant a request
the server declined to serve had already changed the database and possibly woken whoever was on call.

#### Scenario: A malformed incident read raises no incident
- **WHEN** the incident list is read with a malformed limit or cursor
- **THEN** the request is refused and no incident has been materialized by it

### Requirement: A walk over incidents MUST reach every row whose ordering key cannot move

Rows whose ordering key is immutable SHALL be reached exactly once by a walk, even while other rows in
the same read are being updated concurrently.

Incidents are not append-only: an open incident's last-seen is pushed forward when correlation finds new
alerts for it, including from a background loop no operator triggered. A row bumped ahead of the walk
boundary MAY therefore be absent from the rest of that walk. That is an accepted and documented
limitation for open incidents, stated as a permitted weakness and deliberately NOT required — requiring
it would make a future improvement that reached the row a spec violation, and it is not enforced: the
test observes it and reports rather than failing. What is required is that it cannot spread. Triaged
history is what a deep walk exists to read, its ordering key cannot move, and losing a row of it would
be silent loss rather than staleness.

The exposure is narrower than it first appears, and the reason belongs here because the acceptance rests
on it: an incident's last-seen is the newest detection time among its alerts, not the time correlation
ran. Re-materializing with no new alerts therefore moves nothing, so re-running correlation on every page
of a walk does not push open incidents ahead of the boundary by itself — only a genuinely new detection
does.

#### Scenario: Concurrent updates do not drop settled incidents from a walk
- **WHEN** an incident that is not yet reached is updated mid-walk
- **THEN** the incidents whose ordering key did not move are still each reached exactly once
