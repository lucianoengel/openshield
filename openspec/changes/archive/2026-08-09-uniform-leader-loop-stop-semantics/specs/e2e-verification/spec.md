## MODIFIED Requirements

### Requirement: A test stops the background work it starts

A test that starts a goroutine against a resource the test harness owns SHALL wait for that goroutine to
have RETURNED before the resource is released, and SHALL fail rather than hang if it does not. Cancelling
a context is a request, not a stop: it returns while the goroutine may still be inside a query.

A loop still running after its test finished writes into whatever it was given — a closed pool, a
package-level counter, the next test's schema — and the test it breaks is not the test that leaked it.
This is the only defect class in the suite whose blast radius is another file.

Where a test asserts on a counter that is shared across the package, it SHALL assert on the value as it
stands rather than resetting it first, and its failure message SHALL say that the count may belong to a
loop another test leaked. Resetting turns a cross-test leak into a silence, and makes the assertion pass
whether or not the leak exists.

EVERY BACKGROUND LOOP A TEST STARTS AGAINST THE SHARED DATABASE SHALL BE JOINED, not only the ones whose
counters are currently asserted on. A leaked loop is not merely a counter problem: one ticking every 20ms
runs real queries into the next test's `DROP TABLE … CASCADE` and migration, which is a DDL/DML collision
whose symptom is an unrelated test failing intermittently on a schema error.

THE HELPER THAT PERFORMS THE JOIN SHALL ALSO SUPPORT A DELIBERATE MID-TEST STOP, returning a stop
function that is idempotent and is additionally registered for cleanup. Some scenarios must stop a loop
partway through in order to assert what happens afterwards; a helper that can only stop at cleanup
silently converts those into tests that run a loop against the database for the rest of the test, which
changes what they prove while appearing to preserve them.

Taking the owned resource as a parameter is REQUIRED of such a helper, but it is a guardrail rather than
a proof: it makes the common ordering mistake harder without making it impossible, because this package
also builds pools that are released by `defer` (which runs before any cleanup) and pools that register no
release at all. The ordering therefore SHALL be verified by an actual leak test, not asserted from a
signature.

#### Scenario: The loop is gone before the pool is
- **WHEN** a scenario starts a scheduled loop against the test's database
- **THEN** the loop has returned before the pool is closed, so no tick can run against it

#### Scenario: A leak is reported, not absorbed
- **WHEN** a background loop from an earlier test has counted a failure
- **THEN** the test asserting that counter fails and names the leak as a possible cause

#### Scenario: A loop whose counter nobody asserts is joined anyway
- **WHEN** a scenario starts a scheduled loop against the shared database and asserts only on rows
- **THEN** that loop is joined before the test's resources are released, so its queries cannot reach the
  next test's schema migration

#### Scenario: A scenario that must stop its loop early still joins it once
- **WHEN** a test stops a loop partway through in order to assert on what follows
- **THEN** the loop has returned at that point, and the end-of-test cleanup does not stop it a second
  time or hang waiting for a loop that has already gone

<!-- from flaky-counter-tests -->
