# Add the doc-consistency check (T-029)

## Why

Doc drift hit `brief.md` twice — it kept describing a Rust agent after D8 made the project
all-Go — because decisions were paraphrased in many places instead of referenced. And the whole
project's credibility rests on NOT overclaiming: "tamper-evident, not tamper-proof" is a
load-bearing distinction that a single careless README edit could erase. Both risks want a CI
guard.

But the naive guard does not work, and this is proven: a denylist grep for "tamper-proof",
"prevents", "guarantee" false-positived on four legitimate uses on 2026-07-20, because THIS
project's discipline consists of discussing exactly those forbidden words — in negation. "It
cannot prevent exfiltration" and "a tamper-*proof* log is impossible" are the honest claims, and
a grep that flags them punishes the honesty it is meant to protect.

So the check must tell an unqualified CLAIM from honest DISCUSSION, and must scan only the
surfaces where a claim is made.

## What changes

**A claim-surface honesty check (`internal/doccheck`, run as a test and a CI step).** It scans
only claim surfaces — `README.md` today, a configurable list as marketing/user-facing copy
appears — for unqualified positive uses of forbidden terms (tamper-proof, unhackable, "fully
secure", "100% ", prevents/guarantees when asserted). A match is a violation ONLY IF it is not
qualified:
- a **negation cue** on the same line (cannot, not, never, no, impossible, "isn't") makes it
  discussion, not a claim — this is what lets the honest README pass;
- an inline **`<!-- allow: <term> -->`** escape on or just above the line permits a deliberate
  use;
- append-only research reports (`docs/research-*`) and the decision register are out of scope —
  they exist to discuss the words.

**A decision-register consistency check.** The single source of truth (`docs/decisions.md`) must
have **unique** D-numbers — a duplicate or a collision is exactly the drift that let brief.md go
stale while looking maintained. This is robust and testable, unlike the ticket's original
suggestion (flag long paragraphs adjacent to a D-reference), which is the same false-positive-
prone heuristic the claim grep already failed at; that weaker idea is deliberately NOT
implemented, and the substitution is recorded.

**Fixtures prove both directions.** `testdata/` holds a good claim surface that passes and a bad
one ("OpenShield provides tamper-proof audit logs") that fails, so the check is proven to catch
the thing it exists to catch — not merely to pass on today's tree.

## What this does NOT claim or cover

- **It does not understand English.** The negation heuristic is a heuristic: a sufficiently
  convoluted sentence could smuggle a claim past it, and the allow-escape could be abused. It
  raises the cost of an accidental overclaim to near-certain CI failure; it is not a proof of
  honesty, and a reviewer still reads the README.
- **It does not scan all docs for claims.** Only claim surfaces. `docs/` is where the project
  reasons out loud, including about what it cannot do; scanning it would recreate the
  false-positive failure.
- **It does not check that a doc's D-reference is semantically correct** — only that the register's
  numbers are unique. Verifying a reference says the right thing is a reviewer's job.
- **It is not a marketing-copy linter for tone.** It targets specific overclaiming terms with a
  clear honesty rationale, not vague "sounds too confident" judgements.

## Decisions

Depends on the honesty constraints threaded through the whole project (D12/D16 and the intake
threat model: tamper-evident not tamper-proof; detection not prevention) and on D-numbered
referencing being the anti-drift discipline.

Establishes a small new decision: **claim surfaces are checked for unqualified overclaiming with
a negation-aware, escape-hatched check; the decision register's D-numbers must be unique** —
guarding honesty and anti-drift without the false-positive failure of a naive grep.
