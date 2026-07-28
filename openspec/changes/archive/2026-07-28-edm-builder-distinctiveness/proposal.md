# The shipped EDM index builder skips the distinctiveness filter the spec requires

## Why

`exact-data-matching` requires it in as many words:

> **WHEN** a dataset contains short/common tokens alongside distinctive values
> **THEN** the builder indexes the distinctive values and skips the low-entropy ones

`classify.BuildEDMIndex` implements exactly that — it applies `distinctiveEDM`, skips values that are
too short or are short purely-alphabetic tokens (dictionary words), and returns a count of what it
skipped. It is unit-tested, and it **has no caller**.

`openshield-dlp-index edm`, the tool an operator actually runs, builds the index itself:

```go
idx := classify.NewEDMIndex(targetFP, len(values))
for _, v := range values {
    idx.Add(v)          // every value, unfiltered
}
```

So the requirement is satisfied by a function nobody calls and violated by the shipped path. The
`record` builder immediately below it does the right thing — it uses `BuildRecordIndex`, and refuses
outright when nothing distinctive survives — which is what makes the EDM path's omission look like an
oversight rather than a decision.

## Why this is worse than a detection gap

An EDM index is a set of customer values that content is matched against. Indexing non-distinctive
ones does not weaken detection — it **manufactures false positives**. A `city` column, a `status`
column, a column of first names, and every document containing the word "active" or "Smith" now
matches as carrying protected customer data.

In the observe-only default that is noise. With `OPENSHIELD_ENFORCE` set it is **blocked legitimate
traffic**, from a control that is behaving exactly as configured. That is how a DLP deployment gets
switched off, and it is a worse outcome than the detection this feature exists to provide.

The operator has no way to notice, either: the tool prints that the index was built. There is no
skipped count, because the code path that counts skips is the one not being used.

## What Changes

- `openshield-dlp-index edm` uses `classify.BuildEDMIndex`, so the distinctiveness filter the spec
  requires is applied by the tool that ships.
- It **reports** how many values were skipped, so an operator can see that their column was mostly
  discarded rather than discovering it from false-positive volume later.
- It **refuses** when nothing distinctive survives, matching the `record` builder, which already
  fatals with "no records had enough distinctive cells — nothing to index". An index over zero values
  matches nothing, and shipping one silently is a detector that reports itself configured and cannot
  fire.

## Impact

- Affected specs: `exact-data-matching`
- Affected code: `cmd/openshield-dlp-index`
- No proto change, no migration, no library change — `BuildEDMIndex` is already correct and already
  tested; this makes the shipped tool use it.
- **Existing indexes are unaffected** and keep working. This changes what a NEWLY built index
  contains, and an operator who rebuilds may see fewer values indexed — which is the point, and why
  the skipped count is reported rather than left silent.
