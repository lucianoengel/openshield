## Context

`Classify` (internal/classify/classify.go) reads the bytes, then: if OOXML → extract clean text; else
if PDF → extract text; else scan raw. `extractOOXML` (documents.go) only pulls RECOGNIZED OOXML text
members (word/*, xl/*, ppt/*) from an Office doc, bounded by `maxExtractBytes` (16 MiB total),
`maxZipEntries` (4096), `maxEntryBytes` (8 MiB). A general zip (not OOXML) returns false → raw scan of
compressed bytes → PII hidden. Nothing recurses.

## Goals / Non-Goals

**Goals:**
- Extract and classify the content of ANY zip member (not just OOXML), recursively into nested
  containers, so the double-zip evasion is closed.
- Stay decompression-bomb safe: one shared byte budget across the whole recursion + a depth cap.
- Preserve current behavior: OOXML → clean text; PDF → text; non-container → raw scan.

**Non-Goals:**
- tar / gzip / 7z / rar archive formats — ZIP is the ubiquitous case and the stated "double-zip"
  evasion; other container formats are follow-ons.
- RTF / legacy binary `.doc` text extraction — separate DLP-8 items.
- Extracting from encrypted/password-protected archives — an encrypted member is opaque (correctly
  scanned as raw; a policy on "encrypted archive to an exfil channel" is a separate signal).

## Decisions

1. **A unified recursive `extractContent(data, depth, *budget)`.** It tries, in order: OOXML (clean
   Office text), PDF, then a general ZIP (all members). A non-container returns its own bytes. The zip
   path recurses each member through `extractContent`, so a `.docx`-in-a-`.zip` yields clean OOXML text
   (the member hits the OOXML branch), and a `.zip`-in-a-`.zip` is unwrapped. `Classify` calls it once
   with `depth=0` and a fresh budget.

2. **One SHARED byte budget by pointer.** `*budget` starts at `maxExtractBytes` and every extracted run
   decrements it; the recursion stops the moment it hits zero. So total extracted text across ALL
   nesting is bounded by one 16 MiB ceiling — a zip-bomb nested inside a zip cannot multiply the budget
   per level (the classic recursive-decompression amplification). Per-member reads are still bounded by
   `min(budget, maxEntryBytes)`, and per-archive by `maxZipEntries`.

3. **A depth cap (`maxArchiveDepth = 4`).** Beyond it, a member is scanned as-is (its compressed bytes)
   rather than recursed — 5 levels of nesting is generous for legitimate content and deeper is almost
   certainly an evasion/bomb attempt. The cap also guarantees termination independent of the budget.

4. **OOXML tried before the general zip.** An Office doc IS a zip; trying `extractOOXML` first keeps its
   clean XML-stripped text (the general-zip path would dump raw XML). The general path only runs for a
   zip with no recognized OOXML members.

5. **Best-effort per member.** A member that fails to open/read is skipped (one bad member never fails
   the whole extraction), matching the existing OOXML/raw-fallback discipline (D17-consistent: a
   detection MISS degrades to "scan what we can", never a crash or a silent whole-file skip).

## Risks / Trade-offs

- **CPU/memory on a crafted archive.** The shared budget + depth cap + entry cap bound the work; the
  worker already caps raw input at 8 MiB and runs seccomp-sandboxed (D35), so an extraction bomb hits a
  ceiling, not OOM. The bounds are the same class the OOXML extractor already relies on.
- **A zip we can't fully unwrap (depth exceeded / budget spent) is partially scanned.** Correct and
  honest — we scan what the bounds allow and the remainder as raw bytes; a determined bomb is stopped,
  not perfectly extracted. That is the D13/D35 trade (bounded safety over unbounded fidelity).
