## Context

The syslog/DNS/SMTP connectors are pure parsers: the untrusted-bytes surface is isolated and tested in
Go, separate from any socket. CEF is the same shape — a text format from an untrusted source — so it gets
the same treatment. CEF is `CEF:Version|Vendor|Product|DeviceVersion|SigID|Name|Severity|Extension`, with
its own escaping.

## Goals / Non-Goals

**Goals**
- `cef.Parse(line) (Message, error)`: the seven headers + the key=value extension, with escaping.
- Bounded line length; malformed → error.
- Prove the header/extension parse, the escapes, spaces-in-values, and the rejections.

**Non-Goals**
- The live listener + search-path persistence (ingest plumbing; CEF rides syslog).
- WEF (XML) and cloud-JSON parsers (separate parsers, same pattern).
- Semantic interpretation of extension keys (they are decoded as-is).

## Decisions

### D1 — Split the seven headers on unescaped pipes, then unescape
The header is exactly seven `|`-delimited fields after the `CEF:` prefix, but a field may contain a
literal pipe as `\|`. So the split walks the string honoring `\|` (and `\\`) rather than a naive
`strings.Split`, takes the first seven fields, and the remainder (after the seventh pipe) is the
extension. Each header field is then unescaped (`\|`→`|`, `\\`→`\`). Fewer than seven header fields is a
reject — it is not CEF.

### D2 — Parse the extension by locating key= boundaries, so values keep their spaces
A CEF extension is `k1=v1 k2=v2 …` where a value may contain spaces (`msg=worm stopped src=…`). So a
naive space-split is wrong. The parser finds each ` key=` boundary (a space followed by a bareword key
and `=`) and takes the value as everything up to the next boundary, then unescapes the value (`\=`→`=`,
`\\`→`\`, `\n`→newline, `\r`→CR). The first key starts at the extension's beginning. Keys are barewords
(letters/digits/dot/underscore); a stray token that is not `key=` is folded into the previous value,
matching how real CEF producers emit free-text values.

### D3 — Malformed is an error, bounded input
An empty line, a line without `CEF:`, or fewer than seven headers is an error — never a partial Message
(D17): a SIEM that silently accepts half a log is worse than one that rejects it loudly. The line is
length-bounded (a multi-megabyte "line" is an exhaustion vector, not a log), matching the syslog cap.

### D4 — Decode, don't interpret
The parser returns the raw decoded values (vendor, signature id, severity string, extension map); it does
not map CEF severity to a scale, resolve signature ids, or normalize keys. Interpretation belongs to the
ingest/normalization layer that consumes the parsed record — keeping the parser a faithful,
side-effect-free decoder of the untrusted bytes.

## Risks / Trace-offs

- **Extension free-text values** — CEF's grammar is loose (unescaped `=` inside values happens in the
  wild); the key-boundary heuristic (a space + bareword + `=`) handles the common cases and folds
  ambiguity into the value rather than dropping data. Stated.
- **No semantic mapping** — a downstream layer maps severity/keys; the parser stays faithful.

## Migration Plan

Additive: a new connector package. No proto/core/existing-connector change.

## Open Questions

- Whether to normalize a parsed CEF record into a common external-log shape shared with syslog now. Deferred
  to the ingest/normalization follow-on, where the search schema is decided.
