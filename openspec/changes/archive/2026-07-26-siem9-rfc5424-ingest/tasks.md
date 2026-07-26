## 1. Parser
- [x] 1.1 `internal/connectors/rfc5424`: header, nil-value decoding, flattened SD, escape handling.
- [x] 1.2 Tests: full message; escapes inside values (**mutation:** stop honouring `\]`/`\"` → the value
      truncates → FAILS); nil values; every malformed shape is an error, not a partial record.

## 2. Ingest
- [x] 2.1 `syslog.Message.Raw`; the listener tries CEF then RFC 5424.
- [x] 2.2 Tests: both formats on one listener (**mutation:** drop the fallback → FAILS); SD huntable via
      the field filter (**mutation:** do not store SD in `fields` → FAILS); ordering (**mutation:** try
      RFC 5424 first → the CEF line is misread → FAILS, including a pre-existing test).

## 3. Counters
- [x] 3.1 Document the widened meaning at the definition and in the metric help text; update the
      pre-existing fixture that assumed "non-CEF" meant "unparseable".

## 4. Gate and land
- [x] 4.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green.
- [x] 4.2 Record D279; move SIEM-9's ingest-format item forward in the enrichment backlog.
- [x] 4.3 Sync specs and archive.
