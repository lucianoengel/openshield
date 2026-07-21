# Tasks — behavioral detection (D110)

## 1. Analyzer

- [x] 1.1 `internal/behavioral.Analyze` (LOLBin + suspicious-parent lineage + encoded/cradle args → Finding with score+reasons); baseName handles both separators.

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: office→encoded-powershell ≥0.9; webshell + curl|bash flagged; routine command scores 0; score clamps to 1.0 with reasons; Windows path resolves.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D110.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| LOLBin detection disabled | the LOLBin assertion fails |
| lineage detection disabled | the office/webserver lineage assertion fails |
| encoded-command detection disabled | the encoded/cradle assertion fails |
| baseName drops backslash handling | the Windows powershell path no longer matches a LOLBin |
