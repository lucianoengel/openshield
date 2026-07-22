# Design — close the detector evasions

## Match the tool's own semantics, not a token list

PowerShell resolves `-EncodedCommand` from any unambiguous prefix, so the detector must too: a
`-`/`/`-prefixed token whose remainder is a prefix of "encodedcommand". A literal list can never be
complete against a prefix-matching parser. The bare `-e` is excluded (remainder ≥ 2) because it is a
ubiquitous innocent flag and the encoded signal alone is sub-threshold anyway.

## Decode what auditd encoded

auditd's encoding is the crux: it QUOTES a safe value and HEX-ENCODES one with a space/quote/control
char. Every real cradle has a space, so it arrives bare-hex — and the parser was returning the blob
verbatim, so the cradle detector never saw the command. `unquote` now decodes an unquoted,
even-length, all-hex value. A quoted value (auditd's form for a safe printable string) is stripped,
never hex-decoded, so a coincidentally-hex-looking safe arg like `"deadbeef"` is unaffected.

## Any shell, any pipe form

A downloader piped into a shell is the shape; the specific shell is the attacker's choice. Matching
only sh/bash was a token list again — now any common shell with either pipe spacing trips it.

## Mutation proof

Each fix is proven against a REAL evasion and mutation-tested by reverting to the old behavior:
`-encod` stops being detected under the literal set; `curl|zsh` stops under the sh/bash-only pipe;
a hex-encoded `curl … | bash` arrives undecoded (and untripped) when the hex path is disabled.
