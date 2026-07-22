# HIPS-6: close the behavioral-detector 1-char bypasses

## Why

HIPS-5 made the behavioral detectors LIVE, so their trivial evasions now matter. Three let an
attacker sail past detection:
- **Encoded-PowerShell literal match**: it matched only `-enc`/`-e`/`-encodedcommand`, but PowerShell
  accepts ANY unambiguous prefix of `-EncodedCommand` (`-en`, `-enco`, `-encod`, …) — none matched.
- **auditd hex-encoded argv left undecoded**: auditd hex-encodes any arg with a space, which is
  EVERY real download-and-execute cradle; the parser left it as an opaque hex blob, so the cradle
  detector was blind to the commands it exists to catch (the prior "e2e" test dodged this with a
  spaceless payload).
- **Pipe-to-shell only matched sh/bash**: `curl x | zsh`, `wget -O- x | dash`, `…|ksh` evaded it.

## What Changes

- **Encoded-flag prefix match**: a `-`/`/`-prefixed token whose remainder (≥ 2 chars) is a prefix of
  `encodedcommand` trips it — catching `-en`…`-encodedcommand` while excluding the FP-prone bare
  `-e` and non-prefixes like `-encrypt`/`-export`.
- **auditd bare-hex decode** in `unquote`: an unquoted, even-length, all-hex value is hex-decoded
  (auditd quotes safe values, so an unquoted all-hex value IS hex-encoded). Real cradles decode and
  reach the detector.
- **Pipe-to-any-shell**: a downloader piped into sh/bash/zsh/dash/ksh/fish (with or without a space
  after the pipe) trips it.

This modifies the `behavioral-detection` and `execaudit-connector` capabilities.

## Impact

- Affected specs: `behavioral-detection`, `execaudit-connector`
- Affected code: `internal/behavioral/behavioral.go` (encoded-flag + pipe), `internal/connectors/execaudit/execaudit.go` (hex decode).
- Not in scope (stated): renamed-LOLBin evasion (`copy powershell.exe a.exe` then run a.exe) — name-
  based detection is inherently evaded by renaming; the real fix is binary hashing/signing, a
  separate bet; obfuscation beyond hex (base64 argv is already covered by the encoded-command
  detector; deeper deobfuscation is HIPS detection-content, ongoing).
