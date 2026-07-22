# Tasks — HIPS-6 detector evasions
- [x] Encoded-flag: prefix match of "-<prefix-of-encodedcommand>" (remainder >=2), excluding bare -e.
- [x] unquote: hex-decode a bare even-length all-hex value (auditd's spaced-arg encoding); quoted values untouched.
- [x] Pipe-to-shell: any of sh/bash/zsh/dash/ksh/fish, with or without a space after the pipe.
- [x] Tests use REAL evasions: -encod/-enco prefixes; curl|zsh, wget|dash; a hex-encoded cradle decoded + tripping the detector.
- [x] Mutations: revert to literal encoded set; sh/bash-only pipe; disable hex decode — each fails.
- [x] make all clean; docs D153; sync; archive; commit; push; memory.
