// Package behavioral is the process-behavior detection domain (Phase E / HIPS, E2). Where
// the content classifier matches PATTERNS in bytes, this analyzes the SHAPE of a process
// execution — the binary, its lineage, and its arguments — to flag living-off-the-land
// (LOLBin) abuse, suspicious parent→child lineage, and encoded/download-and-execute command
// lines. It is a different classifier shape than content patterns, and a standalone
// analyzer (like peer-UEBA, D53): it produces a Finding a policy acts on, over exec METADATA
// only (D10/D29) — never process memory.
package behavioral

import (
	"strings"
)

// baseName extracts the final path component, handling BOTH separators — a process event
// may carry a Windows path ("C:\\...\\powershell.exe") or a Unix path ("/bin/sh"), and
// path.Base only splits on '/', so a backslash path would otherwise read as one long name.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Finding is the behavioral verdict for one process execution. Score is in [0,1]; Reasons
// explains it (for the audit trail). It is evidence for a policy, not a decision — the
// policy (with the closed action set) decides DENY_EXEC/KILL_PROCESS/ALERT.
type Finding struct {
	LOLBin            string  // the recognized living-off-the-land binary, or ""
	SuspiciousLineage bool    // an unusual parent spawned this (office→shell, server→shell)
	EncodedCommand    bool    // an encoded / download-and-execute command line
	Score             float64 // [0,1]
	Reasons           []string
}

// lolbins are binaries commonly abused to live off the land. Presence is a SIGNAL, not a
// verdict — many are legitimate; the score combines it with lineage and args.
var lolbins = map[string]bool{
	// Windows
	"powershell.exe": true, "powershell": true, "pwsh": true, "pwsh.exe": true,
	"cmd.exe": true, "wscript.exe": true, "cscript.exe": true, "mshta.exe": true,
	"rundll32.exe": true, "regsvr32.exe": true, "certutil.exe": true, "bitsadmin.exe": true,
	"wmic.exe": true, "msbuild.exe": true, "installutil.exe": true, "mshta": true,
	// Unix
	"bash": true, "sh": true, "dash": true, "zsh": true, "python": true, "python3": true,
	"perl": true, "ruby": true, "nc": true, "ncat": true, "socat": true, "curl": true, "wget": true,
}

// suspiciousParents are processes that should rarely spawn a shell/interpreter — an office
// document or a network server doing so is a hallmark of exploitation (macro malware, a
// webshell).
var suspiciousParents = []string{
	"soffice", "winword", "excel", "powerpnt", "outlook", "acrobat", "wps",
	"nginx", "apache", "httpd", "php-fpm", "java", "tomcat",
}

// Analyze scores a process execution. It is pure and deterministic (like the content
// detectors), so it runs anywhere and is fully testable.
func Analyze(execPath, parentPath string, args []string) Finding {
	f := Finding{}
	base := strings.ToLower(baseName(execPath))

	if lolbins[base] {
		f.LOLBin = base
		f.Reasons = append(f.Reasons, "LOLBin: "+base)
		f.Score += 0.35
	}

	parentBase := strings.ToLower(baseName(parentPath))
	for _, p := range suspiciousParents {
		if strings.Contains(parentBase, p) {
			f.SuspiciousLineage = true
			f.Reasons = append(f.Reasons, "suspicious lineage: "+parentBase+" spawned "+base)
			f.Score += 0.4
			break
		}
	}

	if encodedOrDownloadCradle(args) {
		f.EncodedCommand = true
		f.Reasons = append(f.Reasons, "encoded or download-and-execute command line")
		f.Score += 0.35
	}

	if f.Score > 1 {
		f.Score = 1
	}
	return f
}

// encodedOrDownloadCradle spots the two classic abuse shapes in an argument vector: an
// encoded PowerShell command (-enc / -EncodedCommand) and a download-and-execute cradle
// (IEX/DownloadString, or curl|wget piped to a shell).
func encodedOrDownloadCradle(args []string) bool {
	joined := strings.ToLower(strings.Join(args, " "))
	// Encoded PowerShell: -enc, -e, -encodedcommand (each a flag token, to avoid matching
	// an innocent substring).
	for _, a := range args {
		la := strings.ToLower(a)
		if la == "-enc" || la == "-e" || la == "-encodedcommand" || la == "/enc" {
			return true
		}
	}
	// Download-and-execute cradles.
	cradles := []string{
		"downloadstring", "downloadfile", "iex", "invoke-expression",
		"invoke-webrequest", "webclient", "frombase64string",
	}
	for _, c := range cradles {
		if strings.Contains(joined, c) {
			return true
		}
	}
	// curl/wget piped straight into a shell.
	if (strings.Contains(joined, "curl") || strings.Contains(joined, "wget")) &&
		(strings.Contains(joined, "| sh") || strings.Contains(joined, "|sh") ||
			strings.Contains(joined, "| bash") || strings.Contains(joined, "|bash")) {
		return true
	}
	return false
}
