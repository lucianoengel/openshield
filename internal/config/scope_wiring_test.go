package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE SCOPE SPLIT IS ONLY REAL IF main() HONOURS IT.
//
// D263 says a DYNAMIC setting comes from the database and nowhere else: the console is authoritative, and
// a host quietly disagreeing with it is the failure the split exists to refuse. The resolver implements
// that faithfully — it ignores an environment value for a dynamic field and reports the fact.
//
// None of which helps if main() never asks the resolver. And that is exactly what had happened: TWENTY-SIX
// of the control plane's dynamic settings were read straight from the environment, so the process printed
// "IGNORING environment values for dynamic settings [OPENSHIELD_PLAYBOOKS]" and then loaded playbooks from
// that very variable, four lines later, in the same log. A setting saved in the console did nothing; one
// set on the host worked. Both halves of the promise were false, and every package test passed, because
// the defect lived in the wiring rather than in any package.
//
// So this is a WIRING test, and it is deliberately a static one: it reads the command sources and asserts
// no dynamic key is fetched from the environment. Catching this at runtime would need one integration
// scenario per setting; catching it here costs nothing and cannot be outrun by a new setting.
//
// WHAT IT MATCHES IS A CALL, NOT A WORD. An earlier generation of guards in this repository matched text
// and then flagged their own documentation, a help string and a legitimate shell command. This one matches
// the argument of a specific set of environment-reading calls, with comments stripped first — so a line
// like this one, which names os.Getenv("OPENSHIELD_PLAYBOOKS") in prose, does not trip it.
//
// AND SCOPE IS PER-BINARY, which the first version of this test got wrong. OPENSHIELD_RETENTION_INTERVAL
// is dynamic for the control plane and BOOTSTRAP for the gateway and engine — correctly, because neither
// has a database to read it from. Unioning the keys made the guard flag two honest call sites. Each
// command is therefore checked against ITS OWN declared field set.

// envReadCall matches the environment-reading helpers used across cmd/, capturing the key.
var envReadCall = regexp.MustCompile(`\b(?:os\.Getenv|os\.LookupEnv|env|envDuration|envInt|envBool)\(\s*"([A-Z_0-9]+)"`)

// cmdFields maps each command to the field set that declares ITS scopes.
//
// Every directory under cmd/ must appear here — including the ones with no declared configuration, which
// map to an empty set explicitly. A missing entry FAILS rather than being skipped: a new binary silently
// exempt from the rule is how the rule stops meaning anything.
var cmdFields = map[string][]Field{
	"openshield-server":       ServerFields,
	"openshield-gateway":      GatewayFields,
	"openshield-engine":       EngineFields,
	"openshield-agent":        AgentFields,
	"openshield-worker":       WorkerFields,
	"openshield-fleet-agent":  FleetAgentFields,
	"openshield-anchor":       AnchorFields,
	"openshield-print-filter": PrintFilterFields,
	"openshieldctl":           CtlFields,
	// Operator-local tools with no declared configuration surface of their own.
	"openshield-dlp-index":    nil,
	"openshield-fim-baseline": nil,
	"openshield-provision":    nil,
}

// stripComments removes // comments so prose that mentions a call form is not mistaken for one. Crude
// about strings containing "//" — a URL literal loses its tail — which is harmless here, because what
// survives is still the call form and its key.
func stripComments(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

func TestNoDynamicSettingIsReadFromTheEnvironmentInACommand(t *testing.T) {
	root := filepath.Join("..", "..", "cmd")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading cmd/: %v", err)
	}

	var offences []string
	checked := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fields, ok := cmdFields[e.Name()]
		if !ok {
			t.Errorf("cmd/%s is not listed in cmdFields, so it is exempt from the scope-wiring rule by "+
				"accident. Add it, mapped to the field set that declares its configuration (or nil if it "+
				"declares none).", e.Name())
			continue
		}
		dynamic := map[string]bool{}
		for _, f := range fields {
			if f.Scope == ScopeDynamic {
				dynamic[f.Key] = true
			}
		}
		if len(dynamic) == 0 {
			continue // nothing dynamic to get wrong
		}
		checked++
		dir := filepath.Join(root, e.Name())
		files, ferr := filepath.Glob(filepath.Join(dir, "*.go"))
		if ferr != nil {
			t.Fatalf("listing %s: %v", dir, ferr)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatalf("reading %s: %v", path, rerr)
			}
			for n, line := range strings.Split(string(src), "\n") {
				for _, m := range envReadCall.FindAllStringSubmatch(stripComments(line), -1) {
					if dynamic[m[1]] {
						offences = append(offences,
							filepath.ToSlash(path)+":"+itoa(n+1)+": "+m[1])
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no command declares a dynamic setting, so this guard would pass vacuously")
	}
	if len(offences) > 0 {
		t.Errorf("%d dynamic setting(s) are read from the ENVIRONMENT by a command. A dynamic setting is "+
			"stored in the database and changed in the console; reading one from the environment means an "+
			"operator's saved change does nothing, while a value on the host silently wins — and the "+
			"process's own \"IGNORING environment values\" notice becomes a lie. Read it through the "+
			"resolver instead (cfg.String/Duration/Int), or declare the field ScopeBootstrap for THIS "+
			"binary if it genuinely must reach the process before a database does:\n  %s",
			len(offences), strings.Join(offences, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestTheScopeGuardMatchesCallsNotProse pins the property three earlier guards in this repository got
// wrong: they matched TEXT, and then flagged their own documentation, a help string and a legitimate
// shell command. A guard that cries wolf gets deleted, which is worse than never having written it.
func TestTheScopeGuardMatchesCallsNotProse(t *testing.T) {
	cases := []struct {
		line string
		want string // the key it should extract, or "" for no match
	}{
		{`if p := os.Getenv("OPENSHIELD_PLAYBOOKS"); p != "" {`, "OPENSHIELD_PLAYBOOKS"},
		{`	pi := envDuration("OPENSHIELD_PLAYBOOK_INTERVAL", time.Minute)`, "OPENSHIELD_PLAYBOOK_INTERVAL"},
		{`	n := envInt("OPENSHIELD_ALERT_RETRIES", 3)`, "OPENSHIELD_ALERT_RETRIES"},
		{`	v, ok := os.LookupEnv("OPENSHIELD_WEF_DIR")`, "OPENSHIELD_WEF_DIR"},
		// Prose that NAMES a call form. This is the false positive that matters, because these comments
		// are exactly how the code explains itself.
		{`// reads os.Getenv("OPENSHIELD_PLAYBOOKS") — which it must not do`, ""},
		{`	x := 1 // see envDuration("OPENSHIELD_TI_FEED_INTERVAL", time.Hour)`, ""},
		// Reading it through the resolver is the CORRECT form and must never be flagged.
		{`	pi := cfg.Duration("OPENSHIELD_PLAYBOOK_INTERVAL")`, ""},
		{`	p := cfg.String("OPENSHIELD_PLAYBOOKS")`, ""},
	}
	for _, c := range cases {
		m := envReadCall.FindStringSubmatch(stripComments(c.line))
		got := ""
		if m != nil {
			got = m[1]
		}
		if got != c.want {
			t.Errorf("%q\n  extracted %q, want %q", c.line, got, c.want)
		}
	}
}

// TestAnUnreachableThresholdIsRefused covers the range check added in D303.
//
// The peer-UEBA risk score is a z-score SQUASHED to [0,1) — `1 - exp(-z)` never reaches 1. So a
// threshold of 1 or more silently disables the detector: it runs, scores every subject, and can never
// alert, while the process logs "peer-UEBA enabled" with the operator's number in it. That is the exact
// failure PLAT-5 exists to refuse, and it cost a debugging round here — the integration scenario was
// written against a threshold of 1.2 and simply never fired.
func TestAnUnreachableThresholdIsRefused(t *testing.T) {
	var f Field
	for _, c := range ServerFields {
		if c.Key == "OPENSHIELD_PEER_UEBA_THRESHOLD" {
			f = c
		}
	}
	if f.Key == "" {
		t.Fatal("OPENSHIELD_PEER_UEBA_THRESHOLD is not declared")
	}
	for _, ok := range []string{"0", "0.5", "0.9", "0.999"} {
		if err := f.Check(ok); err != nil {
			t.Errorf("a reachable threshold %q was refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"1", "1.2", "2", "-0.1", "high"} {
		if err := f.Check(bad); err == nil {
			t.Errorf("%q was accepted — a threshold at or above the score ceiling runs the detector and "+
				"can never alert, which reads exactly like a quiet fleet", bad)
		}
	}
}
