//go:build linux

package bypassguard

import (
	"fmt"
	"os/exec"
)

// Logf is how this package reports, and it is a plain function rather than a *slog.Logger for a reason
// that a build guard enforces: log/slog pulls encoding/json, and the privileged agent must not hold a
// structured-format decoder (D13, scripts/check-agent-deps.sh). The guard caught this import the first
// time it was written. A nil Logf is silent.
type Logf func(format string, args ...any)

func (l Logf) printf(format string, args ...any) {
	if l != nil {
		l(format, args...)
	}
}

// backends names the binary and the ICMP rejection each address family needs. They are separate binaries
// because they are separate firewalls: a rule installed with iptables does nothing to IPv6 traffic, so an
// endpoint on a dual-stack network would route around a v4-only guard without trying.
type backend struct {
	bin        string
	rejectWith string
}

var (
	v4Backend = backend{"iptables", "icmp-admin-prohibited"}
	v6Backend = backend{"ip6tables", "icmp6-adm-prohibited"}
)

// Install rejects traffic to the protected ranges except through the gateway, for BOTH address families.
//
// Remove-then-add, the TPROXY/dnsredirect idempotency discipline: stale openshield rules are torn down
// first, so a re-run after an unclean shutdown never fails on "exists".
//
// A family with protected ranges whose binary is MISSING is a fatal error, not a skip. Installing the v4
// rules and silently omitting the v6 ones would report success over a guard with a hole in it — and the
// hole would be reachable by any client that prefers AAAA, which on a dual-stack network is most of them.
func Install(cfg Config, log Logf) error {
	v4, v6, err := cfg.split()
	if err != nil {
		return err
	}
	installed := 0
	for _, fam := range []struct {
		b backend
		p plan
	}{{v4Backend, v4}, {v6Backend, v6}} {
		if fam.p.empty() {
			// Nothing to protect in this family. Still tear down any stale rules from a previous
			// configuration that DID protect something here — leaving them would enforce a policy
			// nobody currently holds.
			if path, lerr := exec.LookPath(fam.b.bin); lerr == nil {
				best(path, log, removeArgs())
			}
			continue
		}
		path, lerr := exec.LookPath(fam.b.bin)
		if lerr != nil {
			return fmt.Errorf("bypassguard: %d protected %s range(s) but %s is not present: %w",
				len(fam.p.protected), familyName(fam.b), fam.b.bin, errUnsupported)
		}
		if ierr := install(path, log, removeArgs(), scaffoldArgs(), installArgs(fam.p, fam.b.rejectWith)); ierr != nil {
			return ierr
		}
		installed++
	}
	log.printf("bypassguard: ENDPOINT BYPASS GUARD ACTIVE across %d address famil(ies) — traffic to the "+
		"%d protected range(s) is rejected except through %s. This is the endpoint half; the network "+
		"half (the protected network accepting only the gateway) is where enforcement binds, and root "+
		"on this machine can remove these rules (D16).",
		installed, len(cfg.Protected), cfg.Gateway)
	return nil
}

func familyName(b backend) string {
	if b.bin == "ip6tables" {
		return "IPv6"
	}
	return "IPv4"
}

// Remove tears the guard down in both families. Idempotent: a missing chain is not an error.
func Remove(log Logf) error {
	for _, b := range []backend{v4Backend, v6Backend} {
		if path, err := exec.LookPath(b.bin); err == nil {
			best(path, log, removeArgs())
		}
	}
	return nil
}

// Attempts reports how many packets to protected destinations this guard has rejected, summed across
// both families.
//
// It returns an error rather than a zero when the count cannot be read. "No bypass attempts" and "we
// could not tell" are opposite answers to the only question this number is asked, and the reassuring one
// must never be produced by a failure.
func Attempts() (int64, error) {
	var total int64
	var read int
	var firstErr error
	for _, b := range []backend{v4Backend, v6Backend} {
		path, err := exec.LookPath(b.bin)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, listArgs()...).CombinedOutput()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("bypassguard: %s %v: %v (%s)", b.bin, listArgs(), err, string(out))
			}
			continue
		}
		n, perr := ParseAttempts(string(out))
		if perr != nil {
			if firstErr == nil {
				firstErr = perr
			}
			continue
		}
		total += n
		read++
	}
	if read == 0 {
		if firstErr != nil {
			return 0, firstErr
		}
		return 0, errUnsupported
	}
	return total, nil
}

// install is remove-then-add: idempotent teardown, best-effort scaffold, then FATAL rule adds — a
// half-installed guard must not report success, because a half-installed guard is an unguarded range
// that looks guarded.
func install(bin string, log Logf, teardown, scaffold, rules [][]string) error {
	best(bin, log, teardown)
	best(bin, log, scaffold)
	for _, args := range rules {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("bypassguard: %s %v: %v (%s)", bin, args, err, string(out))
		}
	}
	return nil
}

// best runs commands whose failure is expected and harmless (teardown of something absent, creating a
// chain that exists).
func best(bin string, log Logf, argv [][]string) {
	for _, args := range argv {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			log.printf("bypassguard: best-effort step %s %v failed (expected on a clean state): %v (%s)",
				bin, args, err, string(out))
		}
	}
}
