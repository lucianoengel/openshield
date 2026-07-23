// Package casb is the content-aware CASB engine (DLP-2): it classifies a network
// flow against an operator catalog of cloud services, deriving which service the
// flow addresses, whether that service is operator-SANCTIONED, and whether the flow
// is an UPLOAD — so a policy can BLOCK sensitive content bound for an UNSANCTIONED
// cloud sink while allowing the same to a sanctioned one. "A DLP that watches
// directories but not the channels users exfiltrate through is not a DLP."
//
// Like the exfil channel and the network IOC engine, classification is a PURE,
// content-free derivation of the flow METADATA (destination host + method) — it
// never opens the body. The content half (is the upload sensitive?) already comes
// from the worker's DLP classification; the POLICY ANDs the two.
package casb

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
)

// minHostSuffix is the shortest a service host suffix may be: a suffix shorter than
// this (a bare TLD like "com") would match nearly every flow — a catalog typo that
// silently tags all traffic as one service. Rejected at parse time (the NIPS URI
// min-length discipline).
const minHostSuffix = 4

// Match is the CASB classification of a flow. It is content-free: the service
// identity and flags only, never any body content.
type Match struct {
	Service    string
	Category   string
	Sanctioned bool
	Upload     bool
}

// Service is one catalogued cloud service and the destination host suffixes that
// identify it.
type Service struct {
	Name         string
	Category     string
	Sanctioned   bool
	hostSuffixes []string // lowercased, matched as a domain suffix
}

// Catalog is a parsed, immutable set of cloud services.
type Catalog struct {
	services []Service
}

// Empty reports whether the catalog has no services (the inert engine).
func (c *Catalog) Empty() bool { return c == nil || len(c.services) == 0 }

// Size reports the number of services, for logging.
func (c *Catalog) Size() int {
	if c == nil {
		return 0
	}
	return len(c.services)
}

// Classify returns the CASB match for a flow, or nil if the host is in no catalogued
// service (or the catalog is empty). path is accepted for a forward-compatible
// signature but unused in increment 1 (path-level upload heuristics are deferred).
// Upload is true when the method is mutating (an upload), so a download (GET) to a
// cloud service is recognized but not treated as an upload.
func (c *Catalog) Classify(host, path, method string) *Match {
	_ = path // reserved for a later increment (multipart / /upload heuristics)
	if c.Empty() || host == "" {
		return nil
	}
	host = normalizeHost(host)
	for i := range c.services {
		if c.services[i].matches(host) {
			return &Match{
				Service:    c.services[i].Name,
				Category:   c.services[i].Category,
				Sanctioned: c.services[i].Sanctioned,
				Upload:     isMutating(method),
			}
		}
	}
	return nil
}

// matches reports whether host is, or is a subdomain of, one of the service's host
// suffixes (a component-aware suffix match, like the IOC domain match).
func (s *Service) matches(host string) bool {
	for _, suffix := range s.hostSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// normalizeHost lowercases, drops a trailing dot, and strips a port.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

// isMutating reports whether an HTTP method writes — i.e. the flow is an upload. A
// GET/HEAD/OPTIONS is a read (download/metadata), not an upload.
func isMutating(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// LoadCatalog parses an operator cloud-service catalog file.
func LoadCatalog(path string) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("casb: opening catalog: %w", err)
	}
	defer f.Close()
	return ParseCatalog(f)
}

// ParseCatalog parses the block catalog format from a reader. It is line oriented,
// `#` comments and blank lines skipped, and each service is a block:
//
//	service <name> category <cat> [sanctioned]
//	  host <suffix>       # repeatable; at least one required
//
// A `service` line starts a new service; `host` lines add its destination suffixes.
// A malformed line is an error (never a silent skip, which would leave a service
// unrecognized while the operator believes it is covered).
func ParseCatalog(r io.Reader) (*Catalog, error) {
	cat := &Catalog{}
	sc := bufio.NewScanner(r)
	line := 0
	closeService := func(cur *Service, atLine int) error {
		if cur == nil {
			return nil
		}
		if len(cur.hostSuffixes) == 0 {
			return fmt.Errorf("casb: line %d: service %q has no host", atLine, cur.Name)
		}
		cat.services = append(cat.services, *cur)
		return nil
	}
	var cur *Service
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		keyword, rest, _ := strings.Cut(text, " ")
		rest = strings.TrimSpace(rest)
		switch keyword {
		case "service":
			if err := closeService(cur, line); err != nil {
				return nil, err
			}
			svc, err := parseServiceLine(rest, line)
			if err != nil {
				return nil, err
			}
			cur = svc
		case "host":
			if cur == nil {
				return nil, fmt.Errorf("casb: line %d: 'host' outside a service", line)
			}
			suffix := normalizeHost(rest)
			if len(suffix) < minHostSuffix {
				return nil, fmt.Errorf("casb: line %d: host suffix %q too short (min %d) — it would match nearly every flow", line, rest, minHostSuffix)
			}
			cur.hostSuffixes = append(cur.hostSuffixes, suffix)
		default:
			return nil, fmt.Errorf("casb: line %d: unknown directive %q (want service|host)", line, keyword)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("casb: reading catalog: %w", err)
	}
	if err := closeService(cur, line); err != nil {
		return nil, err
	}
	if len(cat.services) == 0 {
		return cat, nil // an empty catalog is inert, not an error (feature simply off)
	}
	return cat, nil
}

// parseServiceLine parses "<name> category <cat> [sanctioned]".
func parseServiceLine(rest string, line int) (*Service, error) {
	fields := strings.Fields(rest)
	if len(fields) < 3 || fields[1] != "category" {
		return nil, fmt.Errorf("casb: line %d: want 'service <name> category <cat> [sanctioned]', got %q", line, "service "+rest)
	}
	svc := &Service{Name: fields[0], Category: fields[2]}
	for _, extra := range fields[3:] {
		switch extra {
		case "sanctioned":
			svc.Sanctioned = true
		default:
			return nil, fmt.Errorf("casb: line %d: unknown service flag %q (want 'sanctioned')", line, extra)
		}
	}
	return svc, nil
}

// active is the process-wide catalog the policy input consults. It is a runtime-
// configured analogue of exfil.Default: startup sets it from OPENSHIELD_CASB_CATALOG
// and a hot-reload watcher swaps it. A nil active catalog means the feature is off.
var active atomic.Pointer[Catalog]

// SetCatalog installs (or hot-swaps) the active catalog atomically.
func SetCatalog(c *Catalog) { active.Store(c) }

// Classify classifies a flow against the active catalog. Nil when no catalog is
// configured or the host is in no service — so the pipeline is unaffected until an
// operator configures a catalog.
func Classify(host, path, method string) *Match {
	return active.Load().Classify(host, path, method)
}
