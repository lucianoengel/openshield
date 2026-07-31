// Package nips is the network threat-intelligence / signature engine (NIPS-2): it
// matches a flow's destination and request metadata against an operator-loaded IOC
// feed — known-bad domains, IPs/CIDRs, and URI substrings — so the policy can block
// a flow to a known-bad indicator. It is what makes the network plane an IPS rather
// than only a DLP inspector (ADR-8: "without signatures it is not an IPS").
//
// It matches METADATA only (host, IP, path), never the body — that keeps it
// worker-free and parse-failure-free. YARA-style body-content signatures are a
// separate, worker-side follow-up.
package nips

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// Category is the kind of a threat match, mirroring corev1.ThreatCategory but kept
// dependency-light in the engine; the gateway maps it to the proto enum.
type Category int

const (
	CategoryDomain Category = iota
	CategoryIP
	CategoryURI
	// CategoryJA3 is a TLS CLIENT fingerprint match (NIPS-9) — the only category here that describes
	// the client rather than the destination, and therefore the only one that still says something
	// when the domain is new, rotated, or encrypted away.
	CategoryJA3
)

// Match is one threat-intel hit. IndicatorID is an opaque feed identifier (the
// matched indicator), for analyst traceability — the gateway does not put it in the
// classification-crossing as raw content beyond this id.
type Match struct {
	Category    Category
	IndicatorID string
	Confidence  float64
}

// Feed is a parsed IOC feed: known-bad domains, IPs, CIDRs, and URI substrings.
type Feed struct {
	domains map[string]struct{} // exact domain -> also matches its subdomains
	ips     map[string]struct{} // exact IP
	cidrs   []*net.IPNet
	uris    []string
	ja3     map[string]struct{} // TLS client fingerprints (NIPS-9), lower-case hex
}

// Match returns every threat hit for a flow's host, destination IP, and request
// path. A nil or empty Feed matches nothing. IOC matches are definitive (1.0).
func (f *Feed) Match(host, dstIP, path string) []Match {
	if f == nil {
		return nil
	}
	var out []Match
	if d, ok := f.matchDomain(host); ok {
		out = append(out, Match{Category: CategoryDomain, IndicatorID: d, Confidence: 1.0})
	}
	if ip := f.matchIP(dstIP); ip != "" {
		out = append(out, Match{Category: CategoryIP, IndicatorID: ip, Confidence: 1.0})
	}
	if u := f.matchURI(path); u != "" {
		out = append(out, Match{Category: CategoryURI, IndicatorID: u, Confidence: 1.0})
	}
	return out
}

// MatchJA3 reports whether a TLS client fingerprint is on the feed (NIPS-9).
//
// Its confidence is 0.8, NOT the 1.0 the destination indicators carry, and the difference is a claim
// about the world rather than a tuning choice. A domain or an IP identifies a specific endpoint somebody
// chose to list. A JA3 identifies a TLS LIBRARY AT A VERSION, shared by every program built on it — so a
// match is real evidence and is not, by itself, proof this flow is the malware. Reporting it as certain
// would put a legitimate application built on the same stack one policy rule away from being blocked.
func (f *Feed) MatchJA3(fingerprint string) (Match, bool) {
	if f == nil || len(f.ja3) == 0 || fingerprint == "" {
		return Match{}, false
	}
	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	if _, ok := f.ja3[fp]; !ok {
		return Match{}, false
	}
	return Match{Category: CategoryJA3, IndicatorID: fp, Confidence: 0.8}, true
}

// isHex reports whether s is entirely lower-case hex digits.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return len(s) > 0
}

// matchDomain matches host exactly, or as a subdomain of a feed domain: a feed
// entry evil.com matches evil.com AND c2.evil.com (parent-suffix), but not
// notevil.com.
func (f *Feed) matchDomain(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", false
	}
	// Strip a port if present (host:port).
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for h := host; h != ""; {
		if _, ok := f.domains[h]; ok {
			return h, true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return "", false
}

func (f *Feed) matchIP(dstIP string) string {
	if dstIP == "" {
		return ""
	}
	if _, ok := f.ips[dstIP]; ok {
		return dstIP
	}
	ip := net.ParseIP(dstIP)
	if ip == nil {
		return ""
	}
	for _, n := range f.cidrs {
		if n.Contains(ip) {
			return n.String()
		}
	}
	return ""
}

// minURIIndicator is the shortest a URI IOC may be (R34-13): substring matching on a token shorter
// than this (e.g. "/") flags nearly all traffic, so such an indicator is rejected at parse time.
const minURIIndicator = 4

func (f *Feed) matchURI(path string) string {
	if path == "" {
		return ""
	}
	for _, u := range f.uris {
		if strings.Contains(path, u) {
			return u
		}
	}
	return ""
}

// LoadFeed parses an operator IOC feed file. Each non-empty, non-#-comment line is
// "<kind> <indicator>": domain, ip, cidr, or uri. A malformed line is an error
// (surfaced at load, never a silent skip).
func LoadFeed(path string) (*Feed, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("nips: opening IOC feed: %w", err)
	}
	defer file.Close()
	return ParseFeed(file)
}

// ParseFeed parses the feed format from a reader.
func ParseFeed(r io.Reader) (*Feed, error) {
	f := &Feed{domains: map[string]struct{}{}, ips: map[string]struct{}{}}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("nips: line %d: want '<kind> <indicator>', got %q", line, text)
		}
		kind, indicator := strings.ToLower(fields[0]), fields[1]
		if err := addIndicator(f, kind, indicator, fmt.Sprintf("line %d", line)); err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("nips: reading IOC feed: %w", err)
	}
	return f, nil
}

// addIndicator validates and installs ONE indicator. Every format (native, CSV) and every reconstruction
// path (BuildFeed, from the IOC store) goes through it, so the validation rules — a parseable IP, a
// parseable CIDR, and the R34-13 minimum URI length — have exactly one home. A second format with its own
// copy of these checks is how a degenerate indicator eventually gets in through the newer door.
func addIndicator(f *Feed, kind, indicator, where string) error {
	switch kind {
	case KindDomain:
		f.domains[strings.ToLower(strings.TrimSuffix(indicator, "."))] = struct{}{}
	case KindIP:
		if net.ParseIP(indicator) == nil {
			return fmt.Errorf("nips: %s: bad IP %q", where, indicator)
		}
		f.ips[indicator] = struct{}{}
	case KindCIDR:
		_, n, err := net.ParseCIDR(indicator)
		if err != nil {
			return fmt.Errorf("nips: %s: bad CIDR %q: %w", where, indicator, err)
		}
		f.cidrs = append(f.cidrs, n)
	case KindJA3:
		// A JA3 indicator is an MD5 in hex. Anything else is refused at LOAD rather than stored to
		// match nothing: a fingerprint with a stray space or a truncated digest would sit in the feed
		// looking like coverage and never fire once, which is the shape of a detection gap that reports
		// itself as a detection.
		fp := strings.ToLower(strings.TrimSpace(indicator))
		if len(fp) != ja3Len || !isHex(fp) {
			return fmt.Errorf("nips: %s: ja3 indicator %q is not a 32-character hex MD5 — it would be "+
				"stored, look like coverage, and never match", where, indicator)
		}
		if f.ja3 == nil {
			f.ja3 = map[string]struct{}{}
		}
		f.ja3[fp] = struct{}{}
	case KindURI:
		// R34-13: a URI IOC is matched by substring, so a degenerate short token like "/" would match
		// essentially every HTTP path — a feed typo that silently flags all traffic. Require a
		// discriminating minimum length; a real path/URI IOC is far longer.
		if len(indicator) < minURIIndicator {
			return fmt.Errorf("nips: %s: uri indicator %q too short (min %d chars) — it would match nearly every flow",
				where, indicator, minURIIndicator)
		}
		f.uris = append(f.uris, indicator)
	default:
		return fmt.Errorf("nips: %s: unknown kind %q (want domain|ip|cidr|uri|ja3)", where, kind)
	}
	return nil
}

// Indicator kinds, named once so the feed formats, the IOC store and the reconstruction path cannot
// spell them differently.
const (
	KindDomain = "domain"
	KindIP     = "ip"
	KindCIDR   = "cidr"
	KindURI    = "uri"
	KindJA3    = "ja3"
)

// ja3Len is the length of a JA3 fingerprint in hex (an MD5).
const ja3Len = 32

// Size reports the number of indicators loaded, for logging.
func (f *Feed) Size() int {
	if f == nil {
		return 0
	}
	return len(f.domains) + len(f.ips) + len(f.cidrs) + len(f.uris) + len(f.ja3)
}
