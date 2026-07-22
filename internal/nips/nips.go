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
		switch kind {
		case "domain":
			f.domains[strings.ToLower(strings.TrimSuffix(indicator, "."))] = struct{}{}
		case "ip":
			if net.ParseIP(indicator) == nil {
				return nil, fmt.Errorf("nips: line %d: bad IP %q", line, indicator)
			}
			f.ips[indicator] = struct{}{}
		case "cidr":
			_, n, err := net.ParseCIDR(indicator)
			if err != nil {
				return nil, fmt.Errorf("nips: line %d: bad CIDR %q: %w", line, indicator, err)
			}
			f.cidrs = append(f.cidrs, n)
		case "uri":
			f.uris = append(f.uris, indicator)
		default:
			return nil, fmt.Errorf("nips: line %d: unknown kind %q (want domain|ip|cidr|uri)", line, kind)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("nips: reading IOC feed: %w", err)
	}
	return f, nil
}

// Size reports the number of indicators loaded, for logging.
func (f *Feed) Size() int {
	if f == nil {
		return 0
	}
	return len(f.domains) + len(f.ips) + len(f.cidrs) + len(f.uris)
}
