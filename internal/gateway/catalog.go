package gateway

import (
	"fmt"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
)

// Catalog is the registry of internal services the access proxy fronts (D88). It is
// an explicit ALLOW-LIST: a request for a host not in the catalog is refused, never
// forwarded — the access gateway is never an open relay to arbitrary internal hosts
// (an SSRF/pivot surface). Per-service authorization is the policy's job (D87); the
// catalog only routes.
type Catalog struct {
	mu       sync.RWMutex
	services map[string]*service
}

type service struct {
	name     string
	upstream *url.URL
	proxy    *httputil.ReverseProxy
}

func NewCatalog() *Catalog { return &Catalog{services: map[string]*service{}} }

// Add registers an internal service under a host name, with its reverse proxy.
func (c *Catalog) Add(name string, upstream *url.URL) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.services[name] = &service{name: name, upstream: upstream, proxy: httputil.NewSingleHostReverseProxy(upstream)}
}

// Resolve routes a request host to a service. A host not in the catalog is not found —
// the caller refuses it (D88), never forwarding to an uncatalogued host.
func (c *Catalog) Resolve(host string) (*service, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.services[host]
	return s, ok
}

// Len reports how many services are catalogued (for config validation, D90).
func (c *Catalog) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.services)
}

// ParseCatalog builds a Catalog from a config spec "name=url,name2=url2" (D90). A
// malformed entry (no '=') or an unparseable/host-less URL is an ERROR, never silently
// skipped — a misconfigured route must fail loudly, not leave a service unreachable.
func ParseCatalog(spec string) (*Catalog, error) {
	c := NewCatalog()
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, rawURL, ok := strings.Cut(part, "=")
		name, rawURL = strings.TrimSpace(name), strings.TrimSpace(rawURL)
		if !ok || name == "" || rawURL == "" {
			return nil, fmt.Errorf("catalog: bad entry %q — want name=url", part)
		}
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("catalog: bad url in %q: %v", part, err)
		}
		c.Add(name, u)
	}
	return c, nil
}
