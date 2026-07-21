package gateway

import (
	"net/http/httputil"
	"net/url"
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
