// Command openshield-ztna-client is the ENDPOINT half of Zero-Trust access (ZT-4).
//
// Applications point at it with the ordinary HTTP_PROXY convention; it presents THIS DEVICE's
// certificate to the access proxy, so a connection is authorized by device identity rather than by
// whatever the application happened to configure. No application changes, no root, no kernel interface.
//
// THE BINARY IS THIN ON PURPOSE. Everything that decides anything lives in internal/ztna — refusing
// without an identity, refusing a non-loopback bind, not following redirects off the authorized path,
// surfacing a broker refusal rather than falling back. Those behaviours are tested against a real
// access proxy from the gateway package, and a binary that re-implemented any of them would put the
// decision where those tests do not reach.
//
// The library was complete and tested and NOTHING BUILT IT: no binary, no settings, so an operator had
// no way to run it. Same shape as the SMTP connector (D342), found the same way.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/lucianoengel/openshield/internal/ztna"
)

func main() { os.Exit(run()) }

func run() int {
	broker := strings.TrimSpace(os.Getenv("OPENSHIELD_ZTNA_BROKER"))
	certPath := strings.TrimSpace(os.Getenv("OPENSHIELD_ZTNA_CERT"))
	keyPath := strings.TrimSpace(os.Getenv("OPENSHIELD_ZTNA_KEY"))
	caPath := strings.TrimSpace(os.Getenv("OPENSHIELD_ZTNA_CA"))
	listen := strings.TrimSpace(os.Getenv("OPENSHIELD_ZTNA_LISTEN"))
	if listen == "" {
		listen = "127.0.0.1:3128"
	}

	// EVERY CONFIGURATION PROBLEM IS FATAL. A ZTNA client that started without a device certificate
	// would forward traffic unauthenticated while looking like protection — worse than not running,
	// because the application keeps working and nobody learns the identity was never presented.
	for _, m := range []struct{ name, val string }{
		{"OPENSHIELD_ZTNA_BROKER", broker},
		{"OPENSHIELD_ZTNA_CERT", certPath},
		{"OPENSHIELD_ZTNA_KEY", keyPath},
		{"OPENSHIELD_ZTNA_CA", caPath},
	} {
		if m.val == "" {
			return fatal("%s is required", m.name)
		}
	}

	brokerURL, err := url.Parse(broker)
	if err != nil || brokerURL.Host == "" {
		return fatal("OPENSHIELD_ZTNA_BROKER %q is not a usable URL: %v", broker, err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fatal("loading the device identity: %v", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return fatal("reading the broker CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		// NOT a warning. An empty pool would make the client trust nothing and fail every request with
		// a verification error, which reads as a broker problem rather than a configuration one.
		return fatal("OPENSHIELD_ZTNA_CA %q contains no certificates", caPath)
	}

	client, err := ztna.New(brokerURL, cert, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, "")
	if err != nil {
		return fatal("%v", err)
	}

	// THE LIMITS, EVERY TIME IT STARTS. A README is read once; an application that later reaches the
	// network directly is not announced by anything, so the process has to say what it does not do.
	fmt.Fprintf(os.Stderr,
		"openshield-ztna-client: brokering to %s on %s, presenting this device's certificate.\n"+
			"  IT DOES NOT PREVENT BYPASS: an application with a direct route to the internal network "+
			"can still take it. Enforcing the path needs routing/firewall rules (the NIPS-1 inline "+
			"plane) and is a separate ticket — this is an access broker, not a network jail.\n"+
			"  HTTP(S) via the proxy convention only: no CONNECT to arbitrary ports, no SOCKS, no "+
			"split DNS.\n"+
			"  It is not an enrolment tool: the device certificate comes from `openshield-provision "+
			"cert`.\n",
		brokerURL, listen)

	if err := client.ListenAndServe(listen); err != nil {
		return fatal("%v", err)
	}
	return 0
}

func fatal(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "openshield-ztna-client: "+format+"\n", a...)
	return 1
}
