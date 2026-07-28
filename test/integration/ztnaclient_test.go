//go:build integration

package integration

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE ZTNA CLIENT AS A SHIPPED BINARY (ZT-4, `openshield-ztna-client`).
//
// `internal/ztna` was complete and tested — four tests drive it against a real access proxy from the
// gateway package — and NO BINARY BUILT IT. No settings existed either, so an operator had no way to
// run it, however the deployment was configured. The README had to carry a line saying the endpoint
// client was "built and not yet shipped as a binary"; this is what removes it.
//
// The library's behaviour is tested where it lives. What is tested HERE is the part that did not
// exist: that the shipped binary, configured the way an operator configures it, brokers a real request
// to a real access proxy using the device identity it was given.

// TestTheZtnaClientBinaryBrokersToARealAccessProxy.
func TestTheZtnaClientBinaryBrokersToARealAccessProxy(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	origin := startUpstream(t)
	p := newPKI(t)
	m := p.serverMaterial(t)
	proxyAddr := "127.0.0.1:" + freePort(t)

	policyPath := filepath.Join(work, "access.rego")
	if err := os.WriteFile(policyPath, []byte(ztnaAccessPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_ACCESS_MODE=1",
		"OPENSHIELD_ACCESS_LISTEN=" + proxyAddr,
		"OPENSHIELD_ACCESS_CLIENT_CA=" + p.caPEM,
		"OPENSHIELD_ACCESS_SERVER_CERT=" + m.Cert,
		"OPENSHIELD_ACCESS_SERVER_KEY=" + m.Key,
		"OPENSHIELD_ACCESS_POLICY=" + policyPath,
		"OPENSHIELD_ACCESS_CATALOG=payroll=http://" + origin.addr,
	})
	waitTCP(t, proxyAddr, 90*time.Second)

	// THE DEVICE IDENTITY comes from the shipped provisioning tool, so what the client presents is what
	// an operator would actually have — not material minted in Go for the test's convenience.
	devDir := filepath.Join(work, "device")
	if err := os.MkdirAll(devDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := runCapture(t, "openshield-provision", nil, "cert",
		"--ca", filepath.Join(p.dir, "ca"), "--role", "client", "--cn", "ztna-device",
		"--group", "finance", "--out", devDir); err != nil {
		t.Fatalf("issuing the device certificate: %v\n%s", err, out)
	}

	clientAddr := "127.0.0.1:" + freePort(t)
	cl := Start(t, "openshield-ztna-client", []string{
		"OPENSHIELD_ZTNA_BROKER=https://" + proxyAddr,
		"OPENSHIELD_ZTNA_CERT=" + filepath.Join(devDir, "cert.pem"),
		"OPENSHIELD_ZTNA_KEY=" + filepath.Join(devDir, "key.pem"),
		"OPENSHIELD_ZTNA_CA=" + p.caPEM,
		"OPENSHIELD_ZTNA_LISTEN=" + clientAddr,
	})
	cl.WaitForOutput("brokering to", 60*time.Second)
	waitTCP(t, clientAddr, 60*time.Second)

	// THE LIMIT IS ANNOUNCED. The name invites the reading that traffic is confined; an application
	// that later takes a direct route is announced by nothing, so the process has to say so itself.
	if !contains(cl.Output(), "DOES NOT PREVENT BYPASS") {
		t.Errorf("the client does not state that it fails to prevent bypass. An operator who believes "+
			"traffic is confined learns otherwise only when it is not:\n%s", cl.Output())
	}

	// AN ORDINARY APPLICATION REQUEST, through the proxy convention and nothing else — no client
	// certificate configured here, because the whole point is that the CLIENT presents the device's.
	proxyURL, err := url.Parse("http://" + clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	app := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	before := origin.hits.Load()
	resp, err := app.Get("http://payroll/report")
	if err != nil {
		t.Fatalf("a brokered request failed: %v\nclient:\n%s\ngateway:\n%s",
			err, cl.Output(), gw.Output())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a brokered request returned %d %q — the device identity did not authorize it\n%s\n%s",
			resp.StatusCode, strings.TrimSpace(string(body)), cl.Output(), gw.Output())
	}
	// ASSERTED ON THE UPSTREAM. A 200 to the application proves the client answered; only the internal
	// service being reached proves the request went THROUGH the broker to it.
	if n := origin.hits.Load(); n == before {
		t.Errorf("the internal service was never reached (%d -> %d) — the client answered without "+
			"brokering anything", before, n)
	}
}

// ztnaAccessPolicy authorises on the GROUP the device certificate carries, so the decision can only
// change if the client actually presented that certificate to the broker. A policy that allowed
// everything would pass whether or not any identity was presented.
const ztnaAccessPolicy = `package openshield
import rego.v1
authorized if { input.context.role == "finance" }
decision := {"action":"ALLOW","reason":"authorized device","confidence":0.9} if { authorized }
decision := {"action":"BLOCK","reason":"device not authorized","confidence":0.9} if { not authorized }`

// TestTheZtnaClientRefusesToStartWithoutADeviceIdentity.
//
// The fatal path is the security property. A client that started without a device certificate would
// forward traffic unauthenticated while looking like protection — worse than not running at all,
// because the application keeps working and nobody learns the identity was never presented.
func TestTheZtnaClientRefusesToStartWithoutADeviceIdentity(t *testing.T) {
	p := newPKI(t)
	out := refuseToStart(t, "openshield-ztna-client", []string{
		"OPENSHIELD_ZTNA_BROKER=https://127.0.0.1:1",
		"OPENSHIELD_ZTNA_CA=" + p.caPEM,
		"OPENSHIELD_ZTNA_LISTEN=127.0.0.1:0",
	})
	if !contains(out, "OPENSHIELD_ZTNA_CERT") {
		t.Errorf("the refusal does not name the missing setting, so an operator cannot tell it from "+
			"any other startup failure:\n%s", out)
	}
}

// TestTheZtnaClientRefusesANonLoopbackBind.
//
// A broker bound to a routable interface is a relay anyone on the LAN could drive with THIS DEVICE's
// identity — a credential-sharing service wearing a security product's name.
func TestTheZtnaClientRefusesANonLoopbackBind(t *testing.T) {
	work := t.TempDir()
	p := newPKI(t)
	devDir := filepath.Join(work, "device")
	if err := os.MkdirAll(devDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if o, err := runCapture(t, "openshield-provision", nil, "cert",
		"--ca", filepath.Join(p.dir, "ca"), "--role", "client", "--cn", "ztna-bind",
		"--group", "finance", "--out", devDir); err != nil {
		t.Fatalf("issuing the device certificate: %v\n%s", err, o)
	}
	out := refuseToStart(t, "openshield-ztna-client", []string{
		"OPENSHIELD_ZTNA_BROKER=https://127.0.0.1:1",
		"OPENSHIELD_ZTNA_CERT=" + filepath.Join(devDir, "cert.pem"),
		"OPENSHIELD_ZTNA_KEY=" + filepath.Join(devDir, "key.pem"),
		"OPENSHIELD_ZTNA_CA=" + p.caPEM,
		"OPENSHIELD_ZTNA_LISTEN=0.0.0.0:0",
	})
	if !contains(out, "loopback") {
		t.Errorf("the refusal does not say the bind must be loopback:\n%s", out)
	}
}
