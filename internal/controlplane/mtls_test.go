package controlplane_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"github.com/lucianoengel/openshield/internal/transport/tlsconf"
)

// ouList wraps a single OU role (or none) for a cert Subject.
func ouList(ou string) []string {
	if ou == "" {
		return nil
	}
	return []string{ou}
}

// mkCerts issues a CA + a leaf cert/key (with role OU) under dir and returns their paths.
func mkCerts(t *testing.T, dir, cn, ou string) (caPath, certPath, keyPath string) {
	t.Helper()
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	caCert, _ := x509.ParseCertificate(caDER)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn, OrganizationalUnit: ouList(ou)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caPriv)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)

	caPath = filepath.Join(dir, cn+"-ca.pem")
	certPath = filepath.Join(dir, cn+"-cert.pem")
	keyPath = filepath.Join(dir, cn+"-key.pem")
	wr := func(p, typ string, b []byte) {
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wr(caPath, "CERTIFICATE", caDER)
	wr(certPath, "CERTIFICATE", der)
	wr(keyPath, "PRIVATE KEY", keyDER)
	return caPath, certPath, keyPath
}

// 3.2 — enrollment over MUTUAL TLS succeeds with a valid client cert and is
// REFUSED (handshake failure, no enrollment) without one — never downgraded.
func TestEnrollOverMutualTLS(t *testing.T) {
	pool := requireDB(t)
	dir := t.TempDir()
	caPath, certPath, keyPath := mkCerts(t, dir, "server", "agent") // client role for /enroll
	tc, err := tlsconf.Load(caPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := controlplane.New(pool)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeHTTPTLS(ctx, addr, tc.ServerConfig()) }()
	time.Sleep(150 * time.Millisecond)

	tok, err := srv.IssueToken(context.Background(), time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	agentID, _ := identity.Generate("tls-agent")
	body, _ := json.Marshal(map[string]string{
		"token": tok, "agent_id": "tls-agent",
		"public_key": base64.StdEncoding.EncodeToString(agentID.PublicKey()),
	})
	url := "https://" + addr + "/enroll"

	// With a valid client cert: enrollment succeeds.
	good := &http.Client{Transport: &http.Transport{TLSClientConfig: tc.ClientConfig()}}
	resp, err := good.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("mutual-TLS enrollment failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d, want 200", resp.StatusCode)
	}

	// Without a client cert (server-auth only): REFUSED at the handshake, no
	// plaintext fallback. Use the same CA so the server is trusted — only the
	// CLIENT cert is missing.
	pool2 := x509.NewCertPool()
	caPEM, _ := os.ReadFile(caPath)
	pool2.AppendCertsFromPEM(caPEM)
	noCert := &http.Client{Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool2, MinVersion: tls.VersionTLS13}}}
	if _, err := noCert.Post(url, "application/json", bytes.NewReader(body)); err == nil {
		t.Fatal("a client with no certificate enrolled — mutual TLS not enforced")
	}
}

// 3.4 — a peer that completes the mutual-TLS handshake but sends a badly-signed
// message is STILL rejected (D50): channel auth and message attribution are
// independent layers, both enforced. A validly-signed message over the SAME
// mTLS channel is accepted, proving the rejection was the signature, not the TLS.
func TestTLSDoesNotBypassSigning(t *testing.T) {
	pool := requireDB(t)
	dir := t.TempDir()
	caPath, certPath, keyPath := mkCerts(t, dir, "server", "")
	tc, err := tlsconf.Load(caPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Embedded NATS with mutual TLS.
	opts := &natsserver.Options{Host: "127.0.0.1", Port: -1, TLSConfig: tc.ServerConfig()}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("embedded TLS NATS not ready")
	}
	t.Cleanup(ns.Shutdown)

	srv := controlplane.New(pool)
	srv.SetNATSOptions(nats.Secure(tc.ClientConfig()))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx, ns.ClientURL()) }()
	time.Sleep(150 * time.Millisecond)

	// Enroll an agent and connect over the SAME mutual-TLS channel.
	tok, _ := srv.IssueToken(ctx, time.Hour, time.Now())
	id, _ := identity.Generate("tls-signed")
	if err := srv.Enroll(ctx, tok, "tls-signed", id.PublicKey(), time.Now()); err != nil {
		t.Fatal(err)
	}
	conn, err := nats.Connect(ns.ClientURL(), nats.Secure(tc.ClientConfig()))
	if err != nil {
		t.Fatalf("mutual-TLS NATS client failed: %v", err)
	}
	defer conn.Close()

	// A BADLY-SIGNED message over the authenticated channel: still rejected.
	payload, _ := proto.Marshal(&corev1.Event{EventId: "bad-tls", AgentId: "tls-signed"})
	bad := &corev1.SignedTelemetry{AgentId: "tls-signed", Sequence: 1, Kind: "event",
		Payload: payload, Signature: []byte("not a real signature")}
	bb, _ := proto.Marshal(bad)
	_ = conn.Publish(natsx.SubjectSigned, bb)

	waitFor(t, func() bool { return srv.RejectedTelemetry.Load() >= 1 })
	if srv.RejectedTelemetry.Load() < 1 {
		t.Fatal("a cert-authenticated but badly-signed message was not rejected — TLS bypassed signing")
	}

	// A VALIDLY-signed message over the same channel IS accepted — proving the
	// rejection above was the signature layer, not the TLS layer.
	pub := natsx.NewSignedPublisher("tls-signed", id, conn)
	if err := pub.PublishEvent(ctx, &corev1.Event{EventId: "good-tls", AgentId: "tls-signed", Subject: &corev1.Subject{PseudonymousId: "sub_tls"}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		rows, _ := srv.TelemetryForEvent(ctx, "good-tls")
		return len(rows) == 1
	})
}
