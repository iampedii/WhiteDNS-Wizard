package xui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/whitedns/wdns-wizard/internal/output"
)

func TestPublicACMEUsesWildcardRequestAndCoversManagedTLSHosts(t *testing.T) {
	requestDomains := publicACMERequestDomains("example.com")
	if len(requestDomains) != 1 || requestDomains[0] != "*.example.com" {
		t.Fatalf("request domains = %+v, want wildcard only", requestDomains)
	}

	covered := publicACMECoveredHostnames("example.com")
	for _, want := range []string{
		"direct.example.com",
		"hy2.example.com",
		"tor-vless-ws.example.com",
		"tor-vless-ws-8443.example.com",
		"tor-hy2.example.com",
		"tor-direct.example.com",
	} {
		if !containsString(covered, want) {
			t.Fatalf("covered hostnames = %+v, missing %s", covered, want)
		}
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "public.pem")
	keyPath := filepath.Join(dir, "public.key")
	writeSelfSignedWildcardCert(t, certPath, keyPath, "*.example.com")
	project := projectData{Paths: output.ProjectPaths{PublicCert: certPath, PublicKey: keyPath}}
	if !project.publicCertFresh(covered) {
		t.Fatal("wildcard certificate should be fresh for managed public TLS hostnames")
	}
}

func writeSelfSignedWildcardCert(t *testing.T, certPath, keyPath, hostname string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{hostname},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestEnsureCertificatesOriginHTTPSkipsAllCertHandling(t *testing.T) {
	dir := t.TempDir()
	project := projectData{
		Root:   dir,
		Domain: "example.com",
		Paths:  output.Paths(dir, "example.com"),
	}
	progress := newProgressRecorder(nil)
	// origin-http requires NO origin cert and must never call credentials/acme.
	if err := (Provisioner{}).ensureCertificates(nil, project, Input{CertMode: CertModeOriginHTTP}, progress); err != nil {
		t.Fatalf("origin-http ensureCertificates should be a no-op, got: %v", err)
	}
	if _, err := os.Stat(project.Paths.OriginCert); err == nil {
		t.Fatal("origin-http must not create an origin certificate")
	}
}

func TestEnsureCertificatesSelfSignedWritesOriginCert(t *testing.T) {
	dir := t.TempDir()
	project := projectData{
		Root:   dir,
		Domain: "example.com",
		Paths:  output.Paths(dir, "example.com"),
	}
	progress := newProgressRecorder(nil)
	if err := (Provisioner{}).ensureCertificates(nil, project, Input{CertMode: CertModeSelfSigned}, progress); err != nil {
		t.Fatalf("self-signed ensureCertificates returned error: %v", err)
	}
	certPEM, err := os.ReadFile(project.Paths.OriginCert)
	if err != nil {
		t.Fatalf("read self-signed origin cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("self-signed origin cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse self-signed origin cert: %v", err)
	}
	if err := cert.VerifyHostname("abshardejh.ir"); err != nil {
		t.Fatalf("self-signed cert should cover the seeded .ir front: %v", err)
	}
	if _, err := os.Stat(project.Paths.OriginKey); err != nil {
		t.Fatalf("self-signed origin key missing: %v", err)
	}
}
