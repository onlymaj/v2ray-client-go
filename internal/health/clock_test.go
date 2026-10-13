package health

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Round 25: after a power cut the router starts with its clock in the
// past. The probe's certificate was then "not yet valid", every client was
// marked down and the kill switch applied; where the router finds its time
// server through the container, for good. With an unset clock the probe
// checks the chain and the name at a time inside the certificate's
// validity.
func TestProbeTLSWithAnUnsetClock(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().Add(-7 * 24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe.example"},
		DNSNames: []string{"probe.example"}, NotBefore: issued, NotAfter: issued.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	unset := time.Date(1970, 1, 2, 0, 0, 0, 0, time.UTC)

	// What the default check does with that clock.
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "probe.example", Roots: roots, CurrentTime: unset}); err == nil {
		t.Fatal("the certificate verifies in 1970; the test proves nothing")
	}
	if cfg := probeTLS("probe.example", time.Now()); cfg.InsecureSkipVerify || cfg.VerifyConnection != nil {
		t.Fatal("with the clock set, the probe must use the normal check")
	}
	cfg := probeTLS("probe.example", unset)
	cfg.RootCAs = roots
	if err := cfg.VerifyConnection(cs); err != nil {
		t.Fatalf("unset clock, good certificate: %v", err)
	}
	// The name and the chain are still checked.
	other := probeTLS("other.example", unset)
	other.RootCAs = roots
	if err := other.VerifyConnection(cs); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
	noRoot := probeTLS("probe.example", unset)
	noRoot.RootCAs = x509.NewCertPool()
	if err := noRoot.VerifyConnection(cs); err == nil {
		t.Fatal("a certificate from an unknown issuer was accepted")
	}
}
