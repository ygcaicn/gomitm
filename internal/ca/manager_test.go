package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestExpandHomeWithEnvHOME(t *testing.T) {
	t.Setenv("HOME", "/tmp/gomitm-home")

	got, err := expandHome("~/.gomitm/ca")
	if err != nil {
		t.Fatalf("expandHome failed: %v", err)
	}
	want := filepath.Join("/tmp/gomitm-home", ".gomitm", "ca")
	if got != want {
		t.Fatalf("expandHome got=%q want=%q", got, want)
	}
}

func TestExpandHomeFallbackToUserLookup(t *testing.T) {
	t.Setenv("HOME", "")

	oldCurrent := lookupCurrentUser
	oldLookupID := lookupUserByID
	oldUID := currentUID
	t.Cleanup(func() {
		lookupCurrentUser = oldCurrent
		lookupUserByID = oldLookupID
		currentUID = oldUID
	})

	lookupCurrentUser = func() (*user.User, error) {
		return nil, errors.New("current user not available")
	}
	currentUID = func() int { return 1001 }
	lookupUserByID = func(uid string) (*user.User, error) {
		if uid != "1001" {
			t.Fatalf("unexpected uid: %s", uid)
		}
		return &user.User{Uid: uid, HomeDir: "/var/lib/gomitm"}, nil
	}

	got, err := expandHome("~/data")
	if err != nil {
		t.Fatalf("expandHome failed: %v", err)
	}
	want := filepath.Join("/var/lib/gomitm", "data")
	if got != want {
		t.Fatalf("expandHome got=%q want=%q", got, want)
	}
}

func TestExpandHomeErrorWhenNoSource(t *testing.T) {
	t.Setenv("HOME", "")

	oldCurrent := lookupCurrentUser
	oldLookupID := lookupUserByID
	oldUID := currentUID
	t.Cleanup(func() {
		lookupCurrentUser = oldCurrent
		lookupUserByID = oldLookupID
		currentUID = oldUID
	})

	lookupCurrentUser = func() (*user.User, error) {
		return nil, errors.New("no current user")
	}
	currentUID = func() int { return 9999 }
	lookupUserByID = func(uid string) (*user.User, error) {
		return nil, errors.New("lookup failed")
	}

	_, err := expandHome("~/data")
	if err == nil {
		t.Fatal("expected expandHome error")
	}
	if !strings.Contains(err.Error(), "get home dir") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitRootCACommonNameIncludesIssueDate(t *testing.T) {
	m, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("init ca failed: %v", err)
	}

	cn := strings.TrimSpace(m.rootCert.Subject.CommonName)
	prefix := rootCACommonNamePrefix + " "
	if !strings.HasPrefix(cn, prefix) {
		t.Fatalf("common name should start with %q, got=%q", prefix, cn)
	}
	issuedDate := strings.TrimPrefix(cn, prefix)
	if _, err := time.Parse(rootCertNameTimeLayout, issuedDate); err != nil {
		t.Fatalf("common name date format invalid, got=%q err=%v", issuedDate, err)
	}
}

func TestRootCertDownloadFilenameIncludesIssueDate(t *testing.T) {
	m, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("init ca failed: %v", err)
	}

	name := m.RootCertDownloadFilename()
	if !regexp.MustCompile(`^gomitm-root-ca-\d{8}-\d{6}\.crt$`).MatchString(name) {
		t.Fatalf("unexpected download filename: %q", name)
	}

	cnDate := strings.TrimPrefix(m.rootCert.Subject.CommonName, rootCACommonNamePrefix+" ")
	if !strings.Contains(name, cnDate) {
		t.Fatalf("download filename should include issue date from common name, name=%q cn=%q", name, m.rootCert.Subject.CommonName)
	}
}

func TestGetLeafCertificateRegeneratesExpiredCachedCert(t *testing.T) {
	m, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("init ca failed: %v", err)
	}

	host := "youtubei.googleapis.com"
	expired, err := signLeafForTest(m, host, time.Now().Add(-4*time.Hour), time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("build expired cert failed: %v", err)
	}

	m.cache[host] = expired

	got, err := m.GetLeafCertificate(host)
	if err != nil {
		t.Fatalf("GetLeafCertificate failed: %v", err)
	}
	if !isLeafCertUsable(got, time.Now()) {
		t.Fatal("expected regenerated leaf cert to be usable")
	}

	gotLeaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatalf("parse regenerated leaf failed: %v", err)
	}
	expiredLeaf, err := x509.ParseCertificate(expired.Certificate[0])
	if err != nil {
		t.Fatalf("parse expired leaf failed: %v", err)
	}
	if gotLeaf.SerialNumber.Cmp(expiredLeaf.SerialNumber) == 0 {
		t.Fatal("expected expired cached cert to be replaced with a newly signed cert")
	}
}

func TestGetLeafCertificateReusesHealthyCachedCert(t *testing.T) {
	m, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("init ca failed: %v", err)
	}

	host := "example.com"
	first, err := m.GetLeafCertificate(host)
	if err != nil {
		t.Fatalf("GetLeafCertificate first call failed: %v", err)
	}
	second, err := m.GetLeafCertificate(host)
	if err != nil {
		t.Fatalf("GetLeafCertificate second call failed: %v", err)
	}

	firstLeaf, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatalf("parse first leaf failed: %v", err)
	}
	secondLeaf, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatalf("parse second leaf failed: %v", err)
	}
	if firstLeaf.SerialNumber.Cmp(secondLeaf.SerialNumber) != 0 {
		t.Fatal("expected healthy cached cert to be reused")
	}
}

func signLeafForTest(m *Manager, host string, notBefore, notAfter time.Time) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.rootCert, publicKey(priv), m.rootKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf, _ = x509.ParseCertificate(der)
	return cert, nil
}
