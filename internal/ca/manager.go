package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	RootCertFile = "root_ca.crt"
	RootKeyFile  = "root_ca.key"

	rootCACommonNamePrefix = "GoMITM Root CA"
	rootCertDateLayout     = "20060102"
)

type Manager struct {
	dir      string
	rootCert *x509.Certificate
	rootKey  crypto.Signer
	certPEM  []byte

	mu    sync.RWMutex
	cache map[string]tls.Certificate
}

func EnsureCA(dir string) (*Manager, error) {
	dir, err := expandHome(dir)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}

	certPath := filepath.Join(dir, RootCertFile)
	keyPath := filepath.Join(dir, RootKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		return Load(dir)
	}

	return initCA(dir)
}

func Init(dir string) (*Manager, error) {
	dir, err := expandHome(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}
	return initCA(dir)
}

func Load(dir string) (*Manager, error) {
	dir, err := expandHome(dir)
	if err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, RootCertFile)
	keyPath := filepath.Join(dir, RootKeyFile)

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read root cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read root key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("invalid root cert pem")
	}
	rootCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid root key pem")
	}

	parsedKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root key: %w", err)
	}
	signer, ok := parsedKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("root key is not a signer")
	}

	if err := ensurePrivateKeyPermissions(keyPath); err != nil {
		return nil, err
	}

	return &Manager{
		dir:      dir,
		rootCert: rootCert,
		rootKey:  signer,
		certPEM:  certPEM,
		cache:    make(map[string]tls.Certificate),
	}, nil
}

func (m *Manager) Paths() (certPath, keyPath string) {
	return filepath.Join(m.dir, RootCertFile), filepath.Join(m.dir, RootKeyFile)
}

func (m *Manager) ExportCert(outPath string) error {
	if outPath == "" {
		return errors.New("output path is empty")
	}
	if err := os.WriteFile(outPath, m.certPEM, 0o644); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}
	return nil
}

func (m *Manager) RootCertPEM() []byte {
	if m == nil || len(m.certPEM) == 0 {
		return nil
	}
	out := make([]byte, len(m.certPEM))
	copy(out, m.certPEM)
	return out
}

func (m *Manager) RootCertDownloadFilename() string {
	return fmt.Sprintf("gomitm-root-ca-%s.crt", m.rootCertIssueDate())
}

func (m *Manager) rootCertIssueDate() string {
	if m != nil {
		if d := issuedDateFromCommonName(m.rootCommonName()); d != "" {
			return d
		}
		if m.rootCert != nil {
			return m.rootCert.NotBefore.Format(rootCertDateLayout)
		}
	}
	return time.Now().Format(rootCertDateLayout)
}

func (m *Manager) rootCommonName() string {
	if m == nil || m.rootCert == nil {
		return ""
	}
	return strings.TrimSpace(m.rootCert.Subject.CommonName)
}

func issuedDateFromCommonName(commonName string) string {
	prefix := rootCACommonNamePrefix + " "
	if !strings.HasPrefix(commonName, prefix) {
		return ""
	}
	date := strings.TrimPrefix(commonName, prefix)
	if _, err := time.Parse(rootCertDateLayout, date); err != nil {
		return ""
	}
	return date
}

func rootCACommonName(now time.Time) string {
	return fmt.Sprintf("%s %s", rootCACommonNamePrefix, now.Format(rootCertDateLayout))
}

func (m *Manager) GetLeafCertificate(host string) (tls.Certificate, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return tls.Certificate{}, errors.New("host is empty")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}

	m.mu.RLock()
	cached, ok := m.cache[host]
	m.mu.RUnlock()
	if ok {
		return cached, nil
	}

	cert, err := m.signLeaf(host)
	if err != nil {
		return tls.Certificate{}, err
	}

	m.mu.Lock()
	m.cache[host] = cert
	m.mu.Unlock()
	return cert, nil
}

func (m *Manager) signLeaf(host string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	d, err := x509.CreateCertificate(rand.Reader, tmpl, m.rootCert, publicKey(priv), m.rootKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create leaf cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal leaf key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("build tls leaf pair: %w", err)
	}
	return cert, nil
}

func initCA(dir string) (*Manager, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   rootCACommonName(now),
			Organization: []string{"GoMITM"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	certPath := filepath.Join(dir, RootCertFile)
	keyPath := filepath.Join(dir, RootKeyFile)

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write root cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write root key: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}

	return &Manager{
		dir:      dir,
		rootCert: cert,
		rootKey:  key,
		certPEM:  certPEM,
		cache:    make(map[string]tls.Certificate),
	}, nil
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func parsePrivateKey(der []byte) (any, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

var (
	lookupCurrentUser = user.Current
	lookupUserByID    = user.LookupId
	currentUID        = os.Getuid
)

func expandHome(path string) (string, error) {
	if path == "" || path[0] != '~' {
		return path, nil
	}
	home, err := resolveHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:]), nil
	}
	return "", fmt.Errorf("unsupported home path: %s", path)
}

func resolveHomeDir() (string, error) {
	home := strings.TrimSpace(os.Getenv("HOME"))
	if home != "" {
		return home, nil
	}

	if u, err := lookupCurrentUser(); err == nil && strings.TrimSpace(u.HomeDir) != "" {
		return u.HomeDir, nil
	}

	uid := strconv.Itoa(currentUID())
	if u, err := lookupUserByID(uid); err == nil && strings.TrimSpace(u.HomeDir) != "" {
		return u.HomeDir, nil
	}

	return "", errors.New("$HOME is not defined and user home lookup failed")
}

func ensurePrivateKeyPermissions(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key permissions too open: %s (require 0600)", st.Mode().Perm())
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
