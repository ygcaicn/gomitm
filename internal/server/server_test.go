package server

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"gomitm/internal/ca"
	"gomitm/internal/capture"
	"gomitm/internal/policy"
)

func TestApplyRewriteReject200(t *testing.T) {
	s := &Server{rewrite: []policy.RewriteRule{{
		Pattern: regexp.MustCompile(`^https://example\.com/foo$`),
		Action:  policy.RewriteReject200,
	}}, logger: log.New(io.Discard, "", 0)}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	buf := new(bytes.Buffer)
	w := bufio.NewWriter(buf)

	handled, _, _, err := s.applyRewrite(req, w)
	if err != nil {
		t.Fatalf("apply rewrite failed: %v", err)
	}
	if !handled {
		t.Fatal("expected handled=true")
	}
	if !strings.Contains(buf.String(), "200 OK") {
		t.Fatalf("unexpected response: %s", buf.String())
	}
}

func TestShouldCaptureContentType(t *testing.T) {
	cases := []struct {
		contentType string
		filters     []string
		want        bool
	}{
		{"application/json", []string{"application/json", "text/*"}, true},
		{"text/plain; charset=utf-8", []string{"application/json", "text/*"}, true},
		{"application/octet-stream", []string{"application/json", "text/*"}, false},
		{"application/octet-stream", nil, true},
	}

	for _, c := range cases {
		got := shouldCaptureContentType(c.contentType, c.filters)
		if got != c.want {
			t.Fatalf("contentType=%q filters=%v got=%v want=%v", c.contentType, c.filters, got, c.want)
		}
	}
}

func TestShouldForceIdentityEncoding(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://www.google.com/webhp?hl=zh-CN", nil)
	rules := []policy.ScriptRule{
		{
			Name:         "google-home",
			Type:         policy.ScriptTypeHTTPResponse,
			Pattern:      regexp.MustCompile(`^https:\/\/(www\.)?google\.com\/(webhp)?(\?.*)?$`),
			RequiresBody: true,
		},
	}
	if !shouldForceIdentityEncoding(req, rules) {
		t.Fatal("expected identity encoding when response-body script matches")
	}

	req2, _ := http.NewRequest(http.MethodGet, "https://example.com/api", nil)
	if shouldForceIdentityEncoding(req2, rules) {
		t.Fatal("unexpected identity encoding for non-matching url")
	}
}

func TestCaptureTransactionStoresUpstreamAndModified(t *testing.T) {
	s := &Server{
		capCfg: capture.Config{
			MaxBodyBytes: 4 * 1024,
			ContentTypes: []string{"text/*"},
		},
		capStore: capture.NewStore(8),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("Accept", "text/html")

	resp := &http.Response{
		StatusCode:    200,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("<html>after</html>")),
		ContentLength: int64(len("<html>after</html>")),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	upstream := &responseSnapshot{
		Status:  200,
		Headers: map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:    "<html>before</html>",
	}

	s.captureTransaction(req, resp, upstream, time.Now(), "", "")
	entries := s.CaptureEntries()
	if len(entries) != 1 {
		t.Fatalf("entries len=%d", len(entries))
	}
	e := entries[0]
	if e.UpstreamRespBody != "<html>before</html>" {
		t.Fatalf("unexpected upstream body: %q", e.UpstreamRespBody)
	}
	if e.RespBody != "<html>after</html>" {
		t.Fatalf("unexpected final body: %q", e.RespBody)
	}
	if !e.RespModified {
		t.Fatal("resp_modified should be true when upstream and final differ")
	}
}

func TestShouldMITMBuiltinHost(t *testing.T) {
	s := &Server{matcher: nil}
	if !s.shouldMITM("www4.google.com", 443) {
		t.Fatal("builtin host should always be MITM on 443")
	}
	if !s.shouldMITM("198.18.0.1", 443) {
		t.Fatal("builtin HTTP portal host should also be MITM on 443")
	}
	if !s.shouldMITM("8.8.9.9", 443) {
		t.Fatal("builtin HTTP portal alt host should also be MITM on 443")
	}
	if s.shouldMITM("www4.google.com", 80) {
		t.Fatal("builtin host on non-443 should not be MITM")
	}
}

func TestShouldMITMAll(t *testing.T) {
	s := &Server{cfg: Config{MITMAll: true}, matcher: nil}
	if !s.shouldMITM("example.com", 443) {
		t.Fatal("mitm all should force mitm on 443")
	}
	if s.shouldMITM("example.com", 80) {
		t.Fatal("mitm all should not force non-443 ports")
	}
}

func TestHandleBuiltinCAPortal(t *testing.T) {
	dir := t.TempDir()
	caManager, err := ca.Init(dir)
	if err != nil {
		t.Fatalf("init ca failed: %v", err)
	}
	s := &Server{ca: caManager, logger: log.New(io.Discard, "", 0)}

	{
		req, _ := http.NewRequest(http.MethodGet, "https://www4.google.com/", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, resp, err := s.handleBuiltinCAPortal(req, w, "www4.google.com")
		if err != nil {
			t.Fatalf("handle root failed: %v", err)
		}
		if !handled || resp == nil {
			t.Fatal("expected built-in root handled")
		}
		out := buf.String()
		if !strings.Contains(out, "200 OK") {
			t.Fatalf("unexpected status: %s", out)
		}
		if !strings.Contains(out, "GoMITM 根证书安装页") {
			t.Fatalf("unexpected body: %s", out)
		}
		if !strings.Contains(out, "BEGIN CERTIFICATE") {
			t.Fatalf("expected certificate content in portal: %s", out)
		}
	}

	{
		req, _ := http.NewRequest(http.MethodGet, "https://www4.google.com/gomitm-ca.crt", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, resp, err := s.handleBuiltinCAPortal(req, w, "www4.google.com")
		if err != nil {
			t.Fatalf("handle cert failed: %v", err)
		}
		if !handled || resp == nil {
			t.Fatal("expected built-in cert download handled")
		}
		out := buf.String()
		if !strings.Contains(out, "application/x-x509-ca-cert") {
			t.Fatalf("unexpected content-type: %s", out)
		}
		if !regexp.MustCompile(`attachment; filename="gomitm-root-ca-\d{8}-\d{6}\.crt"`).MatchString(out) {
			t.Fatalf("unexpected content-disposition: %s", out)
		}
		if !strings.Contains(out, "BEGIN CERTIFICATE") {
			t.Fatalf("expected certificate body: %s", out)
		}
	}

	{
		req, _ := http.NewRequest(http.MethodGet, "https://www.google.com/", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, _, err := s.handleBuiltinCAPortal(req, w, "www.google.com")
		if err != nil {
			t.Fatalf("handle non builtin failed: %v", err)
		}
		if handled {
			t.Fatal("non builtin host should not be handled")
		}
	}

	{
		req, _ := http.NewRequest(http.MethodGet, "http://198.18.0.1/unknown", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, resp, err := s.handleBuiltinCAPortal(req, w, "198.18.0.1")
		if err != nil {
			t.Fatalf("handle http unknown failed: %v", err)
		}
		if !handled || resp == nil {
			t.Fatal("expected builtin host unknown path still handled with 404")
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status code got=%d", resp.StatusCode)
		}
	}

	{
		req, _ := http.NewRequest(http.MethodGet, "http://8.8.9.9/", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, resp, err := s.handleBuiltinCAPortal(req, w, "8.8.9.9")
		if err != nil {
			t.Fatalf("handle http alt root failed: %v", err)
		}
		if !handled || resp == nil {
			t.Fatal("expected builtin alt host handled")
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status code got=%d", resp.StatusCode)
		}
	}
}
