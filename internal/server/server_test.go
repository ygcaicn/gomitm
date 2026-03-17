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

	"gomitm/internal/ca"
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

func TestShouldMITMBuiltinHost(t *testing.T) {
	s := &Server{matcher: nil}
	if !s.shouldMITM("www4.google.com", 443) {
		t.Fatal("builtin host should always be MITM on 443")
	}
	if s.shouldMITM("www4.google.com", 80) {
		t.Fatal("builtin host on non-443 should not be MITM")
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
		handled, resp, err := s.handleBuiltinCAPortal(req, w)
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
		handled, resp, err := s.handleBuiltinCAPortal(req, w)
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
		if !strings.Contains(out, "attachment; filename=\"gomitm-root-ca.crt\"") {
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
		handled, _, err := s.handleBuiltinCAPortal(req, w)
		if err != nil {
			t.Fatalf("handle non builtin failed: %v", err)
		}
		if handled {
			t.Fatal("non builtin host should not be handled")
		}
	}
}
