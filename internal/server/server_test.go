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

	handled, err := s.applyRewrite(req, w)
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
