package server

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net/http"
	"regexp"
	"testing"

	"gomitm/internal/policy"
)

func BenchmarkApplyRewriteReject200(b *testing.B) {
	s := &Server{
		rewrite: []policy.RewriteRule{{
			Pattern: regexp.MustCompile(`^https://a\.googlevideo\.com/initplayback\?x=1&oad$`),
			Action:  policy.RewriteReject200,
		}},
		logger: log.New(io.Discard, "", 0),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://a.googlevideo.com/initplayback?x=1&oad", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, _, _, err := s.applyRewrite(req, w)
		if err != nil {
			b.Fatal(err)
		}
		if !handled {
			b.Fatal("not handled")
		}
	}
}

func BenchmarkShouldCaptureContentType(b *testing.B) {
	filters := []string{"application/json", "text/*"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !shouldCaptureContentType("application/json; charset=utf-8", filters) {
			b.Fatal("not matched")
		}
	}
}
