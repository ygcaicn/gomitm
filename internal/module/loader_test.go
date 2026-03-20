package module

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoadScriptCodeFromURL(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`$done({body:"ok"})`))
	}))
	defer ts.Close()
	oldFactory := newHTTPClient
	newHTTPClient = func(timeout time.Duration) *http.Client {
		c := ts.Client()
		c.Timeout = timeout
		return c
	}
	t.Cleanup(func() {
		newHTTPClient = oldFactory
	})

	content := `[Script]
demo = type=http-response, pattern=^https:\/\/example\.com\/$, script-path=` + ts.URL + `/script.js, requires-body=true`

	p, err := Parse(strings.NewReader(content))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if err := p.LoadScriptCode(); err != nil {
		t.Fatalf("load script code failed: %v", err)
	}
	if got := strings.TrimSpace(p.Scripts[0].Code); got != `$done({body:"ok"})` {
		t.Fatalf("unexpected script code: %q", got)
	}
}

func TestLoadScriptCodeRejectsHTTPURL(t *testing.T) {
	content := `[Script]
demo = type=http-response, pattern=^https:\/\/example\.com\/$, script-path=http://example.com/script.js, requires-body=true`

	p, err := Parse(strings.NewReader(content))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	err = p.LoadScriptCode()
	if err == nil {
		t.Fatal("expected load script code to reject http url")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Fatalf("unexpected error: %v", err)
	}
}
