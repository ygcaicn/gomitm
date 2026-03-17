package module

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadScriptCodeFromURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`$done({body:"ok"})`))
	}))
	defer ts.Close()

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
