package script

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"gomitm/internal/policy"
)

func TestApplyResponseScriptBinaryBodyViaBodyField(t *testing.T) {
	engine := NewEngine()
	rule := policy.ScriptRule{
		Name:           "binary-body-via-body",
		Type:           policy.ScriptTypeHTTPResponse,
		Pattern:        regexp.MustCompile(`^https://example\.com/bin$`),
		RequiresBody:   true,
		BinaryBodyMode: true,
		Code:           `$done({ body: $response.bodyBytes, headers: {"x-binary":"1"} });`,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/bin", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("abc")),
		Request:    req,
	}

	ok, err := engine.ApplyResponseScripts(req, resp, []policy.ScriptRule{rule})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !ok {
		t.Fatal("expected script to run")
	}
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "abc" {
		t.Fatalf("body got=%q want=%q", got, "abc")
	}
	if resp.Header.Get("x-binary") != "1" {
		t.Fatalf("header x-binary got=%q", resp.Header.Get("x-binary"))
	}
}

func TestApplyResponseScriptDoneResponseWrapper(t *testing.T) {
	engine := NewEngine()
	rule := policy.ScriptRule{
		Name:         "response-wrapper",
		Type:         policy.ScriptTypeHTTPResponse,
		Pattern:      regexp.MustCompile(`^https://example\.com/wrap$`),
		RequiresBody: true,
		Code: `$done({
  response: {
    status: 201,
    headers: {"x-wrap":"1"},
    body: "wrapped"
  }
});`,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/wrap", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("origin")),
		Request:    req,
	}

	ok, err := engine.ApplyResponseScripts(req, resp, []policy.ScriptRule{rule})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !ok {
		t.Fatal("expected script to run")
	}
	if resp.StatusCode != 201 {
		t.Fatalf("status got=%d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "wrapped" {
		t.Fatalf("body got=%q", got)
	}
	if resp.Header.Get("x-wrap") != "1" {
		t.Fatalf("header x-wrap got=%q", resp.Header.Get("x-wrap"))
	}
}

func TestSurgeCompatPersistentStoreAndPrefs(t *testing.T) {
	engine := NewEngine()
	key := "compat-store-test-key"
	rule := policy.ScriptRule{
		Name:         "compat-store-write",
		Type:         policy.ScriptTypeHTTPResponse,
		Pattern:      regexp.MustCompile(`^https://example\.com/store$`),
		RequiresBody: true,
		Code: fmt.Sprintf(`
$persistentStore.write("v1", %q);
$prefs.setValueForKey("v2", %q);
$done({ headers: {
  "x-store-1": $persistentStore.read(%q),
  "x-store-2": $prefs.valueForKey(%q)
} });
`, key, key+"-prefs", key, key+"-prefs"),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/store", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}

	ok, err := engine.ApplyResponseScripts(req, resp, []policy.ScriptRule{rule})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !ok {
		t.Fatal("expected script to run")
	}
	if got := resp.Header.Get("x-store-1"); got != "v1" {
		t.Fatalf("x-store-1 got=%q", got)
	}
	if got := resp.Header.Get("x-store-2"); got != "v2" {
		t.Fatalf("x-store-2 got=%q", got)
	}

	verifyRule := policy.ScriptRule{
		Name:         "compat-store-read",
		Type:         policy.ScriptTypeHTTPResponse,
		Pattern:      regexp.MustCompile(`^https://example\.com/store2$`),
		RequiresBody: true,
		Code: fmt.Sprintf(`
$done({ headers: {"x-store": $persistentStore.read(%q)} });
`, key),
	}
	req2, _ := http.NewRequest(http.MethodGet, "https://example.com/store2", nil)
	resp2 := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req2,
	}
	ok, err = engine.ApplyResponseScripts(req2, resp2, []policy.ScriptRule{verifyRule})
	if err != nil {
		t.Fatalf("verify apply failed: %v", err)
	}
	if !ok {
		t.Fatal("expected verify script to run")
	}
	if got := resp2.Header.Get("x-store"); got != "v1" {
		t.Fatalf("x-store got=%q", got)
	}
}

func TestSurgeCompatHTTPClientGet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Upstream", "yes")
		_, _ = w.Write([]byte("pong"))
	}))
	defer ts.Close()

	engine := NewEngine()
	rule := policy.ScriptRule{
		Name:         "compat-http-client",
		Type:         policy.ScriptTypeHTTPResponse,
		Pattern:      regexp.MustCompile(`^https://example\.com/httpclient$`),
		RequiresBody: true,
		Code: fmt.Sprintf(`
$httpClient.get(%q, function(err, resp, body) {
  if (err) {
    $done({ headers: {"x-http-error": String(err)} });
    return;
  }
  $done({ headers: {
    "x-http-status": String(resp.statusCode || resp.status),
    "x-http-body": body,
    "x-http-upstream": String(resp.headers["X-Upstream"] || "")
  } });
});
`, ts.URL+"/ping"),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/httpclient", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("ok")),
		Request:    req,
	}

	ok, err := engine.ApplyResponseScripts(req, resp, []policy.ScriptRule{rule})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !ok {
		t.Fatal("expected script to run")
	}
	if got := resp.Header.Get("x-http-status"); got != "200" {
		t.Fatalf("x-http-status got=%q", got)
	}
	if got := resp.Header.Get("x-http-body"); got != "pong" {
		t.Fatalf("x-http-body got=%q", got)
	}
	if got := resp.Header.Get("x-http-upstream"); got != "yes" {
		t.Fatalf("x-http-upstream got=%q", got)
	}
}
