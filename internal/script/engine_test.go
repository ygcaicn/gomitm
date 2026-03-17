package script

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"gomitm/internal/policy"
)

func TestApplyResponseScript(t *testing.T) {
	engine := NewEngine()
	rule := policy.ScriptRule{
		Name:         "demo",
		Type:         policy.ScriptTypeHTTPResponse,
		Pattern:      regexp.MustCompile(`^https://example\.com/api$`),
		RequiresBody: true,
		MaxSize:      1024,
		Code: `
let obj = JSON.parse($response.body);
obj.ad = false;
$done({ body: JSON.stringify(obj), headers: {"x-script":"1"} });
`,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/api", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"ad":true}`)),
		Request:    req,
	}

	ok, err := engine.ApplyResponseScripts(req, resp, []policy.ScriptRule{rule})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !ok {
		t.Fatal("expected script to run")
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	if got := buf.String(); got != `{"ad":false}` {
		t.Fatalf("body got=%s", got)
	}
	if resp.Header.Get("x-script") != "1" {
		t.Fatalf("header x-script got=%q", resp.Header.Get("x-script"))
	}
}

func TestApplyResponseScriptMaxSizeExceeded(t *testing.T) {
	engine := NewEngine()
	rule := policy.ScriptRule{
		Name:         "demo",
		Type:         policy.ScriptTypeHTTPResponse,
		Pattern:      regexp.MustCompile(`^https://example\.com/api$`),
		RequiresBody: true,
		MaxSize:      4,
		Code:         `$done({ body: "x" });`,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/api", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`0123456789`)),
		Request:    req,
	}

	ok, err := engine.ApplyResponseScripts(req, resp, []policy.ScriptRule{rule})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if ok {
		t.Fatal("expected script skip due to max-size")
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	if got := buf.String(); got != `0123456789` {
		t.Fatalf("body changed unexpectedly: %s", got)
	}
}

func TestApplyResponseScriptBinaryBodyMode(t *testing.T) {
	engine := NewEngine()
	rule := policy.ScriptRule{
		Name:           "binary",
		Type:           policy.ScriptTypeHTTPResponse,
		Pattern:        regexp.MustCompile(`^https://example\.com/bin$`),
		RequiresBody:   true,
		BinaryBodyMode: true,
		MaxSize:        1024,
		Code: `
let b = $response.bodyBytes;
b[0] = 88; // 'X'
$done({ bodyBytes: b, headers: {"x-binary":"1"} });
`,
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
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	if got := buf.String(); got != "Xbc" {
		t.Fatalf("body got=%q want=%q", got, "Xbc")
	}
	if resp.Header.Get("x-binary") != "1" {
		t.Fatalf("header x-binary got=%q", resp.Header.Get("x-binary"))
	}
}

func TestApplyRequestScript(t *testing.T) {
	engine := NewEngine()
	rule := policy.ScriptRule{
		Name:         "req",
		Type:         policy.ScriptTypeHTTPRequest,
		Pattern:      regexp.MustCompile(`^https://example\.com/path$`),
		RequiresBody: false,
		MaxSize:      1024,
		Code: `
let h = $request.headers;
h["x-req"] = "1";
$done({ url: "https://example.com/newpath", headers: h, method: "POST" });
`,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
	ok, err := engine.ApplyRequestScripts(req, []policy.ScriptRule{rule})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !ok {
		t.Fatal("expected request script to run")
	}
	if req.URL.String() != "https://example.com/newpath" {
		t.Fatalf("url got=%q", req.URL.String())
	}
	if req.Method != http.MethodPost {
		t.Fatalf("method got=%q", req.Method)
	}
	if req.Header.Get("x-req") != "1" {
		t.Fatalf("header x-req got=%q", req.Header.Get("x-req"))
	}
}
