package script

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"gomitm/internal/policy"
)

func BenchmarkApplyResponseScriptsJSON(b *testing.B) {
	engine := NewEngine()
	rule := policy.ScriptRule{
		Name:         "bench",
		Type:         policy.ScriptTypeHTTPResponse,
		Pattern:      regexp.MustCompile(`^https://example\.com/api$`),
		RequiresBody: true,
		MaxSize:      1024 * 1024,
		Code: `
let obj = JSON.parse($response.body);
obj.ok = true;
$done({ body: JSON.stringify(obj) });
`,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/api", nil)
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"hello":"world","n":1}`)),
			Request:    req,
		}
		_, err := engine.ApplyResponseScripts(req, resp, []policy.ScriptRule{rule})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkApplyRequestScriptsHeaderRewrite(b *testing.B) {
	engine := NewEngine()
	rule := policy.ScriptRule{
		Name:    "bench-req",
		Type:    policy.ScriptTypeHTTPRequest,
		Pattern: regexp.MustCompile(`^https://example\.com/path$`),
		MaxSize: 1024,
		Code:    `$done({ method: "POST", headers: {"x-b":"1"} });`,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/path", nil)
		_, err := engine.ApplyRequestScripts(req, []policy.ScriptRule{rule})
		if err != nil {
			b.Fatal(err)
		}
	}
}
