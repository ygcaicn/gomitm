package script

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gomitm/internal/policy"
)

func loadYouTubeWebLiteScript(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	p := filepath.Join(repoRoot, "modules", "youtube-web-lite.js")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read script failed: %v", err)
	}
	return string(data)
}

func TestYouTubeWebLiteAPIScript(t *testing.T) {
	engine := NewEngine()
	code := loadYouTubeWebLiteScript(t)
	rule := policy.ScriptRule{
		Name:         "youtube.web.api",
		Type:         policy.ScriptTypeHTTPResponse,
		Pattern:      regexp.MustCompile(`^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/player`),
		RequiresBody: true,
		MaxSize:      1024 * 1024,
		Argument:     `{"mode":"api"}`,
		Code:         code,
	}

	req, _ := http.NewRequest(http.MethodPost, "https://youtubei.googleapis.com/youtubei/v1/player", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body: io.NopCloser(strings.NewReader(
			`{"adPlacements":[{"x":1}],"playerAds":[{"y":2}],"contents":{"ok":true,"promotedContent":{"a":1}}}`,
		)),
		Request: req,
	}
	resp.Header.Set("Content-Type", "application/json")

	ok, err := engine.ApplyResponseScripts(req, resp, []policy.ScriptRule{rule})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !ok {
		t.Fatal("expected script to run")
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	out := buf.String()
	if strings.Contains(out, "adPlacements") || strings.Contains(out, "playerAds") || strings.Contains(strings.ToLower(out), "promoted") {
		t.Fatalf("ads keys should be removed, got=%s", out)
	}
}

func TestYouTubeWebLiteWatchScript(t *testing.T) {
	engine := NewEngine()
	code := loadYouTubeWebLiteScript(t)
	rule := policy.ScriptRule{
		Name:         "youtube.web.watch",
		Type:         policy.ScriptTypeHTTPResponse,
		Pattern:      regexp.MustCompile(`^https:\/\/www\.youtube\.com\/watch\?v=`),
		RequiresBody: true,
		MaxSize:      1024 * 1024,
		Argument:     `{"mode":"watch","styleCleanup":true}`,
		Code:         code,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://www.youtube.com/watch?v=dQw4w9WgXcQ", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body: io.NopCloser(strings.NewReader(
			`<!doctype html><html><head><title>YouTube</title></head><body><div class="video-ads">ad</div></body></html>`,
		)),
		Request: req,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	ok, err := engine.ApplyResponseScripts(req, resp, []policy.ScriptRule{rule})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !ok {
		t.Fatal("expected script to run")
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	out := buf.String()
	if !strings.Contains(out, "gomitm-youtube-lite-style") {
		t.Fatalf("expected style injection, got=%s", out)
	}
	if !strings.Contains(out, "gomitm-youtube-lite-js") {
		t.Fatalf("expected script injection, got=%s", out)
	}
}
