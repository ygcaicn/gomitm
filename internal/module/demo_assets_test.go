package module

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGoogleHomeDemoModuleCanLoad(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	modulePath := filepath.Join(repoRoot, "modules", "google-home-fun.sgmodule")

	parsed, err := LoadSources([]Source{{
		Name:      "GoogleHomeFunDemo",
		Enabled:   true,
		Path:      modulePath,
		Arguments: map[string]string{"文案": "测试文案"},
	}})
	if err != nil {
		t.Fatalf("LoadSources failed: %v", err)
	}

	if len(parsed.MITMHosts) == 0 || parsed.MITMHosts[0] != "www.google.com" {
		t.Fatalf("unexpected MITM hosts: %v", parsed.MITMHosts)
	}
	if len(parsed.Scripts) != 1 {
		t.Fatalf("unexpected scripts len=%d", len(parsed.Scripts))
	}
	if !parsed.Scripts[0].Match("https://www.google.com/") {
		t.Fatal("google homepage pattern should match")
	}
	if parsed.Scripts[0].Argument != `{"message":"测试文案"}` {
		t.Fatalf("unexpected script argument: %q", parsed.Scripts[0].Argument)
	}
	if !strings.Contains(parsed.Scripts[0].Code, "gomitm-fun-banner") {
		t.Fatal("demo script code not loaded")
	}
}
