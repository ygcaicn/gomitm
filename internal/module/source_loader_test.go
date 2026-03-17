package module

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSourcesRespectsEnableAndArgs(t *testing.T) {
	dir := t.TempDir()

	scriptPath := filepath.Join(dir, "rewrite.js")
	if err := os.WriteFile(scriptPath, []byte(`$done({ body: $response.body })`), 0o644); err != nil {
		t.Fatal(err)
	}

	modulePath := filepath.Join(dir, "a.sgmodule")
	moduleContent := `
#!arguments=debug:false

[MITM]
hostname = %APPEND% a.example.com

[Script]
demo = type=http-response, pattern=^https:\/\/a\.example\.com\/$, script-path=` + scriptPath + `, requires-body=true, argument="{\"debug\":{{{debug}}}}"
`
	if err := os.WriteFile(modulePath, []byte(moduleContent), 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := LoadSources([]Source{
		{
			Name:      "enabled",
			Enabled:   true,
			Path:      modulePath,
			Arguments: map[string]string{"debug": "true"},
		},
		{
			Name:    "disabled",
			Enabled: false,
			Path:    filepath.Join(dir, "missing.sgmodule"),
		},
	})
	if err != nil {
		t.Fatalf("LoadSources failed: %v", err)
	}

	if len(parsed.MITMHosts) != 1 || parsed.MITMHosts[0] != "a.example.com" {
		t.Fatalf("mitm hosts=%v", parsed.MITMHosts)
	}
	if len(parsed.Scripts) != 1 {
		t.Fatalf("scripts=%d", len(parsed.Scripts))
	}
	if parsed.Scripts[0].Argument != `{"debug":true}` {
		t.Fatalf("argument got=%q", parsed.Scripts[0].Argument)
	}
	if strings.TrimSpace(parsed.Scripts[0].Code) != `$done({ body: $response.body })` {
		t.Fatalf("script code got=%q", parsed.Scripts[0].Code)
	}
}
