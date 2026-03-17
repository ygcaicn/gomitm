package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
serve:
  listen: ":2080"
  admin_listen: "127.0.0.1:19090"
  ca_dir: "~/.gomitm/ca"
  dial_timeout: "12s"
mitm:
  hosts:
    - "*.googlevideo.com"
modules:
  - name: YouTubeNoAds
    enable: true
    path: "https://example.com/a.sgmodule"
    arguments:
      foo: "bar"
      debug: false
  - name: DisabledOne
    enable: false
    path: "./local.sgmodule"
capture:
  enabled: true
  max_entries: 123
  max_body_bytes: 456
  content_types:
    - "application/json"
  har_out: "./tmp/out.har"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if cfg.Serve.Listen != ":2080" {
		t.Fatalf("listen got=%q", cfg.Serve.Listen)
	}
	if cfg.Capture.MaxEntries != 123 {
		t.Fatalf("max_entries got=%d", cfg.Capture.MaxEntries)
	}
	if len(cfg.Modules) != 2 {
		t.Fatalf("modules len got=%d", len(cfg.Modules))
	}
	if cfg.Modules[0].Path != "https://example.com/a.sgmodule" {
		t.Fatalf("module path got=%q", cfg.Modules[0].Path)
	}
	if cfg.Modules[0].Arguments["foo"] != "bar" {
		t.Fatalf("arg foo got=%v", cfg.Modules[0].Arguments["foo"])
	}
}
