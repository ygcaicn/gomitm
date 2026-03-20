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
  admin_token: "demo-admin-token"
  ca_dir: "~/.gomitm/ca"
  dial_timeout: "12s"
  script_timeout: "250ms"
  socks_username: "alice"
  socks_password: "secret"
  max_conns: 3000
  udp_max_sessions: 2048
  udp_idle_timeout: "3m"
mitm:
  all: true
  fail_open: true
  hosts:
    - "*.googlevideo.com"
  bypass_hosts:
    - "youtubei.googleapis.com"
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
  redact_headers:
    - "Authorization"
    - "Cookie"
  redact_json_fields:
    - "token"
    - "password"
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
	if cfg.Serve.AdminToken != "demo-admin-token" {
		t.Fatalf("admin token got=%q", cfg.Serve.AdminToken)
	}
	if cfg.Serve.ScriptTimeout != "250ms" {
		t.Fatalf("script timeout got=%q", cfg.Serve.ScriptTimeout)
	}
	if cfg.Serve.SOCKSUsername != "alice" || cfg.Serve.SOCKSPassword != "secret" {
		t.Fatalf("socks auth got user=%q pass=%q", cfg.Serve.SOCKSUsername, cfg.Serve.SOCKSPassword)
	}
	if cfg.Serve.MaxConns != 3000 {
		t.Fatalf("max_conns got=%d", cfg.Serve.MaxConns)
	}
	if cfg.Serve.UDPMaxSessions != 2048 {
		t.Fatalf("udp max sessions got=%d", cfg.Serve.UDPMaxSessions)
	}
	if cfg.Serve.UDPIdleTimeout != "3m" {
		t.Fatalf("udp idle timeout got=%q", cfg.Serve.UDPIdleTimeout)
	}
	if !cfg.MITM.All {
		t.Fatal("mitm.all should be true")
	}
	if !cfg.MITM.FailOpen {
		t.Fatal("mitm.fail_open should be true")
	}
	if len(cfg.MITM.BypassHosts) != 1 || cfg.MITM.BypassHosts[0] != "youtubei.googleapis.com" {
		t.Fatalf("mitm.bypass_hosts got=%v", cfg.MITM.BypassHosts)
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
	if len(cfg.Capture.RedactHeaders) != 2 || cfg.Capture.RedactHeaders[0] != "Authorization" {
		t.Fatalf("redact headers got=%v", cfg.Capture.RedactHeaders)
	}
	if len(cfg.Capture.RedactJSONFields) != 2 || cfg.Capture.RedactJSONFields[0] != "token" {
		t.Fatalf("redact json fields got=%v", cfg.Capture.RedactJSONFields)
	}
}
