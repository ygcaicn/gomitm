package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVersionString(t *testing.T) {
	oldVersion, oldCommit, oldBuildDate := version, commit, buildDate
	version, commit, buildDate = "v1.2.3", "abc123", "2026-03-18T00:00:00Z"
	t.Cleanup(func() {
		version, commit, buildDate = oldVersion, oldCommit, oldBuildDate
	})

	got := versionString()
	want := "gomitm version v1.2.3 (commit=abc123, build_date=2026-03-18T00:00:00Z)"
	if got != want {
		t.Fatalf("versionString() = %q, want %q", got, want)
	}
}

func TestParseServeOptionsWithConfigAndCLIOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
serve:
  listen: "127.0.0.1:2080"
  dial_timeout: "12s"
  max_conns: 1500
  udp_max_sessions: 777
  udp_idle_timeout: "90s"
mitm:
  all: false
  hosts: ["a.com"]
  bypass_hosts: ["b.com"]
  fail_open: true
modules:
  - name: one
    enable: true
    path: "https://example.com/a.sgmodule"
    arguments:
      "屏蔽上传按钮": true
  - name: disabled
    enable: false
    path: "https://example.com/b.sgmodule"
capture:
  enabled: true
  max_entries: 100
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	opts, err := parseServeOptions([]string{
		"--config", cfgPath,
		"--listen", "127.0.0.1:3080",
		"--capture-max-entries", "200",
	})
	if err != nil {
		t.Fatalf("parseServeOptions failed: %v", err)
	}

	if opts.Listen != "127.0.0.1:3080" {
		t.Fatalf("listen got=%q", opts.Listen)
	}
	if opts.DialTimeout.String() != "12s" {
		t.Fatalf("dial timeout got=%s", opts.DialTimeout)
	}
	if opts.MaxConns != 1500 {
		t.Fatalf("max conns got=%d", opts.MaxConns)
	}
	if opts.UDPMaxSessions != 777 {
		t.Fatalf("udp max sessions got=%d", opts.UDPMaxSessions)
	}
	if opts.UDPIdleTimeout.String() != "1m30s" {
		t.Fatalf("udp idle timeout got=%s", opts.UDPIdleTimeout)
	}
	if !opts.CaptureEnabled {
		t.Fatal("capture enabled should come from config")
	}
	if opts.CaptureMaxEntries != 200 {
		t.Fatalf("capture max entries got=%d", opts.CaptureMaxEntries)
	}
	if len(opts.MITMHosts) != 1 || opts.MITMHosts[0] != "a.com" {
		t.Fatalf("mitm hosts=%v", opts.MITMHosts)
	}
	if len(opts.MITMBypassHosts) != 1 || opts.MITMBypassHosts[0] != "b.com" {
		t.Fatalf("mitm bypass hosts=%v", opts.MITMBypassHosts)
	}
	if !opts.MITMFailOpen {
		t.Fatal("mitm fail-open should come from config")
	}
	if opts.MITMAll {
		t.Fatal("mitm all should be false from config")
	}
	if len(opts.ModuleSources) != 1 {
		t.Fatalf("module sources len got=%d want=1", len(opts.ModuleSources))
	}
	if opts.ModuleSources[0].Path != "https://example.com/a.sgmodule" {
		t.Fatalf("module path got=%q", opts.ModuleSources[0].Path)
	}
	if opts.ModuleSources[0].Arguments["屏蔽上传按钮"] != "true" {
		t.Fatalf("module arg got=%q", opts.ModuleSources[0].Arguments["屏蔽上传按钮"])
	}
}

func TestParseServeOptionsUDPCLIOverride(t *testing.T) {
	opts, err := parseServeOptions([]string{
		"--udp-max-sessions", "123",
		"--udp-idle-timeout", "45s",
		"--max-conns", "2222",
		"--mitm-bypass-hosts", "x.com,*.y.com",
		"--mitm-fail-open=true",
	})
	if err != nil {
		t.Fatalf("parseServeOptions failed: %v", err)
	}
	if opts.UDPMaxSessions != 123 {
		t.Fatalf("udp max sessions got=%d", opts.UDPMaxSessions)
	}
	if opts.UDPIdleTimeout.String() != "45s" {
		t.Fatalf("udp idle timeout got=%s", opts.UDPIdleTimeout)
	}
	if opts.MaxConns != 2222 {
		t.Fatalf("max conns got=%d", opts.MaxConns)
	}
	if len(opts.MITMBypassHosts) != 2 || opts.MITMBypassHosts[0] != "x.com" || opts.MITMBypassHosts[1] != "*.y.com" {
		t.Fatalf("mitm bypass hosts=%v", opts.MITMBypassHosts)
	}
	if !opts.MITMFailOpen {
		t.Fatal("mitm fail open should be true")
	}
}

func TestParseServeOptionsMITMAllCLIOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
mitm:
  all: false
  hosts: ["a.com"]
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	opts, err := parseServeOptions([]string{
		"--config", cfgPath,
		"--mitm-all=true",
	})
	if err != nil {
		t.Fatalf("parseServeOptions failed: %v", err)
	}
	if !opts.MITMAll {
		t.Fatal("mitm all should be true after cli override")
	}
}

func TestParseServeOptionsModuleArgsOverrideConfigModules(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
modules:
  - name: one
    enable: true
    path: "https://example.com/a.sgmodule"
    arguments:
      "屏蔽上传按钮": true
      "字幕翻译语言": "off"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	opts, err := parseServeOptions([]string{
		"--config", cfgPath,
		"--module-args", "屏蔽上传按钮=false,字幕翻译语言=ja,新增参数=x",
	})
	if err != nil {
		t.Fatalf("parseServeOptions failed: %v", err)
	}
	if len(opts.ModuleSources) != 1 {
		t.Fatalf("module sources len got=%d want=1", len(opts.ModuleSources))
	}
	args := opts.ModuleSources[0].Arguments
	if args["屏蔽上传按钮"] != "false" {
		t.Fatalf("屏蔽上传按钮 got=%q", args["屏蔽上传按钮"])
	}
	if args["字幕翻译语言"] != "ja" {
		t.Fatalf("字幕翻译语言 got=%q", args["字幕翻译语言"])
	}
	if args["新增参数"] != "x" {
		t.Fatalf("新增参数 got=%q", args["新增参数"])
	}
}

func TestParseServeOptionsResolvesModulePathRelativeToConfig(t *testing.T) {
	dir := t.TempDir()
	modDir := filepath.Join(dir, "modules")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
modules:
  - name: local
    enable: true
    path: "./modules/demo.sgmodule"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	opts, err := parseServeOptions([]string{"--config", cfgPath})
	if err != nil {
		t.Fatalf("parseServeOptions failed: %v", err)
	}
	if len(opts.ModuleSources) != 1 {
		t.Fatalf("module sources len got=%d", len(opts.ModuleSources))
	}
	want := filepath.Join(dir, "modules", "demo.sgmodule")
	if opts.ModuleSources[0].Path != want {
		t.Fatalf("module path got=%q want=%q", opts.ModuleSources[0].Path, want)
	}
}

func TestParseServeOptionsDefaultListenIsLoopback(t *testing.T) {
	opts, err := parseServeOptions(nil)
	if err != nil {
		t.Fatalf("parseServeOptions failed: %v", err)
	}
	if opts.Listen != "127.0.0.1:1080" {
		t.Fatalf("default listen got=%q", opts.Listen)
	}
}

func TestParseServeOptionsRejectsNonLoopbackWithoutSOCKSAuth(t *testing.T) {
	_, err := parseServeOptions([]string{"--listen", ":1080"})
	if err == nil {
		t.Fatal("expected error for non-loopback listen without socks auth")
	}
}

func TestParseServeOptionsAllowsNonLoopbackWithSOCKSAuth(t *testing.T) {
	opts, err := parseServeOptions([]string{
		"--listen", ":1080",
		"--socks-user", "user",
		"--socks-pass", "pass",
	})
	if err != nil {
		t.Fatalf("parseServeOptions failed: %v", err)
	}
	if opts.SOCKSUsername != "user" || opts.SOCKSPassword != "pass" {
		t.Fatalf("unexpected socks auth opts: %#v", opts)
	}
}

func TestParseServeOptionsRejectsPartialSOCKSAuth(t *testing.T) {
	_, err := parseServeOptions([]string{
		"--socks-user", "user",
	})
	if err == nil {
		t.Fatal("expected error for partial socks auth settings")
	}
}

func TestParseServeOptionsRejectsNonLoopbackAdminWithoutToken(t *testing.T) {
	_, err := parseServeOptions([]string{
		"--admin-listen", ":19090",
	})
	if err == nil {
		t.Fatal("expected error for non-loopback admin listen without token")
	}
}
