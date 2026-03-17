package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseServeOptionsWithConfigAndCLIOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
serve:
  listen: ":2080"
  dial_timeout: "12s"
mitm:
  all: false
  hosts: ["a.com"]
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
		"--listen", ":3080",
		"--capture-max-entries", "200",
	})
	if err != nil {
		t.Fatalf("parseServeOptions failed: %v", err)
	}

	if opts.Listen != ":3080" {
		t.Fatalf("listen got=%q", opts.Listen)
	}
	if opts.DialTimeout.String() != "12s" {
		t.Fatalf("dial timeout got=%s", opts.DialTimeout)
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
