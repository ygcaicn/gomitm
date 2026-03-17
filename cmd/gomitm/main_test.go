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
  hosts: ["a.com"]
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
}
