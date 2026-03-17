package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gomitm/internal/ca"
	"gomitm/internal/capture"
	"gomitm/internal/har"
	"gomitm/internal/module"
	"gomitm/internal/policy"
	"gomitm/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "ca":
		if err := runCA(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", ":1080", "SOCKS5 listen address")
	caDir := fs.String("ca-dir", "~/.gomitm/ca", "CA storage directory")
	mitmHosts := fs.String("mitm-hosts", "", "comma-separated MITM hosts, e.g. *.googlevideo.com,youtubei.googleapis.com")
	moduleURLs := fs.String("module-urls", "", "comma-separated sgmodule URLs")
	moduleFiles := fs.String("module-files", "", "comma-separated local sgmodule file paths")
	moduleArgs := fs.String("module-args", "", "module argument overrides, e.g. key1=value1,key2=true")
	dialTimeout := fs.Duration("dial-timeout", 10*time.Second, "upstream dial timeout")
	captureEnabled := fs.Bool("capture-enabled", false, "enable MITM HTTP capture")
	captureMaxEntries := fs.Int("capture-max-entries", 1000, "max in-memory capture entries")
	captureMaxBodyBytes := fs.Int64("capture-max-body-bytes", 2*1024*1024, "max captured response body size in bytes")
	captureTypes := fs.String("capture-content-types", "application/json,text/*", "comma-separated content-type filters")
	harOut := fs.String("har-out", "", "export captured entries to HAR file on exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	caManager, err := ca.EnsureCA(*caDir)
	if err != nil {
		return err
	}

	certPath, keyPath := caManager.Paths()
	log.Printf("CA loaded: cert=%s key=%s", certPath, keyPath)

	hosts := splitCommaList(*mitmHosts)
	rewriteRules := []policy.RewriteRule{}
	scriptRules := []policy.ScriptRule{}

	parsedModule, err := module.LoadAllWithArgs(
		splitCommaList(*moduleURLs),
		splitCommaList(*moduleFiles),
		module.ParseModuleArgs(*moduleArgs),
	)
	if err != nil {
		return err
	}
	if parsedModule != nil {
		hosts = append(hosts, parsedModule.MITMHosts...)
		hosts = dedupStrings(hosts)
		rewriteRules = append(rewriteRules, parsedModule.Rewrite...)
		scriptRules = append(scriptRules, parsedModule.Scripts...)
	}
	log.Printf("policy loaded: mitm_hosts=%d rewrite_rules=%d scripts=%d", len(hosts), len(rewriteRules), len(scriptRules))
	log.Printf("capture config: enabled=%v max_entries=%d max_body_bytes=%d har_out=%q", *captureEnabled, *captureMaxEntries, *captureMaxBodyBytes, *harOut)

	srv := server.New(server.Config{
		ListenAddr:  *listen,
		DialTimeout: *dialTimeout,
		MITMHosts:   hosts,
		Rewrite:     rewriteRules,
		Scripts:     scriptRules,
		Capture: capture.Config{
			Enabled:      *captureEnabled,
			MaxEntries:   *captureMaxEntries,
			MaxBodyBytes: *captureMaxBodyBytes,
			ContentTypes: splitCommaList(*captureTypes),
		},
	}, caManager, log.Default())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	listenErr := srv.ListenAndServe(ctx)
	if *captureEnabled && strings.TrimSpace(*harOut) != "" {
		entries := srv.CaptureEntries()
		if err := har.ExportToFile(*harOut, entries); err != nil {
			return fmt.Errorf("export har: %w", err)
		}
		log.Printf("HAR exported: %s (entries=%d)", *harOut, len(entries))
	}
	if listenErr != nil && !errors.Is(listenErr, context.Canceled) {
		return listenErr
	}
	return nil
}

func runCA(args []string) error {
	if len(args) == 0 {
		return errors.New("missing subcommand: init|export")
	}

	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("ca init", flag.ContinueOnError)
		caDir := fs.String("ca-dir", "~/.gomitm/ca", "CA storage directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		m, err := ca.Init(*caDir)
		if err != nil {
			return err
		}
		certPath, keyPath := m.Paths()
		fmt.Printf("CA initialized\ncert: %s\nkey:  %s\n", certPath, keyPath)
		return nil

	case "export":
		fs := flag.NewFlagSet("ca export", flag.ContinueOnError)
		caDir := fs.String("ca-dir", "~/.gomitm/ca", "CA storage directory")
		out := fs.String("out", "", "output file path for CA cert")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *out == "" {
			return errors.New("--out is required")
		}
		m, err := ca.Load(*caDir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
		if err := m.ExportCert(*out); err != nil {
			return err
		}
		fmt.Printf("CA certificate exported: %s\n", *out)
		return nil

	default:
		return fmt.Errorf("unknown ca subcommand: %s", args[0])
	}
}

func splitCommaList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func usage() {
	fmt.Fprintf(os.Stderr, `gomitm - high performance SOCKS5 MITM proxy (M1 skeleton)

Usage:
  gomitm serve [flags]
  gomitm ca init [flags]
  gomitm ca export [flags]

Examples:
  gomitm serve --listen :1080 --mitm-hosts "*.googlevideo.com,youtubei.googleapis.com"
  gomitm serve --listen :1080 --module-urls "https://example.com/YouTubeNoAd.sgmodule"
  gomitm ca init --ca-dir ~/.gomitm/ca
  gomitm ca export --ca-dir ~/.gomitm/ca --out ./gomitm-ca.crt
`)
}
