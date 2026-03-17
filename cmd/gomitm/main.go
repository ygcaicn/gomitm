package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gomitm/internal/admin"
	"gomitm/internal/ca"
	"gomitm/internal/capture"
	"gomitm/internal/config"
	"gomitm/internal/har"
	"gomitm/internal/module"
	"gomitm/internal/policy"
	"gomitm/internal/server"
)

const (
	defaultListen             = ":1080"
	defaultCADir              = "~/.gomitm/ca"
	defaultDialTimeout        = 10 * time.Second
	defaultCaptureMaxEntries  = 1000
	defaultCaptureMaxBody     = 2 * 1024 * 1024
	defaultCaptureContentType = "application/json,text/*"
)

type serveOptions struct {
	ConfigPath string

	Listen      string
	AdminListen string
	CADir       string
	DialTimeout time.Duration

	MITMHosts []string
	MITMAll   bool

	ModuleSources []module.Source

	CaptureEnabled      bool
	CaptureMaxEntries   int
	CaptureMaxBodyBytes int64
	CaptureTypes        []string
	HAROut              string
}

func defaultServeOptions() serveOptions {
	return serveOptions{
		Listen:              defaultListen,
		CADir:               defaultCADir,
		DialTimeout:         defaultDialTimeout,
		CaptureMaxEntries:   defaultCaptureMaxEntries,
		CaptureMaxBodyBytes: defaultCaptureMaxBody,
		CaptureTypes:        splitCommaList(defaultCaptureContentType),
		ModuleSources:       []module.Source{},
	}
}

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
	opts, err := parseServeOptions(args)
	if err != nil {
		return err
	}

	caManager, err := ca.EnsureCA(opts.CADir)
	if err != nil {
		return err
	}

	certPath, keyPath := caManager.Paths()
	log.Printf("CA loaded: cert=%s key=%s", certPath, keyPath)

	hosts := append([]string{}, opts.MITMHosts...)
	rewriteRules := []policy.RewriteRule{}
	scriptRules := []policy.ScriptRule{}

	parsedModule, err := module.LoadSources(opts.ModuleSources)
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
	log.Printf("capture config: enabled=%v max_entries=%d max_body_bytes=%d har_out=%q", opts.CaptureEnabled, opts.CaptureMaxEntries, opts.CaptureMaxBodyBytes, opts.HAROut)

	srv := server.New(server.Config{
		ListenAddr:  opts.Listen,
		DialTimeout: opts.DialTimeout,
		MITMHosts:   hosts,
		MITMAll:     opts.MITMAll,
		Rewrite:     rewriteRules,
		Scripts:     scriptRules,
		Capture: capture.Config{
			Enabled:      opts.CaptureEnabled,
			MaxEntries:   opts.CaptureMaxEntries,
			MaxBodyBytes: opts.CaptureMaxBodyBytes,
			ContentTypes: opts.CaptureTypes,
		},
	}, caManager, log.Default())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var adminHTTP *http.Server
	if strings.TrimSpace(opts.AdminListen) != "" {
		adminHTTP = &http.Server{
			Addr:              opts.AdminListen,
			Handler:           admin.NewHandler(srv),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Printf("admin API listening on %s", opts.AdminListen)
			if err := adminHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("admin API error: %v", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = adminHTTP.Shutdown(shutdownCtx)
		}()
	}

	listenErr := srv.ListenAndServe(ctx)
	if opts.CaptureEnabled && strings.TrimSpace(opts.HAROut) != "" {
		entries := srv.CaptureEntries()
		if err := har.ExportToFile(opts.HAROut, entries); err != nil {
			return fmt.Errorf("export har: %w", err)
		}
		log.Printf("HAR exported: %s (entries=%d)", opts.HAROut, len(entries))
	}
	if listenErr != nil && !errors.Is(listenErr, context.Canceled) {
		return listenErr
	}
	return nil
}

func parseServeOptions(args []string) (serveOptions, error) {
	opts := defaultServeOptions()

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "", "config file path (YAML)")
	listen := fs.String("listen", "", "SOCKS5 listen address")
	caDir := fs.String("ca-dir", "", "CA storage directory")
	mitmHosts := fs.String("mitm-hosts", "", "comma-separated MITM hosts, e.g. *.googlevideo.com,youtubei.googleapis.com")
	mitmAll := fs.Bool("mitm-all", false, "MITM all HTTPS hosts on port 443")
	moduleURLs := fs.String("module-urls", "", "comma-separated sgmodule URLs")
	moduleFiles := fs.String("module-files", "", "comma-separated local sgmodule file paths")
	moduleArgs := fs.String("module-args", "", "module argument overrides, e.g. key1=value1,key2=true")
	dialTimeout := fs.String("dial-timeout", "", "upstream dial timeout (e.g. 10s)")
	captureEnabled := fs.Bool("capture-enabled", false, "enable MITM HTTP capture")
	captureMaxEntries := fs.Int("capture-max-entries", 0, "max in-memory capture entries")
	captureMaxBodyBytes := fs.Int64("capture-max-body-bytes", 0, "max captured response body size in bytes")
	captureTypes := fs.String("capture-content-types", "", "comma-separated content-type filters")
	harOut := fs.String("har-out", "", "export captured entries to HAR file on exit")
	adminListen := fs.String("admin-listen", "", "admin HTTP listen address, e.g. 127.0.0.1:9090")

	if err := fs.Parse(args); err != nil {
		return opts, err
	}

	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})

	if strings.TrimSpace(*configPath) != "" {
		opts.ConfigPath = strings.TrimSpace(*configPath)
		cfg, err := config.LoadFile(opts.ConfigPath)
		if err != nil {
			return opts, err
		}
		if err := applyConfigFile(&opts, cfg); err != nil {
			return opts, err
		}
	}

	if visited["listen"] {
		opts.Listen = strings.TrimSpace(*listen)
	}
	if visited["ca-dir"] {
		opts.CADir = strings.TrimSpace(*caDir)
	}
	if visited["admin-listen"] {
		opts.AdminListen = strings.TrimSpace(*adminListen)
	}
	if visited["mitm-hosts"] {
		opts.MITMHosts = splitCommaList(*mitmHosts)
	}
	if visited["mitm-all"] {
		opts.MITMAll = *mitmAll
	}
	cliModuleArgs := map[string]string{}
	if visited["module-args"] {
		cliModuleArgs = module.ParseModuleArgs(*moduleArgs)
	}
	if visited["module-urls"] {
		for _, u := range splitCommaList(*moduleURLs) {
			opts.ModuleSources = append(opts.ModuleSources, module.Source{
				Enabled:   true,
				Path:      u,
				Arguments: cloneMap(cliModuleArgs),
			})
		}
	}
	if visited["module-files"] {
		for _, f := range splitCommaList(*moduleFiles) {
			opts.ModuleSources = append(opts.ModuleSources, module.Source{
				Enabled:   true,
				Path:      f,
				Arguments: cloneMap(cliModuleArgs),
			})
		}
	}
	if visited["module-args"] && len(cliModuleArgs) > 0 {
		for i := range opts.ModuleSources {
			if opts.ModuleSources[i].Arguments == nil {
				opts.ModuleSources[i].Arguments = map[string]string{}
			}
			for k, v := range cliModuleArgs {
				opts.ModuleSources[i].Arguments[k] = v
			}
		}
	}
	if visited["dial-timeout"] {
		d, err := time.ParseDuration(strings.TrimSpace(*dialTimeout))
		if err != nil {
			return opts, fmt.Errorf("invalid --dial-timeout: %w", err)
		}
		opts.DialTimeout = d
	}
	if visited["capture-enabled"] {
		opts.CaptureEnabled = *captureEnabled
	}
	if visited["capture-max-entries"] {
		opts.CaptureMaxEntries = *captureMaxEntries
	}
	if visited["capture-max-body-bytes"] {
		opts.CaptureMaxBodyBytes = *captureMaxBodyBytes
	}
	if visited["capture-content-types"] {
		opts.CaptureTypes = splitCommaList(*captureTypes)
	}
	if visited["har-out"] {
		opts.HAROut = strings.TrimSpace(*harOut)
	}

	if opts.Listen == "" {
		opts.Listen = defaultListen
	}
	if opts.CADir == "" {
		opts.CADir = defaultCADir
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = defaultDialTimeout
	}
	if opts.CaptureMaxEntries <= 0 {
		opts.CaptureMaxEntries = defaultCaptureMaxEntries
	}
	if opts.CaptureMaxBodyBytes <= 0 {
		opts.CaptureMaxBodyBytes = defaultCaptureMaxBody
	}
	if len(opts.CaptureTypes) == 0 {
		opts.CaptureTypes = splitCommaList(defaultCaptureContentType)
	}
	return opts, nil
}

func applyConfigFile(opts *serveOptions, cfg *config.File) error {
	if opts == nil || cfg == nil {
		return nil
	}
	if cfg.Serve.Listen != "" {
		opts.Listen = strings.TrimSpace(cfg.Serve.Listen)
	}
	if cfg.Serve.AdminListen != "" {
		opts.AdminListen = strings.TrimSpace(cfg.Serve.AdminListen)
	}
	if cfg.Serve.CADir != "" {
		opts.CADir = strings.TrimSpace(cfg.Serve.CADir)
	}
	if strings.TrimSpace(cfg.Serve.DialTimeout) != "" {
		d, err := time.ParseDuration(strings.TrimSpace(cfg.Serve.DialTimeout))
		if err != nil {
			return fmt.Errorf("invalid config serve.dial_timeout: %w", err)
		}
		opts.DialTimeout = d
	}

	opts.MITMHosts = append([]string{}, cfg.MITM.Hosts...)
	opts.MITMAll = cfg.MITM.All
	opts.ModuleSources = nil
	for _, m := range cfg.Modules {
		enabled := true
		if m.Enable != nil {
			enabled = *m.Enable
		}
		if !enabled {
			continue
		}
		opts.ModuleSources = append(opts.ModuleSources, module.Source{
			Name:      m.Name,
			Enabled:   enabled,
			Path:      resolveConfigPath(opts.ConfigPath, strings.TrimSpace(m.Path)),
			Arguments: stringifyArgs(m.Arguments),
		})
	}

	opts.CaptureEnabled = cfg.Capture.Enabled
	if cfg.Capture.MaxEntries > 0 {
		opts.CaptureMaxEntries = cfg.Capture.MaxEntries
	}
	if cfg.Capture.MaxBodyBytes > 0 {
		opts.CaptureMaxBodyBytes = cfg.Capture.MaxBodyBytes
	}
	if len(cfg.Capture.ContentTypes) > 0 {
		opts.CaptureTypes = append([]string{}, cfg.Capture.ContentTypes...)
	}
	if cfg.Capture.HAROut != "" {
		opts.HAROut = strings.TrimSpace(cfg.Capture.HAROut)
	}

	return nil
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringifyArgs(in map[string]any) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch vv := v.(type) {
		case string:
			out[k] = vv
		case bool:
			if vv {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		default:
			out[k] = fmt.Sprint(vv)
		}
	}
	return out
}

func resolveConfigPath(configPath, v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || filepath.IsAbs(v) {
		return v
	}
	if strings.TrimSpace(configPath) == "" {
		return v
	}
	return filepath.Clean(filepath.Join(filepath.Dir(configPath), v))
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
  gomitm serve --listen :1080 --mitm-all
  gomitm serve --listen :1080 --module-urls "https://example.com/YouTubeNoAd.sgmodule"
  gomitm serve --config ./config.yaml
  gomitm ca init --ca-dir ~/.gomitm/ca
  gomitm ca export --ca-dir ~/.gomitm/ca --out ./gomitm-ca.crt
`)
}
