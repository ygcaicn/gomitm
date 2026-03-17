package module

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gomitm/internal/policy"
)

type Parsed struct {
	MITMHosts []string
	Rewrite   []policy.RewriteRule
	Scripts   []policy.ScriptRule
}

type Source struct {
	Name      string
	Enabled   bool
	Path      string
	Arguments map[string]string
}

func LoadAll(urls []string, files []string) (*Parsed, error) {
	return LoadAllWithArgs(urls, files, nil)
}

func LoadAllWithArgs(urls []string, files []string, args map[string]string) (*Parsed, error) {
	sources := make([]Source, 0, len(urls)+len(files))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		sources = append(sources, Source{Enabled: true, Path: u, Arguments: cloneArgs(args)})
	}

	for _, f := range files {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		sources = append(sources, Source{Enabled: true, Path: f, Arguments: cloneArgs(args)})
	}
	return LoadSources(sources)
}

func LoadSources(sources []Source) (*Parsed, error) {
	combined := &Parsed{}
	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		path := strings.TrimSpace(src.Path)
		if path == "" {
			continue
		}
		var (
			m   *Parsed
			err error
		)
		if isURL(path) {
			m, err = LoadFromURLWithArgs(path, src.Arguments)
		} else {
			m, err = LoadFromFileWithArgs(path, src.Arguments)
		}
		if err != nil {
			if strings.TrimSpace(src.Name) != "" {
				return nil, fmt.Errorf("module %s: %w", src.Name, err)
			}
			return nil, err
		}
		combined.Merge(m)
	}
	combined.DedupHosts()
	if err := combined.LoadScriptCode(); err != nil {
		return nil, err
	}
	return combined, nil
}

func LoadFromURL(u string) (*Parsed, error) {
	return LoadFromURLWithArgs(u, nil)
}

func LoadFromURLWithArgs(u string, args map[string]string) (*Parsed, error) {
	if !strings.HasPrefix(strings.ToLower(u), "http://") && !strings.HasPrefix(strings.ToLower(u), "https://") {
		return nil, fmt.Errorf("module url must start with http/https: %s", u)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("fetch module %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch module %s: status %d", u, resp.StatusCode)
	}
	p, err := ParseWithArgs(resp.Body, args)
	if err != nil {
		return nil, fmt.Errorf("parse module %s: %w", u, err)
	}
	return p, nil
}

func LoadFromFile(path string) (*Parsed, error) {
	return LoadFromFileWithArgs(path, nil)
}

func LoadFromFileWithArgs(path string, args map[string]string) (*Parsed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open module file %s: %w", path, err)
	}
	defer f.Close()
	p, err := ParseWithArgs(f, args)
	if err != nil {
		return nil, fmt.Errorf("parse module file %s: %w", path, err)
	}
	resolveRelativeScriptPaths(p, filepath.Dir(path))
	return p, nil
}

func Parse(r io.Reader) (*Parsed, error) {
	return ParseWithArgs(r, nil)
}

func ParseWithArgs(r io.Reader, args map[string]string) (*Parsed, error) {
	if r == nil {
		return nil, errors.New("nil reader")
	}

	out := &Parsed{}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	section := ""
	defaultArgs := map[string]string{}
	overrideArgs := args
	for s.Scan() {
		raw := strings.TrimSpace(s.Text())
		if raw == "" || strings.HasPrefix(raw, ";") {
			continue
		}

		if strings.HasPrefix(raw, "#!arguments=") {
			meta := strings.TrimSpace(strings.TrimPrefix(raw, "#!arguments="))
			for k, v := range parseArgumentsDefinition(meta) {
				defaultArgs[k] = v
			}
			continue
		}
		if strings.HasPrefix(raw, "#") {
			continue
		}

		line := substituteArgs(raw, mergeArgs(defaultArgs, overrideArgs))
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}

		switch section {
		case "mitm":
			parseMITMLine(out, line)
		case "url rewrite":
			rule, ok := parseRewriteLine(line)
			if ok {
				out.Rewrite = append(out.Rewrite, rule)
			}
		case "script":
			rule, ok := parseScriptLine(line)
			if ok {
				out.Scripts = append(out.Scripts, rule)
			}
		}
	}

	if err := s.Err(); err != nil {
		return nil, err
	}

	out.DedupHosts()
	return out, nil
}

func ParseModuleArgs(v string) map[string]string {
	return parseModuleArgs(v)
}

func (p *Parsed) Merge(other *Parsed) {
	if other == nil {
		return
	}
	p.MITMHosts = append(p.MITMHosts, other.MITMHosts...)
	p.Rewrite = append(p.Rewrite, other.Rewrite...)
	p.Scripts = append(p.Scripts, other.Scripts...)
}

func (p *Parsed) DedupHosts() {
	if p == nil || len(p.MITMHosts) == 0 {
		return
	}
	seen := make(map[string]struct{}, len(p.MITMHosts))
	out := make([]string, 0, len(p.MITMHosts))
	for _, h := range p.MITMHosts {
		h = normalizeHostPattern(h)
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	sort.Strings(out)
	p.MITMHosts = out
}

func parseMITMLine(out *Parsed, line string) {
	if out == nil {
		return
	}
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return
	}
	key := strings.TrimSpace(strings.ToLower(parts[0]))
	if key != "hostname" {
		return
	}
	value := strings.TrimSpace(parts[1])
	value = strings.ReplaceAll(value, "%APPEND%", "")
	for _, h := range strings.Split(value, ",") {
		h = normalizeHostPattern(h)
		if h != "" {
			out.MITMHosts = append(out.MITMHosts, h)
		}
	}
}

func normalizeHostPattern(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimSuffix(v, ".")
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "*.") && len(v) > 2 {
		return v
	}
	if strings.Contains(v, "*") {
		return ""
	}
	return v
}

func parseRewriteLine(line string) (policy.RewriteRule, bool) {
	idx := strings.LastIndex(line, " - ")
	if idx <= 0 {
		return policy.RewriteRule{}, false
	}
	patternText := strings.TrimSpace(line[:idx])
	actionText := strings.ToLower(strings.TrimSpace(line[idx+3:]))
	if patternText == "" {
		return policy.RewriteRule{}, false
	}

	action := policy.RewriteAction(actionText)
	if action != policy.RewriteReject && action != policy.RewriteReject200 {
		return policy.RewriteRule{}, false
	}

	re, err := regexp.Compile(patternText)
	if err != nil {
		return policy.RewriteRule{}, false
	}
	return policy.RewriteRule{Pattern: re, Action: action, Raw: line}, true
}

func parseArgumentsDefinition(v string) map[string]string {
	out := make(map[string]string)
	for _, part := range splitTopLevelCSV(v) {
		k, val, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		value := strings.TrimSpace(val)
		if key != "" {
			out[key] = value
		}
	}
	return out
}

func parseModuleArgs(v string) map[string]string {
	out := make(map[string]string)
	for _, part := range splitTopLevelCSV(v) {
		k, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		value := strings.TrimSpace(val)
		if key != "" {
			out[key] = value
		}
	}
	return out
}

func mergeArgs(defaults, overrides map[string]string) map[string]string {
	if len(defaults) == 0 && len(overrides) == 0 {
		return nil
	}
	out := make(map[string]string, len(defaults)+len(overrides))
	for k, v := range defaults {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

func substituteArgs(line string, args map[string]string) string {
	if len(args) == 0 || line == "" {
		return line
	}
	out := line
	for k, v := range args {
		token := "{{{" + k + "}}}"
		out = strings.ReplaceAll(out, token, v)
	}
	return out
}

func parseScriptLine(line string) (policy.ScriptRule, bool) {
	name, rest, ok := strings.Cut(line, "=")
	if !ok {
		return policy.ScriptRule{}, false
	}
	name = strings.TrimSpace(name)
	rest = strings.TrimSpace(rest)
	if name == "" || rest == "" {
		return policy.ScriptRule{}, false
	}

	parts := splitTopLevelCSV(rest)
	if len(parts) == 0 {
		return policy.ScriptRule{}, false
	}

	r := policy.ScriptRule{Name: name}
	for _, part := range parts {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := trimQuotes(strings.TrimSpace(v))
		switch key {
		case "type":
			r.Type = policy.ScriptType(strings.ToLower(val))
		case "pattern":
			re, err := regexp.Compile(val)
			if err != nil {
				return policy.ScriptRule{}, false
			}
			r.Pattern = re
		case "script-path":
			r.ScriptPath = val
		case "requires-body":
			r.RequiresBody = strings.EqualFold(val, "true")
		case "binary-body-mode":
			r.BinaryBodyMode = strings.EqualFold(val, "true")
		case "max-size":
			n, err := strconv.ParseInt(val, 10, 64)
			if err == nil {
				r.MaxSize = n
			}
		case "argument":
			r.Argument = val
		}
	}

	if r.Type == "" {
		r.Type = policy.ScriptTypeHTTPResponse
	}
	if r.Pattern == nil || r.ScriptPath == "" {
		return policy.ScriptRule{}, false
	}
	return r, true
}

func splitTopLevelCSV(v string) []string {
	var (
		parts    []string
		inQuotes bool
		escape   bool
		braces   int
		start    int
	)

	for i := 0; i < len(v); i++ {
		ch := v[i]
		if escape {
			escape = false
			continue
		}
		if ch == '\\' {
			escape = true
			continue
		}
		switch ch {
		case '"':
			inQuotes = !inQuotes
		case '{':
			if !inQuotes {
				braces++
			}
		case '}':
			if !inQuotes && braces > 0 {
				braces--
			}
		case ',':
			if !inQuotes && braces == 0 {
				part := strings.TrimSpace(v[start:i])
				if part != "" {
					parts = append(parts, part)
				}
				start = i + 1
			}
		}
	}

	last := strings.TrimSpace(v[start:])
	if last != "" {
		parts = append(parts, last)
	}
	return parts
}

func trimQuotes(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`)
	}
	return v
}

func (p *Parsed) LoadScriptCode() error {
	if p == nil || len(p.Scripts) == 0 {
		return nil
	}
	cache := make(map[string]string)
	client := &http.Client{Timeout: 20 * time.Second}
	for i := range p.Scripts {
		path := strings.TrimSpace(p.Scripts[i].ScriptPath)
		if path == "" {
			continue
		}
		if code, ok := cache[path]; ok {
			p.Scripts[i].Code = code
			continue
		}
		code, err := readScriptCode(client, path)
		if err != nil {
			return fmt.Errorf("load script %s: %w", path, err)
		}
		cache[path] = code
		p.Scripts[i].Code = code
	}
	return nil
}

func readScriptCode(client *http.Client, path string) (string, error) {
	lower := strings.ToLower(path)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resp, err := client.Get(path)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("status %d", resp.StatusCode)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func isURL(v string) bool {
	lower := strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func cloneArgs(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func resolveRelativeScriptPaths(p *Parsed, moduleDir string) {
	if p == nil || len(p.Scripts) == 0 {
		return
	}
	for i := range p.Scripts {
		scriptPath := strings.TrimSpace(p.Scripts[i].ScriptPath)
		if scriptPath == "" || isURL(scriptPath) || filepath.IsAbs(scriptPath) {
			continue
		}
		p.Scripts[i].ScriptPath = filepath.Clean(filepath.Join(moduleDir, scriptPath))
	}
}
