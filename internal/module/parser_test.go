package module

import (
	"strings"
	"testing"

	"gomitm/internal/policy"
)

func TestParse(t *testing.T) {
	content := `
#!name=YouTubeNoAds

[URL Rewrite]
^https?:\/\/[\w-]+\.googlevideo\.com\/initplayback.+&oad - reject-200
^https?:\/\/example\.com\/foo - reject
invalid line

[Rule]
AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT
AND,((DOMAIN,youtubei.googleapis.com), (PROTOCOL,UDP)),REJECT

[MITM]
hostname = %APPEND% *.googlevideo.com, youtubei.googleapis.com
`

	p, err := Parse(strings.NewReader(content))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(p.Rewrite) != 2 {
		t.Fatalf("rewrite count got=%d want=2", len(p.Rewrite))
	}
	if p.Rewrite[0].Action != policy.RewriteReject200 {
		t.Fatalf("rewrite[0] action got=%s", p.Rewrite[0].Action)
	}
	if p.Rewrite[1].Action != policy.RewriteReject {
		t.Fatalf("rewrite[1] action got=%s", p.Rewrite[1].Action)
	}

	wantHosts := map[string]bool{
		"*.googlevideo.com":       true,
		"youtubei.googleapis.com": true,
	}
	if len(p.MITMHosts) != 2 {
		t.Fatalf("mitm hosts count got=%d want=2", len(p.MITMHosts))
	}
	for _, h := range p.MITMHosts {
		if !wantHosts[h] {
			t.Fatalf("unexpected host: %s", h)
		}
	}
	if len(p.UDPRules) != 2 {
		t.Fatalf("udp rules count got=%d want=2", len(p.UDPRules))
	}
	if p.UDPRules[0].DomainSuffix != "googlevideo.com" {
		t.Fatalf("udp rule[0] got=%+v", p.UDPRules[0])
	}
	if p.UDPRules[1].Domain != "youtubei.googleapis.com" {
		t.Fatalf("udp rule[1] got=%+v", p.UDPRules[1])
	}
}

func TestParseRewriteLine(t *testing.T) {
	line := `^https?:\/\/a\.com - reject-200`
	r, ok := parseRewriteLine(line)
	if !ok {
		t.Fatal("parse rewrite failed")
	}
	if !r.Match("https://a.com") {
		t.Fatal("regex should match")
	}
}

func TestParseRuleLine(t *testing.T) {
	r, ok := parseRuleLine(`AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT`)
	if !ok {
		t.Fatal("expected rule parse success")
	}
	if r.DomainSuffix != "googlevideo.com" {
		t.Fatalf("domain-suffix got=%q", r.DomainSuffix)
	}

	r2, ok := parseRuleLine(`AND,((DOMAIN,youtubei.googleapis.com), (PROTOCOL,UDP)),REJECT`)
	if !ok {
		t.Fatal("expected domain rule parse success")
	}
	if r2.Domain != "youtubei.googleapis.com" {
		t.Fatalf("domain got=%q", r2.Domain)
	}

	if _, ok := parseRuleLine(`DOMAIN-SUFFIX,googlevideo.com,REJECT`); ok {
		t.Fatal("expected unsupported rule format to be ignored")
	}
}

func TestLoadFromURLRequiresHTTPS(t *testing.T) {
	_, err := LoadFromURL("http://example.com/demo.sgmodule")
	if err == nil {
		t.Fatal("expected http module url to be rejected")
	}
}
