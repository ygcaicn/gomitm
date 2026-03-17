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
