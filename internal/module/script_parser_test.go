package module

import (
	"strings"
	"testing"
)

func TestParseScriptSection(t *testing.T) {
	content := `
[Script]
youtube.response = type=http-response, pattern=^https:\/\/youtubei\.googleapis\.com\/.+$, script-path=https://example.com/youtube.response.js, requires-body=true, binary-body-mode=true, max-size=0, argument="{\"a\":1,\"b\":\"x,y\"}"
`

	p, err := Parse(strings.NewReader(content))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(p.Scripts) != 1 {
		t.Fatalf("script count got=%d want=1", len(p.Scripts))
	}
	s := p.Scripts[0]
	if s.Name != "youtube.response" {
		t.Fatalf("name got=%q", s.Name)
	}
	if s.Type != "http-response" {
		t.Fatalf("type got=%q", s.Type)
	}
	if s.ScriptPath != "https://example.com/youtube.response.js" {
		t.Fatalf("script-path got=%q", s.ScriptPath)
	}
	if !s.RequiresBody {
		t.Fatal("requires-body should be true")
	}
	if !s.BinaryBodyMode {
		t.Fatal("binary-body-mode should be true")
	}
	if s.MaxSize != 0 {
		t.Fatalf("max-size got=%d", s.MaxSize)
	}
	if s.Argument != "{\"a\":1,\"b\":\"x,y\"}" {
		t.Fatalf("argument got=%q", s.Argument)
	}
	if s.Pattern == nil || !s.Pattern.MatchString("https://youtubei.googleapis.com/youtubei/v1/player") {
		t.Fatal("pattern should match")
	}
}

func TestSplitTopLevelCSV(t *testing.T) {
	parts := splitTopLevelCSV(`a=1,b="x,y",c={"k":"v,v2"}`)
	if len(parts) != 3 {
		t.Fatalf("parts count got=%d", len(parts))
	}
	if parts[1] != `b="x,y"` {
		t.Fatalf("unexpected part[1]=%q", parts[1])
	}
}
