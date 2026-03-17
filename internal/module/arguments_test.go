package module

import (
	"strings"
	"testing"
)

func TestParseWithArgsSubstitution(t *testing.T) {
	content := `
#!arguments=foo:bar, enable:true

[Script]
demo = type=http-response, pattern=^https:\/\/example\.com\/$, script-path=https://example.com/demo.js, argument="{\"foo\":\"{{{foo}}}\",\"enable\":{{{enable}}}}"
`

	p, err := ParseWithArgs(strings.NewReader(content), map[string]string{"foo": "baz"})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(p.Scripts) != 1 {
		t.Fatalf("scripts=%d", len(p.Scripts))
	}
	got := p.Scripts[0].Argument
	want := `{"foo":"baz","enable":true}`
	if got != want {
		t.Fatalf("argument got=%q want=%q", got, want)
	}
}

func TestParseModuleArgsOverrides(t *testing.T) {
	args := parseModuleArgs("a=1,b=true,c=zh-Hans")
	if args["a"] != "1" || args["b"] != "true" || args["c"] != "zh-Hans" {
		t.Fatalf("unexpected args: %#v", args)
	}
}
