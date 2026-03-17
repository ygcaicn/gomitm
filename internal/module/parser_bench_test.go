package module

import (
	"strings"
	"testing"
)

func BenchmarkParseModule(b *testing.B) {
	content := `
#!arguments=foo:bar, enable:true

[Rule]
AND,((DOMAIN-SUFFIX,googlevideo.com), (PROTOCOL,UDP)),REJECT

[URL Rewrite]
^https?:\/\/[\w-]+\.googlevideo\.com\/initplayback.+\u0026oad - reject-200
^https?:\/\/example\.com\/foo - reject

[Script]
youtube.response = type=http-response, pattern=^https:\/\/youtubei\.googleapis\.com\/.+$, script-path=https://example.com/youtube.response.js, requires-body=true, binary-body-mode=true, max-size=0, argument="{\"foo\":\"{{{foo}}}\"}"

[MITM]
hostname = %APPEND% *.googlevideo.com, youtubei.googleapis.com
`

	args := map[string]string{"foo": "baz"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := ParseWithArgs(strings.NewReader(content), args)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSplitTopLevelCSV(b *testing.B) {
	v := `type=http-response, pattern=^https:\/\/youtubei\.googleapis\.com\/.+$, script-path=https://example.com/youtube.response.js, requires-body=true, binary-body-mode=true, max-size=0, argument="{\"lyricLang\":\"ja\",\"captionLang\":\"zh-Hans\"}"`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = splitTopLevelCSV(v)
	}
}
