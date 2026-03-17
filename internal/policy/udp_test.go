package policy

import "testing"

func TestUDPRuleMatchHost(t *testing.T) {
	cases := []struct {
		rule UDPRule
		host string
		want bool
	}{
		{UDPRule{Domain: "youtubei.googleapis.com"}, "youtubei.googleapis.com", true},
		{UDPRule{Domain: "youtubei.googleapis.com"}, "YOUTubeI.googleapis.com.", true},
		{UDPRule{Domain: "youtubei.googleapis.com"}, "a.youtubei.googleapis.com", false},
		{UDPRule{DomainSuffix: "googlevideo.com"}, "googlevideo.com", true},
		{UDPRule{DomainSuffix: "googlevideo.com"}, "rr5---sn-a5mlrnl6.googlevideo.com", true},
		{UDPRule{DomainSuffix: "googlevideo.com"}, "googlevideo.com.evil", false},
	}
	for _, c := range cases {
		if got := c.rule.MatchHost(c.host); got != c.want {
			t.Fatalf("rule=%+v host=%q got=%v want=%v", c.rule, c.host, got, c.want)
		}
	}
}
