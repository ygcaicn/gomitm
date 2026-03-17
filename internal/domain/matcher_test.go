package domain

import "testing"

func TestMatcher(t *testing.T) {
	m := NewMatcher([]string{"*.googlevideo.com", "youtubei.googleapis.com", "example.org"})

	cases := []struct {
		host string
		want bool
	}{
		{"r1---sn-xyz.googlevideo.com", true},
		{"googlevideo.com", false},
		{"youtubei.googleapis.com", true},
		{"YouTubeI.GooGleApis.com:443", true},
		{"example.org", true},
		{"sub.example.org", false},
		{"", false},
	}

	for _, c := range cases {
		got := m.Match(c.host)
		if got != c.want {
			t.Fatalf("host=%q got=%v want=%v", c.host, got, c.want)
		}
	}
}
