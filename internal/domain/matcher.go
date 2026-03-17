package domain

import (
	"net"
	"strings"
)

type Matcher struct {
	exact    map[string]struct{}
	suffixes []string
}

func NewMatcher(patterns []string) *Matcher {
	m := &Matcher{exact: make(map[string]struct{})}
	for _, p := range patterns {
		p = normalizeHost(p)
		if p == "" {
			continue
		}

		if strings.HasPrefix(p, "*.") {
			s := strings.TrimPrefix(p, "*")
			if s != "" {
				m.suffixes = append(m.suffixes, s)
			}
			continue
		}
		m.exact[p] = struct{}{}
	}
	return m
}

func (m *Matcher) Match(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	if _, ok := m.exact[host]; ok {
		return true
	}
	for _, s := range m.suffixes {
		if strings.HasSuffix(host, s) && host != strings.TrimPrefix(s, ".") {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	return host
}
