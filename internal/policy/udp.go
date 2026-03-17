package policy

import "strings"

type UDPRule struct {
	Domain       string
	DomainSuffix string
	Raw          string
}

func (r UDPRule) MatchHost(host string) bool {
	host = normalizeUDPHost(host)
	if host == "" {
		return false
	}
	if r.Domain != "" {
		return host == normalizeUDPHost(r.Domain)
	}
	if r.DomainSuffix != "" {
		suffix := normalizeUDPHost(r.DomainSuffix)
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	return false
}

func normalizeUDPHost(v string) string {
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(v)), ".")
}
