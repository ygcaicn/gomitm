package policy

import "regexp"

type RewriteAction string

const (
	RewriteReject    RewriteAction = "reject"
	RewriteReject200 RewriteAction = "reject-200"
)

type RewriteRule struct {
	Pattern *regexp.Regexp
	Action  RewriteAction
	Raw     string
}

func (r RewriteRule) Match(url string) bool {
	if r.Pattern == nil {
		return false
	}
	return r.Pattern.MatchString(url)
}
