package policy

import "regexp"

type ScriptType string

const (
	ScriptTypeHTTPResponse ScriptType = "http-response"
	ScriptTypeHTTPRequest  ScriptType = "http-request"
)

type ScriptRule struct {
	Name           string
	Type           ScriptType
	Pattern        *regexp.Regexp
	ScriptPath     string
	RequiresBody   bool
	BinaryBodyMode bool
	MaxSize        int64
	Argument       string
	Code           string
}

func (r ScriptRule) Match(url string) bool {
	if r.Pattern == nil {
		return false
	}
	return r.Pattern.MatchString(url)
}
