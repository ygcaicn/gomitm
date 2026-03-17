package script

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"gomitm/internal/policy"

	"github.com/dop251/goja"
)

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) ApplyResponseScripts(req *http.Request, resp *http.Response, rules []policy.ScriptRule) (bool, error) {
	if req == nil || resp == nil || len(rules) == 0 {
		return false, nil
	}

	applied := false
	for _, rule := range rules {
		if rule.Type != policy.ScriptTypeHTTPResponse || !rule.Match(fullURL(req)) {
			continue
		}
		if strings.TrimSpace(rule.Code) == "" {
			continue
		}

		bodyBytes, err := readAndResetBody(resp)
		if err != nil {
			return applied, err
		}

		if rule.MaxSize > 0 && int64(len(bodyBytes)) > rule.MaxSize {
			continue
		}

		newResp, changed, err := executeResponseScript(rule, req, resp, bodyBytes)
		if err != nil {
			return applied, fmt.Errorf("script %s: %w", rule.Name, err)
		}
		if changed {
			*resp = *newResp
			applied = true
		}
	}
	return applied, nil
}

func executeResponseScript(rule policy.ScriptRule, req *http.Request, resp *http.Response, body []byte) (*http.Response, bool, error) {
	vm := goja.New()

	reqHeaders := headersToJS(req.Header)
	respHeaders := headersToJS(resp.Header)

	responseObj := map[string]any{
		"status":  resp.StatusCode,
		"headers": respHeaders,
		"body":    string(body),
	}
	if rule.BinaryBodyMode {
		responseObj["bodyBytes"] = append([]byte(nil), body...)
	}

	if err := vm.Set("$request", map[string]any{
		"url":     fullURL(req),
		"method":  req.Method,
		"headers": reqHeaders,
	}); err != nil {
		return nil, false, err
	}
	if err := vm.Set("$response", responseObj); err != nil {
		return nil, false, err
	}
	if err := vm.Set("$argument", rule.Argument); err != nil {
		return nil, false, err
	}

	var (
		doneCalled bool
		override   map[string]any
	)
	if err := vm.Set("$done", func(call goja.FunctionCall) goja.Value {
		doneCalled = true
		if len(call.Arguments) > 0 {
			if m, ok := call.Arguments[0].Export().(map[string]any); ok {
				override = m
			}
		}
		return goja.Undefined()
	}); err != nil {
		return nil, false, err
	}

	if _, err := vm.RunString(rule.Code); err != nil {
		return nil, false, err
	}
	if !doneCalled {
		return resp, false, nil
	}

	out := cloneResponse(resp)

	if override != nil {
		if v, ok := override["status"]; ok {
			if n, ok := toInt(v); ok && n > 0 {
				out.StatusCode = n
				out.Status = fmt.Sprintf("%d %s", n, http.StatusText(n))
			}
		}
		if v, ok := override["headers"]; ok {
			if hm, ok := v.(map[string]any); ok {
				for k, vv := range hm {
					out.Header.Set(k, fmt.Sprint(vv))
				}
			}
		}
		if v, ok := override["bodyBytes"]; ok {
			if b, ok := toBytes(v); ok {
				body = b
			}
		}
		if v, ok := override["body"]; ok {
			body = []byte(fmt.Sprint(v))
		}
	}

	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	if out.Header == nil {
		out.Header = make(http.Header)
	}
	out.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return out, true, nil
}

func readAndResetBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if resp.Header != nil {
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	return body, nil
}

func headersToJS(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ",")
	}
	return out
}

func fullURL(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	if req.URL.IsAbs() {
		return req.URL.String()
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	return "https://" + host + req.URL.RequestURI()
}

func cloneResponse(resp *http.Response) *http.Response {
	out := new(http.Response)
	*out = *resp
	if resp.Header != nil {
		out.Header = resp.Header.Clone()
	}
	return out
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case int32:
		return int(n), true
	case float64:
		return int(n), true
	case float32:
		return int(n), true
	default:
		return 0, false
	}
}

func toBytes(v any) ([]byte, bool) {
	switch b := v.(type) {
	case []byte:
		return append([]byte(nil), b...), true
	case goja.ArrayBuffer:
		return append([]byte(nil), b.Bytes()...), true
	case string:
		return []byte(b), true
	case []any:
		out := make([]byte, 0, len(b))
		for _, item := range b {
			n, ok := toInt(item)
			if !ok || n < 0 || n > math.MaxUint8 {
				return nil, false
			}
			out = append(out, byte(n))
		}
		return out, true
	default:
		return nil, false
	}
}
