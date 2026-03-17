package script

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gomitm/internal/policy"

	"github.com/dop251/goja"
)

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) ApplyRequestScripts(req *http.Request, rules []policy.ScriptRule) (bool, error) {
	if req == nil || len(rules) == 0 {
		return false, nil
	}

	applied := false
	for _, rule := range rules {
		if rule.Type != policy.ScriptTypeHTTPRequest || !rule.Match(fullURL(req)) {
			continue
		}
		if strings.TrimSpace(rule.Code) == "" {
			continue
		}

		var bodyBytes []byte
		if rule.RequiresBody {
			var err error
			bodyBytes, err = readAndResetRequestBody(req)
			if err != nil {
				return applied, err
			}
			if rule.MaxSize > 0 && int64(len(bodyBytes)) > rule.MaxSize {
				continue
			}
		}

		changed, err := executeRequestScript(rule, req, bodyBytes)
		if err != nil {
			return applied, fmt.Errorf("script %s: %w", rule.Name, err)
		}
		if changed {
			applied = true
		}
	}
	return applied, nil
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

func executeRequestScript(rule policy.ScriptRule, req *http.Request, body []byte) (bool, error) {
	vm := goja.New()

	reqHeaders := headersToJS(req.Header)
	requestObj := map[string]any{
		"url":     fullURL(req),
		"method":  req.Method,
		"headers": reqHeaders,
		"body":    string(body),
	}
	if rule.BinaryBodyMode {
		requestObj["bodyBytes"] = append([]byte(nil), body...)
	}

	if err := vm.Set("$request", requestObj); err != nil {
		return false, err
	}
	if err := vm.Set("$argument", rule.Argument); err != nil {
		return false, err
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
		return false, err
	}

	if _, err := vm.RunString(rule.Code); err != nil {
		return false, err
	}
	if !doneCalled {
		return false, nil
	}

	if override == nil {
		return true, nil
	}

	if v, ok := override["url"]; ok {
		newURL := strings.TrimSpace(fmt.Sprint(v))
		if newURL != "" {
			parsed, err := url.Parse(newURL)
			if err != nil {
				return false, err
			}
			req.URL = parsed
			req.Host = parsed.Host
		}
	}
	if v, ok := override["method"]; ok {
		method := strings.TrimSpace(strings.ToUpper(fmt.Sprint(v)))
		if method != "" {
			req.Method = method
		}
	}
	if v, ok := override["headers"]; ok {
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		applyHeadersOverride(req.Header, v)
	}

	newBody := body
	if v, ok := override["bodyBytes"]; ok {
		if b, ok := toBytes(v); ok {
			newBody = b
		}
	}
	if v, ok := override["body"]; ok {
		newBody = []byte(fmt.Sprint(v))
	}
	if rule.RequiresBody {
		req.Body = io.NopCloser(bytes.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
		req.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	}
	return true, nil
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
			applyHeadersOverride(out.Header, v)
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

func readAndResetRequestBody(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	if req.Header != nil {
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
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
	host = normalizeHTTPSHost(host)
	return "https://" + host + req.URL.RequestURI()
}

func normalizeHTTPSHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if p == "443" {
			return h
		}
		return net.JoinHostPort(h, p)
	}
	return host
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

func applyHeadersOverride(dst http.Header, v any) {
	if dst == nil {
		return
	}
	switch hm := v.(type) {
	case map[string]any:
		for k, vv := range hm {
			dst.Set(k, fmt.Sprint(vv))
		}
	case map[string]string:
		for k, vv := range hm {
			dst.Set(k, vv)
		}
	}
}
