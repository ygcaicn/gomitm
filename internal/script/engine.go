package script

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gomitm/internal/policy"

	"github.com/dop251/goja"
)

const defaultScriptTimeout = 200 * time.Millisecond

type Engine struct {
	scriptTimeout time.Duration
}

var (
	compatStoreMu sync.RWMutex
	compatStore   = map[string]string{}
	compatClient  = &http.Client{Timeout: 15 * time.Second}
)

func NewEngine() *Engine {
	return NewEngineWithTimeout(defaultScriptTimeout)
}

func NewEngineWithTimeout(timeout time.Duration) *Engine {
	if timeout <= 0 {
		timeout = defaultScriptTimeout
	}
	return &Engine{scriptTimeout: timeout}
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

		changed, err := executeRequestScript(rule, req, bodyBytes, e.scriptTimeout)
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

		newResp, changed, err := executeResponseScript(rule, req, resp, bodyBytes, e.scriptTimeout)
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

func executeRequestScript(rule policy.ScriptRule, req *http.Request, body []byte, timeout time.Duration) (bool, error) {
	vm := goja.New()
	if err := installSurgeCompat(vm); err != nil {
		return false, err
	}

	reqHeaders := headersToJS(req.Header)
	reqBody, err := jsBodyValue(vm, body, rule.BinaryBodyMode)
	if err != nil {
		return false, err
	}
	requestObj := map[string]any{
		"url":     fullURL(req),
		"method":  req.Method,
		"headers": reqHeaders,
		"body":    reqBody,
	}
	if rule.BinaryBodyMode {
		requestObj["bodyBytes"] = reqBody
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

	if _, err := runScriptWithTimeout(vm, rule.Code, timeout); err != nil {
		return false, err
	}
	if !doneCalled {
		return false, nil
	}

	if override == nil {
		return true, nil
	}
	override = unwrapDoneOverride(override, "request")

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
		if b, ok := toBytes(v); ok {
			newBody = b
		} else {
			newBody = []byte(fmt.Sprint(v))
		}
	}
	if rule.RequiresBody {
		req.Body = io.NopCloser(bytes.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
		req.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	}
	return true, nil
}

func executeResponseScript(rule policy.ScriptRule, req *http.Request, resp *http.Response, body []byte, timeout time.Duration) (*http.Response, bool, error) {
	vm := goja.New()
	if err := installSurgeCompat(vm); err != nil {
		return nil, false, err
	}

	reqHeaders := headersToJS(req.Header)
	respHeaders := headersToJS(resp.Header)
	respBody, err := jsBodyValue(vm, body, rule.BinaryBodyMode)
	if err != nil {
		return nil, false, err
	}

	responseObj := map[string]any{
		"status":  resp.StatusCode,
		"headers": respHeaders,
		"body":    respBody,
	}
	if rule.BinaryBodyMode {
		responseObj["bodyBytes"] = respBody
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

	if _, err := runScriptWithTimeout(vm, rule.Code, timeout); err != nil {
		return nil, false, err
	}
	if !doneCalled {
		return resp, false, nil
	}

	out := cloneResponse(resp)
	override = unwrapDoneOverride(override, "response")

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
			if b, ok := toBytes(v); ok {
				body = b
			} else {
				body = []byte(fmt.Sprint(v))
			}
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

func runScriptWithTimeout(vm *goja.Runtime, code string, timeout time.Duration) (goja.Value, error) {
	if vm == nil {
		return nil, errors.New("nil vm")
	}
	if timeout <= 0 {
		return vm.RunString(code)
	}
	type scriptResult struct {
		value goja.Value
		err   error
	}
	done := make(chan scriptResult, 1)
	go func() {
		v, err := vm.RunString(code)
		done <- scriptResult{value: v, err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-done:
		return res.value, res.err
	case <-timer.C:
		vm.Interrupt(errors.New("script timeout"))
		res := <-done
		if res.err == nil {
			return nil, fmt.Errorf("script timeout after %s", timeout)
		}
		errText := strings.ToLower(res.err.Error())
		if strings.Contains(errText, "interrupted") || strings.Contains(errText, "script timeout") {
			return nil, fmt.Errorf("script timeout after %s", timeout)
		}
		return nil, res.err
	}
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

func unwrapDoneOverride(override map[string]any, key string) map[string]any {
	if override == nil || key == "" {
		return override
	}
	raw, ok := override[key]
	if !ok {
		return override
	}
	switch v := raw.(type) {
	case map[string]any:
		return v
	case map[string]string:
		out := make(map[string]any, len(v))
		for k, vv := range v {
			out[k] = vv
		}
		return out
	default:
		return override
	}
}

func installSurgeCompat(vm *goja.Runtime) error {
	if vm == nil {
		return nil
	}
	if err := vm.Set("console", map[string]any{
		"log": func(args ...any) {
			if len(args) == 0 {
				return
			}
			out := make([]string, 0, len(args))
			for _, a := range args {
				out = append(out, fmt.Sprint(a))
			}
			log.Printf("[script] %s", strings.Join(out, " "))
		},
	}); err != nil {
		return err
	}
	if err := vm.Set("$persistentStore", map[string]any{
		"read": func(key any) string {
			k := strings.TrimSpace(fmt.Sprint(key))
			compatStoreMu.RLock()
			defer compatStoreMu.RUnlock()
			return compatStore[k]
		},
		"write": func(value any, key any) bool {
			k := strings.TrimSpace(fmt.Sprint(key))
			if k == "" {
				return false
			}
			compatStoreMu.Lock()
			compatStore[k] = fmt.Sprint(value)
			compatStoreMu.Unlock()
			return true
		},
	}); err != nil {
		return err
	}
	if err := vm.Set("$notification", map[string]any{
		"post": func(title, subtitle, body string, extras ...any) {},
	}); err != nil {
		return err
	}
	if err := vm.Set("$prefs", map[string]any{
		"valueForKey": func(key any) string {
			k := strings.TrimSpace(fmt.Sprint(key))
			compatStoreMu.RLock()
			defer compatStoreMu.RUnlock()
			return compatStore[k]
		},
		"setValueForKey": func(value any, key any) bool {
			k := strings.TrimSpace(fmt.Sprint(key))
			if k == "" {
				return false
			}
			compatStoreMu.Lock()
			compatStore[k] = fmt.Sprint(value)
			compatStoreMu.Unlock()
			return true
		},
	}); err != nil {
		return err
	}
	if err := vm.Set("$notify", func(title, subtitle, body string, extras ...any) {}); err != nil {
		return err
	}

	httpClientObj := map[string]any{
		"get":    makeSurgeHTTPClientMethod(vm, http.MethodGet),
		"post":   makeSurgeHTTPClientMethod(vm, http.MethodPost),
		"put":    makeSurgeHTTPClientMethod(vm, http.MethodPut),
		"delete": makeSurgeHTTPClientMethod(vm, http.MethodDelete),
	}
	return vm.Set("$httpClient", httpClientObj)
}

func makeSurgeHTTPClientMethod(vm *goja.Runtime, method string) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		if vm == nil || len(call.Arguments) < 2 {
			return goja.Undefined()
		}

		cb, ok := goja.AssertFunction(call.Arguments[1])
		if !ok {
			return goja.Undefined()
		}

		opts, parseErr := parseSurgeHTTPClientArgs(call.Arguments[0])
		if parseErr != nil {
			_, _ = cb(goja.Undefined(), vm.ToValue(parseErr.Error()))
			return goja.Undefined()
		}

		var bodyReader io.Reader
		if len(opts.Body) > 0 {
			bodyReader = bytes.NewReader(opts.Body)
		}
		req, err := http.NewRequest(method, opts.URL, bodyReader)
		if err != nil {
			_, _ = cb(goja.Undefined(), vm.ToValue(err.Error()))
			return goja.Undefined()
		}
		for k, v := range opts.Headers {
			req.Header.Set(k, v)
		}

		resp, err := compatClient.Do(req)
		if err != nil {
			_, _ = cb(goja.Undefined(), vm.ToValue(err.Error()))
			return goja.Undefined()
		}
		defer resp.Body.Close()

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			_, _ = cb(goja.Undefined(), vm.ToValue(err.Error()))
			return goja.Undefined()
		}
		respObj := map[string]any{
			"status":     resp.StatusCode,
			"statusCode": resp.StatusCode,
			"headers":    headersToJS(resp.Header),
		}
		dataVal := vm.ToValue(string(data))
		if opts.BinaryMode {
			dataVal = vm.ToValue(vm.NewArrayBuffer(data))
		}
		_, _ = cb(goja.Undefined(), goja.Null(), vm.ToValue(respObj), dataVal)
		return goja.Undefined()
	}
}

type surgeHTTPClientOptions struct {
	URL        string
	Headers    map[string]string
	Body       []byte
	BinaryMode bool
}

func parseSurgeHTTPClientArgs(arg goja.Value) (surgeHTTPClientOptions, error) {
	opts := surgeHTTPClientOptions{
		Headers: map[string]string{},
	}
	if arg == nil || goja.IsUndefined(arg) || goja.IsNull(arg) {
		return opts, fmt.Errorf("http client options is empty")
	}

	exported := arg.Export()
	switch v := exported.(type) {
	case string:
		opts.URL = strings.TrimSpace(v)
		return opts, nil
	case map[string]any:
		if u, ok := v["url"]; ok {
			opts.URL = strings.TrimSpace(fmt.Sprint(u))
		}
		if hRaw, ok := v["headers"]; ok {
			if hm, ok := hRaw.(map[string]any); ok {
				for hk, hv := range hm {
					opts.Headers[hk] = fmt.Sprint(hv)
				}
			}
			if hm, ok := hRaw.(map[string]string); ok {
				for hk, hv := range hm {
					opts.Headers[hk] = hv
				}
			}
		}
		if b, ok := v["body"]; ok {
			if data, ok := toBytes(b); ok {
				opts.Body = data
			} else {
				opts.Body = []byte(fmt.Sprint(b))
			}
		}
		if b, ok := v["bodyBytes"]; ok {
			if data, ok := toBytes(b); ok {
				opts.Body = data
			}
		}
		if bm, ok := v["binary-mode"]; ok {
			opts.BinaryMode = toBool(bm)
		}
		if bm, ok := v["binaryMode"]; ok {
			opts.BinaryMode = toBool(bm)
		}
	default:
		return opts, fmt.Errorf("unsupported http client options type: %T", exported)
	}

	if opts.URL == "" {
		return opts, fmt.Errorf("http client url is empty")
	}
	return opts, nil
}

func toBool(v any) bool {
	switch vv := v.(type) {
	case bool:
		return vv
	case string:
		vv = strings.TrimSpace(strings.ToLower(vv))
		return vv == "1" || vv == "true" || vv == "yes" || vv == "on"
	case int:
		return vv != 0
	case int64:
		return vv != 0
	case float64:
		return vv != 0
	default:
		return false
	}
}

func jsBodyValue(vm *goja.Runtime, body []byte, binary bool) (any, error) {
	if !binary {
		return string(body), nil
	}
	u8, err := newUint8Array(vm, body)
	if err != nil {
		return nil, err
	}
	return u8, nil
}

func newUint8Array(vm *goja.Runtime, body []byte) (goja.Value, error) {
	if vm == nil {
		return nil, fmt.Errorf("nil vm")
	}
	key := "__gomitm_body_ab"
	if err := vm.Set(key, vm.NewArrayBuffer(append([]byte(nil), body...))); err != nil {
		return nil, err
	}
	v, err := vm.RunString("new Uint8Array(" + key + ")")
	_ = vm.Set(key, goja.Undefined())
	if err != nil {
		return nil, err
	}
	return v, nil
}
