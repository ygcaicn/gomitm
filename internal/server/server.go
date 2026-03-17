package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gomitm/internal/ca"
	"gomitm/internal/capture"
	"gomitm/internal/domain"
	"gomitm/internal/policy"
	"gomitm/internal/script"
)

const (
	socksVersion5 = 0x05

	authNoAcceptable = 0xFF
	authNoAuth       = 0x00

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded          = 0x00
	repGeneralFailure     = 0x01
	repHostUnreachable    = 0x04
	repCmdNotSupported    = 0x07
	repAddrTypeNotSupport = 0x08
)

type Config struct {
	ListenAddr  string
	DialTimeout time.Duration
	MITMHosts   []string
	Rewrite     []policy.RewriteRule
	Scripts     []policy.ScriptRule
	Capture     capture.Config
}

type Server struct {
	cfg      Config
	ca       *ca.Manager
	matcher  *domain.Matcher
	rewrite  []policy.RewriteRule
	scripts  []policy.ScriptRule
	engine   *script.Engine
	capCfg   capture.Config
	capStore *capture.Store
	seq      atomic.Uint64
	logger   *log.Logger
	ln       net.Listener
}

func New(cfg Config, caManager *ca.Manager, logger *log.Logger) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":1080"
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.Capture.MaxEntries <= 0 {
		cfg.Capture.MaxEntries = 1000
	}
	if cfg.Capture.MaxBodyBytes <= 0 {
		cfg.Capture.MaxBodyBytes = 2 * 1024 * 1024
	}
	if logger == nil {
		logger = log.Default()
	}

	var capStore *capture.Store
	if cfg.Capture.Enabled {
		capStore = capture.NewStore(cfg.Capture.MaxEntries)
	}

	return &Server{
		cfg:      cfg,
		ca:       caManager,
		matcher:  domain.NewMatcher(cfg.MITMHosts),
		rewrite:  cfg.Rewrite,
		scripts:  cfg.Scripts,
		engine:   script.NewEngine(),
		capCfg:   cfg.Capture,
		capStore: capStore,
		logger:   logger,
	}
}

func (s *Server) CaptureEntries() []capture.Entry {
	if s.capStore == nil {
		return nil
	}
	return s.capStore.Snapshot()
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.ListenAddr, err)
	}
	s.ln = ln
	s.logger.Printf("socks5 listening on %s", s.cfg.ListenAddr)

	errCh := make(chan error, 1)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					errCh <- nil
					return
				}
				errCh <- fmt.Errorf("accept: %w", err)
				return
			}
			go s.handleConn(conn)
		}
	}()

	return <-errCh
}

func (s *Server) handleConn(client net.Conn) {
	defer client.Close()

	if err := s.handleGreeting(client); err != nil {
		s.logger.Printf("socks greeting failed: %v", err)
		return
	}

	host, port, err := s.readConnectRequest(client)
	if err != nil {
		s.logger.Printf("socks request failed: %v", err)
		return
	}

	target := net.JoinHostPort(host, strconv.Itoa(port))
	useMITM := port == 443 && s.matcher.Match(host)

	if useMITM {
		if err := writeReply(client, repSucceeded, nil, 0); err != nil {
			s.logger.Printf("write socks reply failed: %v", err)
			return
		}
		s.logger.Printf("MITM %s", target)
		if err := s.handleMITM(client, host, port); err != nil {
			s.logger.Printf("mitm failed for %s: %v", target, err)
		}
		return
	}

	upstream, err := (&net.Dialer{Timeout: s.cfg.DialTimeout, KeepAlive: 30 * time.Second}).Dial("tcp", target)
	if err != nil {
		_ = writeReply(client, repHostUnreachable, nil, 0)
		s.logger.Printf("dial failed %s: %v", target, err)
		return
	}
	defer upstream.Close()

	bindIP, bindPort := addrFrom(upstream.LocalAddr())
	if err := writeReply(client, repSucceeded, bindIP, bindPort); err != nil {
		s.logger.Printf("write socks reply failed: %v", err)
		return
	}

	s.logger.Printf("TCP %s", target)
	proxyTCP(client, upstream)
}

func (s *Server) handleGreeting(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 {
		return fmt.Errorf("unsupported socks version: %d", header[0])
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	selected := byte(authNoAcceptable)
	for _, m := range methods {
		if m == authNoAuth {
			selected = authNoAuth
			break
		}
	}
	if _, err := conn.Write([]byte{socksVersion5, selected}); err != nil {
		return err
	}
	if selected == authNoAcceptable {
		return errors.New("no acceptable auth method")
	}
	return nil
}

func (s *Server) readConnectRequest(conn net.Conn) (string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != socksVersion5 {
		return "", 0, fmt.Errorf("invalid request version: %d", header[0])
	}
	if header[1] != cmdConnect {
		_ = writeReply(conn, repCmdNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported command: %d", header[1])
	}

	atyp := header[3]
	host, err := readAddress(conn, atyp)
	if err != nil {
		if errors.Is(err, errAddrTypeNotSupported) {
			_ = writeReply(conn, repAddrTypeNotSupport, nil, 0)
		}
		return "", 0, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", 0, err
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	return host, port, nil
}

var errAddrTypeNotSupported = errors.New("address type not supported")

func readAddress(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	case atypIPv6:
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", err
		}
		domainLen := int(lenBuf[0])
		if domainLen == 0 {
			return "", errors.New("empty domain")
		}
		addr := make([]byte, domainLen)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", err
		}
		return string(addr), nil
	default:
		return "", errAddrTypeNotSupported
	}
}

func writeReply(w io.Writer, rep byte, ip net.IP, port int) error {
	if ip == nil {
		ip = net.IPv4zero
	}
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero
	}
	resp := []byte{
		socksVersion5,
		rep,
		0x00,
		atypIPv4,
		ip4[0], ip4[1], ip4[2], ip4[3],
		byte(port >> 8), byte(port),
	}
	_, err := w.Write(resp)
	return err
}

func (s *Server) handleMITM(rawConn net.Conn, host string, port int) error {
	leafCert, err := s.ca.GetLeafCertificate(host)
	if err != nil {
		return fmt.Errorf("create leaf cert: %w", err)
	}

	clientTLS := tls.Server(rawConn, &tls.Config{
		Certificates: []tls.Certificate{leafCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	defer clientTLS.Close()

	if err := clientTLS.Handshake(); err != nil {
		return fmt.Errorf("client tls handshake: %w", err)
	}

	reader := bufio.NewReader(clientTLS)
	writer := bufio.NewWriter(clientTLS)

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: s.cfg.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
	}
	defer transport.CloseIdleConnections()

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read request: %w", err)
		}
		started := time.Now()

		if handled, rewriteResp, rewriteRule, err := s.applyRewrite(req, writer); err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return err
		} else if handled {
			s.captureTransaction(req, rewriteResp, started, rewriteRule, "")
			if req.Body != nil {
				_ = req.Body.Close()
			}
			if req.Close {
				return nil
			}
			continue
		}

		if _, err := s.engine.ApplyRequestScripts(req, s.scripts); err != nil {
			s.logger.Printf("request script execution failed: %v", err)
		}

		outReq := req.Clone(req.Context())
		outReq.RequestURI = ""
		if outReq.URL.Scheme == "" {
			outReq.URL.Scheme = "https"
		}
		if outReq.URL.Host == "" {
			if req.Host != "" {
				outReq.URL.Host = req.Host
			} else {
				outReq.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
			}
		}
		if outReq.Host == "" {
			outReq.Host = req.Host
		}
		removeHopByHopHeaders(outReq.Header)

		resp, err := transport.RoundTrip(outReq)
		if err != nil {
			_ = writeHTTPError(writer, req, http.StatusBadGateway, err.Error())
			s.captureTransaction(req, nil, started, "", err.Error())
			if req.Body != nil {
				_ = req.Body.Close()
			}
			continue
		}

		if _, err := s.engine.ApplyResponseScripts(req, resp, s.scripts); err != nil {
			s.logger.Printf("script execution failed: %v", err)
		}
		s.captureTransaction(req, resp, started, "", "")

		removeHopByHopHeaders(resp.Header)
		if err := resp.Write(writer); err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			_ = resp.Body.Close()
			return fmt.Errorf("write response: %w", err)
		}
		if err := writer.Flush(); err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			_ = resp.Body.Close()
			return fmt.Errorf("flush response: %w", err)
		}

		if req.Body != nil {
			_ = req.Body.Close()
		}
		_ = resp.Body.Close()

		if req.Close || resp.Close {
			return nil
		}
	}
}

func (s *Server) applyRewrite(req *http.Request, writer *bufio.Writer) (bool, *http.Response, string, error) {
	if req == nil || len(s.rewrite) == 0 {
		return false, nil, "", nil
	}
	fullURL := req.URL.String()
	if req.URL != nil && !req.URL.IsAbs() {
		scheme := "https"
		host := req.Host
		if host == "" && req.URL.Host != "" {
			host = req.URL.Host
		}
		fullURL = scheme + "://" + host + req.URL.RequestURI()
	}

	for _, rule := range s.rewrite {
		if !rule.Match(fullURL) {
			continue
		}
		s.logger.Printf("rewrite hit action=%s url=%s", rule.Action, fullURL)
		switch rule.Action {
		case policy.RewriteReject200:
			rewriteResp := newStaticResponse(req, http.StatusOK, "")
			if err := writeHTTPResponse(writer, rewriteResp); err != nil {
				return true, nil, rule.Raw, fmt.Errorf("write reject-200 response: %w", err)
			}
			return true, rewriteResp, rule.Raw, nil
		case policy.RewriteReject:
			rewriteResp := newStaticResponse(req, http.StatusForbidden, "blocked by rewrite rule\n")
			if err := writeHTTPResponse(writer, rewriteResp); err != nil {
				return true, nil, rule.Raw, fmt.Errorf("write reject response: %w", err)
			}
			return true, rewriteResp, rule.Raw, nil
		}
	}
	return false, nil, "", nil
}

func (s *Server) captureTransaction(req *http.Request, resp *http.Response, started time.Time, rule string, errMsg string) {
	if s.capStore == nil || req == nil {
		return
	}
	entry := capture.Entry{
		ID:         strconv.FormatUint(s.seq.Add(1), 10),
		StartedAt:  started,
		DurationMs: time.Since(started).Milliseconds(),
		Method:     req.Method,
		URL:        requestFullURL(req),
		ReqHeaders: headerToMap(req.Header),
		Rule:       rule,
		Error:      errMsg,
	}

	if resp != nil {
		entry.RespStatus = resp.StatusCode
		entry.RespHeaders = headerToMap(resp.Header)
		body, bodyErr := s.peekResponseBody(resp)
		if bodyErr != nil && entry.Error == "" {
			entry.Error = bodyErr.Error()
		}
		entry.RespBody = body
	}
	s.capStore.Add(entry)
}

func (s *Server) peekResponseBody(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	if !shouldCaptureContentType(resp.Header.Get("Content-Type"), s.capCfg.ContentTypes) {
		return "[body skipped: content-type filtered]", nil
	}
	if resp.ContentLength < 0 {
		return "[body skipped: unknown length]", nil
	}
	if s.capCfg.MaxBodyBytes > 0 && resp.ContentLength > s.capCfg.MaxBodyBytes {
		return "[body skipped: too large]", nil
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return "", err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	resp.ContentLength = int64(len(body))
	if resp.Header != nil {
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	return string(body), nil
}

func requestFullURL(req *http.Request) string {
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

func headerToMap(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ",")
	}
	return out
}

func shouldCaptureContentType(contentType string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	for _, f := range filters {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		if strings.HasSuffix(f, "/*") {
			if strings.HasPrefix(ct, strings.TrimSuffix(f, "*")) {
				return true
			}
			continue
		}
		if strings.HasPrefix(ct, f) {
			return true
		}
	}
	return false
}

func writeHTTPError(w *bufio.Writer, req *http.Request, code int, msg string) error {
	if msg == "" {
		msg = http.StatusText(code)
	}
	body := msg + "\n"
	resp := &http.Response{
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
		Close:         true,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if err := resp.Write(w); err != nil {
		return err
	}
	return w.Flush()
}

func newStaticResponse(req *http.Request, code int, body string) *http.Response {
	resp := &http.Response{
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	return resp
}

func writeHTTPResponse(w *bufio.Writer, resp *http.Response) error {
	if resp == nil {
		return errors.New("nil response")
	}
	if err := resp.Write(w); err != nil {
		return err
	}
	return w.Flush()
}

func removeHopByHopHeaders(h http.Header) {
	if h == nil {
		return
	}
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("Connection")
	h.Del("Keep-Alive")
	h.Del("TE")
	h.Del("Trailer")
	h.Del("Transfer-Encoding")
	h.Del("Upgrade")
}

func proxyTCP(client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		closeWrite(upstream)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()

	wg.Wait()
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

func addrFrom(a net.Addr) (net.IP, int) {
	tcpAddr, ok := a.(*net.TCPAddr)
	if !ok {
		return net.IPv4zero, 0
	}
	ip4 := tcpAddr.IP.To4()
	if ip4 == nil {
		return net.IPv4zero, tcpAddr.Port
	}
	return ip4, tcpAddr.Port
}
