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
	"time"

	"gomitm/internal/ca"
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
}

type Server struct {
	cfg     Config
	ca      *ca.Manager
	matcher *domain.Matcher
	rewrite []policy.RewriteRule
	scripts []policy.ScriptRule
	engine  *script.Engine
	logger  *log.Logger
	ln      net.Listener
}

func New(cfg Config, caManager *ca.Manager, logger *log.Logger) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":1080"
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if logger == nil {
		logger = log.Default()
	}

	return &Server{
		cfg:     cfg,
		ca:      caManager,
		matcher: domain.NewMatcher(cfg.MITMHosts),
		rewrite: cfg.Rewrite,
		scripts: cfg.Scripts,
		engine:  script.NewEngine(),
		logger:  logger,
	}
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

		if handled, err := s.applyRewrite(req, writer); err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return err
		} else if handled {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			if req.Close {
				return nil
			}
			continue
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
			if req.Body != nil {
				_ = req.Body.Close()
			}
			continue
		}

		if _, err := s.engine.ApplyResponseScripts(req, resp, s.scripts); err != nil {
			s.logger.Printf("script execution failed: %v", err)
		}

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

func (s *Server) applyRewrite(req *http.Request, writer *bufio.Writer) (bool, error) {
	if req == nil || len(s.rewrite) == 0 {
		return false, nil
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
			if err := writeStaticResponse(writer, req, http.StatusOK, ""); err != nil {
				return true, fmt.Errorf("write reject-200 response: %w", err)
			}
			return true, nil
		case policy.RewriteReject:
			if err := writeStaticResponse(writer, req, http.StatusForbidden, "blocked by rewrite rule\n"); err != nil {
				return true, fmt.Errorf("write reject response: %w", err)
			}
			return true, nil
		}
	}
	return false, nil
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

func writeStaticResponse(w *bufio.Writer, req *http.Request, code int, body string) error {
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
