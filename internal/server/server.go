package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
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

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded          = 0x00
	repGeneralFailure     = 0x01
	repHostUnreachable    = 0x04
	repCmdNotSupported    = 0x07
	repAddrTypeNotSupport = 0x08

	builtinCAHostHTTPS = "www4.google.com"
	builtinCAHostHTTP  = "198.18.0.1"
	builtinCAHostHTTP2 = "8.8.9.9"
	builtinCACertPath  = "/gomitm-ca.crt"
)

type Config struct {
	ListenAddr  string
	DialTimeout time.Duration
	MITMHosts   []string
	MITMAll     bool
	Rewrite     []policy.RewriteRule
	Scripts     []policy.ScriptRule
	Capture     capture.Config
}

type Server struct {
	cfg       Config
	ca        *ca.Manager
	matcher   *domain.Matcher
	rewrite   []policy.RewriteRule
	scripts   []policy.ScriptRule
	engine    *script.Engine
	transport *http.Transport
	capCfg    capture.Config
	capStore  *capture.Store
	seq       atomic.Uint64
	logger    *log.Logger
	ln        net.Listener
}

type responseSnapshot struct {
	Status  int
	Headers map[string]string
	Body    string
	ReadErr error
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
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
	}

	return &Server{
		cfg:       cfg,
		ca:        caManager,
		matcher:   domain.NewMatcher(cfg.MITMHosts),
		rewrite:   cfg.Rewrite,
		scripts:   cfg.Scripts,
		engine:    script.NewEngine(),
		transport: transport,
		capCfg:    cfg.Capture,
		capStore:  capStore,
		logger:    logger,
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
		if s.transport != nil {
			s.transport.CloseIdleConnections()
		}
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

	cmd, host, port, err := s.readSocksRequest(client)
	if err != nil {
		s.logger.Printf("socks request failed: %v", err)
		return
	}

	if cmd == cmdUDPAssociate {
		if err := s.handleUDPAssociate(client, host, port); err != nil {
			s.logger.Printf("udp associate failed: %v", err)
		}
		return
	}

	target := net.JoinHostPort(host, strconv.Itoa(port))
	if isBuiltinCAPortalHost(host) && port == 80 {
		if err := writeReply(client, repSucceeded, nil, 0); err != nil {
			s.logger.Printf("write socks reply failed: %v", err)
			return
		}
		s.logger.Printf("builtin CA HTTP portal %s", target)
		if err := s.handleBuiltinCAHTTPPortal(client, host); err != nil {
			s.logger.Printf("builtin ca http portal failed for %s: %v", target, err)
		}
		return
	}
	useMITM := s.shouldMITM(host, port)

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

func (s *Server) shouldMITM(host string, port int) bool {
	if port != 443 {
		return false
	}
	if s.cfg.MITMAll {
		return true
	}
	if isBuiltinCAPortalHost(host) {
		return true
	}
	return s.matcher.Match(normalizeHost(host))
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

func (s *Server) readSocksRequest(conn net.Conn) (byte, string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", 0, err
	}
	if header[0] != socksVersion5 {
		return 0, "", 0, fmt.Errorf("invalid request version: %d", header[0])
	}
	cmd := header[1]
	if cmd != cmdConnect && cmd != cmdUDPAssociate {
		_ = writeReply(conn, repCmdNotSupported, nil, 0)
		return 0, "", 0, fmt.Errorf("unsupported command: %d", cmd)
	}

	atyp := header[3]
	host, err := readAddress(conn, atyp)
	if err != nil {
		if errors.Is(err, errAddrTypeNotSupported) {
			_ = writeReply(conn, repAddrTypeNotSupport, nil, 0)
		}
		return 0, "", 0, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return 0, "", 0, err
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	return cmd, host, port, nil
}

func (s *Server) handleUDPAssociate(client net.Conn, host string, port int) error {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		_ = writeReply(client, repGeneralFailure, nil, 0)
		return fmt.Errorf("listen udp relay: %w", err)
	}
	defer udpConn.Close()

	bindIP, bindPort := addrFrom(udpConn.LocalAddr())
	replyIP := bindIP
	if tcpLocalIP, _ := addrFrom(client.LocalAddr()); tcpLocalIP != nil && !tcpLocalIP.IsUnspecified() {
		replyIP = tcpLocalIP
	}
	if err := writeReply(client, repSucceeded, replyIP, bindPort); err != nil {
		return fmt.Errorf("write udp associate reply: %w", err)
	}
	allowedClientIP, _ := addrFrom(client.RemoteAddr())
	s.logger.Printf("UDP ASSOCIATE %s:%d relay=%s:%d", host, port, replyIP.String(), bindPort)

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		_, _ = io.Copy(io.Discard, client)
		_ = udpConn.Close()
	}()

	var clientUDPAddr *net.UDPAddr
	seenTargets := make(map[string]time.Time)
	buf := make([]byte, 64*1024)

	for {
		if err := udpConn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			return fmt.Errorf("set udp read deadline: %w", err)
		}
		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-closed:
					return nil
				default:
				}
				continue
			}
			select {
			case <-closed:
				return nil
			default:
			}
			return fmt.Errorf("read udp relay: %w", err)
		}

		// Client -> relay -> target
		if isFromUDPClient(src, clientUDPAddr, allowedClientIP) {
			if clientUDPAddr == nil {
				clientUDPAddr = src
			}
			dgram, err := parseSocksUDPDatagram(buf[:n])
			if err != nil {
				s.logger.Printf("udp parse failed from %s: %v", src.String(), err)
				continue
			}
			if dgram.Frag != 0 {
				s.logger.Printf("udp fragment not supported from %s frag=%d", src.String(), dgram.Frag)
				continue
			}
			dst, err := resolveUDPAddr(dgram.Host, dgram.Port)
			if err != nil {
				s.logger.Printf("udp resolve failed %s:%d: %v", dgram.Host, dgram.Port, err)
				continue
			}
			seenTargets[dst.String()] = time.Now()
			if _, err := udpConn.WriteToUDP(dgram.Payload, dst); err != nil {
				s.logger.Printf("udp forward failed to %s: %v", dst.String(), err)
			}
			continue
		}

		// Target -> relay -> client
		if clientUDPAddr == nil {
			continue
		}
		if _, ok := seenTargets[src.String()]; !ok {
			continue
		}
		out, err := buildSocksUDPDatagramFromUDPAddr(src, buf[:n])
		if err != nil {
			s.logger.Printf("udp build response failed from %s: %v", src.String(), err)
			continue
		}
		if _, err := udpConn.WriteToUDP(out, clientUDPAddr); err != nil {
			s.logger.Printf("udp relay back to client failed %s: %v", clientUDPAddr.String(), err)
		}
	}
}

var errAddrTypeNotSupported = errors.New("address type not supported")
var errInvalidSocksUDPDatagram = errors.New("invalid socks udp datagram")

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

type socksUDPDatagram struct {
	Frag    byte
	Host    string
	Port    int
	Payload []byte
}

func parseSocksUDPDatagram(packet []byte) (socksUDPDatagram, error) {
	if len(packet) < 4 {
		return socksUDPDatagram{}, errInvalidSocksUDPDatagram
	}
	if packet[0] != 0x00 || packet[1] != 0x00 {
		return socksUDPDatagram{}, errInvalidSocksUDPDatagram
	}

	d := socksUDPDatagram{Frag: packet[2]}
	atyp := packet[3]
	idx := 4

	switch atyp {
	case atypIPv4:
		if len(packet) < idx+net.IPv4len+2 {
			return socksUDPDatagram{}, errInvalidSocksUDPDatagram
		}
		d.Host = net.IP(packet[idx : idx+net.IPv4len]).String()
		idx += net.IPv4len
	case atypIPv6:
		if len(packet) < idx+net.IPv6len+2 {
			return socksUDPDatagram{}, errInvalidSocksUDPDatagram
		}
		d.Host = net.IP(packet[idx : idx+net.IPv6len]).String()
		idx += net.IPv6len
	case atypDomain:
		if len(packet) < idx+1 {
			return socksUDPDatagram{}, errInvalidSocksUDPDatagram
		}
		l := int(packet[idx])
		idx++
		if l == 0 || len(packet) < idx+l+2 {
			return socksUDPDatagram{}, errInvalidSocksUDPDatagram
		}
		d.Host = string(packet[idx : idx+l])
		idx += l
	default:
		return socksUDPDatagram{}, errAddrTypeNotSupported
	}

	d.Port = int(binary.BigEndian.Uint16(packet[idx : idx+2]))
	idx += 2
	d.Payload = append([]byte(nil), packet[idx:]...)
	return d, nil
}

func buildSocksUDPDatagram(host string, port int, payload []byte) ([]byte, error) {
	host = strings.TrimSpace(host)
	if host == "" || port < 0 || port > 65535 {
		return nil, errInvalidSocksUDPDatagram
	}

	buf := make([]byte, 0, 4+len(host)+2+len(payload))
	buf = append(buf, 0x00, 0x00, 0x00) // RSV + FRAG

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, atypIPv4)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, atypIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errInvalidSocksUDPDatagram
		}
		buf = append(buf, atypDomain, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))
	buf = append(buf, payload...)
	return buf, nil
}

func buildSocksUDPDatagramFromUDPAddr(addr *net.UDPAddr, payload []byte) ([]byte, error) {
	if addr == nil {
		return nil, errInvalidSocksUDPDatagram
	}
	return buildSocksUDPDatagram(addr.IP.String(), addr.Port, payload)
}

func resolveUDPAddr(host string, port int) (*net.UDPAddr, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
}

func isFromUDPClient(src *net.UDPAddr, fixedClient *net.UDPAddr, allowedClientIP net.IP) bool {
	if src == nil {
		return false
	}
	if fixedClient != nil {
		return src.Port == fixedClient.Port && src.IP.Equal(fixedClient.IP)
	}
	if allowedClientIP == nil || allowedClientIP.IsUnspecified() {
		return true
	}
	return src.IP.Equal(allowedClientIP)
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

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read request: %w", err)
		}
		started := time.Now()

		if handled, builtinResp, err := s.handleBuiltinCAPortal(req, writer, host); err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return err
		} else if handled {
			s.captureTransaction(req, builtinResp, nil, started, "builtin-ca-portal", "")
			if req.Body != nil {
				_ = req.Body.Close()
			}
			if req.Close {
				return nil
			}
			continue
		}

		if handled, rewriteResp, rewriteRule, err := s.applyRewrite(req, writer); err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return err
		} else if handled {
			s.captureTransaction(req, rewriteResp, nil, started, rewriteRule, "")
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
		if shouldForceIdentityEncoding(req, s.scripts) {
			outReq.Header.Del("Accept-Encoding")
			outReq.Header.Set("Accept-Encoding", "identity")
		}

		resp, err := s.transport.RoundTrip(outReq)
		if err != nil {
			_ = writeHTTPError(writer, req, http.StatusBadGateway, err.Error())
			s.captureTransaction(req, nil, nil, started, "", err.Error())
			if req.Body != nil {
				_ = req.Body.Close()
			}
			continue
		}

		var upstream *responseSnapshot
		if s.capStore != nil {
			snap := s.snapshotResponse(resp)
			upstream = &snap
		}

		appliedRespScript, err := s.engine.ApplyResponseScripts(req, resp, s.scripts)
		if err != nil {
			s.logger.Printf("script execution failed: %v", err)
		}
		if appliedRespScript {
			resp.Header.Del("Content-Encoding")
		}
		s.captureTransaction(req, resp, upstream, started, "", "")

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

func (s *Server) handleBuiltinCAHTTPPortal(rawConn net.Conn, host string) error {
	reader := bufio.NewReader(rawConn)
	writer := bufio.NewWriter(rawConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read request: %w", err)
		}
		started := time.Now()

		handled, resp, err := s.handleBuiltinCAPortal(req, writer, host)
		if err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return err
		}
		if handled {
			s.captureTransaction(req, resp, nil, started, "builtin-ca-portal-http", "")
		}
		if req.Body != nil {
			_ = req.Body.Close()
		}
		if req.Close {
			return nil
		}
	}
}

func (s *Server) handleBuiltinCAPortal(req *http.Request, writer *bufio.Writer, targetHost string) (bool, *http.Response, error) {
	if req == nil || writer == nil || s.ca == nil {
		return false, nil, nil
	}
	if !isBuiltinCAPortalHost(targetHost) {
		return false, nil, nil
	}

	path := "/"
	if req.URL != nil && strings.TrimSpace(req.URL.Path) != "" {
		path = req.URL.Path
	}

	cert := s.ca.RootCertPEM()
	if len(cert) == 0 {
		return true, nil, writeHTTPError(writer, req, http.StatusInternalServerError, "ca certificate is unavailable")
	}

	if path == builtinCACertPath {
		downloadName := s.ca.RootCertDownloadFilename()
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(string(cert))),
			ContentLength: int64(len(cert)),
			Request:       req,
		}
		resp.Header.Set("Content-Type", "application/x-x509-ca-cert; charset=utf-8")
		resp.Header.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, downloadName))
		if err := writeHTTPResponse(writer, resp); err != nil {
			return true, nil, fmt.Errorf("write built-in ca cert response: %w", err)
		}
		return true, resp, nil
	}

	if path != "/" && path != "/index.html" {
		resp := newStaticResponse(req, http.StatusNotFound, "not found\n")
		if err := writeHTTPResponse(writer, resp); err != nil {
			return true, nil, fmt.Errorf("write built-in 404 response: %w", err)
		}
		return true, resp, nil
	}

	htmlBody := buildBuiltinCAPortalPage(string(cert), s.ca.RootCertDownloadFilename())
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(htmlBody)),
		ContentLength: int64(len(htmlBody)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	if err := writeHTTPResponse(writer, resp); err != nil {
		return true, nil, fmt.Errorf("write built-in ca portal response: %w", err)
	}
	return true, resp, nil
}

func buildBuiltinCAPortalPage(certPEM, downloadName string) string {
	escapedCert := html.EscapeString(certPEM)
	return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GoMITM CA 下载页</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; color: #111; }
    .card { max-width: 900px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 12px; }
    h1 { margin: 0 0 12px; }
    a.button { display: inline-block; background: #0b57d0; color: #fff; text-decoration: none; padding: 10px 14px; border-radius: 8px; margin-bottom: 12px; }
    pre { background: #f6f8fa; padding: 12px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
    .tip { color: #444; margin-bottom: 12px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>GoMITM 根证书安装页</h1>
    <p class="tip">你当前访问的是内置 MITM 页面。点击按钮可直接下载根证书，也可手动复制下方 PEM 内容。</p>
    <a class="button" href="` + builtinCACertPath + `">下载 CA 证书 (` + html.EscapeString(downloadName) + `)</a>
    <pre>` + escapedCert + `</pre>
  </div>
</body>
</html>`
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

func (s *Server) captureTransaction(req *http.Request, resp *http.Response, upstream *responseSnapshot, started time.Time, rule string, errMsg string) {
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
	if upstream != nil {
		entry.UpstreamRespStatus = upstream.Status
		entry.UpstreamRespHeaders = cloneHeaderMap(upstream.Headers)
		entry.UpstreamRespBody = upstream.Body
		if upstream.ReadErr != nil && entry.Error == "" {
			entry.Error = upstream.ReadErr.Error()
		}
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
	if upstream != nil && resp != nil {
		entry.RespModified = entry.UpstreamRespStatus != entry.RespStatus ||
			entry.UpstreamRespBody != entry.RespBody ||
			!sameHeaderMap(entry.UpstreamRespHeaders, entry.RespHeaders)
	}
	s.capStore.Add(entry)
}

func (s *Server) snapshotResponse(resp *http.Response) responseSnapshot {
	if resp == nil {
		return responseSnapshot{}
	}
	out := responseSnapshot{
		Status:  resp.StatusCode,
		Headers: headerToMap(resp.Header),
	}
	body, err := s.peekResponseBody(resp)
	out.Body = body
	out.ReadErr = err
	return out
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

func cloneHeaderMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sameHeaderMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		if bv, ok := b[k]; !ok || bv != av {
			return false
		}
	}
	return true
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

func shouldForceIdentityEncoding(req *http.Request, rules []policy.ScriptRule) bool {
	if req == nil || len(rules) == 0 {
		return false
	}
	u := requestFullURL(req)
	for _, rule := range rules {
		if rule.Type != policy.ScriptTypeHTTPResponse {
			continue
		}
		if !rule.RequiresBody {
			continue
		}
		if rule.Match(u) {
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

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}

func isBuiltinCAPortalHost(host string) bool {
	host = normalizeHost(host)
	return host == builtinCAHostHTTPS || host == builtinCAHostHTTP || host == builtinCAHostHTTP2
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
	switch v := a.(type) {
	case *net.TCPAddr:
		ip4 := v.IP.To4()
		if ip4 == nil {
			return v.IP, v.Port
		}
		return ip4, v.Port
	case *net.UDPAddr:
		ip4 := v.IP.To4()
		if ip4 == nil {
			return v.IP, v.Port
		}
		return ip4, v.Port
	default:
		return net.IPv4zero, 0
	}
}
