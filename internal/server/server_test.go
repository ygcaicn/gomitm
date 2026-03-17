package server

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"gomitm/internal/ca"
	"gomitm/internal/capture"
	"gomitm/internal/policy"
)

func TestApplyRewriteReject200(t *testing.T) {
	s := &Server{rewrite: []policy.RewriteRule{{
		Pattern: regexp.MustCompile(`^https://example\.com/foo$`),
		Action:  policy.RewriteReject200,
	}}, logger: log.New(io.Discard, "", 0)}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	buf := new(bytes.Buffer)
	w := bufio.NewWriter(buf)

	handled, _, _, err := s.applyRewrite(req, w)
	if err != nil {
		t.Fatalf("apply rewrite failed: %v", err)
	}
	if !handled {
		t.Fatal("expected handled=true")
	}
	if !strings.Contains(buf.String(), "200 OK") {
		t.Fatalf("unexpected response: %s", buf.String())
	}
}

func TestShouldCaptureContentType(t *testing.T) {
	cases := []struct {
		contentType string
		filters     []string
		want        bool
	}{
		{"application/json", []string{"application/json", "text/*"}, true},
		{"text/plain; charset=utf-8", []string{"application/json", "text/*"}, true},
		{"application/octet-stream", []string{"application/json", "text/*"}, false},
		{"application/octet-stream", nil, true},
	}

	for _, c := range cases {
		got := shouldCaptureContentType(c.contentType, c.filters)
		if got != c.want {
			t.Fatalf("contentType=%q filters=%v got=%v want=%v", c.contentType, c.filters, got, c.want)
		}
	}
}

func TestShouldForceIdentityEncoding(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://www.google.com/webhp?hl=zh-CN", nil)
	rules := []policy.ScriptRule{
		{
			Name:         "google-home",
			Type:         policy.ScriptTypeHTTPResponse,
			Pattern:      regexp.MustCompile(`^https:\/\/(www\.)?google\.com\/(webhp)?(\?.*)?$`),
			RequiresBody: true,
		},
	}
	if !shouldForceIdentityEncoding(req, rules) {
		t.Fatal("expected identity encoding when response-body script matches")
	}

	req2, _ := http.NewRequest(http.MethodGet, "https://example.com/api", nil)
	if shouldForceIdentityEncoding(req2, rules) {
		t.Fatal("unexpected identity encoding for non-matching url")
	}
}

func TestCaptureTransactionStoresUpstreamAndModified(t *testing.T) {
	s := &Server{
		capCfg: capture.Config{
			MaxBodyBytes: 4 * 1024,
			ContentTypes: []string{"text/*"},
		},
		capStore: capture.NewStore(8),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("Accept", "text/html")

	resp := &http.Response{
		StatusCode:    200,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("<html>after</html>")),
		ContentLength: int64(len("<html>after</html>")),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	upstream := &responseSnapshot{
		Status:  200,
		Headers: map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:    "<html>before</html>",
	}

	s.captureTransaction(req, resp, upstream, time.Now(), "", "")
	entries := s.CaptureEntries()
	if len(entries) != 1 {
		t.Fatalf("entries len=%d", len(entries))
	}
	e := entries[0]
	if e.UpstreamRespBody != "<html>before</html>" {
		t.Fatalf("unexpected upstream body: %q", e.UpstreamRespBody)
	}
	if e.RespBody != "<html>after</html>" {
		t.Fatalf("unexpected final body: %q", e.RespBody)
	}
	if !e.RespModified {
		t.Fatal("resp_modified should be true when upstream and final differ")
	}
}

func TestShouldMITMBuiltinHost(t *testing.T) {
	s := &Server{matcher: nil}
	if !s.shouldMITM("www4.google.com", 443) {
		t.Fatal("builtin host should always be MITM on 443")
	}
	if !s.shouldMITM("198.18.0.1", 443) {
		t.Fatal("builtin HTTP portal host should also be MITM on 443")
	}
	if !s.shouldMITM("8.8.9.9", 443) {
		t.Fatal("builtin HTTP portal alt host should also be MITM on 443")
	}
	if s.shouldMITM("www4.google.com", 80) {
		t.Fatal("builtin host on non-443 should not be MITM")
	}
}

func TestShouldMITMAll(t *testing.T) {
	s := &Server{cfg: Config{MITMAll: true}, matcher: nil}
	if !s.shouldMITM("example.com", 443) {
		t.Fatal("mitm all should force mitm on 443")
	}
	if s.shouldMITM("example.com", 80) {
		t.Fatal("mitm all should not force non-443 ports")
	}
}

func TestShouldRejectUDPHost(t *testing.T) {
	s := &Server{
		udpRules: []policy.UDPRule{
			{Domain: "youtubei.googleapis.com"},
			{DomainSuffix: "googlevideo.com"},
		},
	}
	if !s.shouldRejectUDPHost("youtubei.googleapis.com") {
		t.Fatal("exact domain rule should match")
	}
	if !s.shouldRejectUDPHost("rr5---sn-a5mlrnl6.googlevideo.com") {
		t.Fatal("domain suffix rule should match")
	}
	if s.shouldRejectUDPHost("googlevideo.com.evil") {
		t.Fatal("suffix should not match superstring")
	}
}

func TestHandleBuiltinCAPortal(t *testing.T) {
	dir := t.TempDir()
	caManager, err := ca.Init(dir)
	if err != nil {
		t.Fatalf("init ca failed: %v", err)
	}
	s := &Server{ca: caManager, logger: log.New(io.Discard, "", 0)}

	{
		req, _ := http.NewRequest(http.MethodGet, "https://www4.google.com/", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, resp, err := s.handleBuiltinCAPortal(req, w, "www4.google.com")
		if err != nil {
			t.Fatalf("handle root failed: %v", err)
		}
		if !handled || resp == nil {
			t.Fatal("expected built-in root handled")
		}
		out := buf.String()
		if !strings.Contains(out, "200 OK") {
			t.Fatalf("unexpected status: %s", out)
		}
		if !strings.Contains(out, "GoMITM 根证书安装页") {
			t.Fatalf("unexpected body: %s", out)
		}
		if !strings.Contains(out, "BEGIN CERTIFICATE") {
			t.Fatalf("expected certificate content in portal: %s", out)
		}
	}

	{
		req, _ := http.NewRequest(http.MethodGet, "https://www4.google.com/gomitm-ca.crt", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, resp, err := s.handleBuiltinCAPortal(req, w, "www4.google.com")
		if err != nil {
			t.Fatalf("handle cert failed: %v", err)
		}
		if !handled || resp == nil {
			t.Fatal("expected built-in cert download handled")
		}
		out := buf.String()
		if !strings.Contains(out, "application/x-x509-ca-cert") {
			t.Fatalf("unexpected content-type: %s", out)
		}
		if !regexp.MustCompile(`attachment; filename="gomitm-root-ca-\d{8}-\d{6}\.crt"`).MatchString(out) {
			t.Fatalf("unexpected content-disposition: %s", out)
		}
		if !strings.Contains(out, "BEGIN CERTIFICATE") {
			t.Fatalf("expected certificate body: %s", out)
		}
	}

	{
		req, _ := http.NewRequest(http.MethodGet, "https://www.google.com/", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, _, err := s.handleBuiltinCAPortal(req, w, "www.google.com")
		if err != nil {
			t.Fatalf("handle non builtin failed: %v", err)
		}
		if handled {
			t.Fatal("non builtin host should not be handled")
		}
	}

	{
		req, _ := http.NewRequest(http.MethodGet, "http://198.18.0.1/unknown", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, resp, err := s.handleBuiltinCAPortal(req, w, "198.18.0.1")
		if err != nil {
			t.Fatalf("handle http unknown failed: %v", err)
		}
		if !handled || resp == nil {
			t.Fatal("expected builtin host unknown path still handled with 404")
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status code got=%d", resp.StatusCode)
		}
	}

	{
		req, _ := http.NewRequest(http.MethodGet, "http://8.8.9.9/", nil)
		buf := new(bytes.Buffer)
		w := bufio.NewWriter(buf)
		handled, resp, err := s.handleBuiltinCAPortal(req, w, "8.8.9.9")
		if err != nil {
			t.Fatalf("handle http alt root failed: %v", err)
		}
		if !handled || resp == nil {
			t.Fatal("expected builtin alt host handled")
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status code got=%d", resp.StatusCode)
		}
	}
}

func TestReadSocksRequestConnect(t *testing.T) {
	s := &Server{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// VER=5 CMD=1 RSV=0 ATYP=3 DOMAIN=example.com PORT=443
		_, _ = client.Write([]byte{
			0x05, 0x01, 0x00, 0x03,
			0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
			0x01, 0xbb,
		})
	}()

	cmd, host, port, err := s.readSocksRequest(server)
	if err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	if cmd != cmdConnect {
		t.Fatalf("cmd got=%d", cmd)
	}
	if host != "example.com" || port != 443 {
		t.Fatalf("host/port got=%s:%d", host, port)
	}
}

func TestReadSocksRequestUDPAssociate(t *testing.T) {
	s := &Server{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// VER=5 CMD=3 RSV=0 ATYP=1 ADDR=0.0.0.0 PORT=0
		_, _ = client.Write([]byte{
			0x05, 0x03, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		})
	}()

	cmd, host, port, err := s.readSocksRequest(server)
	if err != nil {
		t.Fatalf("read request failed: %v", err)
	}
	if cmd != cmdUDPAssociate {
		t.Fatalf("cmd got=%d", cmd)
	}
	if host != "0.0.0.0" || port != 0 {
		t.Fatalf("host/port got=%s:%d", host, port)
	}
}

func TestSocksUDPDatagramParseAndBuildDomain(t *testing.T) {
	raw, err := buildSocksUDPDatagram("example.com", 5353, []byte("abc"))
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	d, err := parseSocksUDPDatagram(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if d.Host != "example.com" || d.Port != 5353 || d.Frag != 0 {
		t.Fatalf("unexpected parsed header: %+v", d)
	}
	if got := string(d.Payload); got != "abc" {
		t.Fatalf("payload got=%q", got)
	}
}

func TestParseSocksUDPDatagramRejectsInvalid(t *testing.T) {
	_, err := parseSocksUDPDatagram([]byte{0x00, 0x00, 0x00})
	if !errors.Is(err, errInvalidSocksUDPDatagram) {
		t.Fatalf("err got=%v", err)
	}
}

func TestHandleUDPAssociateRelayRoundTrip(t *testing.T) {
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen echo udp failed: %v", err)
	}
	defer echoConn.Close()

	doneEcho := make(chan struct{})
	go func() {
		defer close(doneEcho)
		buf := make([]byte, 2048)
		for {
			_ = echoConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					return
				}
				return
			}
			_, _ = echoConn.WriteToUDP(buf[:n], addr)
		}
	}()

	s := &Server{logger: log.New(io.Discard, "", 0)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp failed: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- s.handleUDPAssociate(conn, "0.0.0.0", 0)
	}()

	ctrl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp failed: %v", err)
	}
	defer ctrl.Close()

	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, reply); err != nil {
		t.Fatalf("read socks reply failed: %v", err)
	}
	if reply[1] != repSucceeded {
		t.Fatalf("reply code got=%d", reply[1])
	}
	relayPort := int(reply[8])<<8 | int(reply[9])
	if relayPort == 0 {
		t.Fatal("relay port should not be zero")
	}

	udpClient, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp client failed: %v", err)
	}
	defer udpClient.Close()

	echoHost, echoPort := addrFrom(echoConn.LocalAddr())
	packet, err := buildSocksUDPDatagram(echoHost.String(), echoPort, []byte("ping"))
	if err != nil {
		t.Fatalf("build udp packet failed: %v", err)
	}
	relayAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: relayPort}
	if _, err := udpClient.WriteToUDP(packet, relayAddr); err != nil {
		t.Fatalf("write udp packet failed: %v", err)
	}

	buf := make([]byte, 2048)
	_ = udpClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := udpClient.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read udp response failed: %v", err)
	}
	dgram, err := parseSocksUDPDatagram(buf[:n])
	if err != nil {
		t.Fatalf("parse udp response failed: %v", err)
	}
	if string(dgram.Payload) != "ping" {
		t.Fatalf("payload got=%q", string(dgram.Payload))
	}

	_ = ctrl.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handle udp associate failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("udp associate handler did not exit")
	}
	<-doneEcho
}

func TestHandleUDPAssociateRelayRejectRule(t *testing.T) {
	s := &Server{
		logger: log.New(io.Discard, "", 0),
		udpRules: []policy.UDPRule{
			{DomainSuffix: "googlevideo.com"},
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp failed: %v", err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- s.handleUDPAssociate(conn, "0.0.0.0", 0)
	}()

	ctrl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp failed: %v", err)
	}
	defer ctrl.Close()

	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, reply); err != nil {
		t.Fatalf("read socks reply failed: %v", err)
	}
	relayPort := int(reply[8])<<8 | int(reply[9])
	if relayPort == 0 {
		t.Fatal("relay port should not be zero")
	}

	udpClient, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp client failed: %v", err)
	}
	defer udpClient.Close()

	packet, err := buildSocksUDPDatagram("rr5---sn-a5mlrnl6.googlevideo.com", 443, []byte("ping"))
	if err != nil {
		t.Fatalf("build udp packet failed: %v", err)
	}
	relayAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: relayPort}
	if _, err := udpClient.WriteToUDP(packet, relayAddr); err != nil {
		t.Fatalf("write udp packet failed: %v", err)
	}

	buf := make([]byte, 128)
	_ = udpClient.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := udpClient.ReadFromUDP(buf); err == nil {
		t.Fatal("expected no udp response for rejected host")
	}

	_ = ctrl.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("handle udp associate failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("udp associate handler did not exit")
	}
}
