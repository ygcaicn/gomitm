package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestNewSOCKS5DialerParsesForms(t *testing.T) {
	d, err := newSOCKS5Dialer("socks5://alice:secret@127.0.0.1:40000", time.Second)
	if err != nil {
		t.Fatalf("parse URL failed: %v", err)
	}
	if d.proxyAddr != "127.0.0.1:40000" || d.username != "alice" || d.password != "secret" {
		t.Fatalf("unexpected dialer: %+v", d)
	}
	if _, err := newSOCKS5Dialer("127.0.0.1:40000", time.Second); err != nil {
		t.Fatalf("parse shorthand failed: %v", err)
	}
	for _, raw := range []string{"http://127.0.0.1:40000", "socks5://127.0.0.1", "socks5://alice@127.0.0.1:40000"} {
		if _, err := newSOCKS5Dialer(raw, time.Second); err == nil {
			t.Fatalf("expected invalid proxy %q", raw)
		}
	}
}

func TestSOCKS5DialerConnectsDomain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			serverErr <- err
			return
		}
		if want := []byte{5, 1, 0}; string(greeting) != string(want) {
			serverErr <- &testError{msg: "unexpected greeting"}
			return
		}
		_, _ = conn.Write([]byte{5, 0})
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			serverErr <- err
			return
		}
		if header[0] != 5 || header[1] != 1 || header[3] != 3 || int(header[4]) != len("example.com") {
			serverErr <- &testError{msg: "unexpected connect header"}
			return
		}
		host := make([]byte, header[4])
		if _, err := io.ReadFull(conn, host); err != nil {
			serverErr <- err
			return
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBuf); err != nil {
			serverErr <- err
			return
		}
		if string(host) != "example.com" || binary.BigEndian.Uint16(portBuf) != 443 {
			serverErr <- &testError{msg: "unexpected connect target"}
			return
		}
		_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		payload := make([]byte, 4)
		if _, err := io.ReadFull(conn, payload); err != nil {
			serverErr <- err
			return
		}
		_, _ = conn.Write(payload)
		serverErr <- nil
	}()

	d, err := newSOCKS5Dialer(ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("dial through SOCKS5 failed: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo got=%q err=%v", got, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
