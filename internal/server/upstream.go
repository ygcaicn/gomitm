package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// socks5Dialer is a small SOCKS5 CONNECT client used for gomitm's egress.
// Domain targets are sent to the proxy so the proxy performs DNS resolution.
type socks5Dialer struct {
	proxyAddr string
	username  string
	password  string
	timeout   time.Duration
}

func ValidateUpstreamProxy(raw string) error {
	_, err := newSOCKS5Dialer(raw, 10*time.Second)
	return err
}

func newSOCKS5Dialer(raw string, timeout time.Duration) (*socks5Dialer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	proxyAddr := raw
	var username, password string
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream proxy: %w", err)
		}
		if u.Scheme != "socks5" && u.Scheme != "socks5h" {
			return nil, fmt.Errorf("unsupported upstream proxy scheme %q (want socks5 or socks5h)", u.Scheme)
		}
		if u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("upstream proxy must be socks5://[user:pass@]host:port")
		}
		proxyAddr = u.Host
		if u.User != nil {
			username = u.User.Username()
			var hasPassword bool
			password, hasPassword = u.User.Password()
			if !hasPassword {
				return nil, errors.New("upstream proxy credentials require user:pass")
			}
		}
	}
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		return nil, fmt.Errorf("invalid upstream proxy address %q: %w", proxyAddr, err)
	}
	_, portText, _ := net.SplitHostPort(proxyAddr)
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid upstream proxy port %q", portText)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &socks5Dialer{proxyAddr: proxyAddr, username: username, password: password, timeout: timeout}, nil
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil {
		return nil, errors.New("nil SOCKS5 dialer")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("SOCKS5 upstream only supports TCP, got %s", network)
	}
	dialer := &net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS5 proxy %s: %w", d.proxyAddr, err)
	}
	deadline := time.Now().Add(d.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	if err := d.handshake(conn, address); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *socks5Dialer) handshake(conn net.Conn, address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid SOCKS5 target %q: %w", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid SOCKS5 target port %q", portText)
	}
	methods := []byte{0x00}
	if d.username != "" || d.password != "" {
		if len([]byte(d.username)) > 255 || len([]byte(d.password)) > 255 {
			return errors.New("SOCKS5 upstream credentials exceed 255 bytes")
		}
		methods = []byte{0x02}
	}
	greeting := append([]byte{5, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("write SOCKS5 greeting: %w", err)
	}
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodResp); err != nil {
		return fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if methodResp[0] != 5 || methodResp[1] == 0xff {
		return errors.New("SOCKS5 proxy rejected authentication methods")
	}
	if methodResp[1] == 0x02 {
		if d.username == "" && d.password == "" {
			return errors.New("SOCKS5 proxy requires authentication")
		}
		auth := append([]byte{1, byte(len([]byte(d.username)))}, []byte(d.username)...)
		auth = append(auth, byte(len([]byte(d.password))))
		auth = append(auth, []byte(d.password)...)
		if _, err := conn.Write(auth); err != nil {
			return fmt.Errorf("write SOCKS5 authentication: %w", err)
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return fmt.Errorf("read SOCKS5 authentication: %w", err)
		}
		if resp[1] != 0 {
			return errors.New("SOCKS5 proxy authentication failed")
		}
	} else if methodResp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 proxy selected unsupported method 0x%02x", methodResp[1])
	}

	hostBytes := []byte(host)
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, 1)
			request = append(request, ip4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(hostBytes) == 0 || len(hostBytes) > 255 {
			return errors.New("invalid SOCKS5 target host")
		}
		request = append(request, 3, byte(len(hostBytes)))
		request = append(request, hostBytes...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	request = append(request, portBuf[:]...)
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("write SOCKS5 connect request: %w", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read SOCKS5 connect response: %w", err)
	}
	if reply[0] != 5 {
		return fmt.Errorf("invalid SOCKS5 response version %d", reply[0])
	}
	if reply[1] != 0 {
		return fmt.Errorf("SOCKS5 connect failed: reply 0x%02x", reply[1])
	}
	addrLen := 0
	switch reply[3] {
	case 1:
		addrLen = 4
	case 4:
		addrLen = 16
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return fmt.Errorf("read SOCKS5 bind address: %w", err)
		}
		addrLen = int(n[0])
	default:
		return fmt.Errorf("invalid SOCKS5 bind address type 0x%02x", reply[3])
	}
	bind := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, bind); err != nil {
		return fmt.Errorf("read SOCKS5 bind address: %w", err)
	}
	return nil
}
