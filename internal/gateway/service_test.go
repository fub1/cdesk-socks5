package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/things-go/go-socks5/statute"
)

func testConfig(port int) Config {
	return Config{
		Listen: "127.0.0.1:1080", Auth: AuthConfig{"test", "test-secret"},
		AllowSources:     []string{"127.0.0.1/32"},
		Targets:          []TargetConfig{{Host: "rustdesk.test", IPs: []string{"127.0.0.1"}, Ports: []int{port}}},
		HandshakeTimeout: "200ms", MaxConnections: 16,
	}
}

func startService(t *testing.T, cfg Config, loggers ...*log.Logger) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	logger := log.New(io.Discard, "", 0)
	if len(loggers) > 0 {
		logger = loggers[0]
	}
	s, err := New(ctx, cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("service shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("service failed to shut down")
		}
	})
	return l.Addr().String(), cancel, done
}

type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *logBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func waitLog(t *testing.T, b *logBuffer, event string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(b.text(), event) {
		if time.Now().After(deadline) {
			t.Fatalf("missing log event %q: %s", event, b.text())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWarnLogsFailuresWithoutSecrets(t *testing.T) {
	port := tcpTarget(t, "echo")
	closed, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(port)
	cfg.Targets[0].Ports = append(cfg.Targets[0].Ports, closedPort)
	cfg.LogLevel = "warn"
	var logs logBuffer
	address, _, _ := startService(t, cfg, log.New(&logs, "", 0))
	_, status := authenticate(t, address, "never-log-this-password")
	if status == 0 {
		t.Fatal("wrong password accepted")
	}
	waitLog(t, &logs, "WARN authentication_failed")
	c, status := authenticate(t, address, "test-secret")
	if status != 0 || request(t, c, 1, "rustdesk.test", 1) == 0 {
		t.Fatal("forbidden port accepted")
	}
	waitLog(t, &logs, "WARN target_denied")
	c2, status := authenticate(t, address, "test-secret")
	if status != 0 || request(t, c2, 1, "other.invalid", port) == 0 {
		t.Fatal("forbidden hostname accepted")
	}
	waitLog(t, &logs, "reason=hostname_not_allowed")
	c3, status := authenticate(t, address, "test-secret")
	if status != 0 || request(t, c3, 1, "rustdesk.test", closedPort) == 0 {
		t.Fatal("unavailable target unexpectedly connected")
	}
	waitLog(t, &logs, "WARN dial_failed")
	text := logs.text()
	if !strings.Contains(text, "src=") || !strings.Contains(text, `target="rustdesk.test:1"`) {
		t.Fatalf("source or target missing: %s", text)
	}
	if strings.Contains(text, "never-log-this-password") || strings.Contains(text, "test-secret") {
		t.Fatal("credentials leaked to logs")
	}
}

func TestInfoLogsSuccessfulTunnel(t *testing.T) {
	port := tcpTarget(t, "echo")
	cfg := testConfig(port)
	cfg.LogLevel = "info"
	var logs logBuffer
	address, _, _ := startService(t, cfg, log.New(&logs, "", 0))
	c, status := authenticate(t, address, "test-secret")
	if status != 0 || request(t, c, 1, "rustdesk.test", port) != 0 {
		t.Fatal("CONNECT failed")
	}
	waitLog(t, &logs, "INFO connected")
	text := logs.text()
	for _, want := range []string{"INFO accepted", "INFO target_allowed", "INFO dial_start", "upstream=\"127.0.0.1:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q: %s", want, text)
		}
	}
}

func tcpTarget(t *testing.T, mode string) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return
				}
				if mode == "half-close" {
					body, err := io.ReadAll(c)
					if err == nil {
						_, _ = c.Write(append([]byte("reply:"), body...))
					}
					return
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func authenticate(t *testing.T, address, password string) (net.Conn, byte) {
	t.Helper()
	c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 2, 0, 2}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{5, 2} {
		t.Fatalf("user/password method: %v %v", reply, err)
	}
	frame := []byte{1, 4, 't', 'e', 's', 't', byte(len(password))}
	frame = append(frame, []byte(password)...)
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	return c, reply[1]
}

func request(t *testing.T, c net.Conn, command byte, host string, port int) byte {
	t.Helper()
	frame := []byte{5, command, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			frame = append(frame, 1)
			frame = append(frame, ip4...)
		} else {
			frame = append(frame, 4)
			frame = append(frame, ip.To16()...)
		}
	} else {
		frame = append(frame, 3, byte(len(host)))
		frame = append(frame, []byte(host)...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	frame = append(frame, p[:]...)
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
	reply, err := statute.ParseReply(c)
	if err != nil {
		t.Fatal(err)
	}
	return reply.Response
}

func TestProxyTCPAndHTTPS(t *testing.T) {
	hbbs, hbbr := tcpTarget(t, "echo"), tcpTarget(t, "half-close")
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/currentUser" || r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"proxy-test"}`)
	}))
	t.Cleanup(api.Close)
	_, apiPort, _ := net.SplitHostPort(api.Listener.Addr().String())
	p, _ := strconv.Atoi(apiPort)
	cfg := testConfig(hbbs)
	cfg.Targets[0].Ports = []int{hbbs, hbbr, p}
	address, _, _ := startService(t, cfg)

	t.Run("hbbs-domain-long-lived", func(t *testing.T) {
		c, status := authenticate(t, address, "test-secret")
		if status != 0 || request(t, c, 1, "RUSTDESK.TEST.", hbbs) != 0 {
			t.Fatal("CONNECT failed")
		}
		// The established session must outlive the handshake deadline.
		time.Sleep(300 * time.Millisecond)
		payload := bytes.Repeat([]byte{0, 1, 255, 32}, 32768)
		writeDone := make(chan error, 1)
		go func() { _, err := c.Write(payload); writeDone <- err }()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(payload, got) {
			t.Fatalf("TCP relay mismatch: %v", err)
		}
		if err := <-writeDone; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("hbbr-ip-half-close", func(t *testing.T) {
		c, status := authenticate(t, address, "test-secret")
		if status != 0 || request(t, c, 1, "127.0.0.1", hbbr) != 0 {
			t.Fatal("CONNECT failed")
		}
		if _, err := c.Write([]byte("relay-payload")); err != nil {
			t.Fatal(err)
		}
		if err := c.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(c)
		if err != nil || string(body) != "reply:relay-payload" {
			t.Fatalf("half-close lost response: %q %v", body, err)
		}
	})
	t.Run("api-ip-tls-verification", func(t *testing.T) {
		c, status := authenticate(t, address, "test-secret")
		if status != 0 || request(t, c, 1, "127.0.0.1", p) != 0 {
			t.Fatal("CONNECT failed")
		}
		roots := x509.NewCertPool()
		roots.AddCert(api.Certificate())
		secure := tls.Client(c, &tls.Config{RootCAs: roots, ServerName: api.Certificate().DNSNames[0], MinVersion: tls.VersionTLS12})
		defer func() { _ = secure.Close() }()
		if err := secure.HandshakeContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(secure, "GET /api/currentUser HTTP/1.1\r\nHost: rustdesk.test\r\nAuthorization: Bearer test-token\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(secure), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		if response.StatusCode != 200 || err != nil || !strings.Contains(string(body), "proxy-test") {
			t.Fatalf("HTTPS API relay: %d %q %v", response.StatusCode, body, err)
		}
	})
}

func TestAuthenticationAndTargetDenials(t *testing.T) {
	port := tcpTarget(t, "echo")
	address, _, _ := startService(t, testConfig(port))
	t.Run("wrong-password", func(t *testing.T) {
		_, status := authenticate(t, address, "wrong-password")
		if status == 0 {
			t.Fatal("wrong password accepted")
		}
	})
	t.Run("anonymous", func(t *testing.T) {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte{5, 1, 0}); err != nil {
			t.Fatal(err)
		}
		var reply [2]byte
		if _, err := io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{5, 255} {
			t.Fatalf("anonymous authentication not denied: %v %v", reply, err)
		}
	})
	for _, tc := range []struct {
		name string
		host string
		port int
		cmd  byte
	}{
		{"unlisted-host", "other.invalid", port, 1},
		{"suffix-host", "rustdesk.test.evil.invalid", port, 1},
		{"unlisted-ip", "127.0.0.2", port, 1},
		{"unlisted-port", "127.0.0.1", 1, 1},
		{"unlisted-domain-port", "rustdesk.test", 1, 1},
		{"udp-associate", "127.0.0.1", port, 3},
		{"bind", "127.0.0.1", port, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, status := authenticate(t, address, "test-secret")
			if status != 0 || request(t, c, tc.cmd, tc.host, tc.port) == 0 {
				t.Fatal("forbidden destination or command accepted")
			}
		})
	}
}

func TestSourceLimitTimeoutAndShutdown(t *testing.T) {
	port := tcpTarget(t, "echo")
	t.Run("source", func(t *testing.T) {
		cfg := testConfig(port)
		cfg.AllowSources = []string{"192.0.2.0/24"}
		var logs logBuffer
		address, _, _ := startService(t, cfg, log.New(&logs, "", 0))
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte{5, 1, 2}); err != nil {
			t.Fatal(err)
		}
		var b [2]byte
		if n, _ := c.Read(b[:]); n != 0 {
			t.Fatal("denied source reached SOCKS negotiation")
		}
		waitLog(t, &logs, "WARN source_denied")
	})
	t.Run("connection-cap-and-timeout", func(t *testing.T) {
		cfg := testConfig(port)
		cfg.MaxConnections = 1
		cfg.HandshakeTimeout = "150ms"
		var logs logBuffer
		address, _, _ := startService(t, cfg, log.New(&logs, "", 0))
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte{5, 1, 2}); err != nil {
			t.Fatal(err)
		}
		var reply [2]byte
		if _, err := io.ReadFull(c, reply[:]); err != nil {
			t.Fatal(err)
		}
		second, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Close() }()
		if err := second.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if n, err := second.Read(reply[:]); n != 0 || err == nil {
			t.Fatal("connection cap not enforced")
		}
		waitLog(t, &logs, "WARN connection_limit")
		if n, err := c.Read(reply[:]); n != 0 || err == nil {
			t.Fatal("incomplete authentication not timed out")
		}
		c2, status := authenticate(t, address, "test-secret")
		if status != 0 || request(t, c2, 1, "127.0.0.1", port) != 0 {
			t.Fatal("timed out connection did not release slot")
		}
	})
	t.Run("shutdown-closes-established-stream", func(t *testing.T) {
		address, cancel, _ := startService(t, testConfig(port))
		c, status := authenticate(t, address, "test-secret")
		if status != 0 || request(t, c, 1, "127.0.0.1", port) != 0 {
			t.Fatal("CONNECT failed")
		}
		cancel()
		var b [1]byte
		if _, err := c.Read(b[:]); err == nil {
			t.Fatal("shutdown left stream open")
		}
	})
}

func TestConfigurationFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"empty-password", func(c *Config) { c.Auth.Password = "" }},
		{"placeholder-password", func(c *Config) { c.Auth.Password = "REPLACE_WITH_SITE_SECRET" }},
		{"no-sources", func(c *Config) { c.AllowSources = nil }},
		{"no-targets", func(c *Config) { c.Targets = nil }},
		{"bad-cidr", func(c *Config) { c.AllowSources = []string{"127.0.0.1"} }},
		{"bad-target-ip", func(c *Config) { c.Targets[0].IPs = []string{"not-an-ip"} }},
		{"wildcard-host", func(c *Config) { c.Targets[0].Host = "*.example.com" }},
		{"empty-ports", func(c *Config) { c.Targets[0].Ports = nil }},
		{"bad-duration", func(c *Config) { c.DialTimeout = "forever" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(21116)
			tc.change(&cfg)
			if _, err := New(context.Background(), cfg, nil); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, content := range []string{`{"unknown":true}`, `{} {}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("invalid JSON configuration accepted")
		}
	}
}
