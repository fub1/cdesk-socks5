package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"github.com/things-go/go-socks5/statute"
)

type credentials struct{ username, password [32]byte }

func (c credentials) Valid(username, password, _ string) bool {
	u, p := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(u[:], c.username[:])&subtle.ConstantTimeCompare(p[:], c.password[:]) == 1
}

type policy struct {
	settings *settings
	logger   *log.Logger
}

func (p policy) event(level, format string, args ...interface{}) {
	if p.logger != nil && (level == "WARN" || p.settings.LogLevel == "info") {
		p.logger.Printf(level+" "+format, args...)
	}
}

func requestTarget(req *socks5.Request) string {
	addr := req.RawDestAddr
	if addr == nil {
		return "unknown"
	}
	host := addr.FQDN
	if host == "" {
		host = addr.IP.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(addr.Port))
}

// Resolve returns only startup-approved addresses; requests cannot trigger DNS lookups.
func (p policy) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if t := p.settings.hosts[hostname(name)]; t != nil {
		return ctx, net.IP(t.ips[0].AsSlice()), nil
	}
	p.event("WARN", "target_denied host=%q reason=hostname_not_allowed", name)
	return ctx, nil, fmt.Errorf("target hostname is not allowed")
}

func (p policy) destinations(req *socks5.Request) []netip.Addr {
	if req.Command != statute.CommandConnect || req.Reserved != 0 || req.DestAddr == nil {
		return nil
	}
	addr := req.DestAddr
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return nil
	}
	ip = ip.Unmap()
	if addr.FQDN != "" {
		t := p.settings.hosts[hostname(addr.FQDN)]
		if t == nil || !t.ports[addr.Port] {
			return nil
		}
		for _, approved := range t.ips {
			if ip == approved {
				return t.ips
			}
		}
		return nil
	}
	if p.settings.ipPorts[ip][addr.Port] {
		return []netip.Addr{ip}
	}
	return nil
}

func (p policy) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	allowed := len(p.destinations(req)) > 0
	if !allowed {
		p.event("WARN", "target_denied src=%q target=%q command=%d reason=address_port_or_command_not_allowed", req.RemoteAddr, requestTarget(req), req.Command)
	}
	return ctx, allowed
}

func (p policy) dial(ctx context.Context, network, _ string, req *socks5.Request) (net.Conn, error) {
	ips := p.destinations(req)
	if network != "tcp" || len(ips) == 0 {
		return nil, fmt.Errorf("destination denied")
	}
	ctx, cancel := context.WithTimeout(ctx, p.settings.dial)
	defer cancel()
	dialer := net.Dialer{KeepAlive: p.settings.keepalive}
	var lastErr error
	started := time.Now()
	for _, ip := range ips {
		upstream := net.JoinHostPort(ip.String(), strconv.Itoa(req.DestAddr.Port))
		p.event("INFO", "dial_start src=%q target=%q upstream=%q", req.RemoteAddr, requestTarget(req), upstream)
		conn, err := dialer.DialContext(ctx, "tcp", upstream)
		if err == nil {
			p.event("INFO", "connected src=%q target=%q upstream=%q elapsed=%s", req.RemoteAddr, requestTarget(req), conn.RemoteAddr(), time.Since(started))
			if p.ossEnabled(req) {
				return newOSSConn(conn, p, req.RemoteAddr.String(), requestTarget(req)), nil
			}
			if p.settings.LogLevel == "info" && p.logger != nil {
				return &observedConn{Conn: conn, policy: p, source: req.RemoteAddr.String(), target: requestTarget(req), started: time.Now()}, nil
			}
			return conn, nil
		}
		p.event("WARN", "dial_failed src=%q target=%q upstream=%q error=%q", req.RemoteAddr, requestTarget(req), upstream, err.Error())
		lastErr = err
	}
	return nil, lastErr
}

type Service struct {
	settings *settings
	server   *socks5.Server
	logger   *log.Logger
}

func New(ctx context.Context, cfg Config, logger *log.Logger) (*Service, error) {
	s, err := prepare(ctx, cfg)
	if err != nil {
		return nil, err
	}
	p := policy{settings: s, logger: logger}
	if logger != nil {
		logger.Printf("INFO policy sources=%v max_connections=%d log_level=%s", cfg.AllowSources, s.MaxConnections, s.LogLevel)
		for _, tc := range cfg.Targets {
			ips := tc.IPs
			if target := s.hosts[hostname(tc.Host)]; target != nil {
				ips = make([]string, 0, len(target.ips))
				for _, ip := range target.ips {
					ips = append(ips, ip.String())
				}
			}
			logger.Printf("INFO target_allowed host=%q ips=%v ports=%v", tc.Host, ips, tc.Ports)
			if tc.OSSHBBSPort != 0 {
				logger.Printf("WARN oss_bridge_enabled host=%q port=%d signalling=legacy_plaintext client=RustDesk-1.5.0", tc.Host, tc.OSSHBBSPort)
			}
		}
	}
	server := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{&socks5.UserPassAuthenticator{Credentials: credentials{
			username: sha256.Sum256([]byte(s.Auth.Username)), password: sha256.Sum256([]byte(s.Auth.Password)),
		}}}),
		socks5.WithRule(p), socks5.WithResolver(p), socks5.WithDialAndRequest(p.dial),
		socks5.WithBufferPool(bufferpool.NewPool(s.BufferBytes)), socks5.WithHandshakeTimeout(s.handshake),
	)
	return &Service{settings: s, server: server, logger: logger}, nil
}

func (s *Service) sourceAllowed(addr net.Addr) bool {
	a, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return false
	}
	for _, prefix := range s.settings.sources {
		if prefix.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

// Serve owns the listener and closes all active streams when ctx is canceled.
func (s *Service) Serve(ctx context.Context, listener net.Listener) error {
	p := policy{settings: s.settings, logger: s.logger}
	var mu sync.Mutex
	var wg sync.WaitGroup
	active := make(map[net.Conn]struct{})
	slots := make(chan struct{}, s.settings.MaxConnections)
	done := make(chan struct{})
	stop := func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range active {
			_ = conn.Close()
		}
	}
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()
	defer func() { close(done); stop(); wg.Wait() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !s.sourceAllowed(conn.RemoteAddr()) {
			p.event("WARN", "source_denied src=%q allowed=%v", conn.RemoteAddr(), s.settings.AllowSources)
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			p.event("WARN", "connection_limit src=%q max_connections=%d", conn.RemoteAddr(), s.settings.MaxConnections)
			_ = conn.Close()
			continue
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			keepaliveErr := tcp.SetKeepAlive(true)
			if keepaliveErr == nil {
				keepaliveErr = tcp.SetKeepAlivePeriod(s.settings.keepalive)
			}
			if keepaliveErr != nil {
				_ = conn.Close()
				<-slots
				if s.logger != nil {
					s.logger.Printf("cannot enable TCP keepalive: %q", keepaliveErr.Error())
				}
				continue
			}
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			_ = conn.Close()
			<-slots
			return nil
		}
		active[conn] = struct{}{}
		mu.Unlock()
		p.event("INFO", "accepted src=%q", conn.RemoteAddr())
		wg.Add(1)
		go func(conn net.Conn) {
			started := time.Now()
			defer func() {
				mu.Lock()
				delete(active, conn)
				mu.Unlock()
				<-slots
				wg.Done()
			}()
			if err := s.server.ServeConn(conn); err != nil {
				if ctx.Err() != nil {
					return
				}
				event := "connection_failed"
				switch {
				case errors.Is(err, statute.ErrUserAuthFailed):
					event = "authentication_failed"
				case errors.Is(err, statute.ErrNoSupportedAuth):
					event = "authentication_method_rejected"
				}
				p.event("WARN", "%s src=%q elapsed=%s error=%q", event, conn.RemoteAddr(), time.Since(started), err.Error())
			} else {
				p.event("INFO", "closed src=%q elapsed=%s", conn.RemoteAddr(), time.Since(started))
			}
		}(conn)
	}
}
