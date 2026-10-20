package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"github.com/things-go/go-socks5/statute"
)

type credentials struct{ username, password [32]byte }

func (c credentials) Valid(username, password, _ string) bool {
	u, p := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(u[:], c.username[:])&subtle.ConstantTimeCompare(p[:], c.password[:]) == 1
}

type policy struct{ settings *settings }

// Resolve returns only startup-approved addresses; requests cannot trigger DNS lookups.
func (p policy) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if t := p.settings.hosts[hostname(name)]; t != nil {
		return ctx, net.IP(t.ips[0].AsSlice()), nil
	}
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
	return ctx, len(p.destinations(req)) > 0
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
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(req.DestAddr.Port)))
		if err == nil {
			return conn, nil
		}
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
	p := policy{s}
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
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
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
		wg.Add(1)
		go func(conn net.Conn) {
			defer func() {
				mu.Lock()
				delete(active, conn)
				mu.Unlock()
				<-slots
				wg.Done()
			}()
			if err := s.server.ServeConn(conn); err != nil && s.settings.LogLevel == "info" && s.logger != nil {
				s.logger.Printf("connection from %s ended: %q", conn.RemoteAddr(), err.Error())
			}
		}(conn)
	}
}
