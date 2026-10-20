package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type AuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TargetConfig struct {
	Host  string   `json:"host"`
	IPs   []string `json:"ips,omitempty"`
	Ports []int    `json:"ports"`
}

type Config struct {
	Listen           string         `json:"listen"`
	Auth             AuthConfig     `json:"auth"`
	AllowSources     []string       `json:"allow_sources"`
	Targets          []TargetConfig `json:"targets"`
	MaxConnections   int            `json:"max_connections"`
	BufferBytes      int            `json:"buffer_bytes"`
	HandshakeTimeout string         `json:"handshake_timeout"`
	DNSTimeout       string         `json:"dns_timeout"`
	DialTimeout      string         `json:"dial_timeout"`
	TCPKeepalive     string         `json:"tcp_keepalive"`
	LogLevel         string         `json:"log_level"`
}

type target struct {
	ips   []netip.Addr
	ports map[int]bool
}

type settings struct {
	Config
	sources   []netip.Prefix
	hosts     map[string]*target
	ipPorts   map[netip.Addr]map[int]bool
	handshake time.Duration
	dial      time.Duration
	keepalive time.Duration
}

func Load(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer func() { _ = f.Close() }()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid configuration: %w", err)
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		return cfg, fmt.Errorf("configuration must contain one JSON object")
	}
	return cfg, nil
}

func hostname(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".")
}

func duration(value, fallback, name string) (time.Duration, error) {
	if value == "" {
		value = fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 || d > 24*time.Hour {
		return 0, fmt.Errorf("%s must be a positive duration no greater than 24h", name)
	}
	return d, nil
}

func prepare(ctx context.Context, cfg Config) (*settings, error) {
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen must be an IP:port")
	}
	ip, err := netip.ParseAddr(host)
	p, portErr := strconv.Atoi(port)
	if err != nil || ip.Zone() != "" || portErr != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("listen must be an IP and a port between 1 and 65535")
	}
	if len(cfg.Auth.Username) < 1 || len(cfg.Auth.Username) > 255 ||
		len(cfg.Auth.Password) < 1 || len(cfg.Auth.Password) > 255 ||
		strings.HasPrefix(cfg.Auth.Password, "REPLACE_") {
		return nil, fmt.Errorf("set a username and a non-placeholder password, each 1-255 bytes")
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 16
	}
	if cfg.BufferBytes == 0 {
		cfg.BufferBytes = 16 * 1024
	}
	if cfg.MaxConnections < 1 || cfg.MaxConnections > 4096 || cfg.BufferBytes < 1024 || cfg.BufferBytes > 65536 {
		return nil, fmt.Errorf("max_connections must be 1-4096; buffer_bytes must be 1024-65536")
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "warn"
	}
	if cfg.LogLevel != "warn" && cfg.LogLevel != "info" {
		return nil, fmt.Errorf("log_level must be warn or info")
	}
	s := &settings{Config: cfg, hosts: make(map[string]*target), ipPorts: make(map[netip.Addr]map[int]bool)}
	if s.handshake, err = duration(cfg.HandshakeTimeout, "10s", "handshake_timeout"); err != nil {
		return nil, err
	}
	if s.dial, err = duration(cfg.DialTimeout, "10s", "dial_timeout"); err != nil {
		return nil, err
	}
	if s.keepalive, err = duration(cfg.TCPKeepalive, "60s", "tcp_keepalive"); err != nil {
		return nil, err
	}
	dnsTimeout, err := duration(cfg.DNSTimeout, "5s", "dns_timeout")
	if err != nil {
		return nil, err
	}
	for _, source := range cfg.AllowSources {
		prefix, err := netip.ParsePrefix(source)
		if err != nil || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid source CIDR %q", source)
		}
		s.sources = append(s.sources, prefix.Masked())
	}
	if len(s.sources) == 0 || len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("allow_sources and targets must not be empty")
	}
	for _, tc := range cfg.Targets {
		name := hostname(tc.Host)
		if name != "" {
			if strings.ContainsAny(name, " /\\:*?\x00\t\r\n") || len(name) > 253 {
				return nil, fmt.Errorf("invalid target hostname %q", tc.Host)
			}
			if _, exists := s.hosts[name]; exists {
				return nil, fmt.Errorf("duplicate target hostname %q", name)
			}
		}
		t := &target{ports: make(map[int]bool)}
		for _, port := range tc.Ports {
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid target port %d", port)
			}
			t.ports[port] = true
		}
		if len(t.ports) == 0 {
			return nil, fmt.Errorf("target %q requires ports", tc.Host)
		}
		for _, value := range tc.IPs {
			addr, err := netip.ParseAddr(value)
			if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
				return nil, fmt.Errorf("invalid target IP %q", value)
			}
			t.ips = append(t.ips, addr.Unmap())
		}
		if len(t.ips) == 0 {
			if name == "" {
				return nil, fmt.Errorf("target needs host or ips")
			}
			lookupCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
			addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, name)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("resolve configured target %q: %w", name, err)
			}
			for _, addr := range addrs {
				if ip, ok := netip.AddrFromSlice(addr.IP); ok && !ip.IsUnspecified() && !ip.IsMulticast() {
					t.ips = append(t.ips, ip.Unmap())
				}
			}
		}
		if len(t.ips) == 0 {
			return nil, fmt.Errorf("target %q resolved to no usable IP addresses", name)
		}
		if name != "" {
			s.hosts[name] = t
		}
		for _, ip := range t.ips {
			if s.ipPorts[ip] == nil {
				s.ipPorts[ip] = make(map[int]bool)
			}
			for port := range t.ports {
				s.ipPorts[ip][port] = true
			}
		}
	}
	return s, nil
}
