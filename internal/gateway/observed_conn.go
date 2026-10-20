package gateway

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// observedConn measures upstream application bytes, excluding SOCKS5 negotiation.
// It retains TCP half-close behavior and never records packet contents.
type observedConn struct {
	// Keep 64-bit atomic counters first for alignment on 32-bit router targets.
	sent     int64
	received int64
	net.Conn
	policy   policy
	source   string
	target   string
	started  time.Time
	close    sync.Once
	closeErr error
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && atomic.AddInt64(&c.received, int64(n)) == int64(n) {
		c.policy.event("INFO", "first_upstream_bytes src=%q target=%q bytes=%d elapsed=%s", c.source, c.target, n, time.Since(c.started))
	}
	if err != nil {
		c.policy.event("INFO", "upstream_read_end src=%q target=%q error=%q", c.source, c.target, err.Error())
	}
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 && atomic.AddInt64(&c.sent, int64(n)) == int64(n) {
		c.policy.event("INFO", "first_client_bytes_forwarded src=%q target=%q bytes=%d elapsed=%s", c.source, c.target, n, time.Since(c.started))
	}
	if err != nil {
		c.policy.event("INFO", "upstream_write_end src=%q target=%q error=%q", c.source, c.target, err.Error())
	}
	return n, err
}

func (c *observedConn) CloseWrite() error {
	c.policy.event("INFO", "client_to_upstream_copy_end src=%q target=%q", c.source, c.target)
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

func (c *observedConn) Close() error {
	c.close.Do(func() {
		c.closeErr = c.Conn.Close()
		c.policy.event("INFO", "transfer_summary src=%q target=%q upstream=%q bytes_to_upstream=%d bytes_from_upstream=%d elapsed=%s",
			c.source, c.target, c.RemoteAddr(), atomic.LoadInt64(&c.sent), atomic.LoadInt64(&c.received), time.Since(c.started))
	})
	return c.closeErr
}
