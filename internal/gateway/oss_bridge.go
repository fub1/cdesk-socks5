package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	socks5 "github.com/things-go/go-socks5"
)

func (p policy) ossEnabled(req *socks5.Request) bool {
	if req.DestAddr.FQDN != "" {
		t := p.settings.hosts[hostname(req.DestAddr.FQDN)]
		return t != nil && t.ossPort != 0 && t.ossPort == req.DestAddr.Port
	}
	ip, ok := netip.AddrFromSlice(req.DestAddr.IP)
	return ok && p.settings.ossIPPorts[ip.Unmap()][req.DestAddr.Port]
}

// Separate pipes retain the half-close required by temporary OSS TCP requests.
type ossConn struct {
	upstream       net.Conn
	clientR        *io.PipeReader
	clientW        *io.PipeWriter
	serverR        *io.PipeReader
	serverW        *io.PipeWriter
	done           chan struct{}
	once           sync.Once
	p              policy
	source, target string
}

func newOSSConn(upstream net.Conn, p policy, source, target string) net.Conn {
	cr, cw := io.Pipe()
	sr, sw := io.Pipe()
	c := &ossConn{upstream: upstream, clientR: cr, clientW: cw, serverR: sr, serverW: sw, done: make(chan struct{}), p: p, source: source, target: target}
	go func() {
		err := c.run()
		if err != nil && err != io.EOF {
			select {
			case <-c.done:
			default:
				p.event("WARN", "oss_bridge_failed src=%q target=%q error=%q", source, target, err.Error())
			}
		}
		_ = c.serverW.CloseWithError(err)
		_ = c.clientR.CloseWithError(err)
		_ = upstream.Close()
	}()
	return c
}

func (c *ossConn) Read(b []byte) (int, error)  { return c.serverR.Read(b) }
func (c *ossConn) Write(b []byte) (int, error) { return c.clientW.Write(b) }
func (c *ossConn) LocalAddr() net.Addr         { return c.upstream.LocalAddr() }
func (c *ossConn) RemoteAddr() net.Addr        { return c.upstream.RemoteAddr() }
func (c *ossConn) SetDeadline(t time.Time) error {
	if !t.IsZero() {
		return fmt.Errorf("adapter deadlines are managed internally")
	}
	return nil
}
func (c *ossConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *ossConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *ossConn) CloseWrite() error                  { return c.clientW.Close() }
func (c *ossConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		_ = c.clientW.Close()
		_ = c.clientR.Close()
		_ = c.serverW.Close()
		_ = c.serverR.Close()
		_ = c.upstream.Close()
	})
	return nil
}

type ossPacket struct {
	data []byte
	err  error
}

func (c *ossConn) frames() <-chan ossPacket {
	ch := make(chan ossPacket, 1)
	go func() {
		for {
			b, err := readOSSFrame(c.clientR)
			select {
			case ch <- ossPacket{b, err}:
			case <-c.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return ch
}

func (c *ossConn) run() error {
	// Registration waits for a server greeting; OSS temporary requests send first.
	// Peek only one byte so a partially arrived control frame never gets a greeting.
	firstByte := make(chan ossPacket, 1)
	go func() { var b [1]byte; _, err := io.ReadFull(c.clientR, b[:]); firstByte <- ossPacket{b[:], err} }()
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	var first ossPacket
	select {
	case first = <-firstByte:
	case <-timer.C:
		c.p.event("INFO", "oss_legacy_greeting src=%q target=%q signalling=plaintext", c.source, c.target)
		if err := writeOSSFrame(c.serverW, nil); err != nil {
			return err
		}
		firstTimer := time.NewTimer(c.p.settings.handshake)
		defer firstTimer.Stop()
		select {
		case first = <-firstByte:
		case <-firstTimer.C:
			return fmt.Errorf("RustDesk first message timeout")
		case <-c.done:
			return nil
		}
	case <-c.done:
		return nil
	}
	if first.err != nil {
		return first.err
	}
	// Reattach the peeked byte; the complete frame has its own time limit.
	frameCh := make(chan ossPacket, 1)
	go func() {
		b, err := readOSSFrame(io.MultiReader(bytes.NewReader(first.data), c.clientR))
		frameCh <- ossPacket{b, err}
	}()
	frameTimer := time.NewTimer(c.p.settings.handshake)
	defer frameTimer.Stop()
	var packet ossPacket
	select {
	case packet = <-frameCh:
	case <-frameTimer.C:
		return fmt.Errorf("RustDesk frame timeout")
	case <-c.done:
		return nil
	}
	if packet.err != nil {
		return packet.err
	}
	number, body, err := ossMessage(packet.data)
	if err != nil {
		return err
	}
	if number == 15 {
		id, err := ossRegistration(body)
		if err != nil {
			return err
		}
		return c.register(packet.data, id)
	}
	if number == 6 {
		return fmt.Errorf("initial RegisterPeer without device public key is unsupported")
	}
	c.p.event("INFO", "oss_tcp_passthrough src=%q target=%q message=%d", c.source, c.target, number)
	if err := writeOSSFrame(c.upstream, packet.data); err != nil {
		return err
	}
	return c.forwardTCP()
}

func (c *ossConn) forwardTCP() error {
	results := make(chan error, 2)
	go func() {
		_, err := io.Copy(c.upstream, c.clientR)
		if tcp, ok := c.upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		results <- err
	}()
	go func() { _, err := io.Copy(c.serverW, c.upstream); _ = c.serverW.CloseWithError(err); results <- err }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				return err
			}
		case <-c.done:
			return nil
		}
	}
	return nil
}

func (c *ossConn) register(initial []byte, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.p.settings.dial)
	udp, err := (&net.Dialer{}).DialContext(ctx, "udp", c.upstream.RemoteAddr().String())
	cancel()
	if err != nil {
		return fmt.Errorf("OSS UDP dial: %w", err)
	}
	defer func() { _ = udp.Close() }()
	_ = c.upstream.Close()
	c.p.event("INFO", "oss_register_start src=%q target=%q udp=%q", c.source, c.target, udp.LocalAddr())
	incoming := make(chan ossPacket, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		b := make([]byte, ossMaxFrame+1)
		for {
			n, err := udp.Read(b)
			if n > ossMaxFrame {
				err = fmt.Errorf("OSS UDP message too large")
			}
			packet := ossPacket{append([]byte(nil), b[:n]...), err}
			select {
			case incoming <- packet:
			case <-stop:
				return
			case <-c.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	client := c.frames()
	registered, pending := false, true
	cached := initial
	lastReply, lastSend := time.Now(), time.Now()
	if _, err := udp.Write(initial); err != nil {
		return err
	}
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case packet := <-client:
			if packet.err != nil {
				return packet.err
			}
			if len(packet.data) == 0 {
				continue
			}
			number, body, err := ossMessage(packet.data)
			if err != nil {
				return err
			}
			switch number {
			case 15:
				nextID, err := ossRegistration(body)
				if err != nil {
					return err
				}
				if nextID != id {
					return fmt.Errorf("device ID changed; reconnect required")
				}
				cached = packet.data
				pending = true
			case 6:
				fields, err := ossFields(body)
				if err != nil {
					return err
				}
				for _, f := range fields {
					if f.number == 1 && string(f.data) != id {
						return fmt.Errorf("registration identity mismatch")
					}
				}
			default:
				return fmt.Errorf("unexpected registration message %d", number)
			}
			if _, err := udp.Write(packet.data); err != nil {
				return err
			}
			lastSend = time.Now()
		case packet := <-incoming:
			if packet.err != nil {
				return packet.err
			}
			number, body, err := ossMessage(packet.data)
			if err != nil {
				return err
			}
			switch number {
			case 16:
				result, err := ossScalar(body, 1)
				if err != nil {
					return err
				}
				registered = result == 0
				pending = false
				c.p.event("INFO", "oss_register_response src=%q target=%q result=%d", c.source, c.target, result)
			case 7, 9, 12, 14, 18:
				c.p.event("INFO", "oss_udp_message src=%q target=%q message=%d", c.source, c.target, number)
			default:
				return fmt.Errorf("unexpected OSS UDP response %d", number)
			}
			lastReply = time.Now()
			if err := writeOSSFrame(c.serverW, packet.data); err != nil {
				return err
			}
		case now := <-timer.C:
			if now.Sub(lastReply) > 30*time.Second {
				return fmt.Errorf("OSS UDP response timeout")
			}
			var send []byte
			if pending && now.Sub(lastSend) >= 5*time.Second {
				send = cached
			}
			if registered && !pending && now.Sub(lastSend) >= 10*time.Second {
				send = ossBytes(6, ossBytes(1, []byte(id)))
			}
			if send != nil {
				if _, err := udp.Write(send); err != nil {
					return err
				}
				lastSend = now
				c.p.event("INFO", "oss_heartbeat_sent src=%q target=%q", c.source, c.target)
			}
		case <-c.done:
			return nil
		}
	}
}
