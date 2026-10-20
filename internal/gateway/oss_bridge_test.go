package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestOSSFrameBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 63, 64, 16383, 16384, 65507} {
		payload := bytes.Repeat([]byte{0x55}, n)
		var framed bytes.Buffer
		if err := writeOSSFrame(&framed, payload); err != nil {
			t.Fatal(err)
		}
		if n == 64 && !bytes.Equal(framed.Bytes()[:2], []byte{1, 1}) {
			t.Fatal("wrong RustDesk header")
		}
		got, err := readOSSFrame(&framed)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("frame %d: %v", n, err)
		}
	}
	if _, err := readOSSFrame(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})); err == nil {
		t.Fatal("oversized frame accepted")
	}
	for _, b := range [][]byte{{0x80}, {0x0a, 0x80}, {0x0a, 0xff, 0x7f}, {0x0b}} {
		if _, err := ossFields(b); err == nil {
			t.Fatalf("malformed protobuf accepted %x", b)
		}
	}
}

func ossFixture(t *testing.T) (int, *net.UDPConn) {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := l.Addr().(*net.TCPAddr)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port})
	if err != nil {
		_ = l.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close(); _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, udp
}

func ossRegisterMessage(id string) []byte {
	b := ossBytes(1, []byte(id))
	b = append(b, ossBytes(2, []byte("device-uuid"))...)
	b = append(b, ossBytes(3, bytes.Repeat([]byte{42}, 32))...)
	return ossBytes(15, b)
}

func TestOSSBridgeRegistrationNotificationAndHeartbeat(t *testing.T) {
	port, udp := ossFixture(t)
	cfg := testConfig(port)
	cfg.Targets[0].OSSHBBSPort = port
	cfg.LogLevel = "info"
	var logs logBuffer
	address, _, _ := startService(t, cfg, log.New(&logs, "", 0))
	var clients []net.Conn
	var peers []*net.UDPAddr
	for _, id := range []string{"device-100", "device-200"} {
		c, status := authenticate(t, address, "test-secret")
		if status != 0 || request(t, c, 1, "RUSTDESK.TEST", port) != 0 {
			t.Fatal("CONNECT failed")
		}
		if err := c.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
			t.Fatal(err)
		}
		greeting, err := readOSSFrame(c)
		if err != nil || len(greeting) != 0 {
			t.Fatalf("legacy server-first greeting: %x %v", greeting, err)
		}
		original := ossRegisterMessage(id)
		if err := writeOSSFrame(c, original); err != nil {
			t.Fatal(err)
		}
		if err := udp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 2048)
		n, peer, err := udp.ReadFromUDP(b)
		if err != nil || !bytes.Equal(b[:n], original) {
			t.Fatalf("original registration not forwarded: %v", err)
		}
		response := ossBytes(16, nil)
		if _, err := udp.WriteToUDP(response, peer); err != nil {
			t.Fatal(err)
		}
		got, err := readOSSFrame(c)
		if err != nil || !bytes.Equal(got, response) {
			t.Fatalf("real registration response lost: %x %v", got, err)
		}
		clients = append(clients, c)
		peers = append(peers, peer)
	}
	if peers[0].String() == peers[1].String() {
		t.Fatal("device UDP identities shared")
	}
	// Notifications may arrive long after registration, independently per device.
	for i, c := range clients {
		notice := ossBytes(18, ossBytes(2, []byte{byte(i + 1)}))
		if _, err := udp.WriteToUDP(notice, peers[i]); err != nil {
			t.Fatal(err)
		}
		got, err := readOSSFrame(c)
		if err != nil || !bytes.Equal(got, notice) {
			t.Fatalf("wrong notification for client %d: %x %v", i, got, err)
		}
	}
	if err := udp.SetReadDeadline(time.Now().Add(17 * time.Second)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2048)
	n, _, err := udp.ReadFromUDP(b)
	if err != nil {
		t.Fatal("missing independent OSS heartbeat:", err)
	}
	number, _, err := ossMessage(b[:n])
	if err != nil || number != 6 {
		t.Fatalf("heartbeat must be RegisterPeer, got %d %v", number, err)
	}
	waitLog(t, &logs, "oss_register_response")
	// Rejection must be forwarded unchanged, not turned into a successful register.
	failure := ossBytes(16, []byte{8, 2})
	if _, err := udp.WriteToUDP(failure, peers[0]); err != nil {
		t.Fatal(err)
	}
	got, err := readOSSFrame(clients[0])
	if err != nil || !bytes.Equal(got, failure) {
		t.Fatalf("registration rejection hidden: %x %v", got, err)
	}
}

func TestOSSBridgeKeepsTemporaryTCPAndPolicy(t *testing.T) {
	port, _ := ossFixture(t)
	cfg := testConfig(port)
	cfg.Targets[0].OSSHBBSPort = port
	address, _, _ := startService(t, cfg)
	c, status := authenticate(t, address, "test-secret")
	if status != 0 || request(t, c, 1, "127.0.0.1", port) != 0 {
		t.Fatal("CONNECT failed")
	}
	// Client-first control traffic must not receive the compatibility greeting.
	packet := ossBytes(19, ossBytes(2, []byte("relay-session")))
	if err := writeOSSFrame(c, packet); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := readOSSFrame(c)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("control/half-close changed: %x %v", got, err)
	}
	bad, status := authenticate(t, address, "wrong-password")
	_ = bad
	if status == 0 {
		t.Fatal("bridge bypassed authentication")
	}
	denied, status := authenticate(t, address, "test-secret")
	if status != 0 || request(t, denied, 1, "other.invalid", port) == 0 {
		t.Fatal("bridge bypassed target ACL")
	}
	cfg.Targets[0].OSSHBBSPort = port + 1
	if _, err := prepare(context.Background(), cfg); err == nil {
		t.Fatal("unapproved UDP port allowed")
	}
}

func TestOSSMessageUsesCanonicalProtobuf(t *testing.T) {
	// Explicit wire bytes pin field numbers independently of the encoder.
	message := ossBytes(6, ossBytes(1, []byte("123456")))
	if !bytes.Equal(message, []byte{0x32, 8, 0x0a, 6, '1', '2', '3', '4', '5', '6'}) {
		t.Fatalf("wrong heartbeat wire %x", message)
	}
	var h [10]byte
	n := binary.PutUvarint(h[:], 16<<3|2)
	if !bytes.Equal(h[:n], []byte{0x82, 1}) {
		t.Fatal("wrong RegisterPkResponse tag")
	}
}

// Opt-in integration against an actual OSS hbbs, without changing its database
// outside the test instance. The ordinary suite uses the local UDP fixture.
func TestOSSRealServer(t *testing.T) {
	address := os.Getenv("CDESK_OSS_TEST_ADDR")
	if address == "" {
		t.Skip("set CDESK_OSS_TEST_ADDR to an isolated real OSS hbbs")
	}
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(port)
	cfg.Targets[0].IPs = []string{host}
	cfg.Targets[0].OSSHBBSPort = port
	cfg.LogLevel = "info"
	var logs logBuffer
	proxy, _, _ := startService(t, cfg, log.New(&logs, "", 0))
	client, status := authenticate(t, proxy, "test-secret")
	if status != 0 || request(t, client, 1, "rustdesk.test", port) != 0 {
		t.Fatal("CONNECT failed")
	}
	if err := client.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
		t.Fatal(err)
	}
	greeting, err := readOSSFrame(client)
	if err != nil || len(greeting) != 0 {
		t.Fatal("registration greeting failed", err)
	}
	id := "bridge" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := writeOSSFrame(client, ossRegisterMessage(id)); err != nil {
		t.Fatal(err)
	}
	response, err := readOSSFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	number, body, err := ossMessage(response)
	if err != nil || number != 16 {
		t.Fatal("no real registration response", number, err)
	}
	result, err := ossScalar(body, 1)
	if err != nil || result != 0 {
		t.Fatal("real OSS rejected registration", result, err)
	}
	// The real server's heartbeat reply proves that the device remains reachable
	// on its UDP mapping after the TCP client has stopped sending RegisterPk.
	for {
		packet, err := readOSSFrame(client)
		if err != nil {
			t.Fatal("OSS heartbeat reply missing", err)
		}
		number, _, err = ossMessage(packet)
		if err != nil {
			t.Fatal(err)
		}
		if number == 7 {
			break
		}
	}
	controller, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = controller.Close() }()
	if err := controller.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	relayRequest := ossBytes(1, []byte(id))
	relayRequest = append(relayRequest, ossBytes(2, []byte("real-relay-session"))...)
	if err := writeOSSFrame(controller, ossBytes(18, relayRequest)); err != nil {
		t.Fatal(err)
	}
	var notice []byte
	for {
		packet, err := readOSSFrame(client)
		if err != nil {
			t.Fatal("real OSS notification missing", err)
		}
		number, body, err = ossMessage(packet)
		if err != nil {
			t.Fatal(err)
		}
		if number == 18 {
			notice = body
			break
		}
	}
	fields, err := ossFields(notice)
	if err != nil {
		t.Fatal(err)
	}
	var socketAddr []byte
	for _, f := range fields {
		if f.number == 3 {
			socketAddr = f.data
		}
	}
	if len(socketAddr) == 0 {
		t.Fatal("real OSS did not include controller address")
	}
	answer, status := authenticate(t, proxy, "test-secret")
	if status != 0 || request(t, answer, 1, "rustdesk.test", port) != 0 {
		t.Fatal("temporary control CONNECT failed")
	}
	relayResponse := ossBytes(1, socketAddr)
	relayResponse = append(relayResponse, ossBytes(2, []byte("real-relay-session"))...)
	relayResponse = append(relayResponse, ossBytes(3, []byte("relay.test:21117"))...)
	if err := writeOSSFrame(answer, ossBytes(19, relayResponse)); err != nil {
		t.Fatal(err)
	}
	packet, err := readOSSFrame(controller)
	if err != nil {
		t.Fatal("real controller got no relay response", err)
	}
	number, _, err = ossMessage(packet)
	if err != nil || number != 19 {
		t.Fatal("wrong real relay response", number, err)
	}
	t.Log("real OSS registration, UDP heartbeat, asynchronous request notification and TCP relay response passed")
}
