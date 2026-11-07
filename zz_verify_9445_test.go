//go:build !windows

// Independent acceptance probe for precheck 9445 (PROXY protocol v2 intake).
// Written by the reviewer; drives a real EventLoop listener over TCP.
package netpoll

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func verifyProxyV2Header(command byte, famProto byte, body []byte) []byte {
	h := []byte("\r\n\r\n\x00\r\nQUIT\n")
	h = append(h, 0x20|command, famProto, byte(len(body)>>8), byte(len(body)))
	return append(h, body...)
}

func verifyTCP4Body(src, dst net.IP, sport, dport uint16) []byte {
	b := make([]byte, 0, 12)
	b = append(b, src.To4()...)
	b = append(b, dst.To4()...)
	b = binary.BigEndian.AppendUint16(b, sport)
	b = binary.BigEndian.AppendUint16(b, dport)
	return b
}

type verifyProxyServer struct {
	mu       sync.Mutex
	events   []string
	payload  []byte
	info     *ProxyInfo
	hadInfo  bool
	onConErr error
}

func verifyStartProxyServer(t *testing.T, trusted func(net.Addr) bool) (*verifyProxyServer, net.Listener, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &verifyProxyServer{}
	onConnect := func(ctx context.Context, c Connection) context.Context {
		s.mu.Lock()
		s.events = append(s.events, "connect")
		if pc, ok := c.(ProxyConn); ok {
			if info, ok := pc.ProxyProtocol(); ok {
				s.info, s.hadInfo = info, true
			}
		}
		s.mu.Unlock()
		return ctx
	}
	onRequest := func(ctx context.Context, c Connection) error {
		n := c.Reader().Len()
		p, err := c.Reader().ReadBinary(n)
		s.mu.Lock()
		s.events = append(s.events, "request")
		s.payload = append(s.payload, p...)
		s.mu.Unlock()
		if err != nil {
			s.mu.Lock()
			s.onConErr = err
			s.mu.Unlock()
		}
		return nil
	}
	evl, err := NewEventLoop(onRequest,
		WithOnConnect(onConnect),
		WithProxyProtocol(ProxyProtocolConfig{
			TrustedPeer:      trusted,
			MaxHeaderSize:    512,
			HandshakeTimeout: 2 * time.Second,
		}),
	)
	if err != nil {
		t.Fatalf("NewEventLoop: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = evl.Serve(ln)
	}()
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = evl.Shutdown(ctx)
		<-done
	}
	return s, ln, cleanup
}

func verifyDialWrite(t *testing.T, addr net.Addr, chunks [][]byte) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	for _, chunk := range chunks {
		if _, err := conn.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return conn
}

func verifyWaitEvents(t *testing.T, s *verifyProxyServer, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		joined := ""
		for _, e := range s.events {
			joined += e + ","
		}
		s.mu.Unlock()
		if joined == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	s.mu.Lock()
	got := append([]string(nil), s.events...)
	s.mu.Unlock()
	t.Fatalf("callback sequence = %v, want %q", got, want)
}

func TestVerify9445OrderingAndAddresses(t *testing.T) {
	s, ln, cleanup := verifyStartProxyServer(t, func(net.Addr) bool { return true })
	defer cleanup()

	header := verifyProxyV2Header(0x1, 0x11, verifyTCP4Body(net.IPv4(1, 2, 3, 4), net.IPv4(5, 6, 7, 8), 1234, 80))
	// fragmented header, payload riding in the last fragment
	chunks := [][]byte{header[:5], header[5:11], append(append([]byte{}, header[11:]...), []byte("hello")...)}
	conn := verifyDialWrite(t, ln.Addr(), chunks)
	defer conn.Close()

	verifyWaitEvents(t, s, "connect,request,", 5*time.Second)
	s.mu.Lock()
	payload := string(s.payload)
	info, had := s.info, s.hadInfo
	s.mu.Unlock()
	if payload != "hello" {
		t.Fatalf("application payload = %q, want %q", payload, "hello")
	}
	if !had || info == nil {
		t.Fatal("ProxyInfo is not available on the connection")
	}
	if got := info.RemoteAddr().String(); got != "1.2.3.4:1234" {
		t.Fatalf("parsed remote = %q, want 1.2.3.4:1234", got)
	}
	if got := info.OriginalRemoteAddr().String(); got == "1.2.3.4:1234" || got == "" {
		t.Fatalf("original remote address was not preserved: %q", got)
	}
}

func TestVerify9445LocalNonZeroBody(t *testing.T) {
	s, ln, cleanup := verifyStartProxyServer(t, func(net.Addr) bool { return true })
	defer cleanup()

	body := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	header := verifyProxyV2Header(0x0, 0x00, body)
	conn := verifyDialWrite(t, ln.Addr(), [][]byte{header, []byte("world")})
	defer conn.Close()

	verifyWaitEvents(t, s, "connect,request,", 5*time.Second)
	s.mu.Lock()
	payload := string(s.payload)
	info, had := s.info, s.hadInfo
	s.mu.Unlock()
	if payload != "world" {
		t.Fatalf("application payload = %q, want %q", payload, "world")
	}
	if !had || info == nil {
		t.Fatal("ProxyInfo missing for a LOCAL header")
	}
	if !info.IsLocal() {
		t.Fatal("LOCAL command was not reported as local")
	}
	if info.RemoteAddr() != nil && info.RemoteAddr().String() == "1.2.3.4:1234" {
		t.Fatal("LOCAL header published a claimed remote address")
	}
}

func TestVerify9445UntrustedPeerIsUntouched(t *testing.T) {
	s, ln, cleanup := verifyStartProxyServer(t, func(net.Addr) bool { return false })
	defer cleanup()

	header := verifyProxyV2Header(0x1, 0x11, verifyTCP4Body(net.IPv4(9, 9, 9, 9), net.IPv4(8, 8, 8, 8), 4321, 80))
	conn := verifyDialWrite(t, ln.Addr(), [][]byte{header, []byte("plain")})
	defer conn.Close()

	verifyWaitEvents(t, s, "connect,request,", 5*time.Second)
	s.mu.Lock()
	payload := s.payload
	had := s.hadInfo
	s.mu.Unlock()
	if had {
		t.Fatal("untrusted peer produced ProxyInfo")
	}
	if len(payload) != len(header)+len("plain") {
		t.Fatalf("untrusted peer payload length = %d, want %d (header must not be consumed)", len(payload), len(header)+5)
	}
}

func TestVerify9445MalformedHeaderCloses(t *testing.T) {
	s, ln, cleanup := verifyStartProxyServer(t, func(net.Addr) bool { return true })
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	_, rerr := conn.Read(buf)
	if rerr == nil {
		t.Fatal("connection stayed open with a malformed preamble")
	}
	if errors.Is(rerr, os.ErrDeadlineExceeded) {
		t.Fatal("malformed preamble did not close the connection: read deadline instead of FIN")
	}
	s.mu.Lock()
	got := append([]string(nil), s.events...)
	s.mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("user callbacks ran for a rejected handshake: %v", got)
	}
}
