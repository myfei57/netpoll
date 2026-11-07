// Copyright 2026 CloudWeGo Authors
//
// Licensed under the Apache License, Version 2.0) (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows

package netpoll

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Integration tests for PROXY protocol v2 reception over real local TCP.
// Clients send the header byte by time (arbitrary fragment boundaries) and
// coalesce application payload with (or right after) the header.

const proxyTestWait = 3 * time.Second

func trustAllProxies(net.Addr) bool { return true }
func trustNoProxies(net.Addr) bool  { return false }

type proxyRequestMsg struct {
	data         string
	remaining    int
	remote       string
	local        string
	info         *ProxyInfo
	connectOrder int32
	requestOrder int32
}

type proxyHarness struct {
	t        *testing.T
	addr     string
	ln       Listener
	loop     EventLoop
	expected int // exact bytes the OnRequest handler reads

	order        int32 // monotonic callback order counter
	connectOrder int32 // order at which OnConnect fired (0 = not fired)

	connected    chan *ProxyInfo
	requests     chan proxyRequestMsg
	requestCalls int32
}

func newProxyHarness(t *testing.T, cfg ProxyProtocolConfig, expectedRead int) *proxyHarness {
	t.Helper()
	ln, err := CreateListener("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h := &proxyHarness{
		t:         t,
		addr:      ln.Addr().String(),
		ln:        ln,
		expected:  expectedRead,
		connected: make(chan *ProxyInfo, 8),
		requests:  make(chan proxyRequestMsg, 8),
	}
	onConnect := func(ctx context.Context, conn Connection) context.Context {
		info, ok := conn.(ProxyConn).ProxyProtocol()
		ctxInfo, ctxOK := ProxyInfoFromContext(ctx)
		if ok != ctxOK || info != ctxInfo {
			t.Errorf("proxy info mismatch: conn=(%v,%v) ctx=(%v,%v)", info, ok, ctxInfo, ctxOK)
		}
		atomic.StoreInt32(&h.connectOrder, atomic.AddInt32(&h.order, 1))
		select {
		case h.connected <- info:
		default:
		}
		return ctx
	}
	onRequest := func(ctx context.Context, conn Connection) error {
		// Next waits (off the poller goroutine) until the exact expected
		// number of bytes is available.
		b, err := conn.Reader().Next(h.expected)
		if err != nil {
			t.Errorf("next: %v", err)
			return nil
		}
		data := string(b)
		remaining := conn.Reader().Len()
		if err := conn.Reader().Release(); err != nil {
			t.Errorf("release: %v", err)
		}
		info, _ := ProxyInfoFromContext(ctx)
		connectOrder := atomic.LoadInt32(&h.connectOrder)
		if connectOrder == 0 {
			t.Errorf("OnRequest fired before OnConnect")
		}
		requestOrder := atomic.AddInt32(&h.order, 1)
		atomic.AddInt32(&h.requestCalls, 1)
		h.requests <- proxyRequestMsg{
			data:         data,
			remaining:    remaining,
			remote:       conn.RemoteAddr().String(),
			local:        conn.LocalAddr().String(),
			info:         info,
			connectOrder: connectOrder,
			requestOrder: requestOrder,
		}
		return nil
	}
	loop, err := NewEventLoop(onRequest,
		WithOnConnect(onConnect),
		WithProxyProtocol(cfg),
	)
	if err != nil {
		t.Fatalf("new event loop: %v", err)
	}
	h.loop = loop
	go func() {
		if err := loop.Serve(ln); err != nil {
			t.Logf("serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()
		_ = loop.Shutdown(ctx)
	})
	return h
}

func (h *proxyHarness) dial() net.Conn {
	c, err := net.DialTimeout("tcp", h.addr, proxyTestWait)
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	return c
}

func (h *proxyHarness) waitConnect() *ProxyInfo {
	h.t.Helper()
	select {
	case info := <-h.connected:
		return info
	case <-time.After(proxyTestWait):
		h.t.Fatal("timeout waiting OnConnect")
		return nil
	}
}

func (h *proxyHarness) waitRequest() proxyRequestMsg {
	h.t.Helper()
	select {
	case msg := <-h.requests:
		return msg
	case <-time.After(proxyTestWait):
		h.t.Fatal("timeout waiting OnRequest")
		return proxyRequestMsg{}
	}
}

func (h *proxyHarness) expectQuiet(d time.Duration) {
	h.t.Helper()
	select {
	case info := <-h.connected:
		h.t.Fatalf("unexpected OnConnect: %v", info)
	case msg := <-h.requests:
		h.t.Fatalf("unexpected OnRequest: %q", msg.data)
	case <-time.After(d):
	}
}

// writeSlow sends the header one byte at a time so the preamble spans many
// read events / fragments.
func writeSlow(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	for i := 0; i < len(b); i++ {
		if _, err := c.Write(b[i : i+1]); err != nil {
			t.Fatalf("slow write at %d: %v", i, err)
		}
		time.Sleep(time.Millisecond)
	}
}

// expectClosed reads until the server closes the connection.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(proxyTestWait))
	buf := make([]byte, 32)
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("expected server close, got %d bytes: %q", n, buf[:n])
	}
}

func proxyCfg() ProxyProtocolConfig {
	return ProxyProtocolConfig{TrustedPeer: trustAllProxies, HandshakeTimeout: 5 * time.Second}
}

// LOCAL with a non-zero body must skip the whole declared body, keep the
// original transport addresses and then deliver the payload.
func TestProxyIntegrationLocalNonZeroBody(t *testing.T) {
	payload := "local-payload-data-0123456789"
	h := newProxyHarness(t, proxyCfg(), len(payload))
	c := h.dial()
	defer c.Close()

	header := v2Header(proxyCommandLocal, 0x00, nil,
		tlvBytes(0xE0, []byte("hello")))
	writeSlow(t, c, header)
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

	info := h.waitConnect()
	if info == nil || !info.IsLocal() || info.HasEndpoints() {
		t.Fatalf("expected LOCAL without endpoints, got %+v", info)
	}
	if v, ok := info.TLV(0xE0); !ok || string(v) != "hello" {
		t.Fatalf("local tlv snapshot: %v %v", v, ok)
	}
	if info.RemoteAddr() != nil || info.LocalAddr() != nil {
		t.Fatal("LOCAL must not expose claimed addresses")
	}
	// original transport address equals the client side of the TCP pair
	if info.OriginalRemoteAddr().String() != c.LocalAddr().String() {
		t.Fatalf("orig remote %v != client local %v", info.OriginalRemoteAddr(), c.LocalAddr())
	}
	if info.OriginalLocalAddr().String() != h.addr {
		t.Fatalf("orig local %v != listener %v", info.OriginalLocalAddr(), h.addr)
	}

	msg := h.waitRequest()
	if msg.data != payload {
		t.Fatalf("payload = %q want %q", msg.data, payload)
	}
	if msg.remaining != 0 {
		t.Fatalf("unexpected trailing bytes: %d", msg.remaining)
	}
	if msg.connectOrder != 1 || msg.requestOrder <= msg.connectOrder {
		t.Fatalf("callback order wrong: connect=%d request=%d", msg.connectOrder, msg.requestOrder)
	}
	if msg.remote != c.LocalAddr().String() {
		t.Fatalf("LOCAL request remote %v", msg.remote)
	}
	if atomic.LoadInt32(&h.requestCalls) != 1 {
		t.Fatalf("OnRequest calls = %d, want 1", h.requestCalls)
	}
	// Metadata survives Reader().Release() and buffer recycling.
	if v, ok := info.TLV(0xE0); !ok || string(v) != "hello" ||
		info.OriginalRemoteAddr().String() != c.LocalAddr().String() {
		t.Fatal("proxy metadata rewritten after release")
	}
}

// PROXY TCP over IPv6 publishes the claimed addresses; the original
// transport addresses remain available and immutable.
func TestProxyIntegrationIPv6(t *testing.T) {
	payload := "ping6"
	h := newProxyHarness(t, proxyCfg(), len(payload))
	c := h.dial()
	defer c.Close()

	var src, dst [16]byte
	src = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x01}
	dst = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x02}
	header := v2Header(proxyCommandProxy, 0x21, v6Block(src, 4242, dst, 5252))
	writeSlow(t, c, header)
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

	info := h.waitConnect()
	if info.IsLocal() || !info.HasEndpoints() {
		t.Fatalf("expected proxied v6 endpoints, got %+v", info)
	}
	if info.RemoteAddr().String() != "[2001:db8::1]:4242" {
		t.Fatalf("claimed remote = %q", info.RemoteAddr())
	}
	if info.LocalAddr().String() != "[2001:db8::2]:5252" {
		t.Fatalf("claimed local = %q", info.LocalAddr())
	}
	if info.OriginalRemoteAddr().String() != c.LocalAddr().String() {
		t.Fatalf("orig remote = %q", info.OriginalRemoteAddr())
	}
	if info.OriginalLocalAddr().String() != h.addr {
		t.Fatalf("orig local = %q", info.OriginalLocalAddr())
	}
	msg := h.waitRequest()
	if msg.data != payload || msg.remaining != 0 {
		t.Fatalf("request = %q rem=%d", msg.data, msg.remaining)
	}
	if msg.remote != "[2001:db8::1]:4242" || msg.local != "[2001:db8::2]:5252" {
		t.Fatalf("callback addrs = %s / %s", msg.remote, msg.local)
	}
}

// Unknown TLVs are preserved verbatim alongside parsed IPv4 addresses.
func TestProxyIntegrationUnknownTLV(t *testing.T) {
	payload := "tlv"
	h := newProxyHarness(t, proxyCfg(), len(payload))
	c := h.dial()
	defer c.Close()

	header := v2Header(proxyCommandProxy, 0x11,
		v4Block([4]byte{198, 51, 100, 7}, 33001, [4]byte{198, 51, 100, 8}, 443),
		tlvBytes(0xEA, []byte("wxyz")),
		tlvBytes(0xEB, nil),
	)
	writeSlow(t, c, header)
	c.Write([]byte(payload))

	info := h.waitConnect()
	v, ok := info.TLV(0xEA)
	if !ok || string(v) != "wxyz" {
		t.Fatalf("unknown tlv = %q ok=%v", v, ok)
	}
	if v2, ok2 := info.TLV(0xEB); !ok2 || len(v2) != 0 || len(info.TLVs()) != 2 {
		t.Fatalf("empty tlv snapshot: %+v", info.TLVs())
	}
	if info.RemoteAddr().String() != "198.51.100.7:33001" {
		t.Fatalf("remote = %q", info.RemoteAddr())
	}
	msg := h.waitRequest()
	if msg.data != payload {
		t.Fatalf("payload = %q", msg.data)
	}
}

// A valid CRC32C TLV protects the whole header; payload still flows.
func TestProxyIntegrationCRC(t *testing.T) {
	payload := "crc-ok"
	h := newProxyHarness(t, proxyCfg(), len(payload))
	c := h.dial()
	defer c.Close()

	header := withCRC(t, tcp4Header(tlvBytes(0xEA, []byte("ab"))))
	writeSlow(t, c, header)
	c.Write([]byte(payload))

	info := h.waitConnect()
	if _, ok := info.TLV(proxyTLVCRC32C); !ok {
		t.Fatal("crc tlv not exposed")
	}
	if msg := h.waitRequest(); msg.data != payload {
		t.Fatalf("payload = %q", msg.data)
	}
}

// The size cap is enforced before waiting for the body.
func TestProxyIntegrationOversize(t *testing.T) {
	cfg := proxyCfg()
	cfg.MaxHeaderSize = 32
	h := newProxyHarness(t, cfg, 1)
	c := h.dial()
	defer c.Close()

	// PROXY/UNSPEC with a declared body of 100 bytes: total 116 > 32,
	// rejected right after the prefix, before body bytes are awaited.
	header := v2Header(proxyCommandProxy, 0x00, make([]byte, 100))
	if _, err := c.Write(header[:proxyV2PrefixLen]); err != nil {
		// RST on write is an acceptable outcome too; still verify quietness.
		t.Logf("prefix write: %v", err)
	}
	h.expectQuiet(200 * time.Millisecond)
	expectClosed(t, c)
}

func TestProxyIntegrationIllegalHeaders(t *testing.T) {
	cases := []struct {
		name   string
		header func() []byte
	}{
		{"bad signature", func() []byte {
			h := tcp4Header()
			h[0] ^= 0xff
			return h
		}},
		{"bad version", func() []byte {
			h := tcp4Header()
			h[proxyV2SigLen] = 0x11 // version 1, command 1
			return h
		}},
		{"bad command", func() []byte {
			h := tcp4Header()
			h[proxyV2SigLen] = 0x22 // version 2, command 2
			return h
		}},
		{"reserved fam proto", func() []byte {
			return v2Header(proxyCommandProxy, 0x41, nil)
		}},
		{"truncated address block", func() []byte {
			return v2Header(proxyCommandProxy, 0x11, make([]byte, 11))
		}},
		{"truncated tlv", func() []byte {
			return v2Header(proxyCommandProxy, 0x00, nil, []byte{0xEA, 0x00, 4, 1})
		}},
		{"crc mismatch", func() []byte {
			h := withCRC(t, tcp4Header())
			h[proxyV2PrefixLen] ^= 0x01
			return h
		}},
		{"crc bad length", func() []byte {
			return tcp4Header([]byte{proxyTLVCRC32C, 0x00, 0x03, 0, 0, 0})
		}},
		{"crc duplicate", func() []byte {
			h := v2Header(proxyCommandProxy, 0x11,
				v4Block([4]byte{10, 0, 0, 1}, 1, [4]byte{10, 0, 0, 2}, 2),
				[]byte{proxyTLVCRC32C, 0, 4, 0, 0, 0, 0},
				[]byte{proxyTLVCRC32C, 0, 4, 0, 0, 0, 0})
			return h
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newProxyHarness(t, proxyCfg(), 1)
			c := h.dial()
			defer c.Close()
			if _, err := c.Write(tc.header()); err != nil {
				t.Logf("write: %v", err)
			}
			h.expectQuiet(150 * time.Millisecond)
			expectClosed(t, c)
		})
	}
}

// An untrusted peer is an ordinary client: no bytes are consumed and a
// PROXY-looking byte stream is delivered verbatim to OnRequest.
func TestProxyIntegrationUntrustedPeer(t *testing.T) {
	raw := tcp4Header(tlvBytes(0xEA, []byte("ab")))
	payload := []byte("plain-data")
	all := append(append([]byte{}, raw...), payload...)
	cfg := ProxyProtocolConfig{TrustedPeer: trustNoProxies, HandshakeTimeout: 5 * time.Second}
	h := newProxyHarness(t, cfg, len(all))
	c := h.dial()
	defer c.Close()

	writeSlow(t, c, raw)
	c.Write(payload)

	// OnConnect still fires for an ordinary connection, without info.
	select {
	case info := <-h.connected:
		if info != nil {
			t.Fatalf("untrusted conn must not carry proxy info: %+v", info)
		}
	case <-time.After(proxyTestWait):
		t.Fatal("timeout waiting OnConnect")
	}
	msg := h.waitRequest()
	if msg.data != string(all) {
		t.Fatalf("raw passthrough = %q want %q", msg.data, string(all))
	}
	if msg.remaining != 0 {
		t.Fatalf("remaining = %d", msg.remaining)
	}
	if msg.remote != c.LocalAddr().String() {
		t.Fatalf("untrusted remote = %q", msg.remote)
	}
	if msg.info != nil {
		t.Fatal("ctx must not carry proxy info for untrusted peer")
	}
}

// Slow fragments do not extend the single handshake deadline.
func TestProxyIntegrationHandshakeTimeout(t *testing.T) {
	cfg := ProxyProtocolConfig{TrustedPeer: trustAllProxies, HandshakeTimeout: 150 * time.Millisecond}
	h := newProxyHarness(t, cfg, 1)
	c := h.dial()
	defer c.Close()

	start := time.Now()
	c.Write(make([]byte, 10)) // partial prefix, then silence
	h.expectQuiet(100 * time.Millisecond)
	expectClosed(t, c)
	if d := time.Since(start); d < 140*time.Millisecond || d > 2*time.Second {
		t.Fatalf("deadline close timing = %v", d)
	}
}

// OnConnect must not run until the header completes, and payload coalesced
// with the final fragment is preserved exactly and delivered once.
func TestProxyIntegrationOrderingAndSamePacket(t *testing.T) {
	payload := []byte("same-packet-payload!!")

	// half header, silence, then the remaining header + payload in ONE write
	t.Run("split then coalesce", func(t *testing.T) {
		h := newProxyHarness(t, proxyCfg(), len(payload))
		c := h.dial()
		defer c.Close()

		header := tcp4Header()
		c.Write(header[:8])
		h.expectQuiet(250 * time.Millisecond)

		tail := append(append([]byte{}, header[8:]...), payload...)
		c.Write(tail)

		info := h.waitConnect()
		if !info.HasEndpoints() || info.RemoteAddr().String() != "10.0.0.1:1234" {
			t.Fatalf("unexpected info: %+v", info)
		}
		msg := h.waitRequest()
		if msg.data != string(payload) || msg.remaining != 0 {
			t.Fatalf("coalesced payload = %q rem=%d", msg.data, msg.remaining)
		}
	})

	// the entire header + payload arriving in a single write
	t.Run("all at once", func(t *testing.T) {
		h := newProxyHarness(t, proxyCfg(), len(payload))
		c := h.dial()
		defer c.Close()

		whole := append(tcp4Header(), payload...)
		c.Write(whole)

		h.waitConnect()
		msg := h.waitRequest()
		if msg.data != string(payload) || msg.remaining != 0 {
			t.Fatalf("single packet payload = %q rem=%d", msg.data, msg.remaining)
		}
		if atomic.LoadInt32(&h.requestCalls) != 1 {
			t.Fatalf("OnRequest calls = %d", h.requestCalls)
		}
	})
}

// Unsupported-but-valid family/protocol combos honor the explicit policy.
func TestProxyIntegrationUnsupportedPolicy(t *testing.T) {
	payload := []byte("udp-payload")

	t.Run("reject", func(t *testing.T) {
		cfg := proxyCfg() // default ProxyUnsupportedReject
		cfg.MaxHeaderSize = 1024
		h := newProxyHarness(t, cfg, len(payload))
		c := h.dial()
		defer c.Close()
		// UDP over IPv4: 12-byte block + TLV
		header := v2Header(proxyCommandProxy, 0x12,
			append(make([]byte, 12), tlvBytes(0xEA, []byte("z"))...))
		writeSlow(t, c, header)
		h.expectQuiet(200 * time.Millisecond)
		expectClosed(t, c)
	})

	t.Run("fallback as unspec", func(t *testing.T) {
		cfg := proxyCfg()
		cfg.MaxHeaderSize = 1024
		cfg.UnsupportedAddressPolicy = ProxyUnsupportedAsUnspec
		h := newProxyHarness(t, cfg, len(payload))
		c := h.dial()
		defer c.Close()
		header := v2Header(proxyCommandProxy, 0x12,
			append(make([]byte, 12), tlvBytes(0xEA, []byte("z"))...))
		writeSlow(t, c, header)
		c.Write(payload)

		info := h.waitConnect()
		if info.IsLocal() || info.HasEndpoints() {
			t.Fatalf("fallback info flags: local=%v endpoint=%v", info.IsLocal(), info.HasEndpoints())
		}
		if v, ok := info.TLV(0xEA); !ok || string(v) != "z" {
			t.Fatalf("fallback tlv: %q %v", v, ok)
		}
		if info.OriginalRemoteAddr().String() != c.LocalAddr().String() {
			t.Fatalf("fallback addr changed: %v", c.LocalAddr())
		}
		msg := h.waitRequest()
		if msg.data != string(payload) {
			t.Fatalf("fallback payload = %q", msg.data)
		}
		if msg.remote != c.LocalAddr().String() {
			t.Fatalf("fallback request remote = %q", msg.remote)
		}
	})
}
