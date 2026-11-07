// Copyright 2026 CloudWeGo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

package netpoll

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"sync/atomic"
	"testing"
)

// ---- header construction helpers ----

func v2Header(command, famProto byte, addrBlock []byte, tlvs ...[]byte) []byte {
	body := make([]byte, 0, len(addrBlock))
	body = append(body, addrBlock...)
	for _, t := range tlvs {
		body = append(body, t...)
	}
	h := make([]byte, proxyV2PrefixLen+len(body))
	copy(h[:proxyV2SigLen], proxyV2Signature[:])
	h[proxyV2SigLen] = proxyV2Version<<4 | command
	h[proxyV2SigLen+1] = famProto
	binary.BigEndian.PutUint16(h[14:16], uint16(len(body)))
	copy(h[proxyV2PrefixLen:], body)
	return h
}

func v4Block(src [4]byte, sport int, dst [4]byte, dport int) []byte {
	b := make([]byte, 12)
	copy(b[0:4], src[:])
	copy(b[4:8], dst[:])
	binary.BigEndian.PutUint16(b[8:10], uint16(sport))
	binary.BigEndian.PutUint16(b[10:12], uint16(dport))
	return b
}

func v6Block(src [16]byte, sport int, dst [16]byte, dport int) []byte {
	b := make([]byte, 36)
	copy(b[0:16], src[:])
	copy(b[16:32], dst[:])
	binary.BigEndian.PutUint16(b[32:34], uint16(sport))
	binary.BigEndian.PutUint16(b[34:36], uint16(dport))
	return b
}

func tlvBytes(typ uint8, val []byte) []byte {
	b := make([]byte, 3+len(val))
	b[0] = typ
	binary.BigEndian.PutUint16(b[1:3], uint16(len(val)))
	copy(b[3:], val)
	return b
}

// withCRC appends a CRC32C TLV to an (otherwise complete) header and fills
// the checksum per spec: CRC over the whole header with the checksum bytes
// temporarily zero.
func withCRC(t *testing.T, h []byte) []byte {
	t.Helper()
	out := append(append([]byte{}, h...), proxyTLVCRC32C, 0x00, 0x04, 0, 0, 0, 0)
	off := len(out) - 4
	// refresh the declared body length before checksumming the whole header
	binary.BigEndian.PutUint16(out[14:16], uint16(len(out)-proxyV2PrefixLen))
	sum := crc32.Checksum(out, castagnoliTable) // value bytes are zero already
	binary.BigEndian.PutUint32(out[off:], sum)
	return out
}

func tcp4Header(tlvs ...[]byte) []byte {
	return v2Header(proxyCommandProxy, 0x11,
		v4Block([4]byte{10, 0, 0, 1}, 1234, [4]byte{10, 0, 0, 2}, 80), tlvs...)
}

func tcp6Header(tlvs ...[]byte) []byte {
	var src, dst [16]byte
	src = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x01}
	dst = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x02}
	return v2Header(proxyCommandProxy, 0x21, v6Block(src, 4242, dst, 5252), tlvs...)
}

// ---- prefix validation ----

func TestCheckProxyV2Prefix(t *testing.T) {
	valid := func(cmd, fp byte, bodyLen int) []byte {
		return v2Header(cmd, fp, make([]byte, bodyLen))
	}
	tests := []struct {
		name   string
		prefix func() []byte
		want   error
	}{
		{"local empty", func() []byte { return valid(proxyCommandLocal, 0x00, 0) }, nil},
		{"local non-zero body", func() []byte { return valid(proxyCommandLocal, 0x00, 8) }, nil},
		{"proxy tcp4", func() []byte { return valid(proxyCommandProxy, 0x11, 12) }, nil},
		{"proxy tcp6", func() []byte { return valid(proxyCommandProxy, 0x21, 36) }, nil},
		{"proxy unspec", func() []byte { return valid(proxyCommandProxy, 0x00, 0) }, nil},
		{"proxy udp4", func() []byte { return valid(proxyCommandProxy, 0x12, 12) }, nil},
		{"unix stream", func() []byte { return valid(proxyCommandProxy, 0x31, 216) }, nil},
		{"bad signature", func() []byte {
			h := valid(proxyCommandLocal, 0x00, 0)
			h[0] ^= 0xff
			return h
		}, errProxySignature},
		{"version one", func() []byte {
			h := valid(proxyCommandLocal, 0x00, 0)
			h[proxyV2SigLen] = 0x10
			return h
		}, errProxyVersion},
		{"command two", func() []byte {
			h := valid(proxyCommandLocal, 0x00, 0)
			h[proxyV2SigLen] = 0x22
			return h
		}, errProxyCommand},
		{"reserved family 0x41", func() []byte { return valid(proxyCommandProxy, 0x41, 0) }, errProxyFamProto},
		{"reserved proto 0x13", func() []byte { return valid(proxyCommandProxy, 0x13, 12) }, errProxyFamProto},
		{"reserved 0x10", func() []byte { return valid(proxyCommandProxy, 0x10, 0) }, errProxyFamProto},
		{"truncated tcp4 block", func() []byte { return valid(proxyCommandProxy, 0x11, 11) }, errProxyTruncated},
		{"truncated tcp6 block", func() []byte { return valid(proxyCommandProxy, 0x21, 35) }, errProxyTruncated},
		{"truncated unix block", func() []byte { return valid(proxyCommandProxy, 0x32, 215) }, errProxyTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := checkProxyV2Prefix(tt.prefix())
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
	if _, _, _, err := checkProxyV2Prefix(make([]byte, 15)); !errors.Is(err, errProxyShortPrefix) {
		t.Fatalf("short prefix err = %v", err)
	}
}

// ---- address parsing ----

func TestParseProxyV2TCP4(t *testing.T) {
	unknown := tlvBytes(0xEA, []byte("ab"))
	h := tcp4Header(unknown)
	parsed, err := parseProxyV2(h)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.isLocal || !parsed.hasEndpoint || parsed.unsupported {
		t.Fatalf("unexpected flags: local=%v endpoint=%v unsupported=%v", parsed.isLocal, parsed.hasEndpoint, parsed.unsupported)
	}
	if got := parsed.remote.String(); got != "10.0.0.1:1234" {
		t.Fatalf("remote = %q", got)
	}
	if got := parsed.local.String(); got != "10.0.0.2:80" {
		t.Fatalf("local = %q", got)
	}
	if len(parsed.tlvs) != 1 || parsed.tlvs[0].Type != 0xEA ||
		string(parsed.tlvs[0].Value) != "ab" {
		t.Fatalf("tlv snapshot wrong: %+v", parsed.tlvs)
	}
	// claimed length must match exactly.
	short := h[:len(h)-1]
	binary.BigEndian.PutUint16(short[14:16], binary.BigEndian.Uint16(h[14:16])-1)
	if _, err := parseProxyV2(short); !errors.Is(err, errProxyTruncated) {
		t.Fatalf("short body err = %v", err)
	}
}

func TestParseProxyV2TCP6(t *testing.T) {
	h := tcp6Header()
	parsed, err := parseProxyV2(h)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.remote.String(); got != "[2001:db8::1]:4242" {
		t.Fatalf("remote = %q", got)
	}
	if got := parsed.local.String(); got != "[2001:db8::2]:5252" {
		t.Fatalf("local = %q", got)
	}
	if ip := parsed.remote.(*net.TCPAddr).IP; ip.To4() != nil || len(ip) != 16 {
		t.Fatalf("expected 16-byte v6 ip, got %v len=%d", ip, len(ip))
	}
}

// LOCAL must consume the whole declared body (often TLVs), never assume it
// is zero length, and must not expose endpoint addresses.
func TestParseProxyV2LocalNonZeroBody(t *testing.T) {
	body := append(tlvBytes(0xE0, []byte("hello")), tlvBytes(0xE1, nil)...)
	h := v2Header(proxyCommandLocal, 0x00, nil, body)
	parsed, err := parseProxyV2(h)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.isLocal || parsed.hasEndpoint {
		t.Fatalf("local=%v endpoint=%v", parsed.isLocal, parsed.hasEndpoint)
	}
	if parsed.remote != nil || parsed.local != nil {
		t.Fatal("LOCAL header must not carry addresses")
	}
	if len(parsed.tlvs) != 2 || string(parsed.tlvs[0].Value) != "hello" || len(parsed.tlvs[1].Value) != 0 {
		t.Fatalf("tlv snapshot wrong: %+v", parsed.tlvs)
	}
}

// A LOCAL body that does not frame as TLVs is opaque and still consumed.
func TestParseProxyV2LocalOpaqueBody(t *testing.T) {
	h := v2Header(proxyCommandLocal, 0x00, nil, []byte("not-a-tlv!"))
	p, err := parseProxyV2(h)
	if err != nil {
		t.Fatal(err)
	}
	if !p.isLocal || p.hasEndpoint || len(p.tlvs) != 0 {
		t.Fatalf("opaque local: local=%v endpoint=%v tlvs=%+v", p.isLocal, p.hasEndpoint, p.tlvs)
	}
	// a malformed CRC inside LOCAL is still rejected
	bad := v2Header(proxyCommandLocal, 0x00, nil, []byte{proxyTLVCRC32C, 0x00, 0x03, 0, 0, 0})
	if _, err := parseProxyV2(bad); !errors.Is(err, errProxyCRCLength) {
		t.Fatalf("local bad crc err = %v", err)
	}
}

func TestParseProxyV2UnspecAndFallback(t *testing.T) {
	// UNSPEC under PROXY: no addresses, TLVs still parsed.
	h := v2Header(proxyCommandProxy, 0x00, nil, tlvBytes(0xEA, []byte{1}))
	parsed, err := parseProxyV2(h)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.unsupported || parsed.hasEndpoint {
		t.Fatalf("unspec unsupported=%v endpoint=%v", parsed.unsupported, parsed.hasEndpoint)
	}
	// UDP/UNIX are flagged unsupported but still parsed safely.
	u := v2Header(proxyCommandProxy, 0x31, make([]byte, 216))
	pu, err := parseProxyV2(u)
	if err != nil || !pu.unsupported || pu.hasEndpoint {
		t.Fatalf("unix stream: err=%v unsupported=%v endpoint=%v", err, pu.unsupported, pu.hasEndpoint)
	}
}

// ---- TLV edge cases ----

func TestParseProxyTLVs(t *testing.T) {
	// truncated TLV head (PROXY framing is strict).
	h := v2Header(proxyCommandProxy, 0x00, nil, []byte{0xEA, 0x00})
	if _, err := parseProxyV2(h); !errors.Is(err, errProxyTruncated) {
		t.Fatalf("truncated tlv head err = %v", err)
	}
	// truncated TLV value.
	h = v2Header(proxyCommandProxy, 0x00, nil, []byte{0xEA, 0x00, 4, 1, 2})
	if _, err := parseProxyV2(h); !errors.Is(err, errProxyTruncated) {
		t.Fatalf("truncated tlv value err = %v", err)
	}
	// zero length unknown TLV is legal and preserved.
	h = v2Header(proxyCommandLocal, 0x00, nil, []byte{0xFF, 0x00, 0x00})
	p, err := parseProxyV2(h)
	if err != nil || len(p.tlvs) != 1 || len(p.tlvs[0].Value) != 0 {
		t.Fatalf("empty tlv err=%v tlvs=%+v", err, p.tlvs)
	}
}

// TLV value copies must be independent of the wire slice.
func TestProxyTLVSnapshotIsCopied(t *testing.T) {
	h := tcp4Header(tlvBytes(0xEA, []byte("orig")))
	p, err := parseProxyV2(h)
	if err != nil {
		t.Fatal(err)
	}
	// mutate wire storage after parsing (simulates buffer reuse)
	for i := range h {
		h[i] = 0
	}
	if string(p.tlvs[0].Value) != "orig" {
		t.Fatalf("snapshot corrupted by wire mutation: %q", p.tlvs[0].Value)
	}
}

// ---- CRC32C ----

func TestParseProxyCRCHappy(t *testing.T) {
	h := withCRC(t, tcp4Header(tlvBytes(0xEA, []byte("x"))))
	p, err := parseProxyV2(h)
	if err != nil {
		t.Fatalf("valid crc rejected: %v", err)
	}
	var crcVal []byte
	for _, t := range p.tlvs {
		if t.Type == proxyTLVCRC32C {
			crcVal = t.Value
		}
	}
	if len(crcVal) != 4 {
		t.Fatalf("crc tlv missing from snapshot: %+v", p.tlvs)
	}
}

func TestParseProxyCRCFailures(t *testing.T) {
	// checksum mismatch.
	h := withCRC(t, tcp4Header())
	h[proxyV2PrefixLen] ^= 0x01 // flip a source-address byte
	if _, err := parseProxyV2(h); !errors.Is(err, errProxyCRCMismatch) {
		t.Fatalf("crc mismatch err = %v", err)
	}
	// bad length.
	bad := tcp4Header([]byte{proxyTLVCRC32C, 0x00, 0x03, 0, 0, 0})
	if _, err := parseProxyV2(bad); !errors.Is(err, errProxyCRCLength) {
		t.Fatalf("crc length err = %v", err)
	}
	// duplicate: build two CRC TLVs where the first one checksum-verifies
	// over the whole buffer; the second must still be rejected as duplicate.
	dupRaw := v2Header(proxyCommandProxy, 0x11,
		v4Block([4]byte{10, 0, 0, 1}, 1, [4]byte{10, 0, 0, 2}, 2),
		[]byte{proxyTLVCRC32C, 0, 4, 0, 0, 0, 0},
		[]byte{proxyTLVCRC32C, 0, 4, 0, 0, 0, 0})
	sum := crc32.Checksum(dupRaw, castagnoliTable)
	binary.BigEndian.PutUint32(dupRaw[proxyV2PrefixLen+12+3:proxyV2PrefixLen+12+7], sum)
	if _, err := parseProxyV2(dupRaw); !errors.Is(err, errProxyCRCDuplicate) {
		t.Fatalf("crc duplicate err = %v", err)
	}
}

// ---- arbitrary fragment boundaries ----

// The driver Peeks through a LinkBuffer whose node chain may split the
// signature, addresses or TLVs at any byte offset. Verify assembly for
// splits over the whole header length.
func TestProxyHeaderPeekAcrossNodes(t *testing.T) {
	header := tcp4Header(tlvBytes(0xEA, []byte("fr")))
	for split := 1; split < len(header); split++ {
		b := &LinkBuffer{}
		n1 := newLinkBufferNode(0)
		n1.buf = append([]byte{}, header[:split]...)
		n1.malloc = len(n1.buf)
		n2 := newLinkBufferNode(0)
		n2.buf = append([]byte{}, header[split:]...)
		n2.malloc = len(n2.buf)
		n1.next = n2
		b.head, b.read, b.flush, b.write = n1, n1, n2, n2
		atomic.StoreInt64(&b.length, int64(len(header)))

		got, err := b.Peek(len(header))
		if err != nil {
			t.Fatalf("split=%d peek err: %v", split, err)
		}
		if string(got) != string(header) {
			t.Fatalf("split=%d assembled header mismatch", split)
		}
		if _, err := parseProxyV2(got); err != nil {
			t.Fatalf("split=%d parse err: %v", split, err)
		}
		n1.Release()
		n2.Release()
	}
}

func TestProxyInfoFromContext(t *testing.T) {
	if _, ok := ProxyInfoFromContext(nil); ok {
		t.Fatal("nil context should miss")
	}
	info := &ProxyInfo{isLocal: true}
	ctx := WithProxyInfo(nil, info)
	got, ok := ProxyInfoFromContext(ctx)
	if !ok || got != info {
		t.Fatal("context round trip failed")
	}
}
