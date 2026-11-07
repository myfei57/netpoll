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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"time"
)

// This file implements reception of the binary version 2 of the PROXY
// protocol (https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt).
//
// It is deliberately split from the network integration:
//   - the option, result types and the pure header parser in this file are
//     platform independent and unit tested directly;
//   - the poller driven handshake state machine lives in
//     proxy_protocol_handshake.go (unix only).

const (
	proxyV2PrefixLen = 16 // fixed prefix: 12-byte signature + ver/cmd + fam/proto + len
	proxyV2SigLen    = 12

	// defaultProxyMaxHeaderSize is the default cap for the whole header
	// (prefix + body). The PROXY protocol specification recommends that
	// receivers enforce a maximum of 512 bytes.
	defaultProxyMaxHeaderSize = 512
	// defaultProxyHandshakeTimeout bounds the total time a trusted peer
	// has to send the complete header. Slow fragments never extend it.
	defaultProxyHandshakeTimeout = 3 * time.Second

	proxyV2Version = 0x2

	proxyCommandLocal = 0x0
	proxyCommandProxy = 0x1

	proxyAFUnspec = 0x0
	proxyAFInet   = 0x1
	proxyAFInet6  = 0x2
	proxyAFUnix   = 0x3

	proxyProtoUnspec = 0x0
	proxyProtoStream = 0x1
	proxyProtoDgram  = 0x2

	// proxyTLVCRC32C is the well-known type of the CRC32C TLV.
	proxyTLVCRC32C = 0x03
)

// proxyV2Signature is the 12-byte binary protocol signature.
var proxyV2Signature = [proxyV2SigLen]byte{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
	0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
}

// castagnoliTable is the CRC32C table required by the PROXY protocol.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// Header validation errors. They are rejected before the application
// callbacks observe any connection state.
var (
	errProxyShortPrefix  = errors.New("proxy protocol: short fixed prefix")
	errProxySignature    = errors.New("proxy protocol: invalid signature")
	errProxyVersion      = errors.New("proxy protocol: unsupported version")
	errProxyCommand      = errors.New("proxy protocol: illegal command")
	errProxyFamProto     = errors.New("proxy protocol: reserved address family/protocol")
	errProxyTruncated    = errors.New("proxy protocol: truncated address block or TLV")
	errProxyCRCLength    = errors.New("proxy protocol: CRC32C TLV must be exactly 4 bytes")
	errProxyCRCDuplicate = errors.New("proxy protocol: duplicate CRC32C TLV")
	errProxyCRCMismatch  = errors.New("proxy protocol: CRC32C checksum mismatch")
	errProxyTooLarge     = errors.New("proxy protocol: header exceeds the configured maximum size")
	errProxyUnsupported  = errors.New("proxy protocol: valid header with unsupported address family/protocol rejected by policy")
)

// legalFamProto enumerates the family/protocol combinations defined by the
// specification. Every other byte value is reserved and must be rejected.
var legalFamProto = map[byte]bool{
	proxyAFUnspec<<4 | proxyProtoUnspec: true, // UNSPEC / UNSPEC
	proxyAFInet<<4 | proxyProtoStream:   true, // TCP over IPv4
	proxyAFInet<<4 | proxyProtoDgram:    true, // UDP over IPv4
	proxyAFInet6<<4 | proxyProtoStream:  true, // TCP over IPv6
	proxyAFInet6<<4 | proxyProtoDgram:   true, // UDP over IPv6
	proxyAFUnix<<4 | proxyProtoStream:   true, // UNIX stream
	proxyAFUnix<<4 | proxyProtoDgram:    true, // UNIX datagram
}

// proxyAddrBlockLen returns the fixed address block size of a family/proto
// combination. Only defined values have a non-zero length.
func proxyAddrBlockLen(famProto byte) int {
	switch famProto {
	case proxyAFInet<<4 | proxyProtoStream, proxyAFInet<<4 | proxyProtoDgram:
		return 12 // IPv4 (TCP and UDP)
	case proxyAFInet6<<4 | proxyProtoStream, proxyAFInet6<<4 | proxyProtoDgram:
		return 36 // IPv6 (TCP and UDP)
	case proxyAFUnix<<4 | proxyProtoStream, proxyAFUnix<<4 | proxyProtoDgram:
		return 216 // UNIX (stream and datagram)
	default:
		return 0
	}
}

// ProxyUnsupportedPolicy decides what happens when a syntactically valid
// PROXY v2 header carries an address family/protocol combination that is
// defined by the specification but not turned into endpoint addresses by
// this implementation (UDP over IPv4/IPv6 and UNIX stream/datagram).
type ProxyUnsupportedPolicy int

const (
	// ProxyUnsupportedReject closes the connection without invoking any
	// OnConnect/OnRequest callback. This is the default: no addresses are
	// exposed for an unsupported transport.
	ProxyUnsupportedReject ProxyUnsupportedPolicy = iota
	// ProxyUnsupportedAsUnspec accepts the connection exactly like an
	// UNSPEC address block: the original transport addresses are kept and
	// the TLV snapshot is still exposed.
	ProxyUnsupportedAsUnspec
)

// ProxyProtocolConfig enables explicit reception of PROXY protocol v2
// headers on server connections.
//
// The feature is strictly opt-in. A connection whose *transport* peer is
// not accepted by TrustedPeer is handled as an ordinary connection: no
// bytes are consumed by netpoll and a normal client is never implicitly
// treated as a proxy. The trust decision is made from the original socket
// peer address, never from an address claimed inside a PROXY header.
//
// The complete header is parsed on the poller before the user OnConnect
// and OnRequest callbacks run, so those callbacks always observe either
// the fully verified result or never run at all (rejected connections are
// closed during the handshake).
type ProxyProtocolConfig struct {
	// TrustedPeer decides, from the ORIGINAL transport RemoteAddr, whether
	// the peer is allowed to send a PROXY v2 header. A nil function keeps
	// the feature disabled.
	TrustedPeer func(remote net.Addr) bool

	// MaxHeaderSize is the maximum accepted total header size in bytes,
	// including the fixed 16-byte prefix. The declared body length is
	// verified against this cap before waiting for the body. Zero selects
	// the default (512 bytes, as recommended by the specification).
	MaxHeaderSize int

	// HandshakeTimeout bounds the total time from connection arrival until
	// the whole header has arrived. Waiting never blocks the poller and
	// slow fragments do not extend the deadline. Zero selects the default
	// of 3 seconds.
	HandshakeTimeout time.Duration

	// UnsupportedAddressPolicy selects the handling of valid v2 headers
	// whose address family/protocol is not supported. The zero value is
	// ProxyUnsupportedReject.
	UnsupportedAddressPolicy ProxyUnsupportedPolicy
}

// WithProxyProtocol enables PROXY protocol v2 reception on the event loop
// using the given configuration. See ProxyProtocolConfig for the security
// guarantees (explicit opt-in, transport based trust).
func WithProxyProtocol(cfg ProxyProtocolConfig) Option {
	return Option{func(op *options) {
		c := cfg
		if c.TrustedPeer == nil {
			return
		}
		if c.MaxHeaderSize < proxyV2PrefixLen {
			c.MaxHeaderSize = defaultProxyMaxHeaderSize
		}
		if c.HandshakeTimeout <= 0 {
			c.HandshakeTimeout = defaultProxyHandshakeTimeout
		}
		op.proxyProtocol = &c
	}}
}

// ProxyTLV is one Type-Length-Value entry copied out of a PROXY v2 header.
// The Value slice is an independent copy owned by the snapshot: recycling
// the connection read buffers (Reader().Release, buffer pools) can never
// rewrite it. Callers must treat Value as read-only.
type ProxyTLV struct {
	Type  uint8
	Value []byte
}

// ProxyInfo is the immutable result of a completed PROXY v2 handshake.
// Use ProxyInfoFromContext or a Connection's ProxyProtocol method to
// retrieve it from OnConnect/OnRequest.
type ProxyInfo struct {
	isLocal     bool
	hasEndpoint bool // parsed claimed endpoint addresses are available
	remote      net.Addr
	local       net.Addr
	origRemote  net.Addr // immutable original transport peer
	origLocal   net.Addr // immutable original local socket address
	tlvs        []ProxyTLV
}

// IsLocal reports whether the header used the LOCAL command. A LOCAL
// header carries no endpoint addresses; the connection keeps its original
// transport addresses even though the declared body (often TLVs) has been
// fully consumed.
func (p *ProxyInfo) IsLocal() bool { return p.isLocal }

// HasEndpoints reports whether claimed endpoint addresses were parsed.
// It is false for LOCAL, UNSPEC and unsupported combinations accepted by
// the ProxyUnsupportedAsUnspec policy.
func (p *ProxyInfo) HasEndpoints() bool { return p.hasEndpoint }

// RemoteAddr returns the claimed source address (PROXY command, TCP over
// IPv4/IPv6). It returns nil when HasEndpoints is false; in that case the
// Connection's RemoteAddr stays the original transport address.
func (p *ProxyInfo) RemoteAddr() net.Addr { return p.remote }

// LocalAddr returns the claimed destination address (PROXY command, TCP
// over IPv4/IPv6). It returns nil when HasEndpoints is false.
func (p *ProxyInfo) LocalAddr() net.Addr { return p.local }

// OriginalRemoteAddr returns the immutable address of the actual transport
// peer, captured before any claimed address was published.
func (p *ProxyInfo) OriginalRemoteAddr() net.Addr { return p.origRemote }

// OriginalLocalAddr returns the immutable local address of the accepting
// socket, captured before any claimed address was published.
func (p *ProxyInfo) OriginalLocalAddr() net.Addr { return p.origLocal }

// TLVs returns the immutable TLV snapshot, in wire order. Unknown TLVs are
// included verbatim. The returned slice and values must not be modified.
func (p *ProxyInfo) TLVs() []ProxyTLV { return p.tlvs }

// TLV returns the raw value of the first TLV of the given type. The ok
// result is false when the TLV is absent.
func (p *ProxyInfo) TLV(typ uint8) (value []byte, ok bool) {
	for i := range p.tlvs {
		if p.tlvs[i].Type == typ {
			return p.tlvs[i].Value, true
		}
	}
	return nil, false
}

// ProxyConn is implemented by connections which may carry PROXY protocol
// information. The result is only available after a successful trusted
// handshake.
type ProxyConn interface {
	ProxyProtocol() (info *ProxyInfo, ok bool)
}

type proxyInfoContextKey struct{}

// WithProxyInfo returns a context carrying the given ProxyInfo. It is
// mainly used internally; callbacks usually retrieve the value with
// ProxyInfoFromContext.
func WithProxyInfo(ctx context.Context, info *ProxyInfo) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, proxyInfoContextKey{}, info)
}

// ProxyInfoFromContext returns the ProxyInfo attached to ctx (the context
// passed to OnConnect/OnRequest), if any.
func ProxyInfoFromContext(ctx context.Context) (info *ProxyInfo, ok bool) {
	if ctx == nil {
		return nil, false
	}
	info, ok = ctx.Value(proxyInfoContextKey{}).(*ProxyInfo)
	return
}

// proxyParsedHeader is the internal, fully validated parsing result.
type proxyParsedHeader struct {
	isLocal     bool
	unsupported bool // a defined combo we do not turn into addresses
	hasEndpoint bool
	remote      net.Addr
	local       net.Addr
	tlvs        []ProxyTLV
}

// checkProxyV2Prefix validates the fixed 16-byte prefix of a binary v2
// header and returns the declared body length plus command and
// family/protocol bytes.
//
// It rejects: a short prefix, a wrong signature, any version other than
// v2, illegal commands and reserved family/protocol combinations. For the
// PROXY command it also rejects a body shorter than the fixed address
// block (LOCAL always carries an opaque body that may be empty).
func checkProxyV2Prefix(prefix []byte) (bodyLen int, command byte, famProto byte, err error) {
	if len(prefix) < proxyV2PrefixLen {
		return 0, 0, 0, errProxyShortPrefix
	}
	if !bytes.Equal(prefix[:proxyV2SigLen], proxyV2Signature[:]) {
		return 0, 0, 0, errProxySignature
	}
	verCmd := prefix[proxyV2SigLen]
	if verCmd>>4 != proxyV2Version {
		return 0, 0, 0, errProxyVersion
	}
	command = verCmd & 0x0f
	if command != proxyCommandLocal && command != proxyCommandProxy {
		return 0, 0, 0, errProxyCommand
	}
	famProto = prefix[proxyV2SigLen+1]
	if !legalFamProto[famProto] {
		return 0, 0, 0, errProxyFamProto
	}
	bodyLen = int(binary.BigEndian.Uint16(prefix[14:16]))
	if command == proxyCommandProxy && bodyLen < proxyAddrBlockLen(famProto) {
		return 0, 0, 0, errProxyTruncated
	}
	return bodyLen, command, famProto, nil
}

// parseProxyV2 parses a complete v2 header: the fixed 16-byte prefix
// followed by exactly the declared number of body bytes.
//
// Only LOCAL and PROXY with TCP over IPv4/IPv6 yield endpoint addresses.
// Other family/protocol combinations defined by the specification are
// parsed (TLVs included) and flagged as unsupported so the caller can
// apply its reject/fallback policy. Unknown TLVs are preserved verbatim.
// A CRC32C TLV, if present, is verified over the whole header; a bad
// length, a duplicate field or a checksum mismatch rejects the header.
func parseProxyV2(header []byte) (*proxyParsedHeader, error) {
	bodyLen, command, famProto, err := checkProxyV2Prefix(header)
	if err != nil {
		return nil, err
	}
	if len(header) != proxyV2PrefixLen+bodyLen {
		return nil, errProxyTruncated
	}
	h := &proxyParsedHeader{
		isLocal: command == proxyCommandLocal,
	}
	body := header[proxyV2PrefixLen:]

	// LOCAL carries no endpoint addresses whatever the family byte says;
	// the whole declared body is skipped as (possibly empty) TLV space.
	tlvStart := 0
	if command == proxyCommandProxy {
		switch famProto {
		case proxyAFInet<<4 | proxyProtoStream: // TCP over IPv4
			if len(body) < 12 {
				return nil, errProxyTruncated
			}
			h.remote = &net.TCPAddr{IP: net.IPv4(body[0], body[1], body[2], body[3]), Port: int(binary.BigEndian.Uint16(body[8:10]))}
			h.local = &net.TCPAddr{IP: net.IPv4(body[4], body[5], body[6], body[7]), Port: int(binary.BigEndian.Uint16(body[10:12]))}
			h.hasEndpoint = true
			tlvStart = 12
		case proxyAFInet6<<4 | proxyProtoStream: // TCP over IPv6
			if len(body) < 36 {
				return nil, errProxyTruncated
			}
			src := make(net.IP, 16)
			dst := make(net.IP, 16)
			copy(src, body[0:16])
			copy(dst, body[16:32])
			h.remote = &net.TCPAddr{IP: src, Port: int(binary.BigEndian.Uint16(body[32:34]))}
			h.local = &net.TCPAddr{IP: dst, Port: int(binary.BigEndian.Uint16(body[34:36]))}
			h.hasEndpoint = true
			tlvStart = 36
		case proxyAFUnspec<<4 | proxyProtoUnspec: // UNSPEC: no address block
			tlvStart = 0
		default: // UDP IPv4/IPv6, UNIX stream/datagram
			h.unsupported = true
			tlvStart = proxyAddrBlockLen(famProto)
		}
	}

	if err := parseProxyTLVs(h, body, tlvStart, header); err != nil {
		// LOCAL headers (e.g. health checks) carry an opaque body that
		// must be skipped by declared length even when it does not frame
		// as TLVs; no claimed address is ever exposed. A well-formed CRC
		// TLV that fails verification is still rejected.
		if !h.isLocal || !errors.Is(err, errProxyTruncated) {
			return nil, err
		}
		h.tlvs = nil
	}
	return h, nil
}

// parseProxyTLVs walks the TLV region of the body. Every value is copied
// so buffer recycling cannot mutate the snapshot.
func parseProxyTLVs(h *proxyParsedHeader, body []byte, start int, header []byte) error {
	if start > len(body) {
		return errProxyTruncated
	}
	rest := body[start:]
	crcSeen := false
	for len(rest) > 0 {
		if len(rest) < 3 {
			return errProxyTruncated
		}
		typ := rest[0]
		vLen := int(binary.BigEndian.Uint16(rest[1:3]))
		if vLen > len(rest)-3 {
			return errProxyTruncated
		}
		value := rest[3 : 3+vLen]
		if typ == proxyTLVCRC32C {
			if vLen != 4 {
				return errProxyCRCLength
			}
			// A duplicate CRC field is structurally illegal regardless of
			// the checksum bytes; reject it before any verification.
			if crcSeen {
				return errProxyCRCDuplicate
			}
			crcSeen = true
			// Offset of the checksum value inside the whole header.
			valOff := len(header) - len(rest) + 3
			if !verifyProxyCRC32C(header, valOff, binary.BigEndian.Uint32(value)) {
				return errProxyCRCMismatch
			}
		}
		h.tlvs = append(h.tlvs, ProxyTLV{Type: typ, Value: cloneBytes(value)})
		rest = rest[3+vLen:]
	}
	return nil
}

// verifyProxyCRC32C computes the CRC32C (Castagnoli) over the whole header
// with the four checksum bytes at valOff treated as zero, as required by
// the specification. The header buffer is never modified.
func verifyProxyCRC32C(header []byte, valOff int, want uint32) bool {
	h := crc32.New(castagnoliTable)
	h.Write(header[:valOff])
	h.Write(zero4[:])
	h.Write(header[valOff+4:])
	return h.Sum32() == want
}

var zero4 = [4]byte{}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return []byte{}
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
