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

//go:build !windows

package netpoll

import (
	"sync"
	"time"
)

// PROXY protocol v2 reception integrated with the poller.
//
// Lifecycle (all buffer access happens on the connection's poller
// goroutine):
//
//  1. onPrepare evaluates trust from the ORIGINAL socket peer address and,
//     for trusted peers only, arms a proxyState in proxyPrefix phase and
//     starts one fixed deadline timer. Nothing is waited for synchronously
//     in OnPrepare; the fd is registered for reads as usual.
//  2. Every inputAck drives the state machine while it is active. Bytes
//     accumulate in the normal input LinkBuffer; the fixed prefix and the
//     declared body are Peeked across arbitrary node/fragment boundaries.
//     While pending, OnConnect/OnRequest are fully suppressed.
//  3. On completion the exact header bytes are skipped, the parsed
//     addresses are published (LOCAL/UNSPEC keep the originals), the
//     immutable snapshot is attached, and the deferred OnConnect (plus
//     OnRequest for bytes already buffered in the same read) is kicked.
//  4. Any protocol violation, the size cap or the single deadline closes
//     the connection before a user callback can observe it. EOF/user close
//     cancels the deadline via a close callback.

type proxyPhase int32

const (
	proxyPrefix proxyPhase = iota // waiting for the fixed 16-byte prefix
	proxyBody                     // prefix validated, waiting for the declared body
	proxyDone                     // handshake completed successfully
	proxyFailed                   // rejected, timed out or closed mid handshake
)

type proxyState struct {
	cfg *ProxyProtocolConfig

	mu    sync.Mutex
	phase proxyPhase
	total int         // proxyV2PrefixLen + declared body length
	info  *ProxyInfo  // set exactly once, on success
	timer *time.Timer // fixed total deadline, never reset by slow fragments

	// driveMu is held read-side by the poller while it touches the input
	// buffer and write-side by the deadline goroutine before closing the
	// connection, so Close() (which recycles buffers) never runs against
	// an in-flight parser on another goroutine.
	driveMu sync.RWMutex
}

// armProxyProtocol is called from onPrepare, before the fd is registered
// for reads. When the feature is disabled or the transport peer is not
// trusted the connection keeps the ordinary, zero-overhead behavior and
// all bytes (including anything looking like a PROXY header) go straight
// to the application.
func (c *connection) armProxyProtocol(cfg *ProxyProtocolConfig) {
	if cfg == nil || cfg.TrustedPeer == nil {
		return
	}
	// Trust uses the original socket peer only; the claimed address is
	// not available yet and must never participate in this decision.
	if !cfg.TrustedPeer(c.remoteAddr) {
		return
	}
	s := &proxyState{
		cfg:   cfg,
		phase: proxyPrefix,
	}
	c.proxy = s
	if cfg.HandshakeTimeout > 0 {
		s.timer = time.AfterFunc(cfg.HandshakeTimeout, func() {
			s.onDeadline(c)
		})
	}
	// Timeout/EOF/Close must not leave handshake state or the timer alive.
	c.AddCloseCallback(func(Connection) error {
		s.mu.Lock()
		if s.phase == proxyPrefix || s.phase == proxyBody {
			s.phase = proxyFailed
		}
		if s.timer != nil {
			s.timer.Stop()
		}
		s.mu.Unlock()
		return nil
	})
}

// intercepts reports whether received bytes still belong to the preamble,
// i.e. user callbacks must stay suppressed.
func (s *proxyState) intercepts() bool {
	s.mu.Lock()
	p := s.phase
	s.mu.Unlock()
	return p == proxyPrefix || p == proxyBody
}

// finished reports a successfully completed handshake. While armed but not
// finished (pending, or failed right before detach), user callbacks and the
// ordinary read path must stay suppressed so a partial preamble is neither
// exposed as application data nor observed with half-parsed addresses.
func (s *proxyState) finished() bool {
	s.mu.Lock()
	p := s.phase
	s.mu.Unlock()
	return p == proxyDone
}

// drive advances the handshake using bytes already buffered by the poller.
// It returns true while the handshake is still pending. It is invoked on
// the poller goroutine from inputAck only.
func (s *proxyState) drive(c *connection) (pending bool) {
	// All inputBuffer access below is covered against the deadline
	// goroutine, which takes driveMu exclusively before closing.
	s.driveMu.RLock()
	defer s.driveMu.RUnlock()
	for {
		s.mu.Lock()
		phase := s.phase
		total := s.total
		s.mu.Unlock()

		if !c.IsActive() {
			return false
		}

		switch phase {
		case proxyPrefix:
			if c.inputBuffer.Len() < proxyV2PrefixLen {
				return true
			}
			prefix, _ := c.inputBuffer.Peek(proxyV2PrefixLen)
			bodyLen, _, _, err := checkProxyV2Prefix(prefix)
			if err != nil {
				s.reject(c, err)
				return false
			}
			total = proxyV2PrefixLen + bodyLen
			// Enforce the size cap before waiting for a single body byte.
			if total > s.cfg.MaxHeaderSize {
				s.reject(c, errProxyTooLarge)
				return false
			}
			s.mu.Lock()
			if s.phase != proxyPrefix {
				s.mu.Unlock()
				return false
			}
			s.total = total
			s.phase = proxyBody
			s.mu.Unlock()
			// LOCAL with an empty declared body completes immediately;
			// otherwise loop and wait for the body.
			if c.inputBuffer.Len() < total {
				return true
			}
		case proxyBody:
			if c.inputBuffer.Len() < total {
				return true
			}
			header, _ := c.inputBuffer.Peek(total)
			parsed, err := parseProxyV2(header)
			if err == nil && parsed.unsupported &&
				s.cfg.UnsupportedAddressPolicy == ProxyUnsupportedReject {
				err = errProxyUnsupported
			}
			if err != nil {
				s.reject(c, err)
				return false
			}
			s.commit(c, parsed, total)
			return false
		default:
			return false
		}
	}
}

// commit publishes a successful handshake. It runs on the poller goroutine.
// The state transition is serialized against the deadline timer; if the
// connection was closed or the deadline fired first, the result is dropped.
func (s *proxyState) commit(c *connection, h *proxyParsedHeader, total int) {
	info := &ProxyInfo{
		isLocal:     h.isLocal,
		hasEndpoint: h.hasEndpoint,
		remote:      h.remote,
		local:       h.local,
		// Original transport addresses are captured before publication.
		origRemote: c.remoteAddr,
		origLocal:  c.localAddr,
		tlvs:       h.tlvs,
	}

	s.mu.Lock()
	if s.phase != proxyBody {
		// Lost the race with the deadline timer or close.
		s.mu.Unlock()
		return
	}
	s.phase = proxyDone
	s.info = info
	if s.timer != nil {
		s.timer.Stop()
	}
	s.mu.Unlock()

	// Consume exactly the header. Trailing application bytes, even when
	// they arrived in the same readv packet, remain buffered and are
	// delivered once through the normal OnRequest path.
	if err := c.inputBuffer.Skip(total); err != nil {
		logger.Printf("NETPOLL: proxy protocol header skip failed: %v", err)
		c.Close()
		return
	}
	// Recycle fully consumed header nodes; all exposed metadata has been
	// copied during parsing, so this cannot rewrite the snapshot.
	c.inputBuffer.Release()

	if !c.IsActive() {
		return
	}

	// Publish the verified result before any user callback can run.
	// LOCAL/UNSPEC/fallback leave the transport addresses untouched.
	if info.hasEndpoint {
		c.remoteAddr = info.remote
		c.localAddr = info.local
	}
	c.ctx = WithProxyInfo(c.ctx, info)

	// Release the deferred OnConnect; onProcess also drains OnRequest for
	// the bytes left in the buffer. Invoke onRequest explicitly for the
	// OnConnect==nil case (its state transition is synchronous there).
	c.onConnect()
	if c.IsActive() && c.inputBuffer.Len() > 0 {
		c.onRequest()
	}
}

// reject terminates a handshake that violated the protocol. No user
// OnConnect/OnRequest has run or will run, and no partially parsed address
// is ever published: RemoteAddr/LocalAddr stay the transport addresses.
func (s *proxyState) reject(c *connection, err error) {
	s.mu.Lock()
	active := s.phase == proxyPrefix || s.phase == proxyBody
	if active {
		s.phase = proxyFailed
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	s.mu.Unlock()
	if active {
		logger.Printf("NETPOLL: closing connection from %s: proxy protocol v2 handshake failed: %v",
			c.remoteAddr, err)
		c.Close()
	}
}

// onDeadline enforces the single, non-extendable handshake deadline from a
// timer goroutine. It never parses the read buffer itself; it waits for an
// in-flight poller driver to leave before Close recycles the buffers.
func (s *proxyState) onDeadline(c *connection) {
	s.mu.Lock()
	if s.phase != proxyPrefix && s.phase != proxyBody {
		s.mu.Unlock()
		return
	}
	s.phase = proxyFailed
	s.mu.Unlock()
	// Block until the poller driver has finished any buffer access.
	s.driveMu.Lock()
	defer s.driveMu.Unlock()
	if !c.IsActive() {
		return
	}
	logger.Printf("NETPOLL: closing connection from %s: proxy protocol v2 handshake timeout",
		c.remoteAddr)
	c.Close()
}

// ProxyProtocol implements ProxyConn.
func (c *connection) ProxyProtocol() (info *ProxyInfo, ok bool) {
	if c.proxy == nil {
		return nil, false
	}
	c.proxy.mu.Lock()
	defer c.proxy.mu.Unlock()
	if c.proxy.phase == proxyDone {
		return c.proxy.info, true
	}
	return nil, false
}
