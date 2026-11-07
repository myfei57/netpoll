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

//go:build linux

package netpoll

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// UnixPacketConnection is a message-oriented AF_UNIX SOCK_SEQPACKET connection.
// Unlike the byte-stream Connection, SendPacket/ReceivePacket preserve message
// boundaries and carry an explicit list of file descriptors (SCM_RIGHTS)
// alongside every non-empty payload. All I/O is non-blocking and driven by the
// netpoll poller; callers never share the kernel read with a LinkBuffer, so
// ancillary data cannot be lost.
//
// UnixPacketConnection is only supported on Linux. On other platforms the
// constructor entry points return ErrUnsupported.
type UnixPacketConnection struct {
	fd      int
	network string
	local   net.Addr
	remote  net.Addr
	cfg     PacketConfig

	operator *FDOperator

	closeOnce sync.Once
	closeCh   chan struct{}
	cbMu      sync.Mutex
	closeCb   []PacketCloseCallback

	payloadPool sync.Pool
	ctrlPool    sync.Pool

	// ---- send side ----
	// sendMu protects sendQ/sendBytes/sendClosed/writeArmed.
	sendMu     sync.Mutex
	sendQ      []*packetSend
	sendBytes  int
	sendClosed bool
	// flushing serializes non-blocking sendmsg attempts between user
	// goroutines and the poller's OnWrite callback.
	flushing   int32
	writeArmed bool

	writeTimeout  time.Duration
	writeDeadline int64 // UnixNano, atomic. 0 means no absolute deadline.

	// ---- receive side ----
	// recvMu protects recvQ/recvErr/recvWait.
	recvMu   sync.Mutex
	recvQ    []*Packet
	recvErr  error
	recvWait chan struct{}

	readTimeout  time.Duration
	readDeadline int64 // UnixNano, atomic. 0 means no absolute deadline.
}

// PacketConfig configures the per-connection limits of a
// UnixPacketConnection. Every zero field is replaced by its default value
// before the connection is created.
type PacketConfig struct {
	// MaxPayload is the maximum payload size in bytes of a single packet.
	// Received packets larger than it fail with ErrPacketPayloadTooLarge
	// (MSG_TRUNC) and are discarded as a whole message.
	MaxPayload int

	// MaxFDs is the maximum number of file descriptors a single packet may
	// carry. Oversized ancillary data fails the receive (MSG_CTRUNC); the
	// send side rejects the packet before taking ownership of the fds.
	MaxFDs int

	// MaxQueuePackets bounds the number of packets accepted by SendPacket
	// that have not been fully handed to the kernel. Once the budget is
	// exhausted, SendPacket fails with ErrPacketQueueFull *before* taking
	// ownership of the caller's fds.
	MaxQueuePackets int

	// MaxQueueBytes bounds the total payload bytes of queued outbound
	// packets. See MaxQueuePackets.
	MaxQueueBytes int
}

const (
	defaultPacketMaxPayload      = 64 * 1024
	defaultPacketMaxFDs          = 64
	defaultPacketMaxQueuePackets = 128
)

func (cfg PacketConfig) withDefaults() PacketConfig {
	if cfg.MaxPayload <= 0 {
		cfg.MaxPayload = defaultPacketMaxPayload
	}
	if cfg.MaxFDs <= 0 {
		cfg.MaxFDs = defaultPacketMaxFDs
	}
	if cfg.MaxQueuePackets <= 0 {
		cfg.MaxQueuePackets = defaultPacketMaxQueuePackets
	}
	if cfg.MaxQueueBytes <= 0 {
		cfg.MaxQueueBytes = cfg.MaxPayload * cfg.MaxQueuePackets
	}
	return cfg
}

// Errors reported by the packet API. All of them are plain sentinel values,
// so callers can use errors.Is to classify failures.
var (
	// ErrPacketPayloadEmpty is returned when SendPacket is called with an
	// empty payload.
	ErrPacketPayloadEmpty = errors.New("netpoll: packet payload must not be empty")
	// ErrPacketPayloadTooLarge is returned when the payload exceeds
	// PacketConfig.MaxPayload, or when an inbound datagram was truncated
	// (MSG_TRUNC).
	ErrPacketPayloadTooLarge = errors.New("netpoll: packet payload exceeds MaxPayload")
	// ErrPacketTooManyFDs is returned when a packet carries more fds than
	// PacketConfig.MaxFDs, including the MSG_CTRUNC receive case.
	ErrPacketTooManyFDs = errors.New("netpoll: packet fd count exceeds MaxFDs")
	// ErrPacketQueueFull is returned when the outbound packet/byte budget
	// is exhausted before SendPacket could accept ownership of the fds.
	ErrPacketQueueFull = errors.New("netpoll: packet send queue is full")
	// ErrPacketTruncated indicates that a received datagram payload was
	// truncated (MSG_TRUNC). The packet is dropped entirely.
	ErrPacketTruncated = errors.New("netpoll: received packet was truncated")
	// ErrPacketControlTruncated indicates that received ancillary data was
	// truncated (MSG_CTRUNC). All fds that were already installed are
	// closed and the packet is dropped.
	ErrPacketControlTruncated = errors.New("netpoll: received packet ancillary data was truncated")
	// ErrPacketControlInvalid indicates a malformed or unexpected control
	// record in a received packet.
	ErrPacketControlInvalid = errors.New("netpoll: received packet ancillary data is invalid")
	// ErrPacketShortWrite is reported when the kernel accepts fewer bytes
	// than a whole packet. SOCK_SEQPACKET never produces a successful short
	// write, so this always tears the connection down.
	ErrPacketShortWrite = errors.New("netpoll: packet short write")
	// ErrPacketReleased is returned by TakeFD after Packet.Release.
	ErrPacketReleased = errors.New("netpoll: packet already released")
	// ErrPacketFDTaken is returned when taking an fd that was already
	// taken.
	ErrPacketFDTaken = errors.New("netpoll: packet fd already taken")
	// ErrPacketFDOutOfRange is returned by TakeFD for a bad index.
	ErrPacketFDOutOfRange = errors.New("netpoll: packet fd index out of range")
)

var _ net.Conn = &UnixPacketConnection{}

// PacketCloseCallback is invoked once when a UnixPacketConnection closes.
type PacketCloseCallback func(connection *UnixPacketConnection) error

// Packet is one complete SOCK_SEQPACKET message. The payload stays valid until
// Release is called. Every descriptor in the packet is either explicitly taken
// via TakeFD (ownership transfers to the caller) or closed exactly once by
// Release. Release must always be called, including after errors while
// handling the packet.
type Packet struct {
	// Payload is the complete, never-merged message payload. It must not be
	// used after Release.
	Payload []byte

	// buf is the full backing allocation, returned to the payload pool.
	buf  []byte
	conn *UnixPacketConnection
	// err carries a per-packet failure; such packets are never exposed.
	err error

	fds   []int
	taken []bool

	mu   sync.Mutex
	done bool
}

// NumFDs returns the number of file descriptors carried by the packet.
func (p *Packet) NumFDs() int {
	return len(p.fds)
}

// TakeFD transfers ownership of the descriptor at index i to the caller, who
// becomes responsible for closing it. Untaken descriptors are closed by
// Release.
func (p *Packet) TakeFD(i int) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return -1, ErrPacketReleased
	}
	if i < 0 || i >= len(p.fds) {
		return -1, ErrPacketFDOutOfRange
	}
	if p.taken[i] {
		return -1, ErrPacketFDTaken
	}
	p.taken[i] = true
	return p.fds[i], nil
}

// Release closes every descriptor that was not taken and recycles the payload
// buffer. It is safe to call concurrently with nothing else and may be called
// once; further calls are no-ops.
func (p *Packet) Release() error {
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		return nil
	}
	p.done = true
	fds, taken := p.fds, p.taken
	p.fds = nil
	p.mu.Unlock()

	closeUntakenFDs(fds, taken)
	if p.conn != nil && p.buf != nil && cap(p.buf) == p.conn.cfg.MaxPayload {
		p.conn.payloadPool.Put(p.buf[:cap(p.buf)])
	}
	p.buf = nil
	p.Payload = nil
	return nil
}

// packetSend is one queued outbound packet. fds are owned internal duplicates
// created with CLOEXEC; they are closed exactly once when the packet leaves the
// queue (sent, failed or connection closed), even when poller shutdown races
// with an in-flight flush.
type packetSend struct {
	payload []byte
	fds     []int
	done    chan error
	once    sync.Once
}

// finish releases the internal descriptor duplicates and wakes the owner
// exactly once.
func (e *packetSend) finish(err error) {
	e.once.Do(func() {
		closeFDs(e.fds)
		select {
		case e.done <- err:
		default:
		}
	})
}

// NewUnixPacketConnection wraps an existing connected AF_UNIX SOCK_SEQPACKET
// socket fd (for example one side of syscall.Socketpair) and takes ownership of
// it. The socket is switched to non-blocking mode and registered with the
// netpoll poller. Pass a nil cfg for defaults.
func NewUnixPacketConnection(fd int, cfg *PacketConfig) (*UnixPacketConnection, error) {
	return newUnixPacketConnection(fd, nil, nil, cfg)
}

// DialUnixPacket connects to the SOCK_SEQPACKET unix socket at address and
// returns a poller-driven UnixPacketConnection.
func DialUnixPacket(address string, cfg *PacketConfig) (*UnixPacketConnection, error) {
	raddr, err := ResolveUnixAddr("unixpacket", address)
	if err != nil {
		return nil, err
	}
	nfd, err := unixSocket(context.Background(), "unixpacket", nil, raddr, "dial")
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: "unixpacket", Addr: raddr.opAddr(), Err: err}
	}
	c, err := newUnixPacketConnection(nfd.fd, nfd.localAddr, nfd.remoteAddr, cfg)
	if err != nil {
		nfd.Close()
		return nil, err
	}
	return c, nil
}

// ListenUnixPacket creates a SOCK_SEQPACKET unix listener bound to address.
// Accepted connections honor cfg.
func ListenUnixPacket(address string, cfg *PacketConfig) (*UnixPacketListener, error) {
	nl, err := CreateListener("unixpacket", address)
	if err != nil {
		return nil, err
	}
	ln, ok := nl.(*listener)
	if !ok {
		nl.Close()
		return nil, errors.New("netpoll: unexpected listener type for unixpacket")
	}
	c := defaultPacketConfig(cfg)
	l := &UnixPacketListener{
		ln:      ln.ln,
		fd:      ln.fd,
		file:    ln.file,
		cfg:     c,
		addr:    ln.addr,
		conns:   make(chan *UnixPacketConnection, packetAcceptBacklog),
		closeCh: make(chan struct{}),
	}
	poll := pollmanager.Pick()
	op := poll.Alloc()
	op.FD = ln.fd
	op.OnRead = l.onAccept
	op.OnHup = l.onHup
	l.operator = op
	if err := op.Control(PollReadable); err != nil {
		op.Free()
		l.cleanupListener()
		return nil, err
	}
	return l, nil
}

const packetAcceptBacklog = 256

// UnixPacketListener accepts SOCK_SEQPACKET connections as
// UnixPacketConnection values.
type UnixPacketListener struct {
	ln       net.Listener
	file     *os.File
	fd       int
	cfg      PacketConfig
	addr     net.Addr
	operator *FDOperator

	conns     chan *UnixPacketConnection
	closeCh   chan struct{}
	closeOnce sync.Once
}

var _ net.Listener = &UnixPacketListener{}

// AcceptPacket waits for and returns the next packet connection.
func (l *UnixPacketListener) AcceptPacket() (*UnixPacketConnection, error) {
	select {
	case c := <-l.conns:
		if c == nil {
			return nil, Exception(ErrConnClosed, "unixpacket listener closed")
		}
		return c, nil
	case <-l.closeCh:
		return nil, Exception(ErrConnClosed, "unixpacket listener closed")
	}
}

// Accept implements net.Listener.
func (l *UnixPacketListener) Accept() (net.Conn, error) {
	return l.AcceptPacket()
}

// Addr implements net.Listener.
func (l *UnixPacketListener) Addr() net.Addr {
	return l.addr
}

// Close stops accepting and releases the listener (including the socket file
// created by the standard library). Already accepted connections are not
// closed.
func (l *UnixPacketListener) Close() error {
	l.closeOnce.Do(func() {
		if l.operator != nil {
			_ = l.operator.Control(PollDetach)
			l.operator.Free()
		}
		close(l.closeCh)
		// Stop accepting new fds before draining the ones the poller already
		// accepted, so no late connection can escape the cleanup.
		l.cleanupListener()
		// close connections accepted but never handed out
		for {
			select {
			case c := <-l.conns:
				if c != nil {
					_ = c.Close()
				}
			default:
				return
			}
		}
	})
	return nil
}

func (l *UnixPacketListener) cleanupListener() {
	if l.file != nil {
		_ = l.file.Close()
	}
	if l.ln != nil {
		_ = l.ln.Close()
	}
}

func (l *UnixPacketListener) onHup(p Poll) error {
	_ = l.Close()
	return nil
}

// onAccept drains all currently pending connections; it never blocks on a
// slow user goroutine.
func (l *UnixPacketListener) onAccept(p Poll) error {
	for {
		nfd, sa, err := syscall.Accept(l.fd)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				return nil
			}
			_ = l.Close()
			return nil
		}
		remote := sockaddrToAddr(sa)
		c, err := newUnixPacketConnection(nfd, l.addr, remote, &l.cfg)
		if err != nil {
			_ = syscall.Close(nfd)
			continue
		}
		select {
		case l.conns <- c:
		default:
			// Never stall the poller waiting for a slow acceptor. Refuse the
			// connection rather than holding its fd outside of epoll.
			_ = c.Close()
		}
	}
}

func defaultPacketConfig(cfg *PacketConfig) PacketConfig {
	if cfg == nil {
		return PacketConfig{}.withDefaults()
	}
	return cfg.withDefaults()
}

func newUnixPacketConnection(fd int, local, remote net.Addr, cfg *PacketConfig) (*UnixPacketConnection, error) {
	if fd <= 0 {
		return nil, errors.New("netpoll: invalid fd for UnixPacketConnection")
	}
	c := defaultPacketConfig(cfg)
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}
	_ = setCloseOnExec(fd)

	cn := &UnixPacketConnection{
		fd:       fd,
		network:  "unixpacket",
		local:    local,
		remote:   remote,
		cfg:      c,
		closeCh:  make(chan struct{}),
		recvWait: make(chan struct{}),
	}
	if local == nil {
		if sa, err := syscall.Getsockname(fd); err == nil {
			cn.local = sockaddrToAddr(sa)
		}
	}
	if remote == nil {
		if sa, err := syscall.Getpeername(fd); err == nil {
			cn.remote = sockaddrToAddr(sa)
		}
	}
	cn.payloadPool = sync.Pool{New: func() interface{} {
		return make([]byte, c.MaxPayload)
	}}
	cn.ctrlPool = sync.Pool{New: func() interface{} {
		return make([]byte, syscall.CmsgSpace(4*c.MaxFDs))
	}}

	poll := pollmanager.Pick()
	op := poll.Alloc()
	op.FD = fd
	op.OnRead = cn.onRead
	op.OnWrite = cn.onWrite
	op.OnHup = cn.onHup
	cn.operator = op

	if err := op.Control(PollReadable); err != nil {
		op.Free()
		_ = syscall.Close(fd)
		return nil, err
	}
	return cn, nil
}

// ------------------------------------------ net.Conn surface ------------------------------------------

// Read is not supported on a packet connection; use ReceivePacket.
func (c *UnixPacketConnection) Read(p []byte) (int, error) {
	return 0, Exception(ErrUnsupported, "UnixPacketConnection.Read, use ReceivePacket")
}

// Write is not supported on a packet connection; use SendPacket.
func (c *UnixPacketConnection) Write(p []byte) (int, error) {
	return 0, Exception(ErrUnsupported, "UnixPacketConnection.Write, use SendPacket")
}

// Close implements net.Conn and Connection-style shutdown. It wakes blocked
// SendPacket/ReceivePacket waiters and releases every still-owned descriptor,
// including unsent outbound duplicates and inbound packets the caller has not
// taken yet.
func (c *UnixPacketConnection) Close() error {
	c.shutdown(Exception(ErrConnClosed, "self close"),
		Exception(ErrConnClosed, "self close"), true)
	return nil
}

// LocalAddr implements net.Conn.
func (c *UnixPacketConnection) LocalAddr() net.Addr { return c.local }

// RemoteAddr implements net.Conn.
func (c *UnixPacketConnection) RemoteAddr() net.Addr { return c.remote }

// SetDeadline implements net.Conn.
func (c *UnixPacketConnection) SetDeadline(t time.Time) error {
	v := int64(0)
	if !t.IsZero() {
		v = t.UnixNano()
	}
	atomic.StoreInt64(&c.readDeadline, v)
	atomic.StoreInt64(&c.writeDeadline, v)
	return nil
}

// SetReadDeadline implements net.Conn.
func (c *UnixPacketConnection) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		atomic.StoreInt64(&c.readDeadline, 0)
	} else {
		atomic.StoreInt64(&c.readDeadline, t.UnixNano())
	}
	return nil
}

// SetWriteDeadline implements net.Conn.
func (c *UnixPacketConnection) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		atomic.StoreInt64(&c.writeDeadline, 0)
	} else {
		atomic.StoreInt64(&c.writeDeadline, t.UnixNano())
	}
	return nil
}

// SetReadTimeout sets a relative timeout for future ReceivePacket calls. A
// zero duration disables the timeout.
func (c *UnixPacketConnection) SetReadTimeout(timeout time.Duration) error {
	if timeout >= 0 {
		c.readTimeout = timeout
	}
	return nil
}

// SetWriteTimeout sets a relative timeout for future SendPacket calls. A zero
// duration disables the timeout.
func (c *UnixPacketConnection) SetWriteTimeout(timeout time.Duration) error {
	if timeout >= 0 {
		c.writeTimeout = timeout
	}
	return nil
}

// IsActive reports whether the connection has not been closed by the user or
// torn down by the poller.
func (c *UnixPacketConnection) IsActive() bool {
	select {
	case <-c.closeCh:
		return false
	default:
		return true
	}
}

// AddCloseCallback registers a callback run once when the connection closes.
func (c *UnixPacketConnection) AddCloseCallback(fn PacketCloseCallback) error {
	if fn == nil {
		return nil
	}
	c.cbMu.Lock()
	defer c.cbMu.Unlock()
	select {
	case <-c.closeCh:
		fn(c)
	default:
		c.closeCb = append(c.closeCb, fn)
	}
	return nil
}

// ------------------------------------------ send ------------------------------------------

// SendPacket atomically delivers one complete message: the non-empty payload
// and all fds travel in a single sendmsg over SOCK_SEQPACKET, so messages are
// never merged or split by the byte stream.
//
// On acceptance, each caller fd is duplicated with O_CLOEXEC; the caller may
// close the original fds as soon as SendPacket returns. The internal duplicate
// is closed exactly once after the packet is sent, fails, or the connection is
// closed. SendPacket never closes the caller's own descriptors.
//
// If the packet exceeds MaxPayload/MaxFDs or the outbound packet/byte budget is
// full, SendPacket fails before duplicating any descriptor (ErrPacketQueueFull
// and friends). When the socket cannot accept the whole packet atomically
// (EAGAIN), the packet is kept intact and the call waits until the poller
// reports writability (or the deadline/close fires).
func (c *UnixPacketConnection) SendPacket(payload []byte, fds []int) error {
	if len(payload) == 0 {
		return ErrPacketPayloadEmpty
	}
	if len(payload) > c.cfg.MaxPayload {
		return ErrPacketPayloadTooLarge
	}
	if len(fds) > c.cfg.MaxFDs {
		return ErrPacketTooManyFDs
	}
	select {
	case <-c.closeCh:
		return Exception(ErrConnClosed, "when send packet")
	default:
	}

	c.sendMu.Lock()
	if c.sendClosed {
		c.sendMu.Unlock()
		return Exception(ErrConnClosed, "when send packet")
	}
	// Reject while still owning nothing: a failed budget/path check must not
	// leave duplicated fds or copied payload behind.
	if len(c.sendQ) >= c.cfg.MaxQueuePackets ||
		c.sendBytes+len(payload) > c.cfg.MaxQueueBytes {
		c.sendMu.Unlock()
		return ErrPacketQueueFull
	}
	dupFDs := make([]int, 0, len(fds))
	for i := range fds {
		nfd, err := dupCloseOnExec(fds[i])
		if err != nil {
			closeFDs(dupFDs)
			c.sendMu.Unlock()
			return os.NewSyscallError("fcntl", err)
		}
		dupFDs = append(dupFDs, nfd)
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)
	e := &packetSend{payload: buf, fds: dupFDs, done: make(chan error, 1)}
	c.sendQ = append(c.sendQ, e)
	c.sendBytes += len(buf)
	c.sendMu.Unlock()

	c.flushSend()
	return c.waitSend(e)
}

func (c *UnixPacketConnection) waitSend(e *packetSend) error {
	// A completed packet always wins over an already-expired deadline.
	select {
	case err := <-e.done:
		return err
	default:
	}
	d, expired := c.currentWriteWait()
	if expired {
		// The packet stays queued; ownership accounting is unchanged until
		// it is eventually sent or the connection closes.
		return Exception(ErrWriteTimeout, c.remoteNetwork())
	}
	if d <= 0 {
		select {
		case err := <-e.done:
			return err
		case <-c.closeCh:
			select {
			case err := <-e.done:
				return err
			default:
				return Exception(ErrConnClosed, "when send packet")
			}
		}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case err := <-e.done:
		return err
	case <-c.closeCh:
		select {
		case err := <-e.done:
			return err
		default:
			return Exception(ErrConnClosed, "when send packet")
		}
	case <-timer.C:
		select {
		case err := <-e.done:
			return err
		default:
			return Exception(ErrWriteTimeout, c.remoteNetwork())
		}
	}
}

func (c *UnixPacketConnection) remoteNetwork() string {
	if c.remote != nil {
		return c.remote.String()
	}
	return c.network
}

func (c *UnixPacketConnection) currentWriteWait() (time.Duration, bool) {
	if dl := atomic.LoadInt64(&c.writeDeadline); dl > 0 {
		d := time.Until(time.Unix(0, dl))
		if d <= 0 {
			return 0, true
		}
		return d, false
	}
	return c.writeTimeout, false
}

// flushSend drives the outbound queue with one owner at a time. It is invoked
// by enqueuing user goroutines and by the poller's writable callback; it only
// performs non-blocking syscalls and never waits on a slow peer.
//
// All write-interest changes happen while sendMu is held, so an enqueue racing
// an empty-queue drain can neither lose its packet nor end up with EPOLLOUT
// disarmed.
func (c *UnixPacketConnection) flushSend() {
	if !atomic.CompareAndSwapInt32(&c.flushing, 0, 1) {
		// The active owner drains the queue under the same lock used to
		// enqueue, so it either already saw this packet or is about to park
		// on EAGAIN; make sure writable notification stays requested.
		c.armWrite()
		return
	}
	defer atomic.StoreInt32(&c.flushing, 0)

	for {
		c.sendMu.Lock()
		if c.sendClosed {
			c.writeArmed = false
			c.sendMu.Unlock()
			return
		}
		if len(c.sendQ) == 0 {
			if c.writeArmed {
				c.writeArmed = false
				_ = c.operator.Control(PollRW2R)
			}
			c.sendMu.Unlock()
			return
		}
		e := c.sendQ[0]
		c.sendMu.Unlock()

		n, err := sendPacketMessage(c.fd, e.payload, e.fds)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				// The whole packet stays queued; wait for the poller.
				c.armWrite()
				return
			}
			// A real error invalidates the connection.
			c.removeHead(e, Exception(err, "when send packet"))
			c.shutdown(Exception(ErrConnClosed, err.Error()),
				Exception(err, "when send packet"), true)
			return
		}
		// SOCK_SEQPACKET writes are atomic: a partial success is impossible
		// and must never be reported as success.
		if n != len(e.payload) {
			c.removeHead(e, ErrPacketShortWrite)
			c.shutdown(Exception(ErrConnClosed, "short write"),
				ErrPacketShortWrite, true)
			return
		}
		c.removeHead(e, nil)
	}
}

// armWrite requests EPOLLOUT while holding sendMu so the decision is atomic
// with respect to the queue and drain state.
func (c *UnixPacketConnection) armWrite() {
	c.sendMu.Lock()
	if !c.writeArmed && !c.sendClosed {
		c.writeArmed = true
		_ = c.operator.Control(PollR2RW)
	}
	c.sendMu.Unlock()
}

// removeHead drops the head packet (if still present) and releases its
// resources exactly once.
func (c *UnixPacketConnection) removeHead(e *packetSend, err error) {
	c.sendMu.Lock()
	if len(c.sendQ) > 0 && c.sendQ[0] == e {
		c.sendQ = c.sendQ[1:]
		c.sendBytes -= len(e.payload)
	}
	c.sendMu.Unlock()
	e.finish(err)
}

// ------------------------------------------ receive ------------------------------------------

// ReceivePacket waits for and returns the next complete message with message
// boundary and SCM_RIGHTS descriptors preserved. The returned Packet must be
// released by the caller; descriptors not taken via Packet.TakeFD are closed by
// Packet.Release.
func (c *UnixPacketConnection) ReceivePacket() (*Packet, error) {
	var timer *time.Timer
	for {
		c.recvMu.Lock()
		if len(c.recvQ) > 0 {
			p := c.recvQ[0]
			c.recvQ = c.recvQ[1:]
			c.recvMu.Unlock()
			if p.err != nil {
				return nil, p.err
			}
			return p, nil
		}
		if c.recvErr != nil {
			err := c.recvErr
			c.recvMu.Unlock()
			return nil, err
		}
		wait := c.recvWait
		d, expired := c.currentReadWait()
		c.recvMu.Unlock()
		if expired {
			return nil, Exception(ErrReadTimeout, c.remoteNetwork())
		}

		if d <= 0 {
			select {
			case <-wait:
			case <-c.closeCh:
			}
			continue
		}
		if timer == nil {
			timer = time.NewTimer(d)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(d)
		}
		select {
		case <-wait:
		case <-c.closeCh:
		case <-timer.C:
			// Re-check under the lock so a packet delivered concurrently
			// with the timeout cannot be lost.
			c.recvMu.Lock()
			if len(c.recvQ) > 0 {
				p := c.recvQ[0]
				c.recvQ = c.recvQ[1:]
				c.recvMu.Unlock()
				if p.err != nil {
					return nil, p.err
				}
				return p, nil
			}
			err := c.recvErr
			c.recvMu.Unlock()
			if err != nil {
				return nil, err
			}
			return nil, Exception(ErrReadTimeout, c.remoteNetwork())
		}
	}
}

func (c *UnixPacketConnection) currentReadWait() (time.Duration, bool) {
	if dl := atomic.LoadInt64(&c.readDeadline); dl > 0 {
		d := time.Until(time.Unix(0, dl))
		if d <= 0 {
			return 0, true
		}
		return d, false
	}
	return c.readTimeout, false
}

// onRead drains ready datagrams in the poller goroutine. Each recvmsg maps to
// exactly one Packet; an EAGAIN ends the burst and epoll level-triggering
// reenters this callback when more datagrams arrive.
func (c *UnixPacketConnection) onRead(p Poll) error {
	for {
		pkt, err := c.readOnePacket()
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				return nil
			}
			// n==0 EOF or a fatal socket error: record the terminal state.
			// The accompanying EPOLLHUP/EPOLLERR drives onHup, which owns
			// the full shutdown. Do not block or detach from inside the
			// poller.
			c.markRecvErr(mapTerminal(err))
			return nil
		}
		c.deliverPacket(pkt)
	}
}

func mapTerminal(err error) error {
	if errors.Is(err, errPacketEOF) {
		return Exception(ErrEOF, "peer close")
	}
	return Exception(err, "when receive packet")
}

// deliverPacket hands one successfully parsed packet (or a per-packet failure
// marker) to waiting receivers. If the connection is closing, the packet is
// cleaned here instead.
func (c *UnixPacketConnection) deliverPacket(p *Packet) {
	c.recvMu.Lock()
	if c.recvErr != nil {
		c.recvMu.Unlock()
		if p.err == nil {
			closeFDs(p.fds)
			c.returnPayload(p.buf)
		}
		return
	}
	c.recvQ = append(c.recvQ, p)
	wait := c.recvWait
	c.recvWait = make(chan struct{})
	c.recvMu.Unlock()
	close(wait)
}

func (c *UnixPacketConnection) markRecvErr(err error) {
	c.recvMu.Lock()
	if c.recvErr == nil {
		c.recvErr = err
	}
	wait := c.recvWait
	c.recvWait = make(chan struct{})
	c.recvMu.Unlock()
	close(wait)
}

// readOnePacket performs exactly one non-blocking recvmsg, validating payload
// and ancillary data. A truncated/invalid packet fails as a whole: every
// descriptor the kernel already installed is returned closed and the message
// boundary is consumed, so a bad datagram can never become the prefix of the
// next packet.
func (c *UnixPacketConnection) readOnePacket() (p *Packet, err error) {
	buf := c.payloadPool.Get().([]byte)
	buf = buf[:c.cfg.MaxPayload]
	ctrl := c.ctrlPool.Get().([]byte)

	n, ctrlLen, flags, rerr := recvPacketMessage(c.fd, buf, ctrl)
	if rerr != nil {
		c.returnPayload(buf)
		c.returnCtrl(ctrl)
		return nil, rerr
	}

	// Parse descriptors while the control buffer is still valid. Even when
	// the datagram or control data is truncated, the fds already installed by
	// the kernel exist in our fd table and must be closed below.
	fds, perr := parsePacketFDs(ctrl[:ctrlLen], c.cfg.MaxFDs)
	// The control buffer is only needed while parsing; the payload buffer is
	// owned by the packet until Release.
	c.returnCtrl(ctrl)

	if n == 0 {
		// SOCK_SEQPACKET peer shutdown (zero read is EOF). Peers built on
		// this API never send empty payloads.
		closeFDs(fds)
		c.returnPayload(buf)
		return nil, errPacketEOF
	}

	if flags&syscall.MSG_CTRUNC != 0 {
		perr = ErrPacketControlTruncated
	}
	if len(fds) > c.cfg.MaxFDs {
		perr = ErrPacketTooManyFDs
	}
	if flags&syscall.MSG_TRUNC != 0 || n > c.cfg.MaxPayload {
		perr = ErrPacketTruncated
	}

	if perr != nil {
		closeFDs(fds)
		c.returnPayload(buf)
		return &Packet{conn: c, err: perr}, nil
	}

	p = &Packet{
		Payload: buf[:n],
		buf:     buf[:cap(buf)],
		conn:    c,
		fds:     fds,
		taken:   make([]bool, len(fds)),
	}
	return p, nil
}

// ------------------------------------------ poller callbacks / shutdown ------------------------------------------

func (c *UnixPacketConnection) onWrite(p Poll) error {
	c.flushSend()
	return nil
}

func (c *UnixPacketConnection) onHup(p Poll) error {
	// Peer shutdown: messages already moved into the receive queue stay
	// drainable before EOF is reported, matching stream half-close
	// semantics; queued outbound packets cannot be delivered and fail.
	c.shutdown(Exception(ErrEOF, "peer close"),
		Exception(ErrConnClosed, "peer close"), false)
	return nil
}

// shutdown drives connection shutdown. recvCause is surfaced to receivers and
// sendCause to blocked senders. When discardRecv is true (user close or fatal
// local error), inbound packets the caller has not taken are cleaned here;
// when false (peer hup) they remain available until drained to EOF.
//
// The fd/operator shutdown runs exactly once; the queue bookkeeping is safe
// to execute again when the user closes a connection the poller already hung
// up.
func (c *UnixPacketConnection) shutdown(recvCause, sendCause error, discardRecv bool) {
	// Fail everything queued for sending.
	c.sendMu.Lock()
	c.sendClosed = true
	c.writeArmed = false
	sq := c.sendQ
	c.sendQ = nil
	c.sendBytes = 0
	c.sendMu.Unlock()
	for _, e := range sq {
		e.finish(sendCause)
	}

	// Wake receivers; clean packets that can no longer be consumed.
	c.recvMu.Lock()
	if c.recvErr == nil {
		c.recvErr = recvCause
	}
	var rq []*Packet
	if discardRecv {
		rq = c.recvQ
		c.recvQ = nil
	}
	wait := c.recvWait
	c.recvWait = make(chan struct{})
	c.recvMu.Unlock()
	for _, p := range rq {
		if p.err == nil {
			closeFDs(p.fds)
			c.returnPayload(p.buf)
		}
	}
	close(wait)

	// Detach from the poller and close the socket exactly once. Close
	// callbacks run in their own goroutine so a blocking user callback can
	// never stall the poller thread when shutdown starts from OnWrite/OnHup.
	var cbs []PacketCloseCallback
	c.closeOnce.Do(func() {
		if c.operator != nil {
			_ = c.operator.Control(PollDetach)
			c.operator.Free()
		}
		_ = syscall.Close(c.fd)
		close(c.closeCh)

		c.cbMu.Lock()
		cbs = c.closeCb
		c.closeCb = nil
		c.cbMu.Unlock()
	})
	if len(cbs) > 0 {
		go func() {
			for _, fn := range cbs {
				_ = fn(c)
			}
		}()
	}
}

func (c *UnixPacketConnection) returnPayload(buf []byte) {
	if buf != nil && cap(buf) == c.cfg.MaxPayload {
		c.payloadPool.Put(buf[:cap(buf)])
	}
}

func (c *UnixPacketConnection) returnCtrl(ctrl []byte) {
	// Control buffers are fixed-size per connection config.
	if cap(ctrl) == syscall.CmsgSpace(4*c.cfg.MaxFDs) {
		c.ctrlPool.Put(ctrl[:cap(ctrl)])
	}
}

// ------------------------------------------ helpers ------------------------------------------

var errPacketEOF = errors.New("unixpacket: end of packet stream")

func closeFDs(fds []int) {
	for i := range fds {
		if fds[i] >= 0 {
			_ = syscall.Close(fds[i])
		}
	}
}

func closeUntakenFDs(fds []int, taken []bool) {
	for i := range fds {
		if taken == nil || i >= len(taken) || !taken[i] {
			_ = syscall.Close(fds[i])
		}
	}
}

// dupCloseOnExec atomically duplicates fd with O_CLOEXEC.
func dupCloseOnExec(fd int) (int, error) {
	r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd),
		uintptr(syscall.F_DUPFD_CLOEXEC), 0)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// setCloseOnExec sets FD_CLOEXEC on the connection socket itself.
func setCloseOnExec(fd int) error {
	r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd),
		uintptr(syscall.F_GETFD), 0)
	if errno != 0 {
		return errno
	}
	if r&uintptr(syscall.FD_CLOEXEC) != 0 {
		return nil
	}
	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd),
		uintptr(syscall.F_SETFD), r|uintptr(syscall.FD_CLOEXEC))
	if errno != 0 {
		return errno
	}
	return nil
}
