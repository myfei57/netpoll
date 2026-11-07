// Copyright 2022 CloudWeGo Authors
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
	"sync/atomic"
	"syscall"
	"time"
)

type connState = int32

const (
	connStateNone         = 0
	connStateConnected    = 1
	connStateDisconnected = 2
)

// connection is the implementation of Connection
type connection struct {
	netFD
	onEvent
	locker
	operator      *FDOperator
	readTimeout   time.Duration
	readDeadline  int64 // UnixNano(). it overwrites readTimeout. 0 if not set.
	readTimer     *time.Timer
	readTrigger   chan error
	waitReadSize  int64
	writeTimeout  time.Duration
	writeDeadline int64 // UnixNano(). it overwrites writeTimeout. 0 if not set.
	writeTimer    *time.Timer
	writeTrigger  chan error
	inputBuffer   *LinkBuffer
	outputBuffer  *LinkBuffer
	outputBarrier *barrier
	// outputMu serializes every access to the committed output chain between
	// the writer goroutine (Flush/Write/FlushAsync publish and direct sendmsg)
	// and the poller goroutine (outputs/outputAck). It is only held over
	// non-blocking operations, never while waiting for the poller.
	outputMu sync.Mutex
	// flushTickets tracks the absolute committed/sent positions and the
	// unfinished FlushAsync tickets. Guarded by outputMu.
	flushTickets flushTicketTracker
	// syncFlushWaiting != 0 while a synchronous Flush/Write is blocked in
	// waitFlush; it gates writeTrigger so asynchronous drains do not leave
	// stale notifications for later synchronous calls.
	syncFlushWaiting int32
	maxSize          int       // The maximum size of data between two Release().
	bookSize         int       // The size of data that can be read at once.
	state            connState // Connection state should be changed sequentially.
}

var (
	_ Connection = &connection{}
	_ Reader     = &connection{}
	_ Writer     = &connection{}
)

// Reader implements Connection.
func (c *connection) Reader() Reader {
	return c
}

// Writer implements Connection.
func (c *connection) Writer() Writer {
	return c
}

// IsActive implements Connection.
func (c *connection) IsActive() bool {
	return c.isCloseBy(none)
}

// SetIdleTimeout implements Connection.
func (c *connection) SetIdleTimeout(timeout time.Duration) error {
	if timeout > 0 {
		return c.SetKeepAlive(int(timeout.Seconds()))
	}
	return nil
}

// SetReadTimeout implements Connection.
func (c *connection) SetReadTimeout(timeout time.Duration) error {
	if timeout >= 0 {
		c.readTimeout = timeout
	}
	c.readDeadline = 0
	return nil
}

// SetWriteTimeout implements Connection.
func (c *connection) SetWriteTimeout(timeout time.Duration) error {
	if timeout >= 0 {
		c.writeTimeout = timeout
	}
	c.writeDeadline = 0
	return nil
}

// SetDeadline implements net.Conn.SetDeadline
func (c *connection) SetDeadline(t time.Time) error {
	v := int64(0)
	if !t.IsZero() {
		v = t.UnixNano()
	}
	c.readDeadline = v
	c.writeDeadline = v
	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline
func (c *connection) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadline = 0
	} else {
		c.readDeadline = t.UnixNano()
	}
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline
func (c *connection) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.writeDeadline = 0
	} else {
		c.writeDeadline = t.UnixNano()
	}
	return nil
}

// ------------------------------------------ implement zero-copy reader ------------------------------------------

// Next implements Connection.
func (c *connection) Next(n int) (p []byte, err error) {
	if err = c.waitRead(n); err != nil {
		return p, err
	}
	return c.inputBuffer.Next(n)
}

// Peek implements Connection.
func (c *connection) Peek(n int) (buf []byte, err error) {
	if err = c.waitRead(n); err != nil {
		return buf, err
	}
	return c.inputBuffer.Peek(n)
}

// Skip implements Connection.
func (c *connection) Skip(n int) (err error) {
	if err = c.waitRead(n); err != nil {
		return err
	}
	return c.inputBuffer.Skip(n)
}

// Release implements Connection.
func (c *connection) Release() (err error) {
	// Check inputBuffer length first to reduce contention in mux situation.
	// c.operator.do competes with c.inputs/c.inputAck
	if c.inputBuffer.Len() == 0 && c.operator.do() {
		maxSize := c.inputBuffer.calcMaxSize()
		// Set the maximum value of maxsize equal to mallocMax to prevent GC pressure.
		if maxSize > mallocMax {
			maxSize = mallocMax
		}

		if maxSize > c.maxSize {
			c.maxSize = maxSize
		}
		// Double check length to reset tail node
		if c.inputBuffer.Len() == 0 {
			c.inputBuffer.resetTail(c.maxSize)
		}
		c.operator.done()
	}
	return c.inputBuffer.Release()
}

// Slice implements Connection.
func (c *connection) Slice(n int) (r Reader, err error) {
	if err = c.waitRead(n); err != nil {
		return nil, err
	}
	return c.inputBuffer.Slice(n)
}

// Len implements Connection.
func (c *connection) Len() (length int) {
	return c.inputBuffer.Len()
}

// Until implements Connection.
func (c *connection) Until(delim byte) (line []byte, err error) {
	var n, l int
	for {
		if err = c.waitRead(n + 1); err != nil {
			// return all the data in the buffer
			line, _ = c.inputBuffer.Next(c.inputBuffer.Len())
			return
		}

		l = c.inputBuffer.Len()
		i := c.inputBuffer.indexByte(delim, n)
		if i < 0 {
			n = l // skip all exists bytes
			continue
		}
		return c.Next(i + 1)
	}
}

// ReadString implements Connection.
func (c *connection) ReadString(n int) (s string, err error) {
	if err = c.waitRead(n); err != nil {
		return s, err
	}
	return c.inputBuffer.ReadString(n)
}

// ReadBinary implements Connection.
func (c *connection) ReadBinary(n int) (p []byte, err error) {
	if err = c.waitRead(n); err != nil {
		return p, err
	}
	return c.inputBuffer.ReadBinary(n)
}

// ReadByte implements Connection.
func (c *connection) ReadByte() (b byte, err error) {
	if err = c.waitRead(1); err != nil {
		return b, err
	}
	return c.inputBuffer.ReadByte()
}

// ------------------------------------------ implement zero-copy writer ------------------------------------------

// Malloc implements Connection.
func (c *connection) Malloc(n int) (buf []byte, err error) {
	if !c.IsActive() {
		return nil, Exception(ErrConnClosed, "when malloc")
	}
	// The poller drains committed nodes concurrently once FlushAsync armed it.
	// Growing the tail reads the flush node, so every submit op is serialized
	// with outputs/outputAck by outputMu.
	c.outputMu.Lock()
	buf, err = c.outputBuffer.Malloc(n)
	c.outputMu.Unlock()
	return buf, err
}

// MallocLen implements Connection.
func (c *connection) MallocLen() (length int) {
	return c.outputBuffer.MallocLen()
}

// Flush will send all malloc data to the peer,
// so must confirm that the allocated bytes have been correctly assigned.
//
// Flush first checks whether the out buffer is empty.
// If empty, it will call syscall.Write to send data directly,
// otherwise the buffer will be sent asynchronously by the epoll trigger.
func (c *connection) Flush() error {
	if !c.IsActive() {
		return Exception(ErrConnClosed, "when flush")
	}

	if !c.lock(flushing) {
		return Exception(ErrConcurrentAccess, "when flush")
	}
	defer c.unlock(flushing)

	_, needWait, err := c.commitOutputLocked(false)
	if !needWait {
		return err
	}
	err = c.waitFlush()
	atomic.StoreInt32(&c.syncFlushWaiting, 0)
	return err
}

// FlushAsync implements Writer.
// It publishes all malloc data and returns a FlushTicket covering the
// submitted prefix, without waiting for the poller to drain the connection.
// Bytes left in the malloc area by a later Malloc are not covered until the
// next submission. With no output pending, the returned ticket is already
// finished.
func (c *connection) FlushAsync() (FlushTicket, error) {
	if !c.IsActive() {
		return nil, Exception(ErrConnClosed, "when flush async")
	}

	if !c.lock(flushing) {
		return nil, Exception(ErrConcurrentAccess, "when flush async")
	}
	defer c.unlock(flushing)

	ticket, _, _ := c.commitOutputLocked(true)
	return ticket, nil
}

// MallocAck implements Connection.
func (c *connection) MallocAck(n int) (err error) {
	if !c.IsActive() {
		return Exception(ErrConnClosed, "when malloc ack")
	}
	// MallocAck can shrink and re-slice the flush node, which the poller may
	// be reading, so serialize it with output acknowledgement.
	c.outputMu.Lock()
	err = c.outputBuffer.MallocAck(n)
	c.outputMu.Unlock()
	return err
}

// Append implements Connection.
func (c *connection) Append(w Writer) (err error) {
	if !c.IsActive() {
		return Exception(ErrConnClosed, "when append")
	}
	// Append splices nodes at the flush/write frontier the poller may scan.
	c.outputMu.Lock()
	err = c.outputBuffer.Append(w)
	c.outputMu.Unlock()
	return err
}

// WriteString implements Connection.
func (c *connection) WriteString(s string) (n int, err error) {
	if !c.IsActive() {
		return 0, Exception(ErrConnClosed, "when write string")
	}
	c.outputMu.Lock()
	n, err = c.outputBuffer.WriteString(s)
	c.outputMu.Unlock()
	return n, err
}

// WriteBinary implements Connection.
func (c *connection) WriteBinary(b []byte) (n int, err error) {
	if !c.IsActive() {
		return 0, Exception(ErrConnClosed, "when write binary")
	}
	c.outputMu.Lock()
	n, err = c.outputBuffer.WriteBinary(b)
	c.outputMu.Unlock()
	return n, err
}

// WriteDirect implements Connection.
func (c *connection) WriteDirect(p []byte, remainCap int) (err error) {
	if !c.IsActive() {
		return Exception(ErrConnClosed, "when write direct")
	}
	// WriteDirect splits and re-links nodes starting at the flush node that
	// the poller may be reading, so serialize it with output acknowledgement.
	c.outputMu.Lock()
	err = c.outputBuffer.WriteDirect(p, remainCap)
	c.outputMu.Unlock()
	return err
}

// WriteByte implements Connection.
func (c *connection) WriteByte(b byte) (err error) {
	if !c.IsActive() {
		return Exception(ErrConnClosed, "when write byte")
	}
	c.outputMu.Lock()
	err = c.outputBuffer.WriteByte(b)
	c.outputMu.Unlock()
	return err
}

// ------------------------------------------ implement net.Conn ------------------------------------------

// Read behavior is the same as net.Conn, it will return io.EOF if buffer is empty.
func (c *connection) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err = c.waitRead(1); err != nil {
		return 0, err
	}
	return c.inputBuffer.readCopy(p), nil
}

// Write will Flush soon.
func (c *connection) Write(p []byte) (n int, err error) {
	if !c.IsActive() {
		return 0, Exception(ErrConnClosed, "when write")
	}

	if !c.lock(flushing) {
		return 0, Exception(ErrConcurrentAccess, "when write")
	}
	defer c.unlock(flushing)

	c.outputMu.Lock()
	dst, _ := c.outputBuffer.Malloc(len(p))
	c.outputMu.Unlock()
	n = copy(dst, p)
	_, needWait, ferr := c.commitOutputLocked(false)
	if ferr != nil {
		return n, ferr
	}
	if needWait {
		err = c.waitFlush()
		atomic.StoreInt32(&c.syncFlushWaiting, 0)
	}
	return n, err
}

// Close implements Connection.
func (c *connection) Close() error {
	return c.onClose()
}

// Detach detaches the connection from poller but doesn't close it.
func (c *connection) Detach() error {
	c.detaching = true
	return c.onClose()
}

// ------------------------------------------ private ------------------------------------------

var barrierPool = sync.Pool{
	New: func() interface{} {
		return &barrier{
			bs:  make([][]byte, barriercap),
			ivs: make([]syscall.Iovec, barriercap),
		}
	},
}

// init initializes the connection with options
func (c *connection) init(conn Conn, opts *options) (err error) {
	// init buffer, barrier, finalizer
	c.readTrigger = make(chan error, 1)
	c.writeTrigger = make(chan error, 1)
	c.bookSize, c.maxSize = defaultLinkBufferSize, defaultLinkBufferSize
	c.inputBuffer, c.outputBuffer = NewLinkBuffer(defaultLinkBufferSize), NewLinkBuffer()
	c.outputBarrier = barrierPool.Get().(*barrier)
	c.state = connStateNone

	c.initNetFD(conn) // conn must be *netFD{}
	c.initFDOperator()
	c.initFinalizer()

	syscall.SetNonblock(c.fd, true)
	// enable TCP_NODELAY by default
	switch c.network {
	case "tcp", "tcp4", "tcp6":
		setTCPNoDelay(c.fd, true)
	}

	// connection initialized and prepare options
	return c.onPrepare(opts)
}

func (c *connection) initNetFD(conn Conn) {
	if nfd, ok := conn.(*netFD); ok {
		c.netFD = *nfd
		return
	}
	c.netFD = netFD{
		fd:         conn.Fd(),
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}
}

func (c *connection) initFDOperator() {
	poll := pollmanager.Pick()
	op := poll.Alloc()
	op.FD = c.fd
	op.OnRead, op.OnWrite, op.OnHup = nil, nil, c.onHup
	op.Inputs, op.InputAck = c.inputs, c.inputAck
	op.Outputs, op.OutputAck = c.outputs, c.outputAck
	c.operator = op
}

func (c *connection) initFinalizer() {
	c.AddCloseCallback(func(connection Connection) (err error) {
		c.stop(flushing)
		c.operator.Free()
		// After Free no poller outputAck can run, so the accepted prefix is
		// final. End every unfinished FlushAsync ticket once before the
		// output buffer is recycled.
		c.failFlushTickets(Exception(ErrConnClosed, "when close"))
		if err = c.netFD.Close(); err != nil {
			logger.Printf("NETPOLL: netFD close failed: %v", err)
		}
		c.closeBuffer()
		return nil
	})
}

func (c *connection) triggerRead(err error) {
	select {
	case c.readTrigger <- err:
	default:
	}
}

func (c *connection) triggerWrite(err error) {
	select {
	case c.writeTrigger <- err:
	default:
	}
}

// waitRead will wait full n bytes.
func (c *connection) waitRead(n int) (err error) {
	if n <= c.inputBuffer.Len() {
		return nil
	}
	atomic.StoreInt64(&c.waitReadSize, int64(n))
	defer atomic.StoreInt64(&c.waitReadSize, 0)
	if dl := c.readDeadline; dl > 0 {
		timeout := time.Duration(dl - time.Now().UnixNano())
		if timeout <= 0 {
			return Exception(ErrReadTimeout, c.remoteAddr.String())
		}
		return c.waitReadWithTimeout(n, timeout)
	} else if c.readTimeout > 0 {
		return c.waitReadWithTimeout(n, c.readTimeout)
	}
	// wait full n
	for c.inputBuffer.Len() < n {
		switch c.status(closing) {
		case poller:
			return Exception(ErrEOF, "wait read")
		case user:
			return Exception(ErrConnClosed, "wait read")
		default:
			err = <-c.readTrigger
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// waitReadWithTimeout will wait full n bytes or until timeout.
func (c *connection) waitReadWithTimeout(n int, timeout time.Duration) (err error) {
	if c.readTimer == nil {
		c.readTimer = time.NewTimer(timeout)
	} else {
		c.readTimer.Reset(timeout)
	}

	for c.inputBuffer.Len() < n {
		switch c.status(closing) {
		case poller:
			// cannot return directly, stop timer first!
			err = Exception(ErrEOF, "wait read")
			goto RET
		case user:
			// cannot return directly, stop timer first!
			err = Exception(ErrConnClosed, "wait read")
			goto RET
		default:
			select {
			case <-c.readTimer.C:
				// double check if there is enough data to be read
				if c.inputBuffer.Len() >= n {
					return nil
				}
				return Exception(ErrReadTimeout, c.remoteAddr.String())
			case err = <-c.readTrigger:
				if err != nil {
					goto RET
				}
				continue
			}
		}
	}
RET:
	// clean timer.C
	if !c.readTimer.Stop() {
		<-c.readTimer.C
	}
	return err
}

// commitOutputLocked publishes all malloc data, advances the shared
// committed/sent accounting and performs one non-blocking send round, arming
// the poller if data remains. The caller must hold the flushing CAS lock; the
// whole operation runs under c.outputMu but never waits for the poller.
//
// For async submissions it registers and returns a FlushTicket. Any send or
// arming failure is recorded on the ticket (which is always returned once the
// commit succeeds), so the returned error is always nil in async mode.
//
// For synchronous submissions it marks a sync waiter before arming the poller
// and reports needWait so the caller blocks in waitFlush outside the mutex.
func (c *connection) commitOutputLocked(async bool) (ticket FlushTicket, needWait bool, err error) {
	c.outputMu.Lock()
	defer c.outputMu.Unlock()

	pendingBefore := c.outputBuffer.Len()
	if ferr := c.outputBuffer.Flush(); ferr != nil {
		return nil, false, ferr
	}
	c.flushTickets.committed += int64(c.outputBuffer.Len() - pendingBefore)

	if async {
		if c.outputBuffer.IsEmpty() {
			// Nothing pending: all committed bytes are already accepted.
			return sharedReadyFlushTicket, false, nil
		}
		ticket = c.flushTickets.register(c.flushTickets.committed)
		// A send failure ends the ticket (with the accepted prefix) instead
		// of being returned as the call error.
		_ = c.kickOutputLocked()
		if c.outputBuffer.IsEmpty() {
			return ticket, false, nil
		}
		if cerr := c.operator.Control(PollR2RW); cerr != nil {
			cerr = Exception(cerr, "when flush async")
			c.teardownOutputLocked(cerr)
		}
		return ticket, false, nil
	}

	if err = c.kickOutputLocked(); err != nil {
		return nil, false, err
	}
	if c.outputBuffer.IsEmpty() {
		return nil, false, nil
	}
	// Publish the waiter flag before arming: the poller checks it under the
	// same outputMu in outputDrainDoneLocked, so the wake cannot be missed.
	atomic.StoreInt32(&c.syncFlushWaiting, 1)
	if cerr := c.operator.Control(PollR2RW); cerr != nil {
		atomic.StoreInt32(&c.syncFlushWaiting, 0)
		return nil, false, Exception(cerr, "when flush")
	}
	return nil, true, nil
}

// kickOutputLocked performs one non-blocking sendmsg over the committed
// output and accounts the accepted bytes. EAGAIN leaves the remainder to the
// armed poller. A fatal send error accepts any partial n, ends the pending
// tickets (each reporting its accepted prefix), disarms write polling and
// wakes a synchronous waiter.
func (c *connection) kickOutputLocked() error {
	if c.outputBuffer.IsEmpty() {
		return nil
	}
	bs := c.outputBuffer.GetBytes(c.outputBarrier.bs)
	n, err := sendmsg(c.fd, bs, c.outputBarrier.ivs, false)
	if err != nil && err != syscall.EAGAIN {
		if n > 0 {
			c.outputConsumedLocked(n)
		}
		sendErr := Exception(err, "when flush")
		c.teardownOutputLocked(sendErr)
		return sendErr
	}
	if n > 0 {
		c.outputConsumedLocked(n)
	}
	return nil
}

// outputConsumedLocked skips and releases n accepted bytes and advances the
// single shared send counter, finishing every ticket whose prefix is now
// fully accepted. n must come from a successful send call on this output.
func (c *connection) outputConsumedLocked(n int) {
	if err := c.outputBuffer.Skip(n); err != nil {
		// The kernel accepted n bytes that the buffer cannot skip; this must
		// not happen as GetBytes produced n. Keep the ticket accounting tied
		// to the real syscall result instead of stalling tickets forever.
		logger.Printf("NETPOLL: output buffer skip %d failed: %v", n, err)
	} else {
		c.outputBuffer.Release()
	}
	c.flushTickets.advance(int64(n))
}

// teardownOutputLocked disarms write polling, finishes unfinished tickets with
// cause and wakes a blocked synchronous flush, if any.
func (c *connection) teardownOutputLocked(cause error) {
	_ = c.operator.Control(PollRW2R)
	c.flushTickets.fail(cause)
	c.triggerWrite(cause)
}

// outputDrainDoneLocked disarms write polling after the committed output
// became empty. A synchronous waiter is woken; asynchronous drains do not
// consume the single-slot writeTrigger.
func (c *connection) outputDrainDoneLocked() {
	_ = c.operator.Control(PollRW2R)
	if atomic.LoadInt32(&c.syncFlushWaiting) != 0 {
		c.triggerWrite(nil)
	}
}

// failFlushTickets finishes unfinished tickets when the connection terminates
// (peer hangup or local close). Already completed tickets stay successful.
func (c *connection) failFlushTickets(cause error) {
	c.outputMu.Lock()
	c.flushTickets.fail(cause)
	c.outputMu.Unlock()
}

func (c *connection) waitFlush() (err error) {
	timeout := c.writeTimeout
	if dl := c.writeDeadline; dl > 0 {
		timeout = time.Duration(dl - time.Now().UnixNano())
		if timeout <= 0 {
			return Exception(ErrWriteTimeout, c.remoteAddr.String())
		}
	}
	// A nil notification only counts when the buffer is really empty. This
	// rejects stale notifications (e.g. a poller outputAck landing just after
	// a prior write timeout) while genuine close/hup errors always terminate
	// the wait. An asynchronous drain never notifies this channel.
	for {
		if timeout == 0 {
			err = <-c.writeTrigger
		} else {
			if c.writeTimer == nil {
				c.writeTimer = time.NewTimer(timeout)
			} else {
				c.writeTimer.Reset(timeout)
			}
			select {
			case err = <-c.writeTrigger:
				if !c.writeTimer.Stop() { // clean timer
					<-c.writeTimer.C
				}
			case <-c.writeTimer.C:
				select {
				// try fetch writeTrigger if both cases fired
				case err = <-c.writeTrigger:
				default:
					// if timeout, remove write event from poller
					// we cannot flush it again, since we don't if the poller is still process outputBuffer
					c.operator.Control(PollRW2R)
					return Exception(ErrWriteTimeout, c.remoteAddr.String())
				}
			}
		}
		if err != nil {
			return err
		}
		if c.outputBuffer.IsEmpty() {
			return nil
		}
	}
}

func (c *connection) getState() connState {
	return atomic.LoadInt32(&c.state)
}

func (c *connection) setState(newState connState) {
	atomic.StoreInt32(&c.state, newState)
}

func (c *connection) changeState(from, to connState) bool {
	return atomic.CompareAndSwapInt32(&c.state, from, to)
}
