// Copyright 2025 CloudWeGo Authors
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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ------------------------------------------ helpers ------------------------------------------

func isTicketDone(t FlushTicket) bool {
	select {
	case <-t.Done():
		return true
	default:
		return false
	}
}

func waitTicket(t *testing.T, tk FlushTicket, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := tk.Wait(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ticket not finished within %v", timeout)
	}
	return err
}

func flushErr(t *testing.T, err error) *FlushAsyncError {
	t.Helper()
	var fe *FlushAsyncError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *FlushAsyncError, got %T: %v", err, err)
	}
	return fe
}

// rawSockPairConn inits only the writer side of a socketpair as a connection;
// the reader fd is used directly with syscall calls.
func rawSockPairConn(t *testing.T) (wconn *connection, rfd int, cleanup func()) {
	r, w := GetSysFdPairs()
	wc := &connection{}
	MustNil(t, wc.init(&netFD{fd: w}, nil))
	return wc, r, func() {
		_ = wc.Close()
		_ = syscall.Close(r)
	}
}

func readFDEventually(t *testing.T, fd int, want int, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	out := make([]byte, 0, want)
	buf := make([]byte, 4096)
	for len(out) < want {
		if time.Now().After(deadline) {
			t.Fatalf("readFDEventually: got %d/%d bytes", len(out), want)
		}
		n, err := syscall.Read(fd, buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			continue
		}
		if err == syscall.EAGAIN {
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatalf("readFDEventually err: %v", err)
		}
	}
	return out[:want]
}

// peerReader drives a plain net.Conn peer in a single goroutine and never
// reads until told, so the sender socket buffer can be deterministically
// saturated.
type peerReader struct {
	conn net.Conn
	mu   sync.Mutex
	data []byte
	cmds chan peerCmd
}

type peerCmd struct {
	want int // >0: read exactly this many bytes; -1: read until EOF; -2: drain until EOF, recording nothing
	done chan int
}

func startPeerReader(t *testing.T, conn net.Conn) *peerReader {
	p := &peerReader{conn: conn, cmds: make(chan peerCmd, 8)}
	go func() {
		buf := make([]byte, 32*1024)
		for cmd := range p.cmds {
			switch {
			case cmd.want > 0:
				got := 0
				for got < cmd.want {
					n, err := conn.Read(buf[:min(cmd.want-got, len(buf))])
					if n > 0 {
						p.mu.Lock()
						p.data = append(p.data, buf[:n]...)
						p.mu.Unlock()
						got += n
					}
					if err != nil {
						break
					}
				}
				cmd.done <- got
			case cmd.want == -1:
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						p.mu.Lock()
						p.data = append(p.data, buf[:n]...)
						p.mu.Unlock()
					}
					if err != nil {
						cmd.done <- len(p.data)
						break
					}
				}
			case cmd.want == -2:
				for {
					n, err := conn.Read(buf)
					if err != nil {
						cmd.done <- 0
						break
					}
					_ = n
				}
			}
		}
	}()
	return p
}

func (p *peerReader) release(n int) {
	done := make(chan int, 1)
	p.cmds <- peerCmd{want: n, done: done}
	<-done
}

func (p *peerReader) drainEOF() int {
	done := make(chan int, 1)
	p.cmds <- peerCmd{want: -1, done: done}
	return <-done
}

// drainBackground consumes and discards everything until the peer EOFs.
func (p *peerReader) drainBackground() <-chan int {
	done := make(chan int, 1)
	p.cmds <- peerCmd{want: -2, done: done}
	return done
}

func (p *peerReader) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.data)
}

func (p *peerReader) snapshot() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]byte, len(p.data))
	copy(out, p.data)
	return out
}

func (p *peerReader) stop() {
	close(p.cmds)
	_ = p.conn.Close()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

const (
	asyncChunkSize = 8192
	asyncSockBuf   = 8192
)

// smallBufferTCPPair returns a netpoll dialed connection with a small
// SO_SNDBUF and a raw peer that does not read until commanded.
func smallBufferTCPPair(t *testing.T) (wconn *connection, peer *peerReader, cleanup func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	MustNil(t, err)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr == nil {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetReadBuffer(asyncSockBuf)
				_ = tc.SetNoDelay(true)
			}
			accepted <- c
		}
	}()

	dialed, err := DialConnection("tcp", ln.Addr().String(), time.Second)
	MustNil(t, err)
	tc, ok := dialed.(*TCPConnection)
	MustTrue(t, ok)
	pc := <-accepted
	MustNil(t, syscall.SetsockoptInt(tc.fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, asyncSockBuf))

	p := startPeerReader(t, pc)
	return &tc.connection, p, func() {
		p.stop()
		_ = tc.Close()
		_ = ln.Close()
	}
}

// chunkPattern fills chunk i with a distinct nonzero byte value.
func chunkPattern(i int) []byte {
	b := make([]byte, asyncChunkSize)
	v := byte(i%251) + 1
	for j := range b {
		b[j] = v
	}
	return b
}

func expectStream(chunks int) []byte {
	out := make([]byte, 0, chunks*asyncChunkSize)
	for i := 0; i < chunks; i++ {
		out = append(out, chunkPattern(i)...)
	}
	return out
}

// fillAsyncChunks writes chunks via WriteBinary+FlushAsync until unfinished
// tickets exist, then keeps writing tail more chunks so later tickets cover a
// strictly larger prefix.
func fillAsyncChunks(t *testing.T, c *connection, tail int) (tickets []FlushTicket, chunks int) {
	sawPending := false
	for i := 0; i < 512; i++ {
		_, err := c.WriteBinary(chunkPattern(i))
		MustNil(t, err)
		tk, err := c.FlushAsync()
		MustNil(t, err)
		tickets = append(tickets, tk)
		if !isTicketDone(tk) {
			sawPending = true
		}
		if sawPending && i >= tail {
			break
		}
	}
	MustTrue(t, sawPending)
	return tickets, len(tickets)
}

// watchAll waits on every ticket in submission order from a single goroutine.
func watchAll(t *testing.T, tickets []FlushTicket, timeout time.Duration) []error {
	results := make([]error, len(tickets))
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		for i, tk := range tickets {
			results[i] = tk.Wait(ctx)
		}
		close(done)
	}()
	<-done
	return results
}

// ------------------------------------------ tracker unit tests ------------------------------------------

func TestFlushTicketTrackerPrefix(t *testing.T) {
	var q flushTicketTracker
	t1 := q.register(10)
	t2 := q.register(20)

	q.advance(4)
	MustTrue(t, !isTicketDone(t1))
	MustTrue(t, !isTicketDone(t2))
	MustTrue(t, q.head == t1)

	q.advance(6) // sent == 10
	MustTrue(t, isTicketDone(t1))
	MustTrue(t, !isTicketDone(t2))
	MustNil(t, waitTicket(t, t1, time.Second))
	MustTrue(t, q.head == t2)

	q.advance(10) // sent == 20
	MustTrue(t, isTicketDone(t2))
	MustNil(t, waitTicket(t, t2, time.Second))
	MustTrue(t, q.head == nil && q.tail == nil)
}

func TestFlushTicketTrackerFailPrefix(t *testing.T) {
	var q flushTicketTracker
	t1 := q.register(10)
	t2 := q.register(20)
	q.advance(5)
	q.fail(io.EOF)
	// repeat must be a no-op (no panic on double close)
	q.fail(io.ErrClosedPipe)

	e1 := flushErr(t, waitTicket(t, t1, time.Second))
	e2 := flushErr(t, waitTicket(t, t2, time.Second))
	Equal(t, e1.SentPrefix, int64(5))
	Equal(t, e2.SentPrefix, int64(5))
	MustTrue(t, errors.Is(e1, io.EOF))
	MustTrue(t, errors.Is(e2, io.EOF))
	MustTrue(t, q.head == nil && q.tail == nil)

	// a ticket completed before a later fail cannot be turned into a failure
	t3 := q.register(30)
	q.advance(25) // sent == 30
	MustNil(t, waitTicket(t, t3, time.Second))
	q.fail(io.ErrUnexpectedEOF)
	MustNil(t, t3.Wait(context.Background()))
}

func TestReadyFlushTicket(t *testing.T) {
	tk := sharedReadyFlushTicket
	MustTrue(t, isTicketDone(tk))
	MustNil(t, tk.Wait(nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	MustNil(t, tk.Wait(ctx)) // already finished, never returns ctx.Err
}

func TestLinkBufferFlushAsyncReady(t *testing.T) {
	b := NewLinkBuffer()
	buf, err := b.Malloc(16)
	MustNil(t, err)
	copy(buf, []byte("hello flushasync"))
	tk, err := b.FlushAsync()
	MustNil(t, err)
	MustTrue(t, isTicketDone(tk))
	MustNil(t, waitTicket(t, tk, time.Second))
	p, err := b.Peek(16)
	MustNil(t, err)
	Equal(t, string(p), "hello flushasync")
}

// ------------------------------------------ connection tests ------------------------------------------

func TestFlushAsyncBasic(t *testing.T) {
	wc, rfd, cleanup := rawSockPairConn(t)
	defer cleanup()
	MustNil(t, syscall.SetNonblock(rfd, true))

	payload := make([]byte, 1357)
	for i := range payload {
		payload[i] = byte(i*7 + 1)
	}
	_, err := wc.WriteBinary(payload)
	MustNil(t, err)
	tk, err := wc.FlushAsync()
	MustNil(t, err)
	MustNil(t, waitTicket(t, tk, 5*time.Second))

	got := readFDEventually(t, rfd, len(payload), 5*time.Second)
	Assert(t, bytes.Equal(got, payload), "peer byte stream mismatch")

	wc.outputMu.Lock()
	MustTrue(t, wc.flushTickets.head == nil && wc.flushTickets.tail == nil)
	Equal(t, wc.flushTickets.sent, int64(len(payload)))
	wc.outputMu.Unlock()
}

func TestFlushAsyncEmptyCommitAndUnflushedMalloc(t *testing.T) {
	wc, rfd, cleanup := rawSockPairConn(t)
	defer cleanup()
	MustNil(t, syscall.SetNonblock(rfd, true))

	// empty submission on an empty writer -> already finished ticket
	tk, err := wc.FlushAsync()
	MustNil(t, err)
	MustTrue(t, isTicketDone(tk))
	MustNil(t, waitTicket(t, tk, time.Second))

	// malloc but not submitted yet: nothing goes out and no ticket covers it
	buf, err := wc.Malloc(20)
	MustNil(t, err)
	for i := range buf {
		buf[i] = 0xAB
	}
	Equal(t, wc.MallocLen(), 20)
	time.Sleep(20 * time.Millisecond)
	n, rerr := syscall.Read(rfd, make([]byte, 64))
	Assert(t, n == 0 && rerr == syscall.EAGAIN, "unsubmitted bytes leaked, n=%d err=%v", n, rerr)

	// FlushAsync commits the completed malloc area, like Flush
	tk2, err := wc.FlushAsync()
	MustNil(t, err)
	MustNil(t, waitTicket(t, tk2, 5*time.Second))
	got := readFDEventually(t, rfd, 20, 5*time.Second)
	Assert(t, bytes.Equal(got, bytes.Repeat([]byte{0xAB}, 20)), "committed payload mismatch")

	// a further empty submission returns immediately finished again
	tk3, err := wc.FlushAsync()
	MustNil(t, err)
	MustTrue(t, isTicketDone(tk3))
}

func TestFlushAsyncUnflushedMallocBeyondPendingTicket(t *testing.T) {
	wc, rfd, cleanup := rawSockPairConn(t)
	defer cleanup()
	MustNil(t, syscall.SetNonblock(rfd, true))

	// first batch + ticket fully accepted
	p1 := bytes.Repeat([]byte{1}, 100)
	_, err := wc.WriteBinary(p1)
	MustNil(t, err)
	t1, err := wc.FlushAsync()
	MustNil(t, err)
	MustNil(t, waitTicket(t, t1, 5*time.Second))
	got := readFDEventually(t, rfd, 100, 5*time.Second)
	Assert(t, bytes.Equal(got, p1), "first batch mismatch")

	// malloc beyond the finished ticket is not sent and does not reopen t1
	buf, err := wc.Malloc(50)
	MustNil(t, err)
	for i := range buf {
		buf[i] = 0xCD
	}
	time.Sleep(20 * time.Millisecond)
	n, rerr := syscall.Read(rfd, make([]byte, 64))
	Assert(t, n == 0 && rerr == syscall.EAGAIN, "leaked unflushed bytes n=%d", n)
	MustTrue(t, isTicketDone(t1))
	MustNil(t, t1.Wait(nil)) // stays successful forever

	// it is delivered only after a later submit
	MustNil(t, wc.Flush())
	got = readFDEventually(t, rfd, 50, 5*time.Second)
	Assert(t, bytes.Equal(got, bytes.Repeat([]byte{0xCD}, 50)), "second batch mismatch")
}

func TestFlushAsyncMultipleTicketsLimitedBuffer(t *testing.T) {
	wc, peer, cleanup := smallBufferTCPPair(t)
	defer cleanup()

	tickets, chunks := fillAsyncChunks(t, wc, 128)
	expected := expectStream(chunks)

	pending := 0
	for _, tk := range tickets {
		if !isTicketDone(tk) {
			pending++
		}
	}
	MustTrue(t, pending > 0)

	// drain the peer from a separate goroutine while watching all tickets
	go peer.release(len(expected))
	for _, tk := range tickets {
		MustNil(t, waitTicket(t, tk, 15*time.Second))
	}
	deadline := time.Now().Add(5 * time.Second)
	for peer.len() < len(expected) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := peer.snapshot()
	Assert(t, bytes.Equal(got, expected),
		"peer stream mismatch: got %d bytes want %d", len(got), len(expected))

	// finished tickets detach and counters agree
	wc.outputMu.Lock()
	MustTrue(t, wc.flushTickets.head == nil && wc.flushTickets.tail == nil)
	Equal(t, wc.flushTickets.sent, wc.flushTickets.committed)
	Equal(t, int(wc.flushTickets.sent), len(expected))
	wc.outputMu.Unlock()
}

func TestFlushAsyncEarlierTicketNotBlockedByLaterWrites(t *testing.T) {
	wc, peer, cleanup := smallBufferTCPPair(t)
	defer cleanup()

	tickets, chunks := fillAsyncChunks(t, wc, 128)
	var t1, t2 FlushTicket
	for _, tk := range tickets {
		if !isTicketDone(tk) {
			if t1 == nil {
				t1 = tk
			}
			t2 = tk
		}
	}
	MustTrue(t, t1 != nil && t2 != nil && t1 != t2)

	// release data one chunk at a time until t1 finishes
	deadline := time.Now().Add(10 * time.Second)
	for !isTicketDone(t1) && time.Now().Before(deadline) {
		peer.release(asyncChunkSize)
		time.Sleep(10 * time.Millisecond)
	}
	MustNil(t, waitTicket(t, t1, time.Second))
	// the later ticket, covering a much larger prefix, must still be waiting
	Assert(t, !isTicketDone(t2), "later ticket must not complete with the earlier one")
	// repeat waiters on an already finished ticket cost nothing
	MustNil(t, waitTicket(t, t1, time.Second))

	// drain the rest: t2 finishes and the stream is byte exact
	result := make(chan error, 1)
	go func() { result <- t2.Wait(nil) }()
	total := int(t2.(*flushTicket).target)
	peer.release(total - peer.len())
	select {
	case err := <-result:
		MustNil(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("later ticket never completed")
	}
	expected := expectStream(chunks)
	dl := time.Now().Add(5 * time.Second)
	for peer.len() < len(expected) && time.Now().Before(dl) {
		time.Sleep(5 * time.Millisecond)
	}
	Assert(t, bytes.Equal(peer.snapshot(), expected),
		"stream mismatch got=%d want=%d", peer.len(), len(expected))
}

func TestFlushAsyncTicketBoundaryPrefixInvariant(t *testing.T) {
	wc, peer, cleanup := smallBufferTCPPair(t)
	defer cleanup()

	tickets, chunks := fillAsyncChunks(t, wc, 32)
	expected := expectStream(chunks)

	moved, rounds := 0, 0
	for {
		closed := 0
		for _, tk := range tickets {
			if isTicketDone(tk) {
				closed++
			}
		}
		// closed tickets must form a strict prefix and open tickets a suffix:
		// one write event cannot finish tickets out of order or past the
		// accepted position.
		for i, tk := range tickets {
			MustTrue(t, isTicketDone(tk) == (i < closed))
		}
		if closed > moved {
			moved = closed
			rounds++
		}
		if closed == len(tickets) {
			break
		}
		peer.release(asyncChunkSize)
		time.Sleep(15 * time.Millisecond)
	}
	MustTrue(t, rounds >= 2)
	// ticket completion means local acceptance, not peer reads: bytes may
	// still be in flight, so drain the rest before checking the stream
	if left := len(expected) - peer.len(); left > 0 {
		peer.release(left)
	}
	Assert(t, bytes.Equal(peer.snapshot(), expected), "stream mismatch")
}

func TestFlushAsyncWaitCancelKeepsOutput(t *testing.T) {
	wc, peer, cleanup := smallBufferTCPPair(t)
	defer cleanup()

	tickets, chunks := fillAsyncChunks(t, wc, 16)
	expected := expectStream(chunks)
	var pending FlushTicket
	for _, tk := range tickets {
		if !isTicketDone(tk) {
			pending = tk
			break
		}
	}
	MustTrue(t, pending != nil)

	// force GC while 8KB nocopy WriteBinary slices are queued: the output
	// chain must keep that memory valid until the bytes are accepted.
	runtime.GC()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := pending.Wait(ctx)
	Assert(t, errors.Is(err, context.Canceled), "expected context.Canceled, got %v", err)
	Assert(t, !isTicketDone(pending), "cancelled wait must not finish the ticket")
	runtime.GC()

	// cancelling did not withdraw anything: draining completes the ticket and
	// the peer receives the exact, uncorrupted stream.
	go peer.release(len(expected))
	MustNil(t, waitTicket(t, pending, 15*time.Second))
	for _, tk := range tickets {
		MustNil(t, waitTicket(t, tk, 15*time.Second))
	}
	dl := time.Now().Add(5 * time.Second)
	for peer.len() < len(expected) && time.Now().Before(dl) {
		time.Sleep(5 * time.Millisecond)
	}
	Assert(t, bytes.Equal(peer.snapshot(), expected), "stream corrupted after wait cancel")
}

func TestFlushAsyncCloseEndsPendingTicketsOnce(t *testing.T) {
	wc, peer, cleanup := smallBufferTCPPair(t)
	defer cleanup()

	tickets, chunks := fillAsyncChunks(t, wc, 16)
	expected := expectStream(chunks)

	var doneTickets, pendingTickets []FlushTicket
	for _, tk := range tickets {
		if isTicketDone(tk) {
			doneTickets = append(doneTickets, tk)
		} else {
			pendingTickets = append(pendingTickets, tk)
		}
	}
	MustTrue(t, len(pendingTickets) > 0)

	// close while the poller may be acknowledging bytes
	MustNil(t, wc.Close())
	results := watchAll(t, pendingTickets, 5*time.Second)

	var sentPrefix int64
	for i, r := range results {
		fe := flushErr(t, r)
		target := pendingTickets[i].(*flushTicket).target
		Assert(t, fe.SentPrefix >= 0 && fe.SentPrefix < target,
			"bad prefix %d for target %d", fe.SentPrefix, target)
		if i == 0 {
			sentPrefix = fe.SentPrefix
		}
	}
	// every failed ticket reports the same final accepted position
	for _, r := range results {
		Equal(t, flushErr(t, r).SentPrefix, sentPrefix)
	}
	// already completed tickets stay successful after close
	for _, tk := range doneTickets {
		MustNil(t, tk.Wait(nil))
	}
	// submitting again is rejected
	_, err := wc.FlushAsync()
	MustTrue(t, errors.Is(err, ErrConnClosed))

	// whatever the peer received is an exact prefix of the committed stream
	total := peer.drainEOF()
	Assert(t, total <= len(expected), "peer got %d > %d", total, len(expected))
	Assert(t, bytes.Equal(peer.snapshot(), expected[:total]), "peer stream corrupted")
}

func TestFlushAsyncPeerHangup(t *testing.T) {
	r, w := GetSysFdPairs()
	wc := &connection{}
	MustNil(t, wc.init(&netFD{fd: w}, nil))
	defer func() {
		_ = wc.Close()
		_ = syscall.Close(r)
	}()

	var tickets []FlushTicket
	sawPending := false
	for i := 0; i < 512 && !sawPending; i++ {
		_, err := wc.WriteBinary(chunkPattern(i))
		MustNil(t, err)
		tk, err := wc.FlushAsync()
		MustNil(t, err)
		tickets = append(tickets, tk)
		if !isTicketDone(tk) {
			sawPending = true
		}
	}
	MustTrue(t, sawPending)

	// peer vanishes: every ticket ends, each with a consistent prefix
	MustNil(t, syscall.Close(r))
	for _, tk := range tickets {
		err := waitTicket(t, tk, 10*time.Second)
		if err == nil {
			continue
		}
		fe := flushErr(t, err)
		Assert(t, fe.SentPrefix >= 0 && fe.SentPrefix <= tk.(*flushTicket).target,
			"bad prefix %d/%d", fe.SentPrefix, tk.(*flushTicket).target)
	}
}

func TestFlushAsyncMixedWithSyncFlushAndWrite(t *testing.T) {
	wc, rfd, cleanup := rawSockPairConn(t)
	defer cleanup()
	MustNil(t, syscall.SetNonblock(rfd, true))

	const rounds = 25
	// A: 3 bytes, B: 7 bytes, C: 4 bytes, D: 4 bytes per round
	total := rounds * (3 + 7 + 4 + 4)
	expected := make([]byte, 0, total)
	record := func(p []byte) { expected = append(expected, p...) }

	for i := 0; i < rounds; i++ {
		a := []byte(fmt.Sprintf("A%02d", i)) // sync Write
		n, err := wc.Write(a)
		MustNil(t, err)
		Equal(t, n, len(a))
		record(a)

		b := []byte(fmt.Sprintf("B:%04d:", i)) // async Flush
		_, err = wc.WriteBinary(b)
		MustNil(t, err)
		tk, err := wc.FlushAsync()
		MustNil(t, err)
		MustNil(t, waitTicket(t, tk, 10*time.Second))
		record(b)

		c := []byte(fmt.Sprintf("C%02d!", i)) // Malloc + sync Flush
		dst, err := wc.Malloc(len(c))
		MustNil(t, err)
		copy(dst, c)
		MustNil(t, wc.Flush())
		record(c)

		d := []byte(fmt.Sprintf("D%03d", i)) // sync Write again
		_, err = wc.Write(d)
		MustNil(t, err)
		record(d)
	}
	Equal(t, len(expected), total)

	got := readFDEventually(t, rfd, total, 15*time.Second)
	Assert(t, bytes.Equal(got, expected), "mixed sync/async stream mismatch:\n got=%v\nwant=%v", got, expected)
}

func TestFlushAsyncCloseOutputAckRace(t *testing.T) {
	const iterations = 120
	base := runtime.NumGoroutine()

	for iter := 0; iter < iterations; iter++ {
		// small TCP buffers plus a fast draining peer force repeated
		// direct sendmsg -> EAGAIN -> armed poller -> outputAck transitions,
		// so Close races with real background acknowledgements.
		wc, peer, cleanup := smallBufferTCPPair(t)
		peerDone := peer.drainBackground()

		var mu sync.Mutex
		var tickets []FlushTicket
		var writerDone sync.WaitGroup
		writerDone.Add(1)
		go func() {
			defer writerDone.Done()
			// 8KB takes the nocopy path; every submission is a fresh node
			payload := make([]byte, asyncChunkSize)
			for i := 0; i < 4096; i++ {
				if !wc.IsActive() {
					return
				}
				if _, err := wc.WriteBinary(payload); err != nil {
					return
				}
				tk, err := wc.FlushAsync()
				if err != nil {
					return
				}
				mu.Lock()
				tickets = append(tickets, tk)
				mu.Unlock()
				if i%7 == 0 {
					runtime.Gosched()
				}
			}
		}()

		// close at a varying point while the poller is acknowledging bytes
		time.Sleep(time.Duration(500+(iter*37)%2500) * time.Microsecond)
		_ = wc.Close()
		writerDone.Wait()

		mu.Lock()
		snapshot := make([]FlushTicket, len(tickets))
		copy(snapshot, tickets)
		mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		for _, tk := range snapshot {
			err := tk.Wait(ctx)
			if err == nil {
				continue
			}
			// every ticket ends exactly once: success, closed or EOF
			var fe *FlushAsyncError
			Assert(t, errors.As(err, &fe) || errors.Is(err, ErrConnClosed) || errors.Is(err, ErrEOF),
				"unexpected ticket error: %v", err)
		}
		cancel()
		<-peerDone
		cleanup()
	}

	// no per-ticket waiting goroutines may accumulate
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= base+8 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: base=%d now=%d", base, runtime.NumGoroutine())
}

func TestFlushAsyncNoPerTicketGoroutines(t *testing.T) {
	wc, rfd, cleanup := rawSockPairConn(t)
	defer cleanup()
	MustNil(t, syscall.SetNonblock(rfd, true))

	runtime.Gosched()
	base := runtime.NumGoroutine()

	const cycles = 2000
	payload := make([]byte, 128)
	for i := 0; i < cycles; i++ {
		payload[i%len(payload)] = byte(i)
		_, err := wc.WriteBinary(payload)
		MustNil(t, err)
		tk, err := wc.FlushAsync()
		MustNil(t, err)
		// drain the peer first so the ticket finishes instead of deadlocking
		// on a full socket buffer
		_ = readFDEventually(t, rfd, len(payload), 5*time.Second)
		MustNil(t, waitTicket(t, tk, 10*time.Second))
		wc.outputMu.Lock()
		head := wc.flushTickets.head
		wc.outputMu.Unlock()
		MustTrue(t, head == nil)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > base+2 {
		time.Sleep(20 * time.Millisecond)
	}
	Assert(t, runtime.NumGoroutine() <= base+2,
		"goroutine accumulation base=%d now=%d", base, runtime.NumGoroutine())
}

func TestFlushAsyncNewConnectionCannotConfirmOldTicket(t *testing.T) {
	wc1, rfd1, cleanup1 := rawSockPairConn(t)
	defer cleanup1()
	wc2, rfd2, cleanup2 := rawSockPairConn(t)
	defer cleanup2()
	MustNil(t, syscall.SetNonblock(rfd1, true))
	MustNil(t, syscall.SetNonblock(rfd2, true))

	// conn1 holds a pending ticket
	var t1 FlushTicket
	sawPending := false
	for i := 0; i < 512 && !sawPending; i++ {
		_, err := wc1.WriteBinary(chunkPattern(i))
		MustNil(t, err)
		tk, err := wc1.FlushAsync()
		MustNil(t, err)
		if !isTicketDone(tk) {
			t1 = tk
			sawPending = true
		}
	}
	MustTrue(t, t1 != nil)

	// heavy fully-acknowledged output on conn2 cannot touch conn1's ticket
	done2 := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		got := 0
		for got < 64*1024 {
			n, _ := syscall.Read(rfd2, buf)
			got += n
		}
		close(done2)
	}()
	for i := 0; i < 8; i++ {
		_, err := wc2.WriteBinary(make([]byte, 8192))
		MustNil(t, err)
		tk, err := wc2.FlushAsync()
		MustNil(t, err)
		MustNil(t, waitTicket(t, tk, 5*time.Second))
	}
	<-done2
	time.Sleep(20 * time.Millisecond)
	Assert(t, !isTicketDone(t1), "old ticket confirmed by another connection")

	// closing conn1 ends it with a flush error
	MustNil(t, wc1.Close())
	err := waitTicket(t, t1, 5*time.Second)
	MustTrue(t, err != nil)
	flushErr(t, err)
}
