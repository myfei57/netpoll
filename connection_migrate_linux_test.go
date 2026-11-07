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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// test harness: a manager with two controlled pollers and real TCP streams
// ---------------------------------------------------------------------------

func newMigrateEnv(t *testing.T, numPolls int) (*manager, []*defaultPoll) {
	t.Helper()
	oldManager := pollmanager
	m := newManager(numPolls)
	polls := make([]*defaultPoll, 0, numPolls)
	seen := make(map[*defaultPoll]struct{})
	for i := 0; i < numPolls; i++ {
		p, ok := m.Pick().(*defaultPoll)
		if !ok {
			t.Fatalf("not a defaultPoll: %T", m.Pick())
		}
		if _, dup := seen[p]; dup {
			t.Fatalf("Pick returned the same poller twice")
		}
		seen[p] = struct{}{}
		polls = append(polls, p)
		// m.Pick() -> m.Run() already started one Wait goroutine per poller.
	}
	pollmanager = m
	t.Cleanup(func() {
		pollmanager = oldManager
		_ = m.Close()
	})
	return m, polls
}

// tcpMigratePair establishes a real TCP connection: a netpoll connection on a
// controlled manager plus a Go *net.TCPConn peer.
func tcpMigratePair(t *testing.T, onRequest OnRequest) (*connection, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	peerConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	peer := peerConn.(*net.TCPConn)

	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	serverTCP := accepted.(*net.TCPConn)
	localAddr, remoteAddr := serverTCP.LocalAddr(), serverTCP.RemoteAddr()

	file, err := serverTCP.File() // duplicates the fd
	if err != nil {
		t.Fatalf("dup fd: %v", err)
	}
	serverFd := int(file.Fd())
	_ = file.Close()
	_ = serverTCP.Close()
	if err = syscall.SetNonblock(serverFd, true); err != nil {
		t.Fatalf("setnonblock: %v", err)
	}

	nfd := &netFD{
		fd:         serverFd,
		network:    "tcp",
		isStream:   true,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	c := new(connection)
	if err = c.init(nfd, &options{onRequest: onRequest}); err != nil {
		t.Fatalf("init connection: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	return c, peer
}

func ownerPoll(t *testing.T, c *connection) *defaultPoll {
	t.Helper()
	p, ok := c.getOperator().poll.(*defaultPoll)
	if !ok {
		t.Fatalf("owner is not defaultPoll: %T", c.getOperator().poll)
	}
	return p
}

func otherPoll(polls []*defaultPoll, current *defaultPoll) *defaultPoll {
	for _, p := range polls {
		if p != current {
			return p
		}
	}
	return nil
}

func waitUntil(t *testing.T, timeout time.Duration, name string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	// final check to avoid a scheduling hair
	if !cond() {
		t.Fatalf("timeout waiting for %s", name)
	}
}

// ---------------------------------------------------------------------------
// validation / edge cases
// ---------------------------------------------------------------------------

func TestMigrateValidation(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, _ := tcpMigratePair(t, nil)
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	// nil / wrong type target
	if err := MigrateConnection(context.Background(), c, nil); !errors.Is(err, ErrMigrationTarget) {
		t.Fatalf("nil target: %v", err)
	}

	// target belonging to another manager
	foreign := newManager(1)
	fp, ok := foreign.Pick().(*defaultPoll)
	if !ok {
		t.Fatal("foreign poll type")
	}
	t.Cleanup(func() { _ = foreign.Close() })
	if err := MigrateConnection(context.Background(), c, fp); !errors.Is(err, ErrMigrationTarget) {
		t.Fatalf("foreign manager target: %v", err)
	}

	// same target is an idempotent no-op
	if err := MigrateConnection(context.Background(), c, src); err != nil {
		t.Fatalf("same target must be idempotent nil: %v", err)
	}

	// canceled ctx before acceptance changes nothing
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	op := c.getOperator()
	if err := MigrateConnection(ctx, c, dst); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ctx: %v", err)
	}
	if c.getOperator() != op {
		t.Fatal("ownership changed despite pre-accept cancellation")
	}

	// closed connection is rejected
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitUntil(t, time.Second, "connection closed", func() bool { return !c.IsActive() })
	if err := MigrateConnection(context.Background(), c, dst); err == nil {
		t.Fatal("migration of closed connection must fail")
	}
}

func TestMigrateRejectsClosedTarget(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, peer := tcpMigratePair(t, nil)
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	if err := dst.Close(); err != nil {
		t.Fatalf("close dst: %v", err)
	}
	if err := MigrateConnection(context.Background(), c, dst); !errors.Is(err, ErrMigrationTarget) {
		t.Fatalf("closed target: %v", err)
	}
	// connection stays usable on its original poller
	if _, err := peer.Write([]byte("ping")); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	buf := make([]byte, 4)
	waitUntil(t, time.Second, "data after rejected migration", func() bool {
		return c.inputBuffer.Len() >= 4
	})
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read after rejected migration: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("unexpected data %q", buf)
	}
}

func TestMigrateRejectsConcurrentMigration(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, _ := tcpMigratePair(t, nil)
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	gate := make(chan struct{})
	entered := make(chan struct{})
	migrateHookAfterDetach = func(*connection) {
		close(entered)
		<-gate
	}
	t.Cleanup(func() { migrateHookAfterDetach = nil })

	var wg sync.WaitGroup
	wg.Add(1)
	var firstErr error
	go func() {
		defer wg.Done()
		firstErr = MigrateConnection(context.Background(), c, dst)
	}()
	<-entered
	if err := MigrateConnection(context.Background(), c, src); !errors.Is(err, ErrMigrationInProgress) {
		t.Fatalf("concurrent migration: %v", err)
	}
	close(gate)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("first migration: %v", firstErr)
	}
}

// ---------------------------------------------------------------------------
// data integrity over real TCP with repeated migrations
// ---------------------------------------------------------------------------

const (
	migrateChunkSize = 4096
	migrateChunks    = 240
)

func makeChunk(seq int) []byte {
	b := make([]byte, migrateChunkSize)
	for i := range b {
		b[i] = byte(seq*31 + i)
	}
	return b
}

// echoOnRequest echoes everything exactly once and counts invocations.
func echoOnRequest(calls *int64) OnRequest {
	return func(ctx context.Context, conn Connection) error {
		atomic.AddInt64(calls, 1)
		reader := conn.Reader()
		n := reader.Len()
		if n == 0 {
			return nil
		}
		p, err := reader.Next(n)
		if err != nil {
			return err
		}
		_, err = conn.Write(p)
		return err
	}
}

func TestMigrateDataIntegrity(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	var calls int64
	c, peer := tcpMigratePair(t, echoOnRequest(&calls))
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	stopMigrate := make(chan struct{})
	var migrateWG sync.WaitGroup
	migrateWG.Add(1)
	go func() {
		defer migrateWG.Done()
		from, to := src, dst
		for i := 0; ; i++ {
			select {
			case <-stopMigrate:
				return
			default:
			}
			oldOp := c.getOperator()
			err := MigrateConnection(context.Background(), c, to)
			if err != nil && !errors.Is(err, ErrMigrationRolledBack) && !errors.Is(err, ErrConnClosed) {
				t.Errorf("migrate %d: %v", i, err)
				return
			}
			if err == nil {
				// unique ownership: current operator must belong to the target
				if c.getOperator().poll != to {
					t.Errorf("migrate %d: owner is not the target poller", i)
					return
				}
				// the old registration must have been released back to the
				// source poller cache (strictly after its event batch)
				deadline := time.Now().Add(2 * time.Second)
				for !oldOp.isUnused() && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if !oldOp.isUnused() {
					t.Errorf("migrate %d: old operator not recycled", i)
					return
				}
			}
			from, to = to, from
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// receiver: exact echo stream
	received := make(chan error, 1)
	go func() {
		buf := make([]byte, migrateChunkSize)
		for seq := 0; seq < migrateChunks; seq++ {
			if _, err := io.ReadFull(peer, buf); err != nil {
				received <- fmt.Errorf("peer read chunk %d: %w", seq, err)
				return
			}
			if !bytes.Equal(makeChunk(seq), buf) {
				received <- fmt.Errorf("chunk %d corrupted (len=%d)", seq, len(buf))
				return
			}
		}
		received <- nil
	}()

	// sender
	for seq := 0; seq < migrateChunks; seq++ {
		if _, err := peer.Write(makeChunk(seq)); err != nil {
			t.Fatalf("peer write chunk %d: %v", seq, err)
		}
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
	close(stopMigrate)
	migrateWG.Wait()

	if atomic.LoadInt64(&calls) == 0 {
		t.Fatal("OnRequest never ran")
	}
	// the connection must still be alive and owned by exactly one poller
	if !c.IsActive() {
		t.Fatal("connection inactive after migrations")
	}
	owner := ownerPoll(t, c)
	if owner != src && owner != dst {
		t.Fatalf("owner unknown: %v", owner)
	}
}

// ---------------------------------------------------------------------------
// buffered input survives, blocking reader survives, deadlines survive
// ---------------------------------------------------------------------------

func TestMigrateBufferedInputAndReadWaiter(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)

	processed := make(chan struct{}, 1)
	release := make(chan struct{})
	var onRequestCalls int64
	onRequest := func(ctx context.Context, conn Connection) error {
		// park the single OnRequest while data is buffered, proving the bytes
		// live in inputBuffer rather than in the old poller
		if atomic.AddInt64(&onRequestCalls, 1) == 1 {
			processed <- struct{}{}
			<-release
		}
		reader := conn.Reader()
		if reader.Len() > 0 {
			p, _ := reader.Next(reader.Len())
			_, _ = conn.Write(p)
		}
		return nil
	}

	c, peer := tcpMigratePair(t, onRequest)
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	first := makeChunk(1)[:100]
	if _, err := peer.Write(first); err != nil {
		t.Fatalf("write first: %v", err)
	}
	<-processed
	waitUntil(t, time.Second, "first chunk in inputBuffer", func() bool {
		return c.inputBuffer.Len() >= 100
	})

	// a blocking reader parked while only 100 of the wanted 150 bytes exist
	readBuf := make([]byte, 150)
	readResult := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(c, readBuf)
		readResult <- err
	}()
	waitUntil(t, time.Second, "reader parked", func() bool {
		return atomic.LoadInt64(&c.waitReadSize) == 150
	})

	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if err := MigrateConnection(context.Background(), c, dst); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if ownerPoll(t, c) != dst {
		t.Fatal("owner did not switch")
	}

	// 100 bytes were buffered before migration; 100 more arrive via the new
	// poller. The parked reader must consume exactly 150, leaving 50 buffered.
	second := makeChunk(2)[:100]
	if _, err := peer.Write(second); err != nil {
		t.Fatalf("write second: %v", err)
	}
	select {
	case err := <-readResult:
		if err != nil {
			t.Fatalf("parked reader: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocking reader never completed after migration")
	}
	expectRead := append(append([]byte{}, first...), second[:50]...)
	if !bytes.Equal(readBuf, expectRead) {
		t.Fatal("buffered bytes delivered to reader mismatch")
	}
	waitUntil(t, time.Second, "50 bytes left buffered", func() bool {
		return c.inputBuffer.Len() == 50
	})

	// completion kick: a parked wait threshold satisfied purely by the bytes
	// already in the buffer must be signaled without the peer resending
	atomic.StoreInt64(&c.waitReadSize, 50)
	c.resumeAfterMigration()
	select {
	case err := <-c.readTrigger:
		if err != nil {
			t.Fatalf("readTrigger kick error: %v", err)
		}
	default:
		t.Fatal("resumeAfterMigration did not kick the parked reader")
	}

	// release OnRequest: it echoes the 50 leftover buffered bytes without any
	// resend
	close(release)
	leftEcho := make([]byte, 50)
	if _, err := io.ReadFull(peer, leftEcho); err != nil {
		t.Fatalf("read leftover echo: %v", err)
	}
	if !bytes.Equal(leftEcho, second[50:]) {
		t.Fatal("leftover buffered bytes were not processed after migration")
	}

	// fresh post-migration data keeps working through the single OnRequest
	third := makeChunk(3)[:53]
	if _, err := peer.Write(third); err != nil {
		t.Fatalf("write third: %v", err)
	}
	thirdEcho := make([]byte, 53)
	if _, err := io.ReadFull(peer, thirdEcho); err != nil {
		t.Fatalf("read third echo: %v", err)
	}
	if !bytes.Equal(thirdEcho, third) {
		t.Fatal("post-migration echo mismatch")
	}
}

// ---------------------------------------------------------------------------
// partial write: pending outputBuffer + blocked Flush survive migration
// ---------------------------------------------------------------------------

func TestMigratePartialWrite(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, peer := tcpMigratePair(t, echoOnRequest(new(int64)))
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	if err := peer.SetReadBuffer(1024); err != nil {
		t.Logf("set small rcvbuf: %v", err)
	}

	const blobSize = 8 << 20 // 8 MiB, larger than any default socket buffer
	pattern := makeChunk(7)
	blob := make([]byte, blobSize)
	for i := range blob {
		blob[i] = pattern[i%len(pattern)]
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := c.Write(blob)
		writeDone <- err
	}()

	// wait until the server has unsent data registered for EPOLLOUT
	waitUntil(t, time.Second, "output buffer pending", func() bool {
		return c.outputBuffer.Len() > 0
	})

	if err := MigrateConnection(context.Background(), c, dst); err != nil {
		t.Fatalf("migrate with pending write: %v", err)
	}
	if ownerPoll(t, c) != dst {
		t.Fatal("owner did not switch during partial write")
	}

	// drain and verify
	got := make([]byte, blobSize)
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatalf("peer drain: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatal("blob mismatch after partial-write migration")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("server Write returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server Flush never completed after migration")
	}
	waitUntil(t, time.Second, "output buffer drained", func() bool {
		return c.outputBuffer.IsEmpty()
	})
}

// ---------------------------------------------------------------------------
// peer sends data and half-closes; FIN handling across migration
// ---------------------------------------------------------------------------

func TestMigratePeerHalfClose(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	var got int64
	onRequest := func(ctx context.Context, conn Connection) error {
		reader := conn.Reader()
		if n := reader.Len(); n > 0 {
			p, _ := reader.Next(n)
			atomic.AddInt64(&got, int64(len(p)))
			_, _ = conn.Write(p)
		}
		return nil
	}
	c, peer := tcpMigratePair(t, onRequest)
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	payload := makeChunk(9)[:5000]
	// first half before migration, second half after it
	if _, err := peer.Write(payload[:2500]); err != nil {
		t.Fatalf("write half1: %v", err)
	}
	waitUntil(t, time.Second, "half1 received", func() bool { return atomic.LoadInt64(&got) >= 2500 })

	if err := MigrateConnection(context.Background(), c, dst); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := peer.Write(payload[2500:]); err != nil {
		t.Fatalf("write half2: %v", err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatalf("closewrite: %v", err)
	}

	// peer must receive the exact payload echoed
	echo := make([]byte, 5000)
	if _, err := io.ReadFull(peer, echo); err != nil {
		t.Fatalf("peer read echo: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatal("half-close payload mismatch")
	}
	// then the server notices the FIN and the poller closes the connection
	waitUntil(t, 3*time.Second, "connection closed after FIN", func() bool { return !c.IsActive() })
	if atomic.LoadInt64(&got) != 5000 {
		t.Fatalf("server observed %d bytes, want 5000", got)
	}
}

// ---------------------------------------------------------------------------
// cancellation after teardown must not abort the migration
// ---------------------------------------------------------------------------

func TestMigrateCancellationIgnoredAfterAccept(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, peer := tcpMigratePair(t, echoOnRequest(new(int64)))
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	ctx, cancel := context.WithCancel(context.Background())
	migrateHookAfterDetach = func(*connection) {
		cancel() // teardown already committed
	}
	t.Cleanup(func() { migrateHookAfterDetach = nil })

	if err := MigrateConnection(ctx, c, dst); err != nil {
		t.Fatalf("migration must finish after teardown despite cancel: %v", err)
	}
	if ownerPoll(t, c) != dst {
		t.Fatal("owner did not switch")
	}
	if _, err := peer.Write([]byte("post-cancel")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len("post-cancel"))
	if _, err := io.ReadFull(peer, echo); err != nil {
		t.Fatalf("echo after canceled migration: %v", err)
	}
	if string(echo) != "post-cancel" {
		t.Fatalf("echo %q", echo)
	}
}

// ---------------------------------------------------------------------------
// new registration failure -> rollback keeps the connection on the old poller
// ---------------------------------------------------------------------------

func TestMigrateRegisterFailureRollback(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, peer := tcpMigratePair(t, echoOnRequest(new(int64)))
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	migrateHookBeforeRegister = func(*defaultPoll) error {
		return errors.New("injected add failure")
	}
	t.Cleanup(func() { migrateHookBeforeRegister = nil })

	err := MigrateConnection(context.Background(), c, dst)
	if !errors.Is(err, ErrMigrationRolledBack) {
		t.Fatalf("want rollback, got %v", err)
	}
	if ownerPoll(t, c) != src {
		t.Fatal("connection not restored on source")
	}
	if !c.IsActive() {
		t.Fatal("connection inactive after rollback")
	}
	if _, err := peer.Write([]byte("after-rollback")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len("after-rollback"))
	if _, err := io.ReadFull(peer, echo); err != nil {
		t.Fatalf("echo after rollback: %v", err)
	}
	if string(echo) != "after-rollback" {
		t.Fatalf("echo %q", echo)
	}
}

// ---------------------------------------------------------------------------
// rollback itself impossible -> deterministic close, all waiters end
// ---------------------------------------------------------------------------

func TestMigrateFatalCloseWhenSourceDies(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, peer := tcpMigratePair(t, echoOnRequest(new(int64)))
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	// fail the destination ADD and simultaneously kill the source poller so
	// restoring the old registration is impossible.
	migrateHookBeforeRegister = func(*defaultPoll) error {
		return errors.New("injected add failure")
	}
	migrateHookAfterDetach = func(*connection) {
		_ = src.Close()
	}
	t.Cleanup(func() {
		migrateHookBeforeRegister = nil
		migrateHookAfterDetach = nil
	})

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := io.ReadFull(c, buf)
		readErr <- err
	}()

	err := MigrateConnection(context.Background(), c, dst)
	if !errors.Is(err, ErrConnClosed) {
		t.Fatalf("want closed error, got %v", err)
	}
	waitUntil(t, 3*time.Second, "connection closed", func() bool { return !c.IsActive() })
	select {
	case e := <-readErr:
		if e == nil {
			t.Fatal("blocking reader should have been ended")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read waiter leaked after fatal migration")
	}
	// peer must observe the shutdown
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	if _, e := peer.Read(buf); e == nil {
		t.Fatal("peer expected EOF after fatal migration")
	}
}

// ---------------------------------------------------------------------------
// Close racing with migration: outcome is always unique-owner-alive or closed
// ---------------------------------------------------------------------------

func TestMigrateCloseRace(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)

	for i := 0; i < 40; i++ {
		c, peer := tcpMigratePair(t, echoOnRequest(new(int64)))
		src := ownerPoll(t, c)
		dst := otherPoll(polls, src)

		var wg sync.WaitGroup
		wg.Add(2)
		var migErr error
		go func() {
			defer wg.Done()
			// several ping-pong attempts; every error is acceptable as long as
			// it returns promptly, except a deadlock
			from, to := src, dst
			for j := 0; j < 4; j++ {
				migErr = MigrateConnection(context.Background(), c, to)
				from, to = to, from
				if !c.IsActive() {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			runtime.Gosched()
			_ = c.Close()
		}()
		waitWG(t, &wg, 5*time.Second)
		if c.IsActive() {
			t.Fatalf("iter %d: connection still active after Close", i)
		}
		if migErr != nil && !errors.Is(migErr, ErrConnClosed) &&
			!errors.Is(migErr, ErrMigrationRolledBack) {
			t.Fatalf("iter %d: unexpected migration error %v", i, migErr)
		}
		// peer must reach EOF
		_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
		tmp := make([]byte, 8)
		if _, e := peer.Read(tmp); e == nil {
			t.Fatalf("iter %d: peer did not see EOF", i)
		}
	}
}

func waitWG(t *testing.T, wg *sync.WaitGroup, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("wait group timeout: migration or close deadlocked")
	}
}

// ---------------------------------------------------------------------------
// stale events and fd number reuse must never reach a new registration
// ---------------------------------------------------------------------------

func TestMigrateStaleTokenAndFdReuse(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, _ := tcpMigratePair(t, nil)
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	oldOp := c.getOperator()
	oldToken := currentToken(oldOp)
	staleEvent := new(epollevent)
	staleEvent.Events = syscall.EPOLLIN | syscall.EPOLLRDHUP
	setEventToken(staleEvent, oldToken)

	// also forge an event carrying a nil / foreign token
	emptyEvent := new(epollevent)
	emptyEvent.Events = syscall.EPOLLIN

	if err := MigrateConnection(context.Background(), c, dst); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	newOp := c.getOperator()
	if newOp == oldOp {
		t.Fatal("operator was not replaced")
	}
	// old operator is recycled back to the source cache
	waitUntil(t, time.Second, "old operator recycled", func() bool { return oldOp.isUnused() })

	// stale event from the old batch must resolve to nothing
	if op := src.getOperator(0, staleEvent.GetDataPtr()); op != nil {
		t.Fatalf("stale token resolved to %v", op)
	}
	if op := src.getOperator(0, emptyEvent.GetDataPtr()); op != nil {
		t.Fatal("empty token resolved to an operator")
	}

	// simulate fd-number reuse: a brand new registration on src for the same
	// fd number must not be reachable through the stale event
	op3 := src.Alloc()
	op3.FD = c.fd
	op3.OnRead = func(Poll) error { return nil }
	if err := op3.Control(PollReadable); err != nil {
		t.Fatalf("register reuse op: %v", err)
	}
	token3 := currentToken(op3)

	// old stale event still dead, new token resolves to the new operator
	if op := src.getOperator(0, staleEvent.GetDataPtr()); op != nil {
		t.Fatal("stale token hijacked by fd-reuse registration")
	}
	evt3 := new(epollevent)
	evt3.Events = syscall.EPOLLIN
	setEventToken(evt3, token3)
	if op := src.getOperator(0, evt3.GetDataPtr()); op != op3 {
		t.Fatal("current token did not resolve to its operator")
	}
	if err := op3.Control(PollDetach); err != nil {
		t.Fatalf("detach op3: %v", err)
	}
	if err := src.submit(func() { src.retireOperator(op3) }); err != nil {
		t.Fatalf("retire op3: %v", err)
	}
}

// high-frequency churn: close, fd number reuse, new connection keeps working
func TestMigrateHighFrequencyFdReuse(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)

	for i := 0; i < 24; i++ {
		c, peer := tcpMigratePair(t, echoOnRequest(new(int64)))
		src := ownerPoll(t, c)
		dst := otherPoll(polls, src)
		fdNum := c.fd

		if err := MigrateConnection(context.Background(), c, dst); err != nil {
			t.Fatalf("iter %d migrate: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("reuse-%d", i))
		if _, err := peer.Write(msg); err != nil {
			t.Fatalf("iter %d write: %v", i, err)
		}
		echo := make([]byte, len(msg))
		if _, err := io.ReadFull(peer, echo); err != nil {
			t.Fatalf("iter %d echo: %v", i, err)
		}
		if !bytes.Equal(echo, msg) {
			t.Fatalf("iter %d cross-talk: %q", i, echo)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("iter %d close: %v", i, err)
		}
		_ = peer.Close()
		waitUntil(t, time.Second, fmt.Sprintf("iter %d conn closed", i), func() bool { return !c.IsActive() })

		// churn fds to encourage reuse of the just-released number
		var holders []int
		stop := false
		for !stop {
			fd, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
			if e != nil {
				break
			}
			if fd == fdNum {
				stop = true
			}
			holders = append(holders, fd)
			if len(holders) > 256 {
				break
			}
		}
		for _, fd := range holders {
			_ = syscall.Close(fd)
		}
	}
}

// ---------------------------------------------------------------------------
// migration issued from inside the source poller goroutine must run inline and
// never deadlock waiting for itself
// ---------------------------------------------------------------------------

func TestMigrateFromPollerTaskRunsInline(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, peer := tcpMigratePair(t, echoOnRequest(new(int64)))
	src := ownerPoll(t, c)
	dst := otherPoll(polls, src)

	done := make(chan error, 1)
	if err := src.submit(func() {
		// we are now running on the src poller goroutine; this must execute
		// the quiesce steps inline instead of waiting for another batch
		done <- MigrateConnection(context.Background(), c, dst)
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("inline migration: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("inline migration deadlocked the poller")
	}
	if ownerPoll(t, c) != dst {
		t.Fatal("owner did not switch from poller task")
	}
	if _, err := peer.Write([]byte("inline")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len("inline"))
	if _, err := io.ReadFull(peer, echo); err != nil {
		t.Fatalf("echo after inline migration: %v", err)
	}
	if string(echo) != "inline" {
		t.Fatalf("echo %q", echo)
	}
}
