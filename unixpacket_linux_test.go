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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// ------------------------------------------ helpers ------------------------------------------

func newSeqPacketFDs(t *testing.T) [2]int {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	MustNil(t, err)
	return [2]int{fds[0], fds[1]}
}

func newPacketPairCfg(t *testing.T, cfgA, cfgB *PacketConfig) (a, b *UnixPacketConnection) {
	t.Helper()
	fds := newSeqPacketFDs(t)
	var err error
	a, err = NewUnixPacketConnection(fds[0], cfgA)
	MustNil(t, err)
	b, err = NewUnixPacketConnection(fds[1], cfgB)
	MustNil(t, err)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func newPacketPair(t *testing.T) (a, b *UnixPacketConnection) {
	return newPacketPairCfg(t, nil, nil)
}

func openDevNullFD(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
	MustNil(t, err)
	return fd
}

func openDevNullFDs(t *testing.T, n int) []int {
	t.Helper()
	fds := make([]int, n)
	for i := range fds {
		fds[i] = openDevNullFD(t)
	}
	return fds
}

func countFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	MustNil(t, err)
	return len(entries)
}

func fdIsOpen(fd int) bool {
	var st syscall.Stat_t
	return syscall.Fstat(fd, &st) == nil
}

func fdHasCloExec(t *testing.T, fd int) bool {
	t.Helper()
	r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd),
		uintptr(syscall.F_GETFD), 0)
	MustTrue(t, errno == 0)
	return r&uintptr(syscall.FD_CLOEXEC) != 0
}

func waitUntil(d time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		runtime.Gosched()
	}
	return fn()
}

func mustReceive(t *testing.T, c *UnixPacketConnection, want []byte, numFDs int) *Packet {
	t.Helper()
	p, err := c.ReceivePacket()
	MustNil(t, err)
	Assert(t, string(p.Payload) == string(want),
		fmt.Sprintf("payload got %q want %q", p.Payload, want))
	Equal(t, p.NumFDs(), numFDs)
	return p
}

func init() {
	Initialize()
}

// ------------------------------------------ tests ------------------------------------------

// Multiple packets over a real SOCK_SEQPACKET socketpair keep their boundaries
// and arrive one-per-ReceivePacket; fds ride along and are independently taken.
func TestUnixPacketMultiplePackets(t *testing.T) {
	a, b := newPacketPair(t)

	sizes := []int{1, 255, 4096}
	for i, n := range sizes {
		payload := make([]byte, n)
		for j := range payload {
			payload[j] = byte(i + 1)
		}
		fds := openDevNullFDs(t, i)
		MustNil(t, a.SendPacket(payload, fds))
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
	}
	for i, n := range sizes {
		p := mustReceive(t, b, nil, i)
		Equal(t, len(p.Payload), n)
		for j := 0; j < i; j++ {
			fd, err := p.TakeFD(j)
			MustNil(t, err)
			MustTrue(t, fdHasCloExec(t, fd))
			_ = syscall.Close(fd)
		}
		MustNil(t, p.Release())
		// Release is idempotent and closes nothing twice.
		MustNil(t, p.Release())
	}

	// Two packets sent back to back must not be merged.
	x, y := []byte("first-message"), []byte("second-message")
	MustNil(t, a.SendPacket(x, nil))
	MustNil(t, a.SendPacket(y, nil))
	p1 := mustReceive(t, b, x, 0)
	p2 := mustReceive(t, b, y, 0)
	MustNil(t, p1.Release())
	MustNil(t, p2.Release())

	// Bidirectional: reverse direction works the same.
	MustNil(t, b.SendPacket([]byte("pong"), nil))
	mustReceive(t, a, []byte("pong"), 0).Release()
}

// SCM_RIGHTS shares the open file description: sender and receiver observe the
// same offset, and closing the caller's original fd right after SendPacket does
// not affect the owned duplicate delivered to the receiver.
func TestUnixPacketFileOffsetAndEarlyClose(t *testing.T) {
	a, b := newPacketPair(t)

	f, err := os.CreateTemp("", "netpoll-packet-*.txt")
	MustNil(t, err)
	content := "hello-netpacket-shared-offset"
	_, err = f.WriteString(content)
	MustNil(t, err)
	// offset is now at len(content)

	MustNil(t, a.SendPacket([]byte("file"), []int{int(f.Fd())}))
	// The caller may drop its own descriptor immediately; SendPacket made an
	// internal CLOEXEC duplicate.
	MustNil(t, f.Close())
	origName := f.Name()
	defer os.Remove(origName)

	p := mustReceive(t, b, []byte("file"), 1)
	rfd, err := p.TakeFD(0)
	MustNil(t, err)
	MustNil(t, p.Release())
	rf := os.NewFile(uintptr(rfd), "received")
	defer rf.Close()

	// The received descriptor references the same open file description, so
	// the offset inherited from the writer is at EOF.
	buf := make([]byte, len(content))
	n, err := rf.Read(buf)
	Equal(t, n, 0)
	Assert(t, errors.Is(err, io.EOF), err)

	// Seek back and read the shared content.
	off, err := rf.Seek(0, io.SeekStart)
	Equal(t, off, int64(0))
	MustNil(t, err)
	n, err = rf.Read(buf)
	MustNil(t, err)
	Equal(t, n, len(content))
	Equal(t, string(buf[:n]), content)

	// Tell the sender to reuse its side; proves the connection survived the
	// original fd close.
	MustNil(t, b.SendPacket([]byte("done"), nil))
	ack := mustReceive(t, a, []byte("done"), 0)
	MustNil(t, ack.Release())

	// Receiver still has a live reference after the original is long gone.
	_, err = rf.Seek(0, io.SeekStart)
	MustNil(t, err)
	n, err = rf.Read(buf)
	MustNil(t, err)
	Equal(t, string(buf[:n]), content)
}

// Taken fds transfer to the caller; untaken fds are closed by Release.
func TestUnixPacketTakeAndRelease(t *testing.T) {
	Initialize()
	baseline := countFDs(t)
	a, b := newPacketPair(t)

	fds := openDevNullFDs(t, 3)
	MustNil(t, a.SendPacket([]byte("fds"), fds))
	// close originals at once: receiver ownership must be unaffected.
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}

	p := mustReceive(t, b, []byte("fds"), 3)
	taken, err := p.TakeFD(1)
	MustNil(t, err)
	// double take is rejected
	_, err = p.TakeFD(1)
	Assert(t, errors.Is(err, ErrPacketFDTaken), err)
	// out of range
	_, err = p.TakeFD(9)
	Assert(t, errors.Is(err, ErrPacketFDOutOfRange), err)
	MustTrue(t, fdIsOpen(taken))
	MustNil(t, p.Release())
	MustTrue(t, fdIsOpen(taken)) // caller-owned now
	MustTrue(t, !fdIsOpen(fds[0]))
	MustTrue(t, !fdIsOpen(fds[2]))
	// TakeFD after Release fails.
	_, err = p.TakeFD(0)
	Assert(t, errors.Is(err, ErrPacketReleased), err)
	_ = syscall.Close(taken)

	MustTrue(t, waitUntil(2*time.Second, func() bool {
		// a/b socket fds remain; the three passed fds must be gone net.
		return countFDs(t) <= baseline+2 && countFDs(t) >= baseline
	}))
}

// Peer sending more fds than our MaxFDs triggers MSG_CTRUNC: the packet fails,
// every descriptor that became visible is closed, and the next packet is
// unaffected (no truncation-as-prefix).
func TestUnixPacketControlTruncation(t *testing.T) {
	baseline := countFDs(t)
	senderCfg := &PacketConfig{MaxPayload: 4096, MaxFDs: 8,
		MaxQueuePackets: 8, MaxQueueBytes: 8 * 4096}
	recvCfg := &PacketConfig{MaxPayload: 4096, MaxFDs: 2,
		MaxQueuePackets: 8, MaxQueueBytes: 8 * 4096}
	a, b := newPacketPairCfg(t, senderCfg, recvCfg)

	fds := openDevNullFDs(t, 3)
	MustNil(t, a.SendPacket([]byte("too-many"), fds))
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
	_, err := b.ReceivePacket()
	Assert(t, errors.Is(err, ErrPacketControlTruncated) || errors.Is(err, ErrPacketTooManyFDs),
		err)
	// visible received fds closed, none leaked
	MustTrue(t, waitUntil(2*time.Second, func() bool {
		return countFDs(t) <= baseline+2
	}))

	// following packet still delivered intact
	MustNil(t, a.SendPacket([]byte("after"), nil))
	p := mustReceive(t, b, []byte("after"), 0)
	MustNil(t, p.Release())
}

// Oversized payload triggers MSG_TRUNC: the whole datagram (with its fds) fails
// and the next packet starts fresh.
func TestUnixPacketPayloadTruncation(t *testing.T) {
	baseline := countFDs(t)
	senderCfg := &PacketConfig{MaxPayload: 4096, MaxFDs: 4,
		MaxQueuePackets: 4, MaxQueueBytes: 4 * 4096}
	recvCfg := &PacketConfig{MaxPayload: 8, MaxFDs: 4,
		MaxQueuePackets: 4, MaxQueueBytes: 4 * 8}
	a, b := newPacketPairCfg(t, senderCfg, recvCfg)

	fd := openDevNullFD(t)
	MustNil(t, a.SendPacket(make([]byte, 64), []int{fd}))
	_ = syscall.Close(fd)
	_, err := b.ReceivePacket()
	Assert(t, errors.Is(err, ErrPacketTruncated), err)
	MustTrue(t, waitUntil(2*time.Second, func() bool {
		return countFDs(t) <= baseline+2
	}))

	MustNil(t, a.SendPacket([]byte("ok"), nil))
	p := mustReceive(t, b, []byte("ok"), 0)
	MustNil(t, p.Release())
}

// Parser hardening for malformed control buffers that a kernel would normally
// never produce.
func TestParsePacketFDs(t *testing.T) {
	hdrLen := syscall.CmsgLen(0)

	// valid single record
	ctrl := make([]byte, hdrLen+syscall.CmsgSpace(8))
	off := putTestCmsg(ctrl, 0, syscall.SOL_SOCKET, syscall.SCM_RIGHTS,
		[]byte{7, 0, 0, 0, 8, 0, 0, 0})
	Equal(t, off, len(ctrl))
	got, err := parsePacketFDs(ctrl, 8)
	MustNil(t, err)
	Equal(t, len(got), 2)
	Equal(t, got[0], 7)
	Equal(t, got[1], 8)

	// two valid records
	ctrl = make([]byte, hdrLen+syscall.CmsgSpace(8)+hdrLen+syscall.CmsgSpace(4))
	off = putTestCmsg(ctrl, 0, syscall.SOL_SOCKET, syscall.SCM_RIGHTS,
		[]byte{7, 0, 0, 0, 8, 0, 0, 0})
	off = putTestCmsg(ctrl, off, syscall.SOL_SOCKET, syscall.SCM_RIGHTS,
		[]byte{9, 0, 0, 0})
	Equal(t, off, len(ctrl))
	got, err = parsePacketFDs(ctrl, 8)
	MustNil(t, err)
	Equal(t, len(got), 3)

	// over limit
	_, err = parsePacketFDs(ctrl, 1)
	Assert(t, errors.Is(err, ErrPacketTooManyFDs), err)

	// trailing garbage smaller than a header
	_, err = parsePacketFDs([]byte{1, 2, 3}, 8)
	Assert(t, errors.Is(err, ErrPacketControlInvalid), err)

	// header length too small
	bad := make([]byte, hdrLen)
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&bad[0]))
	h.Len = 1
	_, err = parsePacketFDs(bad, 8)
	Assert(t, errors.Is(err, ErrPacketControlInvalid), err)

	// header length running past the buffer
	bad = make([]byte, hdrLen+8)
	h = (*syscall.Cmsghdr)(unsafe.Pointer(&bad[0]))
	h.Len = uint64(hdrLen + 16)
	h.Level = syscall.SOL_SOCKET
	h.Type = syscall.SCM_RIGHTS
	_, err = parsePacketFDs(bad, 8)
	Assert(t, errors.Is(err, ErrPacketControlInvalid), err)

	// unexpected record type/level
	bad = make([]byte, hdrLen+syscall.CmsgSpace(4))
	putTestCmsg(bad, 0, syscall.SOL_SOCKET, 12345, []byte{7, 0, 0, 0})
	_, err = parsePacketFDs(bad, 8)
	Assert(t, errors.Is(err, ErrPacketControlInvalid), err)

	// data width not a multiple of the descriptor width
	bad = make([]byte, hdrLen+syscall.CmsgSpace(2))
	hh := (*syscall.Cmsghdr)(unsafe.Pointer(&bad[0]))
	hh.Len = uint64(hdrLen + 2)
	hh.Level = syscall.SOL_SOCKET
	hh.Type = syscall.SCM_RIGHTS
	bad[hdrLen] = 1
	bad[hdrLen+1] = 2
	_, err = parsePacketFDs(bad, 8)
	Assert(t, errors.Is(err, ErrPacketControlInvalid), err)

	// empty input is legal: no descriptors
	got, err = parsePacketFDs(nil, 8)
	MustNil(t, err)
	Equal(t, len(got), 0)
}

func putTestCmsg(buf []byte, off int, level, typ int32, data []byte) int {
	hdrLen := syscall.CmsgLen(0)
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[off]))
	h.Len = uint64(hdrLen + len(data))
	h.Level = level
	h.Type = typ
	copy(buf[off+hdrLen:], data)
	return off + hdrLen + syscall.CmsgSpace(len(data))
}

// Local validation rejects bad packets before taking fd ownership, so the
// caller keeps every descriptor and nothing leaks.
func TestUnixPacketSendValidation(t *testing.T) {
	baseline := countFDs(t)
	a, b := newPacketPairCfg(t,
		&PacketConfig{MaxPayload: 16, MaxFDs: 1, MaxQueuePackets: 1, MaxQueueBytes: 16},
		&PacketConfig{MaxPayload: 16, MaxFDs: 1, MaxQueuePackets: 1, MaxQueueBytes: 16})

	Assert(t, errors.Is(a.SendPacket(nil, nil), ErrPacketPayloadEmpty))
	Assert(t, errors.Is(a.SendPacket(make([]byte, 17), nil), ErrPacketPayloadTooLarge))
	fd := openDevNullFD(t)
	fds2 := openDevNullFDs(t, 2)
	Assert(t, errors.Is(a.SendPacket([]byte("x"), fds2), ErrPacketTooManyFDs))
	for _, d := range fds2 {
		_ = syscall.Close(d)
	}
	// caller's fd is untouched by rejected calls
	MustTrue(t, fdIsOpen(fd))
	_ = syscall.Close(fd)

	// a valid packet still works
	MustNil(t, a.SendPacket([]byte("ok"), nil))
	p := mustReceive(t, b, []byte("ok"), 0)
	MustNil(t, p.Release())

	// only the two packet socket fds remain on top of the baseline
	Assert(t, countFDs(t) == baseline+2,
		fmt.Sprintf("fd count got %d want %d", countFDs(t), baseline+2))
}

// Queue budget: oversized backlog is rejected before ownership transfer while
// queued packets stay whole and block; Close wakes all waiters and releases
// the internal fd duplicates exactly once.
func TestUnixPacketQueueFullAndClose(t *testing.T) {
	const (
		nSenders = 10
		pktSize  = 60 * 1024
	)
	smallBuf := &PacketConfig{MaxPayload: 64 * 1024, MaxFDs: 1,
		MaxQueuePackets: 4, MaxQueueBytes: 4 * 64 * 1024}
	baseline := countFDs(t)
	fds := newSeqPacketFDs(t)
	// force a tiny kernel send buffer so EAGAIN is deterministic
	MustNil(t, syscall.SetsockoptInt(fds[0], syscall.SOL_SOCKET,
		syscall.SO_SNDBUF, 64*1024))
	a, err := NewUnixPacketConnection(fds[0], smallBuf)
	MustNil(t, err)
	b, err := NewUnixPacketConnection(fds[1], smallBuf)
	MustNil(t, err)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	var (
		succeeded int32
		rejected  int32
		closed    int32
		inflight  int32
		wg        sync.WaitGroup
	)
	wg.Add(nSenders)
	for i := 0; i < nSenders; i++ {
		go func() {
			defer wg.Done()
			fd := openDevNullFD(t)
			defer syscall.Close(fd)
			atomic.AddInt32(&inflight, 1)
			err := a.SendPacket(make([]byte, pktSize), []int{fd})
			atomic.AddInt32(&inflight, -1)
			switch {
			case err == nil:
				atomic.AddInt32(&succeeded, 1)
			case errors.Is(err, ErrPacketQueueFull):
				atomic.AddInt32(&rejected, 1)
			case errors.Is(err, ErrConnClosed) || errors.Is(err, ErrWriteTimeout):
				atomic.AddInt32(&closed, 1)
			default:
				t.Errorf("unexpected send error: %v", err)
			}
		}()
	}

	MustTrue(t, waitUntil(3*time.Second, func() bool {
		return atomic.LoadInt32(&rejected) > 0 && atomic.LoadInt32(&inflight) > 0
	}))
	MustTrue(t, atomic.LoadInt32(&succeeded) >= 1)

	// Close while senders are blocked on the full queue.
	MustNil(t, a.Close())
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("blocked senders not woken: success=%d rejected=%d closed=%d inflight=%d",
			succeeded, rejected, atomic.LoadInt32(&closed), inflight)
	}
	Assert(t, atomic.LoadInt32(&rejected) >= 1)
	Assert(t, atomic.LoadInt32(&succeeded)+atomic.LoadInt32(&rejected)+
		atomic.LoadInt32(&closed) == nSenders)

	// Further sends fail immediately.
	Assert(t, errors.Is(a.SendPacket([]byte("x"), nil), ErrConnClosed))

	// receiver Close is a safe no-op on a torn-down pair; double Close safe.
	MustNil(t, b.Close())
	MustNil(t, a.Close())

	// No queued dup fds, /dev/null originals or packet sockets left behind.
	MustTrue(t, waitUntil(2*time.Second, func() bool {
		return countFDs(t) == baseline
	}))
}

// Concurrent send/receive/close never corrupts state or blocks the poller.
func TestUnixPacketCloseRace(t *testing.T) {
	for i := 0; i < 8; i++ {
		a, b := newPacketPair(t)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := a.SendPacket([]byte("x"), nil); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				p, err := b.ReceivePacket()
				if err != nil {
					return
				}
				_ = p.Release()
			}
		}()
		time.Sleep(5 * time.Millisecond)
		close(stop)
		var cw sync.WaitGroup
		for j := 0; j < 4; j++ {
			cw.Add(1)
			go func() { defer cw.Done(); _ = a.Close() }()
		}
		cw.Wait()
		_ = b.Close()
		wait := make(chan struct{})
		go func() { wg.Wait(); close(wait) }()
		select {
		case <-wait:
		case <-time.After(5 * time.Second):
			t.Fatal("goroutines stuck after Close")
		}
	}
}

// Peer shutdown surfaces ErrEOF to receivers and rejects later sends; messages
// already in flight stay drainable before the EOF is reported.
func TestUnixPacketPeerCloseEOF(t *testing.T) {
	a, b := newPacketPair(t)
	MustNil(t, a.SetReadDeadline(time.Now().Add(5*time.Second)))
	MustNil(t, b.SendPacket([]byte("one"), nil))
	MustNil(t, b.SendPacket([]byte("two"), nil))
	_ = b.Close()
	p1 := mustReceive(t, a, []byte("one"), 0)
	MustNil(t, p1.Release())
	p2 := mustReceive(t, a, []byte("two"), 0)
	MustNil(t, p2.Release())
	_, err := a.ReceivePacket()
	Assert(t, errors.Is(err, ErrEOF), err)
	MustTrue(t, waitUntil(2*time.Second, func() bool { return !a.IsActive() }))
	Assert(t, errors.Is(a.SendPacket([]byte("x"), nil), ErrConnClosed))
	MustNil(t, a.Close())
}

// Read deadline wakes a blocked ReceivePacket with ErrReadTimeout; clearing the
// deadline restores normal operation.
func TestUnixPacketReceiveTimeout(t *testing.T) {
	a, b := newPacketPair(t)
	MustNil(t, a.SetReadDeadline(time.Now().Add(80*time.Millisecond)))
	start := time.Now()
	_, err := a.ReceivePacket()
	Assert(t, errors.Is(err, ErrReadTimeout), err)
	Assert(t, time.Since(start) >= 50*time.Millisecond)
	MustNil(t, a.SetReadDeadline(time.Time{}))

	MustNil(t, b.SendPacket([]byte("late"), nil))
	p := mustReceive(t, a, []byte("late"), 0)
	MustNil(t, p.Release())

	// relative timeout API behaves the same and keeps the connection usable
	MustNil(t, a.SetReadTimeout(80*time.Millisecond))
	_, err = a.ReceivePacket()
	Assert(t, errors.Is(err, ErrReadTimeout), err)
	MustNil(t, a.SetReadTimeout(0))
	MustNil(t, b.SendPacket([]byte("again"), nil))
	p = mustReceive(t, a, []byte("again"), 0)
	MustNil(t, p.Release())
}

// Close callbacks run exactly once and after waiters have been woken.
func TestUnixPacketCloseCallback(t *testing.T) {
	a, b := newPacketPair(t)
	called := make(chan struct{}, 2)
	MustNil(t, a.AddCloseCallback(func(c *UnixPacketConnection) error {
		called <- struct{}{}
		return nil
	}))
	MustNil(t, a.Close())
	MustNil(t, a.Close())
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("close callback not fired")
	}
	select {
	case <-called:
		t.Fatal("close callback fired twice")
	case <-time.After(50 * time.Millisecond):
	}
	_ = b.Close()
}

// Received fds carry O_CLOEXEC (atomic MSG_CMSG_CLOEXEC), and an exec'ed child
// does not inherit them or the packet socket fds.
func TestUnixPacketCloExec(t *testing.T) {
	if os.Getenv("NETPOLL_PACKET_HELPER") == "1" {
		packetCloExecHelper()
		return
	}
	a, b := newPacketPair(t)

	f, err := os.CreateTemp("", "netpoll-cloexec-*")
	MustNil(t, err)
	defer os.Remove(f.Name())
	_, err = f.WriteString("secret")
	MustNil(t, err)
	MustNil(t, a.SendPacket([]byte("fd"), []int{int(f.Fd())}))
	MustNil(t, f.Close())

	p := mustReceive(t, b, []byte("fd"), 1)
	rfd, err := p.TakeFD(0)
	MustNil(t, err)
	MustTrue(t, fdHasCloExec(t, rfd))
	MustNil(t, p.Release())

	cmd := exec.Command("/proc/self/exe", "-test.run=^TestUnixPacketCloExec$")
	cmd.Env = append(os.Environ(),
		"NETPOLL_PACKET_HELPER=1",
		"NETPOLL_PACKET_SOCKA="+strconv.Itoa(a.fd),
		"NETPOLL_PACKET_SOCKB="+strconv.Itoa(b.fd),
		"NETPOLL_PACKET_RECVFD="+strconv.Itoa(rfd),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v, output: %s", err, out)
	}
	inherited := strings.Fields(strings.TrimSpace(string(out)))
	for _, label := range []struct {
		name string
		fd   int
	}{
		{"received", rfd}, {"socket-a", a.fd}, {"socket-b", b.fd},
	} {
		for _, n := range inherited {
			Assert(t, n != strconv.Itoa(label.fd),
				fmt.Sprintf("%s fd %d inherited across exec, child fds=%v", label.name, label.fd, inherited))
		}
	}

	// the received fd remains open and usable in the parent
	var st syscall.Stat_t
	MustNil(t, syscall.Fstat(rfd, &st))
	_ = syscall.Close(rfd)
}

func packetCloExecHelper() {
	var inherited []string
	entries, _ := os.ReadDir("/proc/self/fd")
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n <= 2 {
			continue
		}
		inherited = append(inherited, e.Name())
	}
	if len(inherited) > 0 {
		fmt.Print(strings.Join(inherited, " "))
	}
	os.Exit(0)
}

// Full listener/dial roundtrip on a filesystem unixpacket address.
func TestUnixPacketListenerDial(t *testing.T) {
	dir := t.TempDir()
	addr := filepath.Join(dir, "seq.sock")
	ln, err := ListenUnixPacket(addr, nil)
	MustNil(t, err)
	defer ln.Close()

	accepted := make(chan *UnixPacketConnection, 1)
	go func() {
		c, err := ln.AcceptPacket()
		if err != nil {
			return
		}
		accepted <- c
	}()

	client, err := DialUnixPacket(addr, nil)
	MustNil(t, err)
	defer client.Close()
	var server *UnixPacketConnection
	select {
	case server = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("accept timeout")
	}
	defer server.Close()

	fds := openDevNullFDs(t, 2)
	MustNil(t, client.SendPacket([]byte("ping"), fds))
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
	p := mustReceive(t, server, []byte("ping"), 2)
	f0, err := p.TakeFD(0)
	MustNil(t, err)
	MustTrue(t, fdHasCloExec(t, f0))
	_ = syscall.Close(f0)
	MustNil(t, p.Release())

	MustNil(t, server.SendPacket([]byte("pong"), nil))
	p = mustReceive(t, client, []byte("pong"), 0)
	MustNil(t, p.Release())

	// listener implements net.Listener surface
	var _ net.Listener = ln
}

// Ordinary unix stream connections keep their byte-stream behavior; the packet
// entry is strictly additive.
func TestUnixStreamStillCompatible(t *testing.T) {
	rfd, wfd := GetSysFdPairs()
	r, err := NewFDConnection(rfd)
	MustNil(t, err)
	w, err := NewFDConnection(wfd)
	MustNil(t, err)
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })

	msg := []byte("stream-unchanged")
	_, err = w.Write(msg)
	MustNil(t, err)
	got, err := r.Reader().Next(len(msg))
	MustNil(t, err)
	Equal(t, string(got), string(msg))

	// DialUnix on a stream network still returns the LinkBuffer connection.
	dir := t.TempDir()
	addr := filepath.Join(dir, "stream.sock")
	nl, err := CreateListener("unix", addr)
	MustNil(t, err)
	defer nl.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, _ := nl.Accept()
			if c == nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			buf := make([]byte, 4)
			_, _ = c.Read(buf)
			_ = c.Close()
			return
		}
	}()
	uc, err := DialUnix("unix", nil, &UnixAddr{UnixAddr: net.UnixAddr{Name: addr, Net: "unix"}})
	MustNil(t, err)
	var _ *UnixConnection = uc
	_, err = uc.Write([]byte("data"))
	MustNil(t, err)
	MustNil(t, uc.Close())
	<-done
}
