//go:build linux

// Independent acceptance probe for precheck 9452 (AF_UNIX SOCK_SEQPACKET
// connection with SCM_RIGHTS passing). Written by the reviewer.
package netpoll

import (
	"bytes"
	"syscall"
	"testing"
	"time"
)

func verifyOpenDevNull(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	return fd
}

func verifyCloExec(t *testing.T, fd int) bool {
	t.Helper()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_GETFD), 0)
	if errno != 0 {
		t.Fatalf("fcntl(%d): %v", fd, errno)
	}
	return flags&uintptr(syscall.FD_CLOEXEC) != 0
}

func TestVerify9452MessageBoundariesAndFDs(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	a, err := NewUnixPacketConnection(fds[0], nil)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	b, err := NewUnixPacketConnection(fds[1], nil)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}
	defer a.Close()
	defer b.Close()

	one := []byte{0x01}
	two := bytes.Repeat([]byte{0x02}, 255)
	three := bytes.Repeat([]byte{0x03}, 4096)
	devNull := verifyOpenDevNull(t)
	defer syscall.Close(devNull)

	if err := a.SendPacket(one, nil); err != nil {
		t.Fatalf("send 1: %v", err)
	}
	if err := a.SendPacket(two, []int{devNull}); err != nil {
		t.Fatalf("send 2: %v", err)
	}
	if err := a.SendPacket(three, nil); err != nil {
		t.Fatalf("send 3: %v", err)
	}

	wants := [][]byte{one, two, three}
	wantFDs := []int{0, 1, 0}
	_ = b.SetReadTimeout(3 * time.Second)
	for i, want := range wants {
		p, err := b.ReceivePacket()
		if err != nil {
			t.Fatalf("receive %d: %v", i, err)
		}
		if p == nil {
			t.Fatalf("receive %d: nil packet", i)
		}
		if !bytes.Equal(p.Payload, want) {
			t.Fatalf("packet %d payload got %d bytes %q..., want %d bytes", i, len(p.Payload), firstBytes(p.Payload, 4), len(want))
		}
		if p.NumFDs() != wantFDs[i] {
			t.Fatalf("packet %d carries %d fds, want %d", i, p.NumFDs(), wantFDs[i])
		}
		if wantFDs[i] == 1 {
			fd, err := p.TakeFD(0)
			if err != nil {
				t.Fatalf("TakeFD: %v", err)
			}
			if !verifyCloExec(t, fd) {
				t.Fatalf("received fd %d is not close-on-exec", fd)
			}
			if _, err := p.TakeFD(0); err == nil {
				t.Fatal("TakeFD accepted the same index twice")
			}
			_ = syscall.Close(fd)
		}
		if err := p.Release(); err != nil {
			t.Fatalf("release %d: %v", i, err)
		}
		if err := p.Release(); err != nil {
			t.Fatalf("second release %d: %v", i, err)
		}
	}
}

func firstBytes(p []byte, n int) []byte {
	if len(p) < n {
		return p
	}
	return p[:n]
}

func TestVerify9452CloseWakesReceiver(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	a, err := NewUnixPacketConnection(fds[0], nil)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	b, err := NewUnixPacketConnection(fds[1], nil)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, rerr := b.ReceivePacket()
		done <- rerr
	}()
	time.Sleep(50 * time.Millisecond)
	if err := a.Close(); err != nil {
		t.Fatalf("close a: %v", err)
	}
	select {
	case rerr := <-done:
		if rerr == nil {
			t.Fatal("ReceivePacket returned a packet after the peer closed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not wake the blocked ReceivePacket")
	}
	_ = b.Close()
}
