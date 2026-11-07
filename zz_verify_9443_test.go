//go:build !windows

// Independent acceptance probe for precheck 9443 (non-blocking FlushAsync).
// Written by the reviewer; reuses only the raw socket pair helper.
package netpoll

import (
	"bytes"
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

func verify9443Read(t *testing.T, fd int, want int, timeout time.Duration) []byte {
	t.Helper()
	out := make([]byte, 0, want)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	for len(out) < want && time.Now().Before(deadline) {
		n, err := syscall.Read(fd, buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			continue
		}
		if err != nil && err != syscall.EAGAIN && err != syscall.EWOULDBLOCK {
			t.Fatalf("peer read: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	if len(out) < want {
		t.Fatalf("peer received %d bytes, want %d", len(out), want)
	}
	return out
}

func TestVerify9443KernelAcceptedCompletesTicket(t *testing.T) {
	wc, rfd, cleanup := rawSockPairConn(t)
	defer cleanup()
	if err := syscall.SetNonblock(rfd, true); err != nil {
		t.Fatalf("setnonblock: %v", err)
	}

	payload := bytes.Repeat([]byte{0x5a}, 4096)
	if _, err := wc.WriteBinary(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	ticket, err := wc.FlushAsync()
	if err != nil {
		t.Fatalf("FlushAsync: %v", err)
	}
	// The peer has not read anything yet: the ticket must still finish once the
	// local kernel accepted the bytes.
	deadline := time.Now().Add(2 * time.Second)
	for !isTicketDone(ticket) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !isTicketDone(ticket) {
		t.Fatal("ticket did not finish after the kernel accepted the bytes")
	}
	if err := ticket.Wait(nil); err != nil {
		t.Fatalf("finished ticket reported an error: %v", err)
	}
	got := verify9443Read(t, rfd, len(payload), 3*time.Second)
	if !bytes.Equal(got, payload) {
		t.Fatal("peer received different bytes than submitted")
	}

	// mallocs that were never submitted must not be sent
	unsubmitted, err := wc.Malloc(32)
	if err != nil {
		t.Fatalf("malloc: %v", err)
	}
	for i := range unsubmitted {
		unsubmitted[i] = 0xcd
	}
	time.Sleep(20 * time.Millisecond)
	n, rerr := syscall.Read(rfd, make([]byte, 64))
	if n > 0 {
		t.Fatalf("%d unsubmitted malloc bytes were sent", n)
	}
	if rerr != syscall.EAGAIN && rerr != syscall.EWOULDBLOCK {
		t.Fatalf("unexpected read result n=%d err=%v", n, rerr)
	}

	// submitting them afterwards covers exactly those bytes
	ticket2, err := wc.FlushAsync()
	if err != nil {
		t.Fatalf("second FlushAsync: %v", err)
	}
	if err := ticket2.Wait(nil); err != nil {
		t.Fatalf("second ticket: %v", err)
	}
	got2 := verify9443Read(t, rfd, 32, 3*time.Second)
	if !bytes.Equal(got2, bytes.Repeat([]byte{0xcd}, 32)) {
		t.Fatal("submitted malloc bytes were not delivered intact")
	}
}

func TestVerify9443CloseFailsPendingTicket(t *testing.T) {
	wc, rfd, cleanup := rawSockPairConn(t)
	defer cleanup()
	if err := syscall.SetNonblock(rfd, true); err != nil {
		t.Fatalf("setnonblock: %v", err)
	}

	// fill the socket send buffer so a ticket cannot complete before Close
	var pending FlushTicket
	for i := 0; i < 256 && pending == nil; i++ {
		chunk := bytes.Repeat([]byte{byte(i%251) + 1}, 64*1024)
		if _, err := wc.WriteBinary(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		ticket, err := wc.FlushAsync()
		if err != nil {
			t.Fatalf("FlushAsync %d: %v", i, err)
		}
		if !isTicketDone(ticket) {
			pending = ticket
		}
	}
	if pending == nil {
		t.Fatal("could not create a pending ticket with a blocked peer")
	}

	// a cancelled wait only abandons that wait
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := pending.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled wait returned %v, want context deadline", err)
	}

	if err := wc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !isTicketDone(pending) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !isTicketDone(pending) {
		t.Fatal("Close did not end the pending ticket")
	}
	err := pending.Wait(nil)
	if err == nil {
		t.Fatal("pending ticket reported success after the connection closed")
	}
	var fa *FlushAsyncError
	if !errors.As(err, &fa) {
		t.Fatalf("pending ticket error = %T %v, want FlushAsyncError", err, err)
	}
	if fa.SentPrefix < 0 {
		t.Fatalf("SentPrefix = %d, want >= 0", fa.SentPrefix)
	}
}
