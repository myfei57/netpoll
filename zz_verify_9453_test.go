//go:build linux

// Independent acceptance probe for precheck 9453 (live connection migration).
// Written by the reviewer. It builds its own TCP pair because the model's own
// test helper closes the duplicated fd before handing it to the connection.
package netpoll

import (
	"context"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func verify9453TCPPair(t *testing.T) (*connection, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
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

	file, err := serverTCP.File() // duplicate of the accepted fd
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	_ = file.Close()
	_ = serverTCP.Close()
	if err != nil {
		t.Fatalf("dup fd: %v", err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatalf("setnonblock: %v", err)
	}

	c := new(connection)
	nfd := &netFD{fd: fd, network: "tcp", isStream: true, localAddr: localAddr, remoteAddr: remoteAddr}
	if err := c.init(nfd, &options{}); err != nil {
		t.Fatalf("init connection: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	return c, peer
}

func verify9453WaitRead(t *testing.T, c *connection, n int, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for c.Reader().Len() < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.Reader().Len() < n {
		t.Fatalf("only %d buffered bytes, want %d", c.Reader().Len(), n)
	}
	p, err := c.Next(n)
	if err != nil {
		t.Fatalf("next(%d): %v", n, err)
	}
	return p
}

func TestVerify9453MigrationKeepsTCPFlow(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, peer := verify9453TCPPair(t)
	current := ownerPoll(t, c)
	target := otherPoll(polls, current)
	if target == nil {
		t.Fatal("no second poller")
	}
	fdBefore := c.getOperator().FD

	if _, err := peer.Write([]byte("before")); err != nil {
		t.Fatalf("peer write before: %v", err)
	}
	if got := verify9453WaitRead(t, c, 6, 3*time.Second); string(got) != "before" {
		t.Fatalf("pre-migration read = %q", got)
	}
	if err := c.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := MigrateConnection(ctx, c, target); err != nil {
		t.Fatalf("MigrateConnection: %v", err)
	}
	if ownerPoll(t, c) != target {
		t.Fatal("connection still owned by the old poller after a successful migration")
	}
	if c.getOperator().FD != fdBefore {
		t.Fatalf("fd changed across migration: %d -> %d", fdBefore, c.getOperator().FD)
	}
	if err := MigrateConnection(ctx, c, target); err != nil {
		t.Fatalf("idempotent migration returned error: %v", err)
	}

	if _, err := peer.Write([]byte("after")); err != nil {
		t.Fatalf("peer write after: %v", err)
	}
	if got := verify9453WaitRead(t, c, 5, 3*time.Second); string(got) != "after" {
		t.Fatalf("post-migration read = %q", got)
	}

	if _, err := c.Write([]byte("pong")); err != nil {
		t.Fatalf("write after migration: %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	rb := make([]byte, 4)
	if _, err := io.ReadFull(peer, rb); err != nil || string(rb) != "pong" {
		t.Fatalf("peer read after migration = %q, %v", rb, err)
	}
}

func TestVerify9453RejectsForeignOrCancelledTarget(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, _ := verify9453TCPPair(t)
	current := ownerPoll(t, c)
	target := otherPoll(polls, current)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := MigrateConnection(cancelled, c, target); err == nil {
		t.Fatal("migration accepted a cancelled context")
	}
	if ownerPoll(t, c) != current {
		t.Fatal("cancelled migration changed ownership")
	}

	other := newManager(1)
	foreign := other.Pick()
	if err := MigrateConnection(context.Background(), c, foreign); err == nil {
		t.Fatal("migration accepted a poller outside the active manager")
	}
	if ownerPoll(t, c) != current {
		t.Fatal("foreign-target migration changed ownership")
	}
	_ = other.Close()
}
