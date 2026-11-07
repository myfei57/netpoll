//go:build linux

// Independent acceptance probe for precheck 9453 (live connection migration).
// Written by the reviewer, not by the model: it reuses only the model's test
// harness (controlled manager + real TCP pair) and asserts user-observable
// behavior through the public entry point.
package netpoll

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestVerify9453MigrationKeepsTCPFlow(t *testing.T) {
	_, polls := newMigrateEnv(t, 2)
	c, peer := tcpMigratePair(t, nil)

	current := ownerPoll(t, c)
	target := otherPoll(polls, current)
	if target == nil {
		t.Fatal("no second poller")
	}
	fdBefore := c.getOperator().FD

	// data written before the migration is buffered and readable afterwards
	if _, err := peer.Write([]byte("before")); err != nil {
		t.Fatalf("peer write before: %v", err)
	}
	waitUntil(t, 2*time.Second, "pre-migration bytes", func() bool { return c.Reader().Len() >= 6 })
	if got, err := c.Next(6); err != nil || string(got) != "before" {
		t.Fatalf("read before migration = %q, %v", got, err)
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

	// same target is idempotent
	if err := MigrateConnection(ctx, c, target); err != nil {
		t.Fatalf("idempotent migration returned error: %v", err)
	}

	// the peer keeps sending on the same socket, the migrated connection reads it
	if _, err := peer.Write([]byte("after")); err != nil {
		t.Fatalf("peer write after: %v", err)
	}
	waitUntil(t, 3*time.Second, "post-migration bytes", func() bool { return c.Reader().Len() >= 5 })
	if got, err := c.Next(5); err != nil || string(got) != "after" {
		t.Fatalf("read after migration = %q, %v", got, err)
	}

	// and it can still write back through the new poller
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
	c, _ := tcpMigratePair(t, nil)
	current := ownerPoll(t, c)
	target := otherPoll(polls, current)

	// cancelled context before the migration is accepted must not move ownership
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := MigrateConnection(cancelled, c, target); err == nil {
		t.Fatal("migration accepted a cancelled context")
	}
	if ownerPoll(t, c) != current {
		t.Fatal("cancelled migration changed ownership")
	}

	// a poller from another manager must be rejected
	other := newManager(1)
	if _, ok := other.Pick().(*defaultPoll); !ok {
		t.Fatal("unexpected poll type")
	}
	foreign := other.Pick()
	if err := MigrateConnection(context.Background(), c, foreign); err == nil {
		t.Fatal("migration accepted a poller outside the active manager")
	}
	if ownerPoll(t, c) != current {
		t.Fatal("foreign-target migration changed ownership")
	}
	_ = other.Close()
}
