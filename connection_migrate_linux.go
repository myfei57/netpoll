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
	"sync/atomic"
)

// Live connection migration between epoll pollers.
//
// Protocol (all buffer-touching steps are serialized with event processing):
//
//	src poller goroutine: [re-check alive] -> EPOLL_CTL_DEL -> invalidate token
//	caller goroutine:      allocate new operator -> publish it -> EPOLL_CTL_ADD dst
//	src poller goroutine: retire the old operator (returned to pool only here)
//
// Every registration has its own token carried in epoll event data, so events
// epoll_wait already returned but which are processed late become no-ops once
// the token is replaced; fd number reuse cannot redirect them to a new
// connection either. The old operator is recycled on the source poller only
// after a full event batch boundary, i.e. strictly after any event that could
// still reference it.
//
// Migration never closes nor recreates the socket: inputBuffer/outputBuffer,
// read/write waiters and deadlines all stay with the connection.

var (
	// ErrMigrationTarget is returned when the destination poller is nil, does
	// not belong to the connection's manager, or has already been closed.
	ErrMigrationTarget = errors.New("netpoll: migration target is not an active poller of the same manager")

	// ErrMigrationInProgress is returned when another migration of the same
	// connection has not finished yet.
	ErrMigrationInProgress = errors.New("netpoll: connection migration already in progress")

	// ErrMigrationRolledBack is returned when the destination registration
	// failed but the connection was successfully re-registered on its original
	// poller. The connection remains usable; its ownership did not change.
	ErrMigrationRolledBack = errors.New("netpoll: connection migration rolled back to the original poller")
)

// Test-only seams. They are nil outside of migration tests.
var (
	// migrateHookAfterDetach runs on the migration caller after the source
	// poller has detached and quiesced the connection, before destination
	// registration (i.e. after teardown became committed).
	migrateHookAfterDetach func(conn *connection)
	// migrateHookBeforeRegister is consulted immediately before adding the
	// operator to the destination poller. Returning an error simulates a
	// failed new registration.
	migrateHookBeforeRegister func(target *defaultPoll) error
)

// MigrateConnection moves a live connection from its current epoll poller to
// target without closing or re-establishing the socket. The connection keeps
// its unconsumed input, unsent output, read/write waiters and deadlines; data
// already buffered is processed on the new poller without the peer resending.
//
// target must be another active poller of the same manager. A closed target is
// rejected, and migrating to the poller that already owns the connection is an
// idempotent no-op. No automatic rebalancing/scaling policy is implemented;
// the caller chooses the target.
//
// A ctx error observed before the migration is accepted leaves ownership
// untouched. Once the old registration teardown has started, ctx cancellation
// is ignored: the call either completes the new registration or restores the
// old one, so it can never leave the connection monitored by neither poller.
//
// If the new registration fails, the connection is restored on the original
// poller (ErrMigrationRolledBack) or, when restoration is impossible, closed
// deterministically with all waiters released.
//
// Linux epoll only.
func MigrateConnection(ctx context.Context, conn Connection, target Poll) error {
	return pollmanager.migrateConnection(ctx, conn, target)
}

func (m *manager) migrateConnection(ctx context.Context, connI Connection, target Poll) error {
	c, ok := connI.(*connection)
	if !ok || c == nil {
		return ErrMigrationTarget
	}
	oldOp := c.getOperator()
	if oldOp == nil || !c.IsActive() || c.status(closing) != 0 {
		return Exception(ErrConnClosed, "when migrate")
	}
	src, ok := oldOp.poll.(*defaultPoll)
	if !ok || src == nil || !m.isActivePoll(src) {
		// source gone: nothing safe to migrate.
		return Exception(ErrConnClosed, "when migrate")
	}
	dst, ok := target.(*defaultPoll)
	if !ok || dst == nil || !m.isActivePoll(dst) {
		return ErrMigrationTarget
	}
	if src == dst {
		// idempotent: identical target means ownership is already as desired
		return nil
	}
	// A cancellation observed before accepting the request changes nothing.
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	// Accept: serialize migrations per connection.
	if !atomic.CompareAndSwapInt32(&c.migrating, 1, 1) {
		return ErrMigrationInProgress
	}
	c.migMu.Lock()

	// Re-validate under the exclusive migration lock.
	if !c.IsActive() || c.status(closing) != 0 || c.getOperator() != oldOp {
		c.migMu.Unlock()
		atomic.StoreInt32(&c.migrating, 0)
		return Exception(ErrConnClosed, "when migrate")
	}
	if !m.isActivePoll(dst) {
		c.migMu.Unlock()
		atomic.StoreInt32(&c.migrating, 0)
		return ErrMigrationTarget
	}

	result := c.migrateLocked(src, dst, oldOp)

	c.migMu.Unlock()
	atomic.StoreInt32(&c.migrating, 0)

	switch result {
	case migrateOK:
		// Re-arm processing using the new owner: pending write interest, and
		// buffered input whose consumer may already be waiting.
		c.resumeAfterMigration()
		return nil
	case migrateClosed:
		// Teardown started but neither the new nor the old registration could
		// be kept. Close deterministically ourselves unless a racing Close is
		// already taking care of it.
		c.finishCloseAfterMigration()
		return Exception(ErrConnClosed, "when migrate")
	default: // migrateRolledBack
		// Connection is usable again on the original poller.
		c.resumeAfterMigration()
		return ErrMigrationRolledBack
	}
}

type migrateResult int

const (
	migrateOK migrateResult = iota
	migrateRolledBack
	migrateClosed
)

// migrateLocked runs the transfer while c.migMu is held. It never blocks
// waiting for this connection's operator state on a poller goroutine: all
// source-side steps execute through the source poller's serialized task queue.
func (c *connection) migrateLocked(src, dst *defaultPoll, oldOp *FDOperator) migrateResult {
	// ---- Phase A: quiesce & detach on the source poller -----------------
	// The task runs between two event batches, so no readv/sendmsg for this
	// operator is in flight and every event already dequeued for it is done.
	var (
		writable  bool
		detachErr error
		closed    bool
	)
	detachTask := func() {
		if !c.IsActive() || c.status(closing) != 0 {
			closed = true
			return
		}
		writable = !c.outputBuffer.IsEmpty()
		detachErr = src.detachMigrated(oldOp)
	}
	if err := src.submit(detachTask); err != nil || closed {
		// Source poller is gone, or a close won before teardown. No ownership
		// change happened; the (possibly blocked) close path finalizes.
		return migrateClosed
	}
	if detachErr != nil {
		// Unexpected detach error while nothing was removed: the connection is
		// still fully owned by src. Surface a rollback-style failure while it
		// remains monitored.
		return migrateRolledBack
	}

	// From here on teardown is committed: ctx is irrelevant and we must either
	// register on dst or restore the registration on src.
	if migrateHookAfterDetach != nil {
		migrateHookAfterDetach(c)
	}

	// ---- Phase B: register a fresh operator on the destination ---------
	newOp := c.newOperator(dst)
	c.setOperator(newOp)

	var addErr error
	if migrateHookBeforeRegister != nil {
		addErr = migrateHookBeforeRegister(dst)
	}
	if addErr == nil {
		addErr = dst.registerMigrated(newOp, writable)
	}
	if addErr != nil {
		// Restore ownership on the source poller before releasing the lock.
		c.setOperator(oldOp)
		// The new operator never became an owner: return it to the destination
		// cache on the destination poller (it may be state 0 if the failure was
		// injected before inuse, or state 1 after a failed epoll_ctl).
		_ = dst.submit(func() {
			if currentToken(newOp) != nil {
				invalidateToken(newOp)
			}
			switch atomic.LoadInt32(&newOp.state) {
			case 0:
				newOp.reset()
				dst.opcache.appendFreelist(newOp)
			default:
				if !dst.opcache.recycle(newOp) {
					dst.deferTask(func() { dst.retireOperator(newOp) })
				}
			}
		})
		restoreErr := errMigrationRestoreFailed
		_ = src.submit(func() {
			restoreErr = src.registerMigrated(oldOp, writable)
		})
		if restoreErr != nil {
			// submit failed (source closed) or re-ADD failed: the fd must end
			// up definitively closed.
			return migrateClosed
		}
		return migrateRolledBack
	}

	// ---- Phase C: retire the old operator on the source poller ---------
	if err := src.submit(func() {
		src.retireOperator(oldOp)
	}); err != nil {
		// The new registration is live on dst; the source disappeared before
		// recycling the old operator. Invalidate it and keep the connection
		// usable on its unique owner.
		invalidateToken(oldOp)
	}
	return migrateOK
}

var errMigrationRestoreFailed = errors.New("migration restore failed")

// resumeAfterMigration restarts interest processing after a successful move or
// rollback. Called without the migration lock.
func (c *connection) resumeAfterMigration() {
	// Write side: the interest may need upgrading if outputBuffer gained data
	// during the transfer (or if registration had to fall back to read-only).
	// Never signal writeTrigger ourselves: only the poller's outputAck->rw2r
	// path knows that the buffer actually drained, so a blocked Flush cannot be
	// completed prematurely. Level-triggered EPOLLOUT then drives the drain.
	if !c.outputBuffer.IsEmpty() {
		if err := c.controlOperator(PollR2RW); err != nil {
			// Connection-level close will surface the error to waiters.
			logger.Printf("NETPOLL: re-arm write interest after migrate failed: %v", err)
		}
	}
	// Read side: data might already be in the application buffer. There is at
	// most one OnRequest (processing lock), and a blocking reader waits on
	// readTrigger; make both observe the buffered bytes without peer resend.
	if c.inputBuffer.Len() > 0 {
		if c.inputBuffer.Len() >= int(atomic.LoadInt64(&c.waitReadSize)) {
			c.triggerRead(nil)
		}
		c.onRequest()
	}
}

// finishCloseAfterMigration ends the connection when it cannot be registered
// on any poller. A racing user/poller close blocked on the migration lock will
// perform the finalization itself; otherwise we drive a user-style close here.
func (c *connection) finishCloseAfterMigration() {
	c.triggerRead(Exception(ErrConnClosed, "when migrate"))
	c.triggerWrite(Exception(ErrConnClosed, "when migrate"))
	if c.status(closing) == 0 {
		_ = c.onClose()
		return
	}
	// The winning closer is inside or about to enter closeCallback and will
	// detach/free the operator and close the fd after the migration lock was
	// released. Nothing else to do.
}
