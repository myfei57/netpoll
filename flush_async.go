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

package netpoll

import "context"

// FlushTicket represents one non-blocking submission returned by Writer.FlushAsync.
//
// A ticket covers an absolute prefix of the connection output stream: every
// byte that was committed up to (and including) its FlushAsync call. The
// ticket is finished successfully once the send interface of the LOCAL kernel
// has accepted the last byte of that prefix. That neither waits for bytes
// committed by later Flush/FlushAsync calls, nor means the peer application
// has read the bytes, nor means the peer TCP stack has acknowledged them.
//
// Multiple tickets may cover different (nested) prefixes. An earlier ticket
// finishes as soon as its own boundary is accepted, even if the writer keeps
// submitting more data afterwards.
//
// Tickets are channel based, so no per-ticket waiting goroutine is required
// and no user code runs on the poller goroutine. Cancelling the context of a
// Wait call only abandons that single wait: it never withdraws already
// committed output and never releases memory referenced by a WriteBinary call
// ahead of schedule.
type FlushTicket interface {
	// Done returns a channel that is closed exactly once, when the ticket
	// finishes -- either after all covered bytes were accepted by the local
	// kernel, or because the connection terminated beforehand (in which case
	// Wait reports the cause).
	Done() <-chan struct{}

	// Wait blocks until the ticket finishes or ctx is done.
	// A non-nil ctx.Err() result only cancels this wait; the committed bytes
	// are still sent and the ticket may finish later.
	// A nil context waits without cancellation.
	Wait(ctx context.Context) error
}

// FlushAsyncError ends a FlushTicket when the connection stops sending before
// every covered byte is accepted by the local kernel: the connection was
// closed locally, the peer hung up, or a send syscall failed.
//
// It reports the length of the covered prefix that had already been accepted,
// so callers can distinguish the bytes that really left the process from the
// ones that were lost with the connection.
type FlushAsyncError struct {
	// Cause is why the ticket ended early.
	Cause error

	// SentPrefix is the number of bytes covered by this ticket that the
	// local kernel send interface had accepted when the ticket ended.
	// It never exceeds the ticket's committed length.
	SentPrefix int64
}

// Error implements error.
func (e *FlushAsyncError) Error() string {
	if e == nil || e.Cause == nil {
		return "netpoll: flush async ticket ended before completion"
	}
	return "netpoll: flush async ticket ended before completion: " + e.Cause.Error()
}

// Unwrap supports errors.Is/errors.As on the cause.
func (e *FlushAsyncError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// flushTicket is the connection-backed FlushTicket implementation.
// It is linked into the connection ticket queue and unlinked on its single
// terminal transition (success or failure), so retaining a finished ticket
// never keeps later tickets alive.
type flushTicket struct {
	// target is the absolute committed position covered by this ticket.
	// It finishes successfully once sent >= target.
	target int64

	// next links tickets in submission order; it is cleared when the ticket
	// is dequeued, breaking any reference a user-held finished ticket would
	// otherwise keep on the following tickets.
	next *flushTicket

	done   chan struct{}
	result error // written before close(done); only read after it
}

// Done implements FlushTicket.
func (t *flushTicket) Done() <-chan struct{} { return t.done }

// Wait implements FlushTicket.
func (t *flushTicket) Wait(ctx context.Context) error {
	if ctx == nil {
		<-t.done
		return t.result
	}
	select {
	case <-t.done:
		return t.result
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closedFlushChan is shared by every already finished ticket.
var closedFlushChan = make(chan struct{})

func init() {
	close(closedFlushChan)
}

// readyFlushTicket is returned by submissions whose covered prefix is already
// fully accepted (an empty FlushAsync, or any FlushAsync on a writer that has
// no kernel output, such as a bare LinkBuffer).
type readyFlushTicket struct{}

// Done implements FlushTicket.
func (readyFlushTicket) Done() <-chan struct{} { return closedFlushChan }

// Wait implements FlushTicket.
func (readyFlushTicket) Wait(context.Context) error { return nil }

var sharedReadyFlushTicket FlushTicket = readyFlushTicket{}

// flushTicketTracker owns the absolute send accounting of a single connection
// and the queue of its unfinished tickets.
//
// Every method MUST be called while holding the connection's outputMu, which
// is the single exclusion point shared by the writer goroutine (direct
// sendmsg, partial write) and the poller goroutine (outputs/outputAck after
// EAGAIN). Bytes are acknowledged in strict FIFO order, so direct sends,
// poller partial writes and poller outputAck all advance one and the same
// counter, and a single write event can never finish a ticket past the real
// accepted position.
//
// A tracker is embedded in a connection object and is never reused. When the
// operator/fd is recycled a fresh connection -- with a fresh tracker -- is
// bound, and old tickets cannot be completed by the new connection's output
// acknowledgements.
type flushTicketTracker struct {
	// committed is the absolute number of bytes published out of the output
	// buffer by Flush/FlushAsync; sent is the absolute number of bytes the
	// local kernel send interface accepted. committed-sent always equals the
	// pending output length.
	committed int64
	sent      int64

	// head/tail bound the FIFO queue of unfinished tickets.
	head *flushTicket
	tail *flushTicket
}

// register enqueues a ticket covering the absolute committed position target.
func (q *flushTicketTracker) register(target int64) *flushTicket {
	t := &flushTicket{target: target, done: make(chan struct{})}
	if q.tail == nil {
		q.head = t
	} else {
		q.tail.next = t
	}
	q.tail = t
	return t
}

// advance records n newly kernel-accepted bytes -- a direct sendmsg, a poller
// partial write or a poller outputAck after EAGAIN -- and finishes every
// ticket whose covered prefix is fully accepted.
func (q *flushTicketTracker) advance(n int64) {
	if n <= 0 {
		return
	}
	q.sent += n
	for q.head != nil && q.head.target <= q.sent {
		t := q.head
		q.head = t.next
		t.next = nil
		if q.head == nil {
			q.tail = nil
		}
		close(t.done)
	}
}

// fail finishes every ticket still queued when the connection terminates,
// reporting the accepted prefix of each ticket. Tickets completed beforehand
// are already detached and can never be turned into failures. It is safe to
// call repeatedly (close, hangup and send error races): each ticket is
// dequeued exactly once and therefore ended exactly once.
func (q *flushTicketTracker) fail(cause error) {
	for q.head != nil {
		t := q.head
		q.head = t.next
		t.next = nil
		prefix := q.sent
		if prefix > t.target {
			prefix = t.target
		}
		t.result = &FlushAsyncError{Cause: cause, SentPrefix: prefix}
		close(t.done)
	}
	q.tail = nil
}
