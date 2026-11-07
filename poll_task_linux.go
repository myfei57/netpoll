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
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
)

// pollFunc is a unit of work executed serially by the poller goroutine.
type pollFunc func()

// errPollClosed is returned when a task cannot be handed to a poller that is
// no longer running.
var errPollClosed = errors.New("poller has been closed")

// currentGoid returns the id of the current goroutine. It parses the stack
// header; it is only used on the rare migration control path.
func currentGoid() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	// header looks like "goroutine 123 [..."
	b := buf[:n]
	if len(b) < 12 {
		return 0
	}
	b = b[10:] // skip "goroutine "
	end := 0
	for end < len(b) && b[end] >= '0' && b[end] <= '9' {
		end++
	}
	id, _ := strconv.ParseInt(string(b[:end]), 10, 64)
	return id
}

// onPollerGoroutine reports whether the caller is running inside p.Wait.
func (p *defaultPoll) onPollerGoroutine() bool {
	goid := atomic.LoadInt64(&p.goid)
	return goid != 0 && goid == currentGoid()
}

// submit enqueues fn to be executed by the poller goroutine (between two event
// batches, hence with no in-flight event callback) and blocks until it has run.
// If the caller is itself the poller goroutine (e.g. migration initiated from a
// poller callback), fn is executed inline so the poller never blocks waiting
// for itself.
func (p *defaultPoll) submit(fn pollFunc) error {
	if p.onPollerGoroutine() {
		fn()
		return nil
	}
	done := make(chan struct{})
	p.taskMu.Lock()
	p.tasks = append(p.tasks, func() {
		fn()
		close(done)
	})
	p.taskMu.Unlock()

	if err := p.Trigger(); err != nil && !p.isClosed() {
		// Trigger can only fail on a broken eventfd; surface it instead of
		// blocking forever.
		return err
	}
	select {
	case <-done:
		return nil
	case <-p.closedCh:
		return errPollClosed
	}
}

// runTasks executes all pending tasks. It is called on the poller goroutine
// only after the current event batch has been fully processed.
func (p *defaultPoll) runTasks() {
	p.taskMu.Lock()
	tasks := p.tasks
	p.tasks = nil
	p.taskMu.Unlock()
	for i := range tasks {
		tasks[i]()
	}
}

// deferTask queues fn for a later poller iteration and wakes the loop. It is
// used when a task cannot finish right away (e.g. an external goroutine still
// holds the operator's do-state): the poller must not spin waiting for it.
func (p *defaultPoll) deferTask(fn pollFunc) {
	p.taskMu.Lock()
	p.tasks = append(p.tasks, fn)
	p.taskMu.Unlock()
	_ = p.Trigger()
}

// detachMigrated removes op from this poller without touching its connection
// state, and invalidates the registration token so that any late event is a
// no-op. It must run on the poller goroutine (via submit).
func (p *defaultPoll) detachMigrated(op *FDOperator) error {
	var evt epollevent
	setEventToken(&evt, currentToken(op))
	if err := EpollCtl(p.fd, syscall.EPOLL_CTL_DEL, op.FD, &evt); err != nil && err != syscall.ENOENT {
		return err
	}
	invalidateToken(op)
	return nil
}

// registerMigrated adds op to this poller with a fresh registration token and
// the requested read/write interest. It may be invoked for both the initial
// move to the destination poller and the rollback to the source poller. When
// invoked through submit it is serialized with event processing.
func (p *defaultPoll) registerMigrated(op *FDOperator, writable bool) error {
	op.inuse()
	var evt epollevent
	setEventToken(&evt, mintToken(op))
	events := syscall.EPOLLIN | syscall.EPOLLRDHUP | syscall.EPOLLERR
	if writable {
		events |= syscall.EPOLLOUT
	}
	return EpollCtl(p.fd, syscall.EPOLL_CTL_ADD, op.FD, &evt)
}

// retireOperator releases an operator that is guaranteed not to be referenced
// by any event of this poller anymore. It must run on the poller goroutine;
// the actual return to the allocation pool happens in Wait's opcache.free().
//
// If an external caller still holds the operator's do()-state (Release,
// IsHealthyForReuse), the recycle is deferred to a later iteration instead of
// spinning on the poller goroutine.
func (p *defaultPoll) retireOperator(op *FDOperator) {
	if atomic.LoadInt32(&op.state) == 0 {
		// already retired
		return
	}
	if currentToken(op) != nil {
		invalidateToken(op)
	}
	if !p.opcache.recycle(op) {
		p.deferTask(func() {
			p.retireOperator(op)
		})
	}
}
