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
	"sync/atomic"
	"unsafe"
)

// registrationToken is the immutable identity of one epoll registration.
// Its address is stored into the epoll_event data area and is returned
// unchanged by epoll_wait. A fresh token is minted on every EPOLL_CTL_ADD
// (including re-adding the same fd during live connection migration), and the
// operator publishes it atomically.
//
// This makes stale events provably harmless:
//   - an event that epoll_wait already returned, but which is processed only
//     after the registration was detached/migrated, still carries the old
//     token and fails the token comparison in getOperator;
//   - when the fd number is later reused by a brand new connection, the stale
//     event resolves through its own old token instead of the fd number, so it
//     can never reach the new connection.
//
// The atomic publication also gives the cross-goroutine handoff (Control in
// one goroutine, handler in the poller goroutine) a happens-before edge that
// the race detector understands, replacing the previous fd->operator map.
type registrationToken struct {
	// op is read by the poller goroutine after the token traveled through the
	// kernel inside epoll event data; the atomic load pairs with the atomic
	// store in mintToken and gives the cross-goroutine handoff a happens-before
	// edge (the kernel path itself is invisible to the race detector).
	op  unsafe.Pointer // *FDOperator
	gen uint64
}

// mintToken creates a fresh registration token for op and publishes it.
func mintToken(op *FDOperator) *registrationToken {
	gen := atomic.AddUint64(&op.gen, 1)
	token := &registrationToken{gen: gen}
	atomic.StorePointer(&token.op, unsafe.Pointer(op))
	atomic.StorePointer(&op.token, unsafe.Pointer(token))
	return token
}

// currentToken returns the token the operator is currently registered with.
func currentToken(op *FDOperator) *registrationToken {
	return (*registrationToken)(atomic.LoadPointer(&op.token))
}

// invalidateToken marks the current registration dead. Any event carrying the
// previous token will afterwards be rejected by getOperator.
func invalidateToken(op *FDOperator) {
	atomic.StorePointer(&op.token, nil)
}

// setEventToken writes the token into an epoll event's 8-byte data area.
func setEventToken(evt *epollevent, token *registrationToken) {
	*(*unsafe.Pointer)(evt.GetDataPtr()) = unsafe.Pointer(token)
}

// getOperator resolves an epoll event to its FDOperator, returning nil for any
// event whose token is no longer (or never was) the operator's current one.
func (p *defaultPoll) getOperator(fd int, ptr unsafe.Pointer) *FDOperator {
	token := *(**registrationToken)(ptr)
	if token == nil {
		return nil
	}
	op := (*FDOperator)(atomic.LoadPointer(&token.op))
	if op == nil {
		return nil
	}
	// Reject events from a previous registration: stale events of a migrated
	// connection, and events whose fd number has been reused.
	if currentToken(op) != token {
		return nil
	}
	return op
}
