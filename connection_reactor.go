// Copyright 2022 CloudWeGo Authors
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

//go:build !windows

package netpoll

import (
	"sync/atomic"
)

// ------------------------------------------ implement FDOperator ------------------------------------------

// onHup means close by poller.
func (c *connection) onHup(p Poll) error {
	if !c.closeBy(poller) {
		return nil
	}
	// The operator is detached from this point on, so no further bytes can
	// be accepted; unfinished tickets end now (already completed ones are
	// unaffected).
	c.failFlushTickets(Exception(ErrEOF, "peer close"))
	c.triggerRead(Exception(ErrEOF, "peer close"))
	c.triggerWrite(Exception(ErrConnClosed, "peer close"))

	// call Disconnect callback first
	c.onDisconnect()

	// It depends on closing by user if OnConnect and OnRequest is nil, otherwise it needs to be released actively.
	// It can be confirmed that the OnRequest goroutine has been exited before closeCallback executing,
	// and it is safe to close the buffer at this time.
	onConnect := c.onConnectCallback.Load()
	onRequest := c.onRequestCallback.Load()
	needCloseByUser := onConnect == nil && onRequest == nil
	if !needCloseByUser {
		// already PollDetach when call OnHup
		c.closeCallback(true, false)
	}
	return nil
}

// onClose means close by user.
func (c *connection) onClose() error {
	// user code close the connection
	if c.closeBy(user) {
		c.triggerRead(Exception(ErrConnClosed, "self close"))
		c.triggerWrite(Exception(ErrConnClosed, "self close"))
		// Detach from poller when processing finished, otherwise it will cause race
		c.closeCallback(true, true)
		return nil
	}

	// closed by poller
	// still need to change closing status to `user` since OnProcess should not be processed again
	c.force(closing, user)

	// user code should actively close the connection to recycle resources.
	// poller already detached operator
	return c.closeCallback(true, false)
}

// closeBuffer recycle input & output LinkBuffer.
func (c *connection) closeBuffer() {
	onConnect, _ := c.onConnectCallback.Load().(OnConnect)
	onRequest, _ := c.onRequestCallback.Load().(OnRequest)
	// if client close the connection, we cannot ensure that the poller is not process the buffer,
	// so we need to check the buffer length, and if it's an "unclean" close operation, let's give up to reuse the buffer
	if c.inputBuffer.Len() == 0 || onConnect != nil || onRequest != nil {
		c.inputBuffer.Close()
	}
	if c.outputBuffer.Len() == 0 || onConnect != nil || onRequest != nil {
		c.outputBuffer.Close()
		barrierPool.Put(c.outputBarrier)
	}
}

// inputs implements FDOperator.
func (c *connection) inputs(vs [][]byte) (rs [][]byte) {
	vs[0] = c.inputBuffer.book(c.bookSize, c.maxSize)
	return vs[:1]
}

// inputAck implements FDOperator.
func (c *connection) inputAck(n int) (err error) {
	if n <= 0 {
		c.inputBuffer.bookAck(0)
		return nil
	}

	// Auto size bookSize.
	if n == c.bookSize && c.bookSize < mallocMax {
		c.bookSize <<= 1
	}

	length, _ := c.inputBuffer.bookAck(n)
	if c.maxSize < length {
		c.maxSize = length
	}
	if c.maxSize > mallocMax {
		c.maxSize = mallocMax
	}

	needTrigger := true
	if length == n { // first start onRequest
		needTrigger = c.onRequest()
	}
	if needTrigger && length >= int(atomic.LoadInt64(&c.waitReadSize)) {
		c.triggerRead(nil)
	}
	return nil
}

// outputs implements FDOperator.
//
// The FDOperator contract is "Outputs locks, OutputAck unlocks" when it returns
// data: outputMu is held across the poller sendmsg and released in outputAck,
// so a concurrent FlushAsync and the poller can never issue two sendmsg calls
// whose ordering would disagree with the committed byte order. All operations
// under outputMu are non-blocking.
func (c *connection) outputs(vs [][]byte) (rs [][]byte, _ bool) {
	c.outputMu.Lock()
	if c.outputBuffer.IsEmpty() {
		// No data remains: stop watching write events and release the lock.
		c.outputDrainDoneLocked()
		c.outputMu.Unlock()
		return rs, false
	}
	rs = c.outputBuffer.GetBytes(vs)
	if len(rs) == 0 {
		// Defensive: Len reported data but GetBytes produced none.
		c.outputDrainDoneLocked()
		c.outputMu.Unlock()
		return rs, false
	}
	// outputMu stays held; outputAck must be called by the poller next.
	return rs, false
}

// outputAck implements FDOperator.
// It is the unlock counterpart of outputs for a non-empty send, and advances
// the same shared send counter a direct sendmsg uses, finishing the tickets
// whose prefix has just been accepted.
func (c *connection) outputAck(n int) (err error) {
	if n > 0 {
		if e := c.outputBuffer.Skip(n); e == nil {
			c.outputBuffer.Release()
		}
		// the n bytes are already accepted by the kernel, so the shared send
		// counter advances even if buffer bookkeeping somehow disagreed
		c.flushTickets.advance(int64(n))
	}
	if c.outputBuffer.IsEmpty() {
		c.outputDrainDoneLocked()
	}
	c.outputMu.Unlock()
	return nil
}
