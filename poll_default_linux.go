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

package netpoll

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
)

func openPoll() (Poll, error) {
	return openDefaultPoll()
}

func openDefaultPoll() (*defaultPoll, error) {
	poll := new(defaultPoll)

	poll.buf = make([]byte, 8)
	p, err := EpollCreate(0)
	if err != nil {
		return nil, err
	}
	poll.fd = p

	r0, _, e0 := syscall.Syscall(syscall.SYS_EVENTFD2, 0, 0, 0)
	if e0 != 0 {
		_ = syscall.Close(poll.fd)
		return nil, e0
	}

	poll.Reset = poll.reset
	poll.Handler = poll.handler
	poll.wop = &FDOperator{FD: int(r0)}
	poll.wop.poll = poll
	poll.closedCh = make(chan struct{})

	if err = poll.Control(poll.wop, PollReadable); err != nil {
		_ = syscall.Close(poll.wop.FD)
		_ = syscall.Close(poll.fd)
		return nil, err
	}

	poll.opcache = newOperatorCache()
	return poll, nil
}

type defaultPoll struct {
	pollArgs
	fd       int            // epoll fd
	wop      *FDOperator    // eventfd, wake epoll_wait
	buf      []byte         // read wfd trigger msg
	trigger  uint32         // trigger flag
	opcache  *operatorCache // operator cache
	closed   int32          // atomic: 1 after Close
	closeOne sync.Once
	closedCh chan struct{} // closed once when Close is called
	// tasks are executed serially by the poller goroutine between two event
	// batches, i.e. when no event callback of this poller is in flight. It is
	// the quiescence mechanism used by live connection migration.
	taskMu sync.Mutex
	tasks  []pollFunc
	goid   int64 // goroutine id of the running Wait loop, 0 if not running
	// fns for handle events
	Reset   func(size, caps int)
	Handler func(events []epollevent) (closed bool)
}

type pollArgs struct {
	size     int
	caps     int
	events   []epollevent
	barriers []barrier
	hups     []func(p Poll) error
}

func (a *pollArgs) reset(size, caps int) {
	a.size, a.caps = size, caps
	a.events, a.barriers = make([]epollevent, size), make([]barrier, size)
	for i := range a.barriers {
		a.barriers[i].bs = make([][]byte, a.caps)
		a.barriers[i].ivs = make([]syscall.Iovec, a.caps)
	}
}

// Wait implements Poll.
func (p *defaultPoll) Wait() (err error) {
	// init
	caps, msec, n := barriercap, -1, 0
	p.Reset(128, caps)
	atomic.StoreInt64(&p.goid, currentGoid())
	// wait
	for {
		if n == p.size && p.size < 128*1024 {
			p.Reset(p.size<<1, caps)
		}
		n, err = EpollWait(p.fd, p.events, msec)
		if err != nil && err != syscall.EINTR {
			return err
		}
		if n <= 0 {
			msec = -1
			runtime.Gosched()
			continue
		}
		msec = 0
		if p.Handler(p.events[:n]) {
			return nil
		}
		// Migration (and similar) jobs run on the poller goroutine only after
		// the whole event batch has finished, so no callback is still touching
		// the operator's buffers when a detach/quiesce job observes it.
		p.runTasks()
		// we can make sure that there is no op remaining if Handler finished.
		// Operators retired by the tasks above are returned to the pool here,
		// after every event that could reference them is done.
		p.opcache.free()
	}
}

func (p *defaultPoll) handler(events []epollevent) (closed bool) {
	var triggerRead, triggerWrite, triggerHup, triggerError bool
	var err error
	for i := range events {
		operator := p.getOperator(0, events[i].GetDataPtr())
		// The token check in getOperator rejects stale registrations; the owner
		// check is a second line of defense: an operator that has been migrated
		// to another poller can never be driven by this poller.
		if operator == nil || operator.poll != p || !operator.do() {
			continue
		}

		var totalRead int
		evt := events[i].Events
		triggerRead = evt&syscall.EPOLLIN != 0
		triggerWrite = evt&syscall.EPOLLOUT != 0
		triggerHup = evt&(syscall.EPOLLHUP|syscall.EPOLLRDHUP) != 0
		triggerError = evt&syscall.EPOLLERR != 0

		// trigger or exit gracefully
		if operator.FD == p.wop.FD {
			// must clean trigger first
			syscall.Read(p.wop.FD, p.buf)
			atomic.StoreUint32(&p.trigger, 0)
			// if closed & exit
			if p.buf[0] > 0 {
				syscall.Close(p.wop.FD)
				syscall.Close(p.fd)
				operator.done()
				return true
			}
			operator.done()
			continue
		}

		if triggerRead {
			if operator.OnRead != nil {
				// for non-connection
				operator.OnRead(p)
			} else if operator.Inputs != nil {
				// for connection
				bs := operator.Inputs(p.barriers[i].bs)
				if len(bs) > 0 {
					n, err := ioread(operator.FD, bs, p.barriers[i].ivs)
					operator.InputAck(n)
					totalRead += n
					if err != nil {
						p.appendHup(operator)
						continue
					}
				}
			} else {
				logger.Printf("NETPOLL: operator has critical problem! event=%d operator=%v", evt, operator)
			}
		}
		if triggerHup {
			if triggerRead && operator.Inputs != nil {
				// read all left data if peer send and close
				var leftRead int
				// read all left data if peer send and close
				if leftRead, err = readall(operator, p.barriers[i]); err != nil && !errors.Is(err, ErrEOF) {
					logger.Printf("NETPOLL: readall(fd=%d)=%d before close: %s", operator.FD, totalRead, err.Error())
				}
				totalRead += leftRead
			}
			// only close connection if no further read bytes
			if totalRead == 0 {
				p.appendHup(operator)
				continue
			}
		}
		if triggerError {
			// Under block-zerocopy, the kernel may give an error callback, which is not a real error, just an EAGAIN.
			// So here we need to check this error, if it is EAGAIN then do nothing, otherwise still mark as hup.
			if _, _, _, _, err := syscall.Recvmsg(operator.FD, nil, nil, syscall.MSG_ERRQUEUE); err != syscall.EAGAIN {
				p.appendHup(operator)
			} else {
				operator.done()
			}
			continue
		}
		if triggerWrite {
			if operator.OnWrite != nil {
				// for non-connection
				operator.OnWrite(p)
			} else if operator.Outputs != nil {
				// for connection
				bs, _ := operator.Outputs(p.barriers[i].bs)
				if len(bs) > 0 {
					n, err := iosend(operator.FD, bs, p.barriers[i].ivs, false)
					operator.OutputAck(n)
					if err != nil {
						p.appendHup(operator)
						continue
					}
				}
			} else {
				logger.Printf("NETPOLL: operator has critical problem! event=%d operator=%v", evt, operator)
			}
		}
		operator.done()
	}
	// hup conns together to avoid blocking the poll.
	p.onhups()
	return false
}

// Close will write 10000000
func (p *defaultPoll) Close() error {
	p.closeOne.Do(func() {
		atomic.StoreInt32(&p.closed, 1)
		close(p.closedCh)
	})
	_, err := syscall.Write(p.wop.FD, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	return err
}

// isClosed reports whether the poller has been closed.
func (p *defaultPoll) isClosed() bool {
	return atomic.LoadInt32(&p.closed) != 0
}

// Trigger implements Poll.
func (p *defaultPoll) Trigger() error {
	if atomic.AddUint32(&p.trigger, 1) > 1 {
		return nil
	}
	// MAX(eventfd) = 0xfffffffffffffffe
	_, err := syscall.Write(p.wop.FD, []byte{0, 0, 0, 0, 0, 0, 0, 1})
	return err
}

// Control implements Poll.
func (p *defaultPoll) Control(operator *FDOperator, event PollEvent) error {
	// DON'T move `fd=operator.FD` behind inuse() call, we can only access operator before op.inuse() for avoid race
	// G1:              G2:
	// op.inuse()       op.unused()
	// op.FD  -- T1     op.FD = 0  -- T2
	// T1 and T2 may happen together
	fd := operator.FD
	var op int
	var evt epollevent
	switch event {
	case PollReadable: // server accept a new connection and wait read
		operator.inuse()
		// A fresh registration identity: stale events can never be mistaken
		// for this one.
		setEventToken(&evt, mintToken(operator))
		op, evt.Events = syscall.EPOLL_CTL_ADD, syscall.EPOLLIN|syscall.EPOLLRDHUP|syscall.EPOLLERR
	case PollWritable: // client create a new connection and wait connect finished
		operator.inuse()
		setEventToken(&evt, mintToken(operator))
		op, evt.Events = syscall.EPOLL_CTL_ADD, EPOLLET|syscall.EPOLLOUT|syscall.EPOLLRDHUP|syscall.EPOLLERR
	case PollDetach: // deregister
		setEventToken(&evt, currentToken(operator))
		op, evt.Events = syscall.EPOLL_CTL_DEL, syscall.EPOLLIN|syscall.EPOLLOUT|syscall.EPOLLRDHUP|syscall.EPOLLERR
		err := EpollCtl(p.fd, op, fd, &evt)
		// Invalidate the identity only after the kernel removed the entry; any
		// event returned afterwards for this fd cannot carry a valid token.
		invalidateToken(operator)
		return err
	case PollR2RW: // connection wait read/write
		setEventToken(&evt, currentToken(operator))
		op, evt.Events = syscall.EPOLL_CTL_MOD, syscall.EPOLLIN|syscall.EPOLLOUT|syscall.EPOLLRDHUP|syscall.EPOLLERR
	case PollRW2R: // connection wait read
		setEventToken(&evt, currentToken(operator))
		op, evt.Events = syscall.EPOLL_CTL_MOD, syscall.EPOLLIN|syscall.EPOLLRDHUP|syscall.EPOLLERR
	}
	return EpollCtl(p.fd, op, fd, &evt)
}
