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
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
)

const (
	managerUninitialized = iota
	managerInitializing
	managerInitialized
)

func newManager(numLoops int) *manager {
	m := new(manager)
	m.SetLoadBalance(RoundRobin)
	m.SetNumLoops(numLoops)
	return m
}

// LoadBalance is used to do load balancing among multiple pollers.
// a single poller may not be optimal if the number of cores is large (40C+).
type manager struct {
	numLoops int32
	status   int32       // 0: uninitialized, 1: initializing, 2: initialized
	balance  loadbalance // load balancing method
	polls    []Poll      // all the polls
	// mu protects polls slice replacement (Run/Close/Reset) and is used by
	// live migration to validate that a target poller belongs to this manager
	// and is still active.
	mu sync.RWMutex
}

// SetNumLoops will return error when set numLoops < 1
func (m *manager) SetNumLoops(numLoops int) (err error) {
	if numLoops < 1 {
		return fmt.Errorf("set invalid numLoops[%d]", numLoops)
	}
	// note: set new numLoops first and then change the status
	atomic.StoreInt32(&m.numLoops, int32(numLoops))
	atomic.StoreInt32(&m.status, managerUninitialized)
	return nil
}

// SetLoadBalance set load balance.
func (m *manager) SetLoadBalance(lb LoadBalance) error {
	if m.balance != nil && m.balance.LoadBalance() == lb {
		return nil
	}
	m.balance = newLoadbalance(lb, m.polls)
	return nil
}

// Close release all resources.
func (m *manager) Close() (err error) {
	m.mu.Lock()
	polls := m.polls
	m.numLoops = 0
	m.balance = nil
	m.polls = nil
	m.mu.Unlock()
	for _, poll := range polls {
		err = poll.Close()
	}
	return err
}

// Run all pollers.
func (m *manager) Run() (err error) {
	defer func() {
		if err != nil {
			_ = m.Close()
		}
	}()

	m.mu.Lock()
	defer m.mu.Unlock()
	numLoops := int(atomic.LoadInt32(&m.numLoops))
	if numLoops == len(m.polls) {
		return nil
	}
	polls := make([]Poll, numLoops)
	if numLoops < len(m.polls) {
		// shrink polls
		copy(polls, m.polls[:numLoops])
		for idx := numLoops; idx < len(m.polls); idx++ {
			// close redundant polls
			if err = m.polls[idx].Close(); err != nil {
				logger.Printf("NETPOLL: poller close failed: %v\n", err)
			}
		}
	} else {
		// growth polls
		copy(polls, m.polls)
		for idx := len(m.polls); idx < numLoops; idx++ {
			var poll Poll
			poll, err = openPoll()
			if err != nil {
				return err
			}
			polls[idx] = poll
			go poll.Wait()
		}
	}
	m.polls = polls

	// LoadBalance must be set before calling Run, otherwise it will panic.
	m.balance.Rebalance(m.polls)
	return nil
}

// Reset pollers, this operation is very dangerous, please make sure to do this when calling !
func (m *manager) Reset() error {
	m.mu.Lock()
	polls := m.polls
	m.polls = nil
	m.mu.Unlock()
	for _, poll := range polls {
		poll.Close()
	}
	return m.Run()
}

// isActivePoll reports whether poll currently belongs to this manager and has
// not been closed. It is used to validate live migration targets/sources.
func (m *manager) isActivePoll(poll Poll) bool {
	dp, ok := poll.(*defaultPoll)
	if !ok || dp == nil || dp.isClosed() {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, candidate := range m.polls {
		if candidate == poll {
			return true
		}
	}
	return false
}

// Pick will select the poller for use each time based on the LoadBalance.
func (m *manager) Pick() Poll {
START:
	// fast path
	if atomic.LoadInt32(&m.status) == managerInitialized {
		return m.balance.Pick()
	}
	// slow path
	// try to get initializing lock failed, wait others finished the init work, and try again
	if !atomic.CompareAndSwapInt32(&m.status, managerUninitialized, managerInitializing) {
		runtime.Gosched()
		goto START
	}
	// adjust polls
	// m.Run() will finish very quickly, so will not many goroutines block on Pick.
	_ = m.Run()

	//nolint:staticcheck // SA9003: empty branch
	if !atomic.CompareAndSwapInt32(&m.status, managerInitializing, managerInitialized) {
		// SetNumLoops called during m.Run() which cause CAS failed
		// The polls will be adjusted next Pick
	}
	return m.balance.Pick()
}
