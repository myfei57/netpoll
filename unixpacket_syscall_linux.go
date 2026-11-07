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
	"syscall"
	"unsafe"
)

// recvPacketMessage performs one non-blocking recvmsg. MSG_CMSG_CLOEXEC
// atomically installs every received SCM_RIGHTS descriptor with O_CLOEXEC,
// so an exec racing this call cannot inherit a new fd.
func recvPacketMessage(fd int, payload, ctrl []byte) (n, ctrlN, flags int, err error) {
	for {
		n, ctrlN, flags, _, err = syscall.Recvmsg(fd, payload, ctrl, syscall.MSG_CMSG_CLOEXEC)
		if err == syscall.EINTR {
			continue
		}
		return n, ctrlN, flags, err
	}
}

// sendPacketMessage performs one non-blocking sendmsg carrying the whole
// payload as a single iovec and fds as one SCM_RIGHTS control record. The
// socket itself is non-blocking, so EAGAIN leaves the datagram intact.
func sendPacketMessage(fd int, payload []byte, fds []int) (n int, err error) {
	var rights []byte
	if len(fds) > 0 {
		rights = syscall.UnixRights(fds...)
	}
	for {
		n, err = syscall.SendmsgN(fd, payload, rights, nil, 0)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

// parsePacketFDs walks raw recvmsg control bytes and accepts nothing other
// than well-formed SOL_SOCKET/SCM_RIGHTS records. It validates every record
// header length, the payload width and the total descriptor count, so malformed
// ancillary data can never throw parsing out of sync.
//
// Returned fds are exactly the descriptors the kernel installed; the caller
// owns them and must close them on every failure path.
func parsePacketFDs(ctrl []byte, maxFDs int) (fds []int, err error) {
	hdrLen := syscall.CmsgLen(0)
	for len(ctrl) > 0 {
		// A trailing chunk smaller than a header is invalid: the kernel
		// reports exact, aligned control length, so padding never reaches us
		// as data.
		if len(ctrl) < hdrLen {
			return fds, ErrPacketControlInvalid
		}
		h := (*syscall.Cmsghdr)(unsafe.Pointer(&ctrl[0]))
		l := int(h.Len)
		// l must describe a complete header and must not run past the bytes
		// the kernel actually wrote.
		if l < hdrLen || uint64(l) > uint64(len(ctrl)) {
			return fds, ErrPacketControlInvalid
		}
		if h.Level != syscall.SOL_SOCKET || h.Type != syscall.SCM_RIGHTS {
			// Any non-SCM_RIGHTS record is unexpected capability data: fail
			// the packet rather than silently dropping it.
			return fds, ErrPacketControlInvalid
		}
		data := ctrl[hdrLen:l]
		if len(data) == 0 || len(data)%4 != 0 {
			return fds, ErrPacketControlInvalid
		}
		for i := 0; i < len(data); i += 4 {
			// SCM_RIGHTS stores native-endian int32 descriptors.
			fd := int(*(*int32)(unsafe.Pointer(&data[i])))
			fds = append(fds, fd)
			if len(fds) > maxFDs {
				return fds, ErrPacketTooManyFDs
			}
		}
		// Skip the record and its trailing alignment padding. The reported
		// control length may omit the final record's tail padding, in which
		// case there is simply nothing left to walk.
		rest := ctrl[l:]
		pad := syscall.CmsgSpace(l-hdrLen) - (l - hdrLen)
		if pad >= len(rest) {
			return fds, nil
		}
		ctrl = rest[pad:]
	}
	return fds, nil
}
