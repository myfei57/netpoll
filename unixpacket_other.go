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

//go:build !linux

package netpoll

import (
	"net"
	"time"
)

// PacketConfig mirrors the Linux API so code can compile cross-platform;
// every entry point reports ErrUnsupported off Linux.
type PacketConfig struct {
	MaxPayload      int
	MaxFDs          int
	MaxQueuePackets int
	MaxQueueBytes   int
}

// UnixPacketConnection is only implemented on Linux; off Linux the type exists
// solely to keep cross-platform code compiling and every operation fails with
// ErrUnsupported.
type UnixPacketConnection struct{}

// Packet mirrors the Linux API; it carries no data off Linux.
type Packet struct {
	Payload []byte
}

// UnixPacketListener mirrors the Linux API; it cannot accept off Linux.
type UnixPacketListener struct{}

var errUnixPacketUnsupported = Exception(ErrUnsupported, "UnixPacketConnection requires linux")

// NewUnixPacketConnection is not supported on this platform.
func NewUnixPacketConnection(fd int, cfg *PacketConfig) (*UnixPacketConnection, error) {
	return nil, errUnixPacketUnsupported
}

// DialUnixPacket is not supported on this platform.
func DialUnixPacket(address string, cfg *PacketConfig) (*UnixPacketConnection, error) {
	return nil, errUnixPacketUnsupported
}

// ListenUnixPacket is not supported on this platform.
func ListenUnixPacket(address string, cfg *PacketConfig) (*UnixPacketListener, error) {
	return nil, errUnixPacketUnsupported
}

// SendPacket is not supported on this platform.
func (c *UnixPacketConnection) SendPacket(payload []byte, fds []int) error {
	return errUnixPacketUnsupported
}

// ReceivePacket is not supported on this platform.
func (c *UnixPacketConnection) ReceivePacket() (*Packet, error) {
	return nil, errUnixPacketUnsupported
}

// NumFDs is not supported on this platform.
func (p *Packet) NumFDs() int { return 0 }

// TakeFD is not supported on this platform.
func (p *Packet) TakeFD(i int) (int, error) { return -1, errUnixPacketUnsupported }

// Release is not supported on this platform.
func (p *Packet) Release() error { return errUnixPacketUnsupported }

// IsActive is not supported on this platform.
func (c *UnixPacketConnection) IsActive() bool { return false }

// PacketCloseCallback mirrors the Linux API off Linux.
type PacketCloseCallback func(connection *UnixPacketConnection) error

// AddCloseCallback is not supported on this platform.
func (c *UnixPacketConnection) AddCloseCallback(fn PacketCloseCallback) error {
	return errUnixPacketUnsupported
}

// SetReadTimeout is not supported on this platform.
func (c *UnixPacketConnection) SetReadTimeout(timeout time.Duration) error {
	return errUnixPacketUnsupported
}

// SetWriteTimeout is not supported on this platform.
func (c *UnixPacketConnection) SetWriteTimeout(timeout time.Duration) error {
	return errUnixPacketUnsupported
}

// Read implements net.Conn and is not supported on this platform.
func (c *UnixPacketConnection) Read(p []byte) (int, error) {
	return 0, errUnixPacketUnsupported
}

// Write implements net.Conn and is not supported on this platform.
func (c *UnixPacketConnection) Write(p []byte) (int, error) {
	return 0, errUnixPacketUnsupported
}

// Close implements net.Conn and is not supported on this platform.
func (c *UnixPacketConnection) Close() error { return errUnixPacketUnsupported }

// LocalAddr implements net.Conn.
func (c *UnixPacketConnection) LocalAddr() net.Addr { return nil }

// RemoteAddr implements net.Conn.
func (c *UnixPacketConnection) RemoteAddr() net.Addr { return nil }

// SetDeadline implements net.Conn.
func (c *UnixPacketConnection) SetDeadline(t time.Time) error {
	return errUnixPacketUnsupported
}

// SetReadDeadline implements net.Conn.
func (c *UnixPacketConnection) SetReadDeadline(t time.Time) error {
	return errUnixPacketUnsupported
}

// SetWriteDeadline implements net.Conn.
func (c *UnixPacketConnection) SetWriteDeadline(t time.Time) error {
	return errUnixPacketUnsupported
}

// AcceptPacket is not supported on this platform.
func (l *UnixPacketListener) AcceptPacket() (*UnixPacketConnection, error) {
	return nil, errUnixPacketUnsupported
}

// Accept implements net.Listener and is not supported on this platform.
func (l *UnixPacketListener) Accept() (net.Conn, error) {
	return nil, errUnixPacketUnsupported
}

// Addr implements net.Listener.
func (l *UnixPacketListener) Addr() net.Addr { return nil }

// Close implements net.Listener and is not supported on this platform.
func (l *UnixPacketListener) Close() error { return errUnixPacketUnsupported }
