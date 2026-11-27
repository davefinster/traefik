//go:build !linux

package udp

import "net"

// newDatagramConn is a plain conn: replying from the address a datagram was
// sent to is implemented for Linux only.
func newDatagramConn(pc net.PacketConn) datagramConn {
	return plainConn{PacketConn: pc}
}
