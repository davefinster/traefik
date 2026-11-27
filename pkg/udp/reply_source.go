package udp

import (
	"net"
	"net/netip"
)

// datagramConn is how a Listener reads and writes its datagrams. It carries
// the address each datagram was sent to, where the socket can say, so that
// a session replies from that address.
//
// A socket bound to a wildcard address receives for every address the host
// has, and the kernel picks a reply's source by routing alone, which on a
// host with several addresses is often not the one the client sent to.
// A client that compares the two -- a connected socket, a NAT, a stateful
// firewall -- then drops the reply. A host serving a Tailscale Service or a
// routed address beside its own, as one behind a multits gateway does, is
// such a host: the client sends to the Service's address, and without this
// the reply comes from the node's.
type datagramConn interface {
	// readFrom reads one datagram into b, returning its sender and the
	// local address it was sent to: an invalid netip.Addr where the socket
	// does not say.
	readFrom(b []byte) (n int, raddr net.Addr, local netip.Addr, err error)
	// writeTo sends b to raddr from local, or as the socket chooses when
	// local is invalid.
	writeTo(b []byte, raddr net.Addr, local netip.Addr) (int, error)
}

// plainConn is a packet conn that does not say: one bound to a specific
// address, where the source of a reply is that address anyway, a packet
// conn that is not a host socket, and every socket where the operating
// system offers no destination address.
type plainConn struct {
	net.PacketConn
}

func (c plainConn) readFrom(b []byte) (int, net.Addr, netip.Addr, error) {
	n, raddr, err := c.ReadFrom(b)
	return n, raddr, netip.Addr{}, err
}

func (c plainConn) writeTo(b []byte, raddr net.Addr, _ netip.Addr) (int, error) {
	return c.WriteTo(b, raddr)
}

// sessionKey identifies a session: its client, and the local address the
// client sends to where that is known. A client talking to two of the
// host's addresses holds two sessions, each answered from its own address.
func sessionKey(raddr net.Addr, local netip.Addr) string {
	if !local.IsValid() {
		return raddr.String()
	}
	return raddr.String() + " " + local.String()
}
