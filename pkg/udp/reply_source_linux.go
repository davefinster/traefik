//go:build linux

package udp

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

// newDatagramConn asks a host socket bound to a wildcard address for the
// destination of every datagram it receives: IPV6_RECVPKTINFO on an IPv6
// socket, which reports a dual-stack socket's IPv4 datagrams as IPv4-mapped
// addresses too, and IP_PKTINFO on an IPv4 one. Anything else, or a socket
// that refuses, is a plain conn.
func newDatagramConn(pc net.PacketConn) datagramConn {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return plainConn{PacketConn: pc}
	}
	la, ok := uc.LocalAddr().(*net.UDPAddr)
	if !ok || !la.IP.IsUnspecified() {
		return plainConn{PacketConn: pc}
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return plainConn{PacketConn: pc}
	}
	var family int
	var serr error
	err = rc.Control(func(fd uintptr) {
		// The family, not the address it was bound to: Go binds a
		// dual-stack IPv6 socket for "udp" on 0.0.0.0 as well as on ::.
		if family, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN); serr != nil {
			return
		}
		switch family {
		case unix.AF_INET6:
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
		case unix.AF_INET:
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
		default:
			serr = errors.New("not an IP socket")
		}
	})
	if err = errors.Join(err, serr); err != nil {
		log.Debug().Err(err).Stringer("address", la).Msg("UDP replies will come from the address the kernel chooses")
		return plainConn{PacketConn: pc}
	}
	return &pktinfoConn{
		UDPConn: uc,
		v6:      family == unix.AF_INET6,
		oob:     make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo)+unix.CmsgSpace(unix.SizeofInet4Pktinfo)),
	}
}

// pktinfoConn reads each datagram's destination from its control message,
// and sends each reply with that address as its source.
type pktinfoConn struct {
	*net.UDPConn

	// v6 is an IPv6 socket, whose replies name their source in IPV6_PKTINFO,
	// IPv4-mapped for an IPv4 client; on an IPv4 socket it is IP_PKTINFO.
	v6 bool

	// oob is the read loop's control message buffer. readFrom has only
	// that one caller.
	oob []byte

	// fallback logs, once, a reply that could not be sent from its
	// address and was sent as the kernel chose.
	fallback sync.Once
}

func (c *pktinfoConn) readFrom(b []byte) (int, net.Addr, netip.Addr, error) {
	n, oobn, _, ap, err := c.ReadMsgUDPAddrPort(b, c.oob)
	if err != nil {
		return 0, nil, netip.Addr{}, err
	}
	// Unmapped, so a session's client reads as it does from ReadFrom, and
	// keys and logs are unchanged.
	raddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	return n, raddr, destination(c.oob[:oobn]), nil
}

// destination is the address a datagram was sent to, from its control
// messages, if a reply may be sent from it. A multicast or broadcast
// destination may not: the reply's source is then the kernel's to choose,
// as without this.
func destination(oob []byte) netip.Addr {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}
	}
	for _, m := range msgs {
		var a netip.Addr
		switch {
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_PKTINFO && len(m.Data) >= unix.SizeofInet6Pktinfo:
			// in6_pktinfo: the address, then the interface index.
			a = netip.AddrFrom16([16]byte(m.Data[:16]))
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO && len(m.Data) >= unix.SizeofInet4Pktinfo:
			// in_pktinfo: the interface index, the local address routing
			// would use, then the header's destination address.
			a = netip.AddrFrom4([4]byte(m.Data[8:12]))
		default:
			continue
		}
		u := a.Unmap()
		if !u.IsValid() || u.IsUnspecified() || u.IsMulticast() || u == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return netip.Addr{}
		}
		return a
	}
	return netip.Addr{}
}

func (c *pktinfoConn) writeTo(b []byte, raddr net.Addr, local netip.Addr) (int, error) {
	ua, ok := raddr.(*net.UDPAddr)
	if !local.IsValid() || !ok {
		return c.WriteTo(b, raddr)
	}
	var oob []byte
	if c.v6 {
		// An IPv4 local address is IPv4-mapped here already, as the
		// socket reported it, which is how an IPv6 socket names an IPv4
		// source.
		oob = unix.PktInfo6(&unix.Inet6Pktinfo{Addr: local.As16()})
	} else {
		oob = unix.PktInfo4(&unix.Inet4Pktinfo{Spec_dst: local.As4()})
	}
	n, _, err := c.WriteMsgUDPAddrPort(b, oob, ua.AddrPort())
	if errors.Is(err, unix.EINVAL) {
		// The kernel will not send from an address the host receives for
		// but has not assigned, such as one only in an AnyIP route: reply
		// as the kernel chooses, which is what a plain conn does.
		c.fallback.Do(func() {
			log.Warn().Err(err).Stringer("source", local).Msg("UDP reply could not be sent from the address it was sent to; replying from the kernel's choice")
		})
		return c.WriteTo(b, raddr)
	}
	return n, err
}
