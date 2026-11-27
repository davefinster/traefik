//go:build linux

package udp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echo accepts sessions on l and echoes every datagram back on its session,
// reporting each session as it is accepted.
func echo(t *testing.T, l *Listener) <-chan *Conn {
	t.Helper()
	accepted := make(chan *Conn, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
			go func() {
				buf := make([]byte, maxDatagramSize)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	return accepted
}

// ask sends msg from client to addr and returns the reply and who sent it.
func ask(t *testing.T, client *net.UDPConn, addr netip.AddrPort, msg string) (string, netip.AddrPort) {
	t.Helper()
	_, err := client.WriteToUDPAddrPort([]byte(msg), addr)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 1500)
	n, from, err := client.ReadFromUDPAddrPort(buf)
	require.NoError(t, err)
	return string(buf[:n]), netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
}

// Every 127/8 address is the loopback's, so a client on 127.0.0.1 sending
// to 127.0.0.2 is a client sending to an address other than the one the
// kernel would pick to reach it: without the destination, the reply would
// come from 127.0.0.1, and a client that checks its source would drop it.
func TestReplyComesFromTheAddressSentTo(t *testing.T) {
	for _, tc := range []struct{ network, address string }{
		{"udp", ":0"},         // dual-stack IPv6: IPV6_PKTINFO, IPv4-mapped
		{"udp", "0.0.0.0:0"},  // still dual-stack, as Go binds it
		{"udp4", "0.0.0.0:0"}, // IPv4: IP_PKTINFO
	} {
		t.Run(tc.network+" "+tc.address, func(t *testing.T) {
			l, err := Listen(net.ListenConfig{}, tc.network, tc.address, 3*time.Second)
			require.NoError(t, err)
			t.Cleanup(func() { _ = l.Close() })
			_, isPktinfo := l.dgram.(*pktinfoConn)
			require.True(t, isPktinfo, "a wildcard socket reads its datagrams' destinations")
			echo(t, l)
			port := uint16(l.Addr().(*net.UDPAddr).Port)

			client, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			for _, dst := range []string{"127.0.0.1", "127.0.0.2"} {
				to := netip.AddrPortFrom(netip.MustParseAddr(dst), port)
				reply, from := ask(t, client, to, "to "+dst)
				assert.Equal(t, "to "+dst, reply)
				assert.Equal(t, to, from, "the reply's source")
			}
		})
	}
}

// IPv6 the same way, over the one IPv6 loopback address there is.
func TestReplyComesFromTheAddressSentToOverIPv6(t *testing.T) {
	l, err := Listen(net.ListenConfig{}, "udp", ":0", 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	echo(t, l)
	client, err := net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[::1]:0")))
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	to := netip.AddrPortFrom(netip.IPv6Loopback(), uint16(l.Addr().(*net.UDPAddr).Port))
	reply, from := ask(t, client, to, "six")
	assert.Equal(t, "six", reply)
	assert.Equal(t, to, from)
}

// One client sending to two of the host's addresses holds two sessions,
// each answering from its own address; a single session would answer both
// from whichever it saw first.
func TestASessionPerLocalAddress(t *testing.T) {
	l, err := Listen(net.ListenConfig{}, "udp", ":0", 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	accepted := echo(t, l)
	port := uint16(l.Addr().(*net.UDPAddr).Port)
	client, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	locals := map[netip.Addr]bool{}
	for _, dst := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.1"} {
		ask(t, client, netip.AddrPortFrom(netip.MustParseAddr(dst), port), dst)
	}
	for range 2 {
		select {
		case c := <-accepted:
			locals[c.local.Unmap()] = true
		case <-time.After(3 * time.Second):
			t.Fatal("fewer than two sessions")
		}
	}
	select {
	case c := <-accepted:
		t.Fatalf("a third session, at %s", c.local)
	case <-time.After(200 * time.Millisecond):
	}
	assert.Equal(t, map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true, netip.MustParseAddr("127.0.0.2"): true}, locals)
}

// A socket bound to one address replies from it anyway, and keeps the
// plain conn.
func TestABoundSocketIsPlain(t *testing.T) {
	l, err := Listen(net.ListenConfig{}, "udp", "127.0.0.2:0", 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	_, plain := l.dgram.(plainConn)
	assert.True(t, plain)
	echo(t, l)
	client, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	to := l.Addr().(*net.UDPAddr).AddrPort()
	_, from := ask(t, client, netip.AddrPortFrom(to.Addr().Unmap(), to.Port()), "bound")
	assert.Equal(t, netip.MustParseAddr("127.0.0.2"), from.Addr())
}

func TestDestinationIgnoresWhatCannotBeASource(t *testing.T) {
	assert.False(t, destination(nil).IsValid())
	assert.False(t, destination([]byte{1, 2, 3}).IsValid())
}
