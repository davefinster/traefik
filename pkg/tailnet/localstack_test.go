package tailnet

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

// crossWire joins two devices back to back, so what one stack sends the other
// receives. It stands in for the tailnet node, which is exactly that: the
// other end of the device, moving packets on and off the wire.
func crossWire(t *testing.T, a, b *memTUN) {
	t.Helper()

	// Driven through the tun.Device interface rather than the internal
	// queues, because that is what the tailnet node does: Read takes what
	// the local stack produced, Write hands over what arrives for it.
	pump := func(from, to *memTUN) {
		bufs := [][]byte{make([]byte, tunMTU+128)}
		sizes := make([]int, 1)
		for {
			n, err := from.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if n == 0 || sizes[0] == 0 {
				continue
			}
			if _, err := to.Write([][]byte{bufs[0][:sizes[0]]}, 0); err != nil {
				return
			}
		}
	}

	go pump(a, b)
	go pump(b, a)
}

// twoStacks returns two stacks wired together, each holding one address.
func twoStacks(t *testing.T, addrA, addrB netip.Addr) (*localStack, *localStack) {
	t.Helper()

	devA, devB := newMemTUN(), newMemTUN()

	stackA, err := newLocalStack(devA)
	require.NoError(t, err)
	t.Cleanup(stackA.close)

	stackB, err := newLocalStack(devB)
	require.NoError(t, err)
	t.Cleanup(stackB.close)

	require.NoError(t, stackA.addAddr(addrA))
	require.NoError(t, stackB.addAddr(addrB))

	crossWire(t, devA, devB)

	t.Cleanup(func() {
		_ = devA.Close()
		_ = devB.Close()
	})

	return stackA, stackB
}

func fullAddr(addr netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv4.ProtocolNumber
	if addr.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()),
		Port: addr.Port(),
	}, proto
}

// A real TCP connection has to survive the whole path: gVisor on one side,
// the device queues, and gVisor on the other. This is the plumbing a
// Tailscale Service in TUN mode depends on, minus the tailnet.
func TestLocalStackTCPRoundTrip(t *testing.T) {
	addrA := netip.MustParseAddr("100.64.0.1")
	addrB := netip.MustParseAddr("100.64.0.2")
	stackA, stackB := twoStacks(t, addrA, addrB)

	listener, err := stackA.listenTCP(netip.AddrPortFrom(addrA, 8443))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	target, proto := fullAddr(netip.AddrPortFrom(addrA, 8443))
	conn, err := gonet.DialContextTCP(ctx, stackB.ipstack, target, proto)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.NoError(t, conn.SetDeadline(time.Now().Add(15*time.Second)))

	payload := []byte("tcp across two userspace stacks")
	_, err = conn.Write(payload)
	require.NoError(t, err)

	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)

	assert.Equal(t, payload, got)
}

// UDP is the protocol a Service in TUN mode exists to carry, and the one
// tsnet cannot serve on a VIP alongside TCP.
func TestLocalStackUDPRoundTrip(t *testing.T) {
	addrA := netip.MustParseAddr("100.64.0.1")
	addrB := netip.MustParseAddr("100.64.0.2")
	stackA, stackB := twoStacks(t, addrA, addrB)

	server, err := stackA.listenUDP(netip.AddrPortFrom(addrA, 8053))
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = server.WriteTo(buf[:n], from)
		}
	}()

	client, err := stackB.listenUDP(netip.AddrPortFrom(addrB, 0))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	payload := []byte("udp across two userspace stacks")
	target := &net.UDPAddr{IP: addrA.AsSlice(), Port: 8053}

	require.NoError(t, client.SetDeadline(time.Now().Add(15*time.Second)))
	_, err = client.WriteTo(payload, target)
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := client.ReadFrom(buf)
	require.NoError(t, err)

	assert.Equal(t, payload, buf[:n])
}

// Both protocols on one address at once is the whole point: it is what a
// single Service VIP cannot do through tsnet alone.
func TestLocalStackTCPAndUDPOnOneAddress(t *testing.T) {
	addrA := netip.MustParseAddr("100.64.0.1")
	addrB := netip.MustParseAddr("100.64.0.2")
	stackA, stackB := twoStacks(t, addrA, addrB)

	listener, err := stackA.listenTCP(netip.AddrPortFrom(addrA, 443))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	packets, err := stackA.listenUDP(netip.AddrPortFrom(addrA, 443))
	require.NoError(t, err)
	t.Cleanup(func() { _ = packets.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("tcp"))
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			_, from, err := packets.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = packets.WriteTo([]byte("udp"), from)
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	target, proto := fullAddr(netip.AddrPortFrom(addrA, 443))
	conn, err := gonet.DialContextTCP(ctx, stackB.ipstack, target, proto)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.NoError(t, conn.SetDeadline(time.Now().Add(15*time.Second)))
	got := make([]byte, 3)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, "tcp", string(got))

	client, err := stackB.listenUDP(netip.AddrPortFrom(addrB, 0))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, client.SetDeadline(time.Now().Add(15*time.Second)))
	_, err = client.WriteTo([]byte("ping"), &net.UDPAddr{IP: addrA.AsSlice(), Port: 443})
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := client.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "udp", string(buf[:n]))
}

// A stack whose node never took it, after a failed join, is released on its
// own. It must not wait for the device to be closed by anything else, and it
// takes the device with it.
func TestLocalStackReleaseDoesNotWaitForTheDevice(t *testing.T) {
	dev := newMemTUN()
	local, err := newLocalStack(dev)
	require.NoError(t, err)

	released := make(chan struct{})
	go func() {
		local.release()
		close(released)
	}()

	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("release blocked waiting for the device")
	}

	_, ok := dev.receive(nil)
	assert.False(t, ok)
}
