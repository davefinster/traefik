package udp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrappedPacketConn is a net.PacketConn that is not a *net.UDPConn, which is
// what a tailnet entryPoint gets: its packets come from the in-process
// userspace network stack rather than from a host socket.
type wrappedPacketConn struct {
	net.PacketConn
}

// A listener must work on any net.PacketConn. It used to require a
// *net.UDPConn, which silently ruled out every packet source that is not a
// host socket.
func TestListenPacketConnAcceptsAnyPacketConn(t *testing.T) {
	underlying, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	listener, err := ListenPacketConn(&wrappedPacketConn{PacketConn: underlying}, 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Shutdown(0) })

	assert.Equal(t, underlying.LocalAddr().String(), listener.Addr().String())

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()

	client, err := net.Dial("udp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Write([]byte("tailnet"))
	require.NoError(t, err)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	require.NoError(t, err)

	assert.Equal(t, "tailnet", string(buf[:n]))
}

func TestListenPacketConnRequiresAConn(t *testing.T) {
	_, err := ListenPacketConn(nil, time.Second)
	require.ErrorContains(t, err, "packet conn is required")
}
