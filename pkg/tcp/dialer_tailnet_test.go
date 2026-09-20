package tcp

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// fakeTailnetDialer records the tailnet it was asked for and dials a fixed
// local address instead, standing in for a tsnet node.
type fakeTailnetDialer struct {
	target      string
	known       bool
	seenTailnet string
	seenAddr    string
}

func (f *fakeTailnetDialer) DialContext(ctx context.Context, tailnet, network, addr string) (net.Conn, error) {
	f.seenTailnet = tailnet
	f.seenAddr = addr
	return (&net.Dialer{}).DialContext(ctx, network, f.target)
}

func (f *fakeTailnetDialer) Has(string) bool { return f.known }

// echoListener answers one connection with a fixed payload.
func echoListener(t *testing.T, payload string) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(payload))
	}()

	return ln
}

func TestTCPDialerUsesTailnet(t *testing.T) {
	ln := echoListener(t, "tailnet")

	tailnetDialer := &fakeTailnetDialer{target: ln.Addr().String(), known: true}

	dialerManager := NewDialerManager(nil)
	dialerManager.SetTailnetDialer(tailnetDialer)

	st := &dynamic.TCPServersTransport{Tailnet: "corp"}
	st.SetDefaults()
	dialerManager.Update(map[string]*dynamic.TCPServersTransport{"test": st})

	dialer, err := dialerManager.Build(&dynamic.TCPServersLoadBalancer{ServersTransport: "test"}, false)
	require.NoError(t, err)

	// The host is deliberately unresolvable: reaching the backend at all
	// proves the tailnet dialer carried the connection.
	conn, err := dialer.Dial("tcp", "backend.tail0000.ts.net:8080", nil)
	require.NoError(t, err)
	defer conn.Close()

	payload, err := io.ReadAll(conn)
	require.NoError(t, err)

	assert.Equal(t, "tailnet", string(payload))
	assert.Equal(t, "corp", tailnetDialer.seenTailnet)
	assert.Equal(t, "backend.tail0000.ts.net:8080", tailnetDialer.seenAddr)
}

// A TCP transport bound to a tailnet must fail rather than reach the backend
// over the host network.
func TestTCPDialerWithoutTailnetDialerFailsClosed(t *testing.T) {
	ln := echoListener(t, "host")

	dialerManager := NewDialerManager(nil)

	st := &dynamic.TCPServersTransport{Tailnet: "corp"}
	st.SetDefaults()
	dialerManager.Update(map[string]*dynamic.TCPServersTransport{"test": st})

	dialer, err := dialerManager.Build(&dynamic.TCPServersLoadBalancer{ServersTransport: "test"}, false)
	require.NoError(t, err)

	_, err = dialer.Dial("tcp", ln.Addr().String(), nil)
	require.ErrorContains(t, err, "no tailnets configured")
}

// Without a tailnet, nothing about the dial path may change.
func TestTCPDialerWithoutTailnetUsesHostNetwork(t *testing.T) {
	ln := echoListener(t, "host")

	tailnetDialer := &fakeTailnetDialer{target: "127.0.0.1:1", known: true}

	dialerManager := NewDialerManager(nil)
	dialerManager.SetTailnetDialer(tailnetDialer)

	st := &dynamic.TCPServersTransport{}
	st.SetDefaults()
	dialerManager.Update(map[string]*dynamic.TCPServersTransport{"test": st})

	dialer, err := dialerManager.Build(&dynamic.TCPServersLoadBalancer{ServersTransport: "test"}, false)
	require.NoError(t, err)

	conn, err := dialer.Dial("tcp", ln.Addr().String(), nil)
	require.NoError(t, err)
	defer conn.Close()

	payload, err := io.ReadAll(conn)
	require.NoError(t, err)

	assert.Equal(t, "host", string(payload))
	assert.Empty(t, tailnetDialer.seenTailnet)
}
