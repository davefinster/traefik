package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ptypes "github.com/traefik/paerser/types"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/network"
)

// fakeNetworks is a networks extension that answers for one serversTransport,
// and reaches a fixed local address whatever the address it is asked for.
type fakeNetworks struct {
	network.Nop

	served *dynamic.TCPServersTransport
	target string
	err    error

	seenAddr string
}

func (f *fakeNetworks) TCPDialer(serversTransport *dynamic.TCPServersTransport) (network.DialContextFunc, bool) {
	if serversTransport != f.served {
		return nil, false
	}

	return func(ctx context.Context, netw, addr string) (net.Conn, error) {
		f.seenAddr = addr

		if f.err != nil {
			return nil, f.err
		}

		return (&net.Dialer{}).DialContext(ctx, netw, f.target)
	}, true
}

// payloadListener answers one connection with a fixed payload.
func payloadListener(t *testing.T, payload string) net.Listener {
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

func defaultTCPServersTransport() *dynamic.TCPServersTransport {
	serversTransport := &dynamic.TCPServersTransport{}
	serversTransport.SetDefaults()

	return serversTransport
}

func TestDialerDialsThroughTheNetworksExtension(t *testing.T) {
	ln := payloadListener(t, "extension")

	serversTransport := defaultTCPServersTransport()
	networks := &fakeNetworks{served: serversTransport, target: ln.Addr().String()}

	dialerManager := NewDialerManager(nil)
	dialerManager.SetNetworks(networks)
	dialerManager.Update(map[string]*dynamic.TCPServersTransport{"test": serversTransport})

	dialer, err := dialerManager.Build(&dynamic.TCPServersLoadBalancer{ServersTransport: "test"}, false)
	require.NoError(t, err)

	// The host is deliberately unresolvable:
	// reaching the server at all proves the extension carried the connection.
	conn, err := dialer.Dial("tcp", "backend.invalid:8080", nil)
	require.NoError(t, err)
	defer conn.Close()

	payload, err := io.ReadAll(conn)
	require.NoError(t, err)

	assert.Equal(t, "extension", string(payload))
	assert.Equal(t, "backend.invalid:8080", networks.seenAddr)
}

// A transport the extension answers for must never quietly fall back to the host network.
func TestDialerOfTheNetworksExtensionNeverFallsBackToTheHostNetwork(t *testing.T) {
	// The target is reachable over the host network: the dial must still fail.
	ln := payloadListener(t, "host")

	serversTransport := defaultTCPServersTransport()
	networks := &fakeNetworks{served: serversTransport, err: errors.New("network unavailable")}

	dialerManager := NewDialerManager(nil)
	dialerManager.SetNetworks(networks)
	dialerManager.Update(map[string]*dynamic.TCPServersTransport{"test": serversTransport})

	dialer, err := dialerManager.Build(&dynamic.TCPServersLoadBalancer{ServersTransport: "test"}, false)
	require.NoError(t, err)

	_, err = dialer.Dial("tcp", ln.Addr().String(), nil)
	require.ErrorContains(t, err, "network unavailable")
}

// The extension's dial has no timeout of its own, so the transport's is applied to it.
func TestDialerBoundsTheNetworksExtensionDialWithItsDialTimeout(t *testing.T) {
	serversTransport := defaultTCPServersTransport()
	serversTransport.DialTimeout = ptypes.Duration(50 * time.Millisecond)

	dialerManager := NewDialerManager(nil)
	dialerManager.SetNetworks(blockingNetworks{})
	dialerManager.Update(map[string]*dynamic.TCPServersTransport{"test": serversTransport})

	dialer, err := dialerManager.Build(&dynamic.TCPServersLoadBalancer{ServersTransport: "test"}, false)
	require.NoError(t, err)

	start := time.Now()
	_, err = dialer.Dial("tcp", "backend.invalid:8080", nil)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
}

// blockingNetworks answers for every serversTransport with a dial that never completes by itself,
// as a network that is not up does.
type blockingNetworks struct {
	network.Nop
}

func (blockingNetworks) TCPDialer(*dynamic.TCPServersTransport) (network.DialContextFunc, bool) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, true
}

// Without an answer from the extension, nothing about the dial path may change.
func TestDialerTheNetworksExtensionDoesNotAnswerForUsesTheHostNetwork(t *testing.T) {
	ln := payloadListener(t, "host")

	networks := &fakeNetworks{served: defaultTCPServersTransport(), target: "127.0.0.1:1"}

	dialerManager := NewDialerManager(nil)
	dialerManager.SetNetworks(networks)
	dialerManager.Update(map[string]*dynamic.TCPServersTransport{"test": defaultTCPServersTransport()})

	dialer, err := dialerManager.Build(&dynamic.TCPServersLoadBalancer{ServersTransport: "test"}, false)
	require.NoError(t, err)

	conn, err := dialer.Dial("tcp", ln.Addr().String(), nil)
	require.NoError(t, err)
	defer conn.Close()

	payload, err := io.ReadAll(conn)
	require.NoError(t, err)

	assert.Equal(t, "host", string(payload))
	assert.Empty(t, networks.seenAddr)
}
