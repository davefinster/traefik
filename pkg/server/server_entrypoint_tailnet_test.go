package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/tailnet"
)

func testRegistry(t *testing.T) *tailnet.Registry {
	t.Helper()

	registry, err := tailnet.NewRegistry(map[string]*static.Tailnet{
		"corp": {StateDir: t.TempDir()},
	})
	require.NoError(t, err)
	t.Cleanup(registry.Close)

	return registry
}

func tailnetEntryPoint(tailnetName string) *static.EntryPoint {
	epConfig := &static.EntryPointsTransport{}
	epConfig.SetDefaults()

	return &static.EntryPoint{
		Address:          "127.0.0.1:0",
		Tailnet:          tailnetName,
		Transport:        epConfig,
		ForwardedHeaders: &static.ForwardedHeaders{},
		HTTP2:            &static.HTTP2Config{},
	}
}

// A tailnet entryPoint must not block startup on the tailnet: the listener
// comes back straight away and binds on its first Accept.
func TestBuildTailnetListenerDoesNotWaitForTheTailnet(t *testing.T) {
	listener, err := buildListener(t.Context(), "web", tailnetEntryPoint("corp"), testRegistry(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	// Nothing is bound yet, but the address is already reportable.
	require.NotNil(t, listener.Addr())
	assert.Equal(t, "127.0.0.1:0", listener.Addr().String())
}

func TestBuildTailnetListenerUnknownTailnet(t *testing.T) {
	_, err := buildListener(t.Context(), "web", tailnetEntryPoint("typo"), testRegistry(t))
	require.ErrorContains(t, err, `unknown tailnet "typo"`)
}

func TestBuildTailnetListenerWithoutTailnetsConfigured(t *testing.T) {
	_, err := buildListener(t.Context(), "web", tailnetEntryPoint("corp"), nil)
	require.ErrorIs(t, err, tailnet.ErrNoTailnets)
}

// reusePort has no host socket to apply to on a tailnet entryPoint, so it is
// rejected rather than silently ignored.
func TestBuildTailnetListenerRejectsReusePort(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.ReusePort = true

	_, err := buildListener(t.Context(), "web", config, testRegistry(t))
	require.ErrorContains(t, err, "reusePort is not supported on a tailnet entryPoint")
}

func TestNewUDPEntryPointRejectsReusePortOnTailnet(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:0/udp"
	config.ReusePort = true
	config.UDP = &static.UDPConfig{}

	_, err := NewUDPEntryPoint(config, "dns", testRegistry(t))
	require.ErrorContains(t, err, "reusePort is not supported on a tailnet entryPoint")
}

func TestNewUDPEntryPointUnknownTailnet(t *testing.T) {
	config := tailnetEntryPoint("typo")
	config.Address = "127.0.0.1:0/udp"
	config.UDP = &static.UDPConfig{}

	_, err := NewUDPEntryPoint(config, "dns", testRegistry(t))
	require.ErrorContains(t, err, `unknown tailnet "typo"`)
}

// A whole TCP entryPoint, HTTP/3 included, must build without the tailnet
// being reachable.
func TestNewTCPEntryPointOnTailnetBuildsWithoutTheTailnet(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.HTTP3 = &static.HTTP3Config{}

	entryPoint, err := NewTCPEntryPoint(t.Context(), "websecure", config, nil, nil, testRegistry(t))
	require.NoError(t, err)
	t.Cleanup(func() { entryPoint.Shutdown(t.Context()) })

	// The HTTP/3 server exists but has bound nothing: tsnet needs a concrete
	// address per packet conn, and the node has none until it has joined.
	require.NotNil(t, entryPoint.http3Server)
	assert.Nil(t, entryPoint.http3Server.http3conn)
}

// closeWriteConn is a connection that is not a *net.TCPConn but does close
// its write half, which is what a tailnet (userspace netstack) conn is.
type closeWriteConn struct {
	net.Conn
	closedWrite bool
}

func (c *closeWriteConn) CloseWrite() error {
	c.closedWrite = true
	return nil
}

func TestWriteCloserAcceptsTailnetConn(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	conn := &closeWriteConn{Conn: server}

	writeCloser, err := writeCloser(conn)
	require.NoError(t, err)

	require.NoError(t, writeCloser.CloseWrite())
	assert.True(t, conn.closedWrite)
}

// A connection that cannot close its write half is still rejected, rather
// than silently proxied without the half-close the TCP path relies on.
func TestWriteCloserRejectsConnWithoutCloseWrite(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	_, err := writeCloser(server)
	require.ErrorContains(t, err, "unknown connection type")
}
