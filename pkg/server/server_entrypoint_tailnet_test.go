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
		"corp": {
			StateDir:      t.TempDir(),
			AdvertiseTags: []string{"tag:proxy"},
			Services:      map[string]*static.TailnetService{"myapp": {}},
		},
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

// A Service entryPoint binds the Service rather than the node's own
// addresses, and must not wait for the tailnet to do it.
func TestBuildTailnetServiceListenerDoesNotWait(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8443"
	config.TailnetService = "myapp"

	listener, err := buildListener(t.Context(), "websecure", config, testRegistry(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	// The address stands in for the Service until it is hosted.
	require.NotNil(t, listener.Addr())
	assert.Equal(t, "myapp:8443", listener.Addr().String())
}

func TestBuildTailnetServiceListenerUnknownService(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8443"
	config.TailnetService = "typo"

	_, err := buildListener(t.Context(), "websecure", config, testRegistry(t))
	require.ErrorContains(t, err, `unknown Tailscale Service "typo"`)
}

func TestTailnetServiceRequiresATailnet(t *testing.T) {
	config := tailnetEntryPoint("")
	config.TailnetService = "myapp"

	_, err := buildListener(t.Context(), "websecure", config, testRegistry(t))
	require.ErrorContains(t, err, "tailnetService requires the entryPoint to name a tailnet")
}

// A Service is advertised on a named port, so an entryPoint that lets the
// kernel choose one has nothing to advertise.
func TestTailnetServiceRejectsPortZero(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:0"
	config.TailnetService = "myapp"

	_, err := buildListener(t.Context(), "websecure", config, testRegistry(t))
	require.ErrorContains(t, err, "must name the port it advertises")
}

// The entryPoint's own proxyProtocol judges the peer, which for a Service is
// always the loopback forwarder, so the two must not be combined.
func TestTailnetServiceRejectsEntryPointProxyProtocol(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8443"
	config.TailnetService = "myapp"
	config.ProxyProtocol = &static.ProxyProtocol{Insecure: true}

	_, err := buildListener(t.Context(), "websecure", config, testRegistry(t))
	require.ErrorContains(t, err, "use the Service's own proxyProtocol option")
}

func TestTailnetServiceRejectsHTTP3(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8443"
	config.TailnetService = "myapp"
	config.HTTP3 = &static.HTTP3Config{}

	_, err := NewTCPEntryPoint(t.Context(), "websecure", config, nil, nil, testRegistry(t))
	require.ErrorContains(t, err, "http3 is not supported on a Tailscale Service entryPoint")
}

func TestTailnetServiceRejectedOnUDPEntryPoint(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8053/udp"
	config.TailnetService = "myapp"
	config.UDP = &static.UDPConfig{}

	_, err := NewUDPEntryPoint(config, "dns", testRegistry(t))
	require.ErrorContains(t, err, "tailnetService is not supported on a UDP entryPoint")
}
