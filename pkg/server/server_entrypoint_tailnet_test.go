package server

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

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
			Services: map[string]*static.TailnetService{
				"myapp":    {},
				"bothprot": {Mode: static.TailnetServiceModeTUN},
			},
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

// A tcp-mode Service is forwarded as TCP, so QUIC has no packets to read.
func TestTailnetTCPServiceRejectsHTTP3(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8443"
	config.TailnetService = "myapp"
	config.HTTP3 = &static.HTTP3Config{}

	_, err := NewTCPEntryPoint(t.Context(), "websecure", config, nil, nil, testRegistry(t))
	require.ErrorContains(t, err, "http3 is not supported on a Tailscale Service entryPoint in tcp mode")
}

// A Service in TUN mode delivers its UDP to the in-process stack, so HTTP/3
// is served on it like on any other packet conn, bound once it is hosted.
func TestTailnetTUNServiceAllowsHTTP3(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8443"
	config.TailnetService = "bothprot"
	config.HTTP3 = &static.HTTP3Config{}

	entryPoint, err := NewTCPEntryPoint(t.Context(), "websecure", config, nil, nil, testRegistry(t))
	require.NoError(t, err)
	t.Cleanup(func() { entryPoint.Shutdown(t.Context()) })

	require.NotNil(t, entryPoint.http3Server)
	assert.Nil(t, entryPoint.http3Server.http3conn)
	require.Len(t, entryPoint.http3Server.tailnetSources, 1)
	assert.Equal(t, "bothprot", entryPoint.http3Server.tailnetSources[0].service)
}

// Tailscale forwards a tcp-mode Service as TCP, so a UDP entryPoint has
// nothing to accept from one.
func TestTailnetTCPServiceRejectedOnUDPEntryPoint(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8053/udp"
	config.TailnetService = "myapp"
	config.UDP = &static.UDPConfig{}

	_, err := NewUDPEntryPoint(config, "dns", testRegistry(t))
	require.ErrorContains(t, err, `must be in "tun" mode to carry UDP`)
}

// A Service in TUN mode does carry UDP, which is the whole reason the mode
// exists: its packets arrive at the in-process stack rather than being
// forwarded as TCP.
func TestTailnetTUNServiceAcceptedOnUDPEntryPoint(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8053/udp"
	config.TailnetService = "bothprot"
	config.UDP = &static.UDPConfig{}

	entryPoint, err := NewUDPEntryPoint(config, "dns", testRegistry(t))
	require.NoError(t, err)
	require.NotNil(t, entryPoint)
}

// The same Service name on a TCP entryPoint: one Service, both protocols,
// which is what no tcp-mode Service can do.
func TestTailnetTUNServiceAcceptedOnTCPEntryPoint(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8443"
	config.TailnetService = "bothprot"

	listener, err := buildListener(t.Context(), "websecure", config, testRegistry(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	assert.Equal(t, "bothprot:8443", listener.Addr().String())
}

// proxyProtocol is refused on a forwarded Service, where the peer is always
// the loopback forwarder, but allowed in TUN mode, where the peer is the
// client.
func TestTailnetTUNServiceAllowsEntryPointProxyProtocol(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8443"
	config.TailnetService = "bothprot"
	config.ProxyProtocol = &static.ProxyProtocol{Insecure: true}

	listener, err := buildListener(t.Context(), "websecure", config, testRegistry(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
}

// freePort returns a port nothing is bound to on the loopback address. A
// Service listener takes the entryPoint's port, and refuses port 0, so the
// host side of these entryPoints needs a real one.
func freePort(t *testing.T, network string) int {
	t.Helper()

	if network == "udp" {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).Port
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func hostEntryPoint(address string, listeners ...*static.TailnetListener) *static.EntryPoint {
	config := tailnetEntryPoint("")
	config.Address = address
	config.TailnetListeners = listeners
	return config
}

func TestTailnetListenersValidation(t *testing.T) {
	testCases := []struct {
		desc      string
		primary   func(*static.EntryPoint)
		listeners []*static.TailnetListener
		expectErr string
	}{
		{
			desc:      "tailnet is required",
			listeners: []*static.TailnetListener{{Service: "bothprot"}},
			expectErr: "tailnetListeners[0]: tailnet is required",
		},
		{
			desc:      "unknown tailnet",
			listeners: []*static.TailnetListener{{Tailnet: "typo"}},
			expectErr: `tailnetListeners[0]: unknown tailnet "typo"`,
		},
		{
			desc:      "service and address together",
			listeners: []*static.TailnetListener{{Tailnet: "corp", Service: "bothprot", Address: "100.64.30.5"}},
			expectErr: "service and address are mutually exclusive",
		},
		{
			desc:      "unknown service",
			listeners: []*static.TailnetListener{{Tailnet: "corp", Service: "typo"}},
			expectErr: `unknown Tailscale Service "typo"`,
		},
		{
			desc:      "a host name",
			listeners: []*static.TailnetListener{{Tailnet: "corp", Address: "edge.example.com:443"}},
			expectErr: "the host must be an IP",
		},
		{
			desc:      "not an address",
			listeners: []*static.TailnetListener{{Tailnet: "corp", Address: "100.64.30.5/32"}},
			expectErr: "want an IP, an IP and port, or a port alone",
		},
		{
			desc: "a Service taken twice",
			listeners: []*static.TailnetListener{
				{Tailnet: "corp", Service: "bothprot"},
				{Tailnet: "corp", Service: "bothprot"},
			},
			expectErr: `tailnetListeners[1]: Service "bothprot" on tailnet "corp" is already tailnetListeners[0]`,
		},
		{
			desc: "the same address written two ways",
			listeners: []*static.TailnetListener{
				{Tailnet: "corp", Address: "100.64.30.5"},
				{Tailnet: "corp", Address: "100.64.30.5:8443"},
			},
			expectErr: "is already tailnetListeners[0]",
		},
		{
			desc: "the entryPoint's own Service",
			primary: func(config *static.EntryPoint) {
				config.Tailnet = "corp"
				config.TailnetService = "bothprot"
			},
			listeners: []*static.TailnetListener{{Tailnet: "corp", Service: "bothprot"}},
			expectErr: "is already the entryPoint's own address",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := hostEntryPoint("127.0.0.1:8443", test.listeners...)
			if test.primary != nil {
				test.primary(config)
			}

			_, err := buildListener(t.Context(), "websecure", config, testRegistry(t))
			require.ErrorContains(t, err, test.expectErr)
		})
	}
}

func TestTailnetListenerAddress(t *testing.T) {
	testCases := []struct {
		address string
		expect  string
	}{
		{address: "", expect: ":443"},
		{address: "100.64.30.5", expect: "100.64.30.5:443"},
		{address: "fd7a:115c:a1e0::5", expect: "[fd7a:115c:a1e0::5]:443"},
		{address: "100.64.30.5:8443", expect: "100.64.30.5:8443"},
		{address: ":8443", expect: ":8443"},
	}

	for _, test := range testCases {
		t.Run(test.address, func(t *testing.T) {
			got, err := tailnetListenerAddress(&static.EntryPoint{Address: ":443/tcp"}, test.address)
			require.NoError(t, err)
			assert.Equal(t, test.expect, got)
		})
	}
}

// The reason tailnetListeners exist: an edge's public host listener and its
// tailnet listeners are one entryPoint, and the host side serves while the
// tailnet is still unreachable.
func TestHostListenerServesWhileTailnetListenersWait(t *testing.T) {
	config := hostEntryPoint(fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
		&static.TailnetListener{Tailnet: "corp", Service: "bothprot"},
		&static.TailnetListener{Tailnet: "corp", Address: "100.64.30.5"},
	)

	listener, err := buildListener(t.Context(), "websecure", config, testRegistry(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	// The merged listener is known by the entryPoint's own address.
	host, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	assert.True(t, host.IP.IsLoopback())

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	client, err := net.DialTimeout("tcp", host.String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the host listener did not accept while the tailnet listeners waited")
	}

	require.NoError(t, listener.Close())
	_, err = listener.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

// HTTP/3 is served on the host conn and on every tailnet listener that
// carries UDP; a tcp-mode Service does not, and is left out rather than
// refused.
func TestHTTP3SourcesWithTailnetListeners(t *testing.T) {
	port := freePort(t, "udp")
	config := hostEntryPoint(fmt.Sprintf("127.0.0.1:%d", port),
		&static.TailnetListener{Tailnet: "corp", Service: "myapp"},
		&static.TailnetListener{Tailnet: "corp", Service: "bothprot"},
		&static.TailnetListener{Tailnet: "corp", Address: "100.64.30.5"},
	)
	config.HTTP3 = &static.HTTP3Config{}

	entryPoint, err := NewTCPEntryPoint(t.Context(), "websecure", config, nil, nil, testRegistry(t))
	require.NoError(t, err)
	t.Cleanup(func() { entryPoint.Shutdown(t.Context()) })

	require.NotNil(t, entryPoint.http3Server)
	assert.NotNil(t, entryPoint.http3Server.http3conn)

	var got []string
	for _, source := range entryPoint.http3Server.tailnetSources {
		got = append(got, source.description())
	}
	assert.Equal(t, []string{`Service "bothprot" on tailnet "corp"`, fmt.Sprintf(`100.64.30.5:%d on tailnet "corp"`, port)}, got)
}

func TestUDPEntryPointWithTailnetListeners(t *testing.T) {
	config := hostEntryPoint(fmt.Sprintf("127.0.0.1:%d/udp", freePort(t, "udp")), &static.TailnetListener{Tailnet: "corp", Service: "bothprot"})
	config.UDP = &static.UDPConfig{}
	config.UDP.SetDefaults()

	entryPoint, err := NewUDPEntryPoint(config, "stun", testRegistry(t))
	require.NoError(t, err)
	t.Cleanup(func() { entryPoint.Shutdown(t.Context()) })

	assert.Len(t, entryPoint.listeners, 1)
	require.Len(t, entryPoint.tailnetSources, 1)
	assert.Equal(t, "bothprot", entryPoint.tailnetSources[0].service)
}

func TestUDPEntryPointRejectsTCPServiceListener(t *testing.T) {
	config := hostEntryPoint("127.0.0.1:8053/udp", &static.TailnetListener{Tailnet: "corp", Service: "myapp"})
	config.UDP = &static.UDPConfig{}

	_, err := NewUDPEntryPoint(config, "stun", testRegistry(t))
	require.ErrorContains(t, err, `must be in "tun" mode to carry UDP`)
}

// stubListener is a listener whose Accept is scripted: it returns each
// queued result in turn, then blocks until closed.
type stubListener struct {
	results chan acceptResult
	closed  chan struct{}
	once    sync.Once
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func newStubListener(results ...acceptResult) *stubListener {
	l := &stubListener{results: make(chan acceptResult, len(results)), closed: make(chan struct{})}
	for _, r := range results {
		l.results <- r
	}
	return l
}

func (l *stubListener) Accept() (net.Conn, error) {
	select {
	case r := <-l.results:
		return r.conn, r.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *stubListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *stubListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func pipeConn(t *testing.T) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return server
}

// One listener failing for good must not stop the others: a tailnet going
// away leaves the host listener serving.
func TestMergedListenerOutlivesAFailedListener(t *testing.T) {
	failed := newStubListener(acceptResult{err: errors.New("tailnet gone")})
	conn := pipeConn(t)
	healthy := newStubListener()

	merged := newMergedListener(t.Context(), []net.Listener{healthy, failed})
	t.Cleanup(func() { _ = merged.Close() })

	// Give the failed listener's error time to be taken, and dropped.
	time.Sleep(50 * time.Millisecond)
	healthy.results <- acceptResult{conn: conn}

	got, err := merged.Accept()
	require.NoError(t, err)
	assert.Equal(t, conn, got)
}

// A temporary error reaches the accept loop, which logs it and carries on,
// and the listener that raised it keeps accepting.
func TestMergedListenerPassesTemporaryErrors(t *testing.T) {
	temporary := &net.OpError{Op: "accept", Err: &temporaryError{}}
	conn := pipeConn(t)
	listener := newStubListener(acceptResult{err: temporary}, acceptResult{conn: conn})

	merged := newMergedListener(t.Context(), []net.Listener{listener})
	t.Cleanup(func() { _ = merged.Close() })

	_, err := merged.Accept()
	require.ErrorIs(t, err, temporary)

	got, err := merged.Accept()
	require.NoError(t, err)
	assert.Equal(t, conn, got)
}

// Once every listener has failed, Accept fails for good, with the reason.
func TestMergedListenerFailsWhenEveryListenerHas(t *testing.T) {
	cause := errors.New("tailnet gone")
	merged := newMergedListener(t.Context(), []net.Listener{
		newStubListener(acceptResult{err: cause}),
		newStubListener(acceptResult{err: cause}),
	})
	t.Cleanup(func() { _ = merged.Close() })

	_, err := merged.Accept()
	require.ErrorIs(t, err, cause)
}

type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary" }
func (temporaryError) Timeout() bool   { return false }
func (temporaryError) Temporary() bool { return true }
