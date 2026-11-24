package tailnet

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
	"github.com/traefik/traefik/v3/pkg/observability/metrics"
	"github.com/traefik/traefik/v3/pkg/server"
)

func testTailnets(t *testing.T) map[string]*static.Tailnet {
	t.Helper()

	return map[string]*static.Tailnet{
		"corp": {
			StateDir:      t.TempDir(),
			AdvertiseTags: []string{"tag:proxy"},
			Services: map[string]*static.TailnetService{
				"myapp":    {},
				"bothprot": {Mode: static.TailnetServiceModeTUN},
			},
		},
	}
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()

	registry, err := NewRegistry(testTailnets(t))
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

func udpEntryPoint(config *static.EntryPoint, address string) *static.EntryPoint {
	config.Address = address
	config.UDP = &static.UDPConfig{}
	config.UDP.SetDefaults()

	return config
}

func hostEntryPoint(address string, listeners ...*static.TailnetListener) *static.EntryPoint {
	config := tailnetEntryPoint("")
	config.Address = address
	config.TailnetListeners = listeners

	return config
}

// freePort returns a TCP port nothing is bound to on the loopback address. A
// Service listener takes the entryPoint's port, and refuses port 0, so the
// host side of such an entryPoint needs a real one.
func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	return ln.Addr().(*net.TCPAddr).Port
}

func names(sources []network.Source) []string {
	var names []string
	for _, src := range sources {
		names = append(names, src.String())
	}

	return names
}

// A tailnet entryPoint must not block startup on the tailnet: the listener
// comes back straight away and binds on its first Accept.
func TestSourceListenDoesNotWaitForTheTailnet(t *testing.T) {
	sources, err := testRegistry(t).resolveEntryPoint(tailnetEntryPoint("corp"))
	require.NoError(t, err)

	require.NotNil(t, sources.Primary)
	assert.Empty(t, sources.Additional)

	listener := sources.Primary.Listen(t.Context())
	t.Cleanup(func() { _ = listener.Close() })

	// Nothing is bound yet, but the address is already reportable.
	require.NotNil(t, listener.Addr())
	assert.Equal(t, "127.0.0.1:0", listener.Addr().String())
}

func TestResolveEntryPointOnTheHost(t *testing.T) {
	sources, err := testRegistry(t).resolveEntryPoint(tailnetEntryPoint(""))
	require.NoError(t, err)

	assert.Equal(t, network.Sources{}, sources)
}

func TestResolveEntryPointUnknownTailnet(t *testing.T) {
	_, err := testRegistry(t).resolveEntryPoint(tailnetEntryPoint("typo"))
	require.ErrorContains(t, err, `unknown tailnet "typo"`)
}

func TestResolveEntryPointWithoutTailnetsConfigured(t *testing.T) {
	var registry *Registry

	_, err := registry.resolveEntryPoint(tailnetEntryPoint("corp"))
	require.ErrorIs(t, err, ErrNoTailnets)
}

// reusePort has no host socket to apply to on a tailnet entryPoint, so it is
// rejected rather than silently ignored.
func TestResolveEntryPointRejectsReusePort(t *testing.T) {
	testCases := []struct {
		desc   string
		config *static.EntryPoint
	}{
		{desc: "tcp", config: tailnetEntryPoint("corp")},
		{desc: "udp", config: udpEntryPoint(tailnetEntryPoint("corp"), "127.0.0.1:0/udp")},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			test.config.ReusePort = true

			_, err := testRegistry(t).resolveEntryPoint(test.config)
			require.ErrorContains(t, err, "reusePort is not supported on a tailnet entryPoint")
		})
	}
}

func TestResolveUDPEntryPointUnknownTailnet(t *testing.T) {
	_, err := testRegistry(t).resolveEntryPoint(udpEntryPoint(tailnetEntryPoint("typo"), "127.0.0.1:0/udp"))
	require.ErrorContains(t, err, `unknown tailnet "typo"`)
}

// A Service entryPoint binds the Service rather than the node's own
// addresses, and must not wait for the tailnet to do it.
func TestServiceSourceListenDoesNotWait(t *testing.T) {
	testCases := []struct {
		desc    string
		service string
	}{
		{desc: "tcp mode", service: "myapp"},
		// The same Service name on a TCP entryPoint and a UDP one: one
		// Service, both protocols, which is what no tcp-mode Service can do.
		{desc: "tun mode", service: "bothprot"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := tailnetEntryPoint("corp")
			config.Address = "127.0.0.1:8443"
			config.TailnetService = test.service

			sources, err := testRegistry(t).resolveEntryPoint(config)
			require.NoError(t, err)
			require.NotNil(t, sources.Primary)

			listener := sources.Primary.Listen(t.Context())
			t.Cleanup(func() { _ = listener.Close() })

			// The address stands in for the Service until it is hosted.
			require.NotNil(t, listener.Addr())
			assert.Equal(t, test.service+":8443", listener.Addr().String())
		})
	}
}

func TestResolveEntryPointUnknownService(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:8443"
	config.TailnetService = "typo"

	_, err := testRegistry(t).resolveEntryPoint(config)
	require.ErrorContains(t, err, `unknown Tailscale Service "typo"`)
}

func TestTailnetServiceRequiresATailnet(t *testing.T) {
	config := tailnetEntryPoint("")
	config.TailnetService = "myapp"

	_, err := testRegistry(t).resolveEntryPoint(config)
	require.ErrorContains(t, err, "tailnetService requires the entryPoint to name a tailnet")
}

// A Service is advertised on a named port, so an entryPoint that lets the
// kernel choose one has nothing to advertise.
func TestTailnetServiceRejectsPortZero(t *testing.T) {
	config := tailnetEntryPoint("corp")
	config.Address = "127.0.0.1:0"
	config.TailnetService = "myapp"

	_, err := testRegistry(t).resolveEntryPoint(config)
	require.ErrorContains(t, err, "must name the port it advertises")
}

// The entryPoint's own proxyProtocol judges the peer, which for a forwarded
// Service is always the loopback forwarder, so the two must not be combined.
// In TUN mode the peer is the client, and the option is allowed.
func TestTailnetServiceAndEntryPointProxyProtocol(t *testing.T) {
	testCases := []struct {
		desc      string
		service   string
		expectErr string
	}{
		{desc: "tcp mode", service: "myapp", expectErr: "use the Service's own proxyProtocol option"},
		{desc: "tun mode", service: "bothprot"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := tailnetEntryPoint("corp")
			config.Address = "127.0.0.1:8443"
			config.TailnetService = test.service
			config.ProxyProtocol = &static.ProxyProtocol{Insecure: true}

			_, err := testRegistry(t).resolveEntryPoint(config)
			if test.expectErr != "" {
				require.ErrorContains(t, err, test.expectErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

// A tcp-mode Service is forwarded as TCP, so QUIC has no packets to read. A
// Service in TUN mode delivers its UDP to the in-process stack, so HTTP/3 is
// served on it like on any other packet conn, bound once it is hosted.
func TestTailnetServiceAndHTTP3(t *testing.T) {
	testCases := []struct {
		desc      string
		service   string
		expectErr string
	}{
		{desc: "tcp mode", service: "myapp", expectErr: "http3 is not supported on a Tailscale Service entryPoint in tcp mode"},
		{desc: "tun mode", service: "bothprot"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := tailnetEntryPoint("corp")
			config.Address = "127.0.0.1:8443"
			config.TailnetService = test.service
			config.HTTP3 = &static.HTTP3Config{}

			sources, err := testRegistry(t).resolveEntryPoint(config)
			if test.expectErr != "" {
				require.ErrorContains(t, err, test.expectErr)
				return
			}
			require.NoError(t, err)

			require.NotNil(t, sources.Primary)
			assert.True(t, sources.Primary.CarriesPackets())
			assert.Equal(t, `Service "bothprot" on tailnet "corp"`, sources.Primary.String())
		})
	}
}

// Tailscale forwards a tcp-mode Service as TCP, so a UDP entryPoint has
// nothing to accept from one. A Service in TUN mode does carry UDP, which is
// the whole reason the mode exists: its packets arrive at the in-process
// stack rather than being forwarded as TCP.
func TestTailnetServiceOnUDPEntryPoint(t *testing.T) {
	testCases := []struct {
		desc      string
		service   string
		expectErr string
	}{
		{desc: "tcp mode", service: "myapp", expectErr: `must be in "tun" mode to carry UDP`},
		{desc: "tun mode", service: "bothprot"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := udpEntryPoint(tailnetEntryPoint("corp"), "127.0.0.1:8053/udp")
			config.TailnetService = test.service

			sources, err := testRegistry(t).resolveEntryPoint(config)
			if test.expectErr != "" {
				require.ErrorContains(t, err, test.expectErr)
				return
			}
			require.NoError(t, err)

			require.NotNil(t, sources.Primary)
			assert.True(t, sources.Primary.CarriesPackets())
		})
	}
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

			_, err := testRegistry(t).resolveEntryPoint(config)
			require.ErrorContains(t, err, test.expectErr)
		})
	}
}

func TestListenerAddress(t *testing.T) {
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
			got, err := listenerAddress(&static.EntryPoint{Address: ":443/tcp"}, test.address)
			require.NoError(t, err)
			assert.Equal(t, test.expect, got)
		})
	}
}

// The reason tailnetListeners exist: an edge's public host listener and its
// tailnet listeners are one entryPoint. The entryPoint keeps its own address
// on the host, and every listener is an additional source. HTTP/3 is then
// served on every one that carries UDP; a tcp-mode Service does not, and is
// left out by the entryPoint rather than refused here.
func TestTailnetListenersAreAdditionalSources(t *testing.T) {
	config := hostEntryPoint("127.0.0.1:8443",
		&static.TailnetListener{Tailnet: "corp", Service: "myapp"},
		&static.TailnetListener{Tailnet: "corp", Service: "bothprot"},
		&static.TailnetListener{Tailnet: "corp", Address: "100.64.30.5"},
	)
	config.HTTP3 = &static.HTTP3Config{}

	sources, err := testRegistry(t).resolveEntryPoint(config)
	require.NoError(t, err)

	assert.Nil(t, sources.Primary)
	assert.Equal(t, []string{
		`Service "myapp" on tailnet "corp"`,
		`Service "bothprot" on tailnet "corp"`,
		`100.64.30.5:8443 on tailnet "corp"`,
	}, names(sources.Additional))

	var carryPackets []bool
	for _, src := range sources.Additional {
		carryPackets = append(carryPackets, src.CarriesPackets())
	}
	assert.Equal(t, []bool{false, true, true}, carryPackets)
}

func TestTailnetListenersOnUDPEntryPoint(t *testing.T) {
	testCases := []struct {
		desc      string
		service   string
		expectErr string
	}{
		{desc: "tcp mode", service: "myapp", expectErr: `must be in "tun" mode to carry UDP`},
		{desc: "tun mode", service: "bothprot"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := udpEntryPoint(hostEntryPoint("", &static.TailnetListener{Tailnet: "corp", Service: test.service}), "127.0.0.1:8053/udp")

			sources, err := testRegistry(t).resolveEntryPoint(config)
			if test.expectErr != "" {
				require.ErrorContains(t, err, test.expectErr)
				return
			}
			require.NoError(t, err)

			assert.Nil(t, sources.Primary)
			assert.Equal(t, []string{fmt.Sprintf("Service %q on tailnet %q", test.service, "corp")}, names(sources.Additional))
		})
	}
}

// The registry is handed to the entryPoints as their network extension, and
// whole entryPoints, HTTP/3 and UDP included, must build on it without the
// tailnet being reachable: tsnet needs a concrete address per packet conn,
// and the node has none until it has joined.
func TestEntryPointsBuildOnTheRegistryWithoutTheTailnet(t *testing.T) {
	websecure := tailnetEntryPoint("corp")
	websecure.HTTP3 = &static.HTTP3Config{}

	edge := hostEntryPoint(fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		&static.TailnetListener{Tailnet: "corp", Service: "bothprot"},
		&static.TailnetListener{Tailnet: "corp", Address: "100.64.30.5"},
	)

	entryPoints := static.EntryPoints{
		"websecure": websecure,
		"edge":      edge,
		"dns":       udpEntryPoint(tailnetEntryPoint("corp"), "127.0.0.1:8053/udp"),
		"host":      tailnetEntryPoint(""),
	}

	registry, err := New(testTailnets(t), entryPoints)
	require.NoError(t, err)
	t.Cleanup(registry.Close)

	assert.NotNil(t, registry.Sources("websecure").Primary)
	assert.Len(t, registry.Sources("edge").Additional, 2)
	assert.NotNil(t, registry.Sources("dns").Primary)
	assert.Equal(t, network.Sources{}, registry.Sources("host"))
	assert.Equal(t, network.Sources{}, registry.Sources("unknown"))

	tcpEntryPoints, err := server.NewTCPEntryPoints(entryPoints, nil, metrics.NewVoidRegistry(), registry)
	require.NoError(t, err)
	t.Cleanup(tcpEntryPoints.Stop)

	assert.Len(t, tcpEntryPoints, 3)

	udpEntryPoints, err := server.NewUDPEntryPoints(entryPoints, registry)
	require.NoError(t, err)
	t.Cleanup(udpEntryPoints.Stop)

	assert.Len(t, udpEntryPoints, 1)
}

func TestNewRefusesAnEntryPointItCannotServe(t *testing.T) {
	testCases := []struct {
		desc      string
		tailnets  map[string]*static.Tailnet
		expectErr string
	}{
		{
			desc:      "an unknown tailnet",
			tailnets:  testTailnets(t),
			expectErr: `error while building entryPoint web: unknown tailnet "typo"`,
		},
		{
			desc:      "no tailnet at all",
			expectErr: "error while building entryPoint web: no tailnets configured",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			_, err := New(test.tailnets, static.EntryPoints{"web": tailnetEntryPoint("typo")})
			require.EqualError(t, err, test.expectErr)
		})
	}
}

// Without tailnets there is no registry, and the nil one is still the
// extension: it serves no entryPoint.
func TestNewWithoutTailnets(t *testing.T) {
	registry, err := New(nil, static.EntryPoints{"web": tailnetEntryPoint("")})
	require.NoError(t, err)

	assert.Nil(t, registry)
	assert.Equal(t, network.Sources{}, registry.Sources("web"))
}
