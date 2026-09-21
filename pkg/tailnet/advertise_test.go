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
	"github.com/traefik/traefik/v3/pkg/config/static"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

func TestRegistryRoutes(t *testing.T) {
	testCases := []struct {
		desc      string
		routes    []string
		expectErr string
		expect    []netip.Prefix
	}{
		{
			desc:   "none",
			routes: nil,
		},
		{
			desc:   "IPv4 and IPv6",
			routes: []string{"100.64.30.0/24", "fd7a:115c:a1e0::/48"},
			expect: []netip.Prefix{
				netip.MustParsePrefix("100.64.30.0/24"),
				netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
			},
		},
		{
			desc:   "single address",
			routes: []string{"100.64.30.5/32"},
			expect: []netip.Prefix{netip.MustParsePrefix("100.64.30.5/32")},
		},
		{
			desc:      "not a prefix",
			routes:    []string{"100.64.30.5"},
			expectErr: `parsing route "100.64.30.5"`,
		},
		{
			desc:      "nonsense",
			routes:    []string{"not-an-address/24"},
			expectErr: `parsing route "not-an-address/24"`,
		},
		{
			// The control plane rejects these, and masking it silently would
			// advertise something other than what was written.
			desc:      "host bits set beyond the prefix length",
			routes:    []string{"100.64.30.5/24"},
			expectErr: `did you mean "100.64.30.0/24"`,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			registry, err := NewRegistry(map[string]*static.Tailnet{
				"corp": {StateDir: t.TempDir(), Routes: test.routes},
			})

			if test.expectErr != "" {
				require.ErrorContains(t, err, test.expectErr)
				return
			}
			require.NoError(t, err)

			node, err := registry.Node("corp")
			require.NoError(t, err)
			assert.Equal(t, test.expect, node.routes)
		})
	}
}

func TestRegistryServices(t *testing.T) {
	testCases := []struct {
		desc       string
		tags       []string
		services   map[string]*static.TailnetService
		expectErr  string
		expectName string
	}{
		{
			desc:       "name defaults to the configuration key",
			tags:       []string{"tag:proxy"},
			services:   map[string]*static.TailnetService{"myapp": {}},
			expectName: "svc:myapp",
		},
		{
			desc:       "explicit name",
			tags:       []string{"tag:proxy"},
			services:   map[string]*static.TailnetService{"myapp": {Name: "svc:something-else"}},
			expectName: "svc:something-else",
		},
		{
			// Only tagged nodes may host a Service, so a configuration that
			// could never work is named here rather than at the first listen.
			desc:      "requires advertiseTags",
			services:  map[string]*static.TailnetService{"myapp": {}},
			expectErr: "requires advertiseTags",
		},
		{
			desc:      "name must carry the svc: prefix",
			tags:      []string{"tag:proxy"},
			services:  map[string]*static.TailnetService{"myapp": {Name: "myapp"}},
			expectErr: "must start with 'svc:'",
		},
		{
			desc:      "name must be a DNS label",
			tags:      []string{"tag:proxy"},
			services:  map[string]*static.TailnetService{"myapp": {Name: "svc:not a label"}},
			expectErr: `invalid name "svc:not a label"`,
		},
		{
			desc:      "nil entry",
			tags:      []string{"tag:proxy"},
			services:  map[string]*static.TailnetService{"myapp": nil},
			expectErr: `service "myapp": missing configuration`,
		},
		{
			desc:      "proxyProtocol out of range",
			tags:      []string{"tag:proxy"},
			services:  map[string]*static.TailnetService{"myapp": {ProxyProtocol: 3}},
			expectErr: "proxyProtocol must be 0, 1 or 2",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			registry, err := NewRegistry(map[string]*static.Tailnet{
				"corp": {StateDir: t.TempDir(), AdvertiseTags: test.tags, Services: test.services},
			})

			if test.expectErr != "" {
				require.ErrorContains(t, err, test.expectErr)
				return
			}
			require.NoError(t, err)

			node, err := registry.Node("corp")
			require.NoError(t, err)

			assert.True(t, node.HasService("myapp"))
			assert.False(t, node.HasService("typo"))
			assert.Equal(t, test.expectName, node.services["myapp"].name.String())
		})
	}
}

// A Service that is not configured must fail by name rather than reach the
// tailnet and be refused there.
func TestListenServiceUnknown(t *testing.T) {
	registry, err := NewRegistry(map[string]*static.Tailnet{
		"corp": {StateDir: t.TempDir(), AdvertiseTags: []string{"tag:proxy"}},
	})
	require.NoError(t, err)
	t.Cleanup(registry.Close)

	node, err := registry.Node("corp")
	require.NoError(t, err)

	_, err = node.ListenService("typo", 443)
	require.ErrorContains(t, err, `unknown Service "typo"`)
}

func TestRegistryServiceModes(t *testing.T) {
	testCases := []struct {
		desc      string
		mode      string
		routes    []string
		expectErr string
		expect    string
	}{
		{
			desc:   "unset defaults to tcp",
			expect: static.TailnetServiceModeTCP,
		},
		{
			desc:   "explicit tcp",
			mode:   static.TailnetServiceModeTCP,
			expect: static.TailnetServiceModeTCP,
		},
		{
			desc:   "tun",
			mode:   static.TailnetServiceModeTUN,
			expect: static.TailnetServiceModeTUN,
		},
		{
			desc:      "unknown mode",
			mode:      "wireguard",
			expectErr: `unknown mode "wireguard"`,
		},
		{
			// A node given a device stops absorbing subnet traffic into its
			// own stack, and the local stack answers for routed addresses
			// instead, so the two coexist.
			desc:   "tun coexists with routes",
			mode:   static.TailnetServiceModeTUN,
			routes: []string{"100.64.30.0/24"},
			expect: static.TailnetServiceModeTUN,
		},
		{
			desc:   "tcp mode coexists with routes",
			mode:   static.TailnetServiceModeTCP,
			routes: []string{"100.64.30.0/24"},
			expect: static.TailnetServiceModeTCP,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			registry, err := NewRegistry(map[string]*static.Tailnet{
				"corp": {
					StateDir:      t.TempDir(),
					AdvertiseTags: []string{"tag:proxy"},
					Routes:        test.routes,
					Services:      map[string]*static.TailnetService{"myapp": {Mode: test.mode}},
				},
			})

			if test.expectErr != "" {
				require.ErrorContains(t, err, test.expectErr)
				return
			}
			require.NoError(t, err)
			t.Cleanup(registry.Close)

			node, err := registry.Node("corp")
			require.NoError(t, err)
			assert.Equal(t, test.expect, node.ServiceMode("myapp"))
			assert.Equal(t, test.expect == static.TailnetServiceModeTUN, node.tun)
		})
	}
}

// A Service in tcp mode must not be reachable through the TUN path, and vice
// versa: the two take delivery of traffic in entirely different ways.
func TestListenServiceTUNRejectsTCPModeService(t *testing.T) {
	registry, err := NewRegistry(map[string]*static.Tailnet{
		"corp": {
			StateDir:      t.TempDir(),
			AdvertiseTags: []string{"tag:proxy"},
			Services:      map[string]*static.TailnetService{"myapp": {Mode: static.TailnetServiceModeTCP}},
		},
	})
	require.NoError(t, err)
	t.Cleanup(registry.Close)

	node, err := registry.Node("corp")
	require.NoError(t, err)

	_, err = node.ListenServiceTUN(t.Context(), "myapp", 443)
	require.ErrorContains(t, err, `is not in "tun" mode`)

	_, err = node.ListenServiceTUN(t.Context(), "typo", 443)
	require.ErrorContains(t, err, `unknown Service "typo"`)
}

func TestRoutedAddr(t *testing.T) {
	testCases := []struct {
		desc   string
		tun    bool
		addr   string
		expect netip.AddrPort
	}{
		{
			desc:   "IPv4 inside a route",
			tun:    true,
			addr:   "100.64.30.5:443",
			expect: netip.MustParseAddrPort("100.64.30.5:443"),
		},
		{
			desc:   "IPv6 inside a route",
			tun:    true,
			addr:   "[fd7a:115c:a1e0:ab12::5]:443",
			expect: netip.MustParseAddrPort("[fd7a:115c:a1e0:ab12::5]:443"),
		},
		{
			desc:   "IPv4-mapped IPv6 is the IPv4 address",
			tun:    true,
			addr:   "[::ffff:100.64.30.5]:443",
			expect: netip.MustParseAddrPort("100.64.30.5:443"),
		},
		{
			desc: "outside every route",
			tun:  true,
			addr: "100.64.31.5:443",
		},
		{
			desc: "the node's own addresses",
			tun:  true,
			addr: ":443",
		},
		{
			// Without a device tsnet takes subnet traffic itself, so its own
			// listener is the one that sees it.
			desc: "a node without a device",
			addr: "100.64.30.5:443",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			node := &Node{
				tun: test.tun,
				routes: []netip.Prefix{
					netip.MustParsePrefix("100.64.30.0/24"),
					netip.MustParsePrefix("fd7a:115c:a1e0:ab12::/64"),
				},
			}

			got, ok := node.routedAddr(test.addr)
			assert.Equal(t, test.expect.IsValid(), ok)
			assert.Equal(t, test.expect, got)
		})
	}
}

// A routed address on a node with a device is served by the local stack,
// which is where the node releases the packets for it. The second stack
// plays the tailnet peer.
func TestRoutedAddressServedByLocalStack(t *testing.T) {
	registry, err := NewRegistry(map[string]*static.Tailnet{
		"corp": {
			StateDir:      t.TempDir(),
			AdvertiseTags: []string{"tag:proxy"},
			Routes:        []string{"100.64.30.0/24"},
			Services:      map[string]*static.TailnetService{"myapp": {Mode: static.TailnetServiceModeTUN}},
		},
	})
	require.NoError(t, err)
	t.Cleanup(registry.Close)

	node, err := registry.Node("corp")
	require.NoError(t, err)

	nodeAddr := netip.MustParseAddr("100.64.0.1")
	peerAddr := netip.MustParseAddr("100.64.0.2")
	local, peer := twoStacks(t, nodeAddr, peerAddr)

	node.mu.Lock()
	node.local = local
	node.mu.Unlock()

	routed := netip.MustParseAddrPort("100.64.30.5:443")

	listener, err := node.listenRoutedTCP(routed)
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

	packets, err := node.listenRoutedUDP(routed)
	require.NoError(t, err)
	t.Cleanup(func() { _ = packets.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := packets.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = packets.WriteTo(buf[:n], from)
		}
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	target, proto := fullAddr(routed)
	conn, err := gonet.DialContextTCP(ctx, peer.ipstack, target, proto)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(15*time.Second)))

	payload := []byte("tcp to a routed address")
	_, err = conn.Write(payload)
	require.NoError(t, err)

	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	assert.Equal(t, payload, got)

	client, err := peer.listenUDP(netip.AddrPortFrom(peerAddr, 0))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(15*time.Second)))

	datagram := []byte("udp to a routed address")
	_, err = client.WriteTo(datagram, net.UDPAddrFromAddrPort(routed))
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, from, err := client.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, datagram, buf[:n])
	assert.Equal(t, routed.String(), from.String())
}
