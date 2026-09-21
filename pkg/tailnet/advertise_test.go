package tailnet

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
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
			// own stack, so advertised routes would go unanswered. Refused
			// rather than half-working.
			desc:      "tun cannot be combined with routes",
			mode:      static.TailnetServiceModeTUN,
			routes:    []string{"100.64.30.0/24"},
			expectErr: "cannot be combined with routes",
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
