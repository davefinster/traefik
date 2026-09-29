package tailnet

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// startControl runs a Tailscale control plane and DERP server in the test,
// as tsnet's own tests do.
func startControl(t *testing.T) (string, *testcontrol.Server) {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	control := &testcontrol.Server{
		DERPMap:        integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"),
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL, control
}

// advertisedRoutes is what the control plane holds as the node's advertised
// routes.
func advertisedRoutes(control *testcontrol.Server, hostname string) ([]netip.Prefix, bool) {
	for _, n := range control.AllNodes() {
		if n.Hostinfo.Hostname() == hostname {
			return n.Hostinfo.RoutableIPs().AsSlice(), true
		}
	}
	return nil, false
}

// Withdrawing takes a node's routes out of the tailnet while it stays joined,
// so peers can move elsewhere before its listeners close; a join still in
// progress does not put them back.
func TestWithdrawTakesRoutesOutWhileStayingJoined(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a control plane")
	}
	controlURL, control := startControl(t)
	route := netip.MustParsePrefix("100.64.30.0/24")

	registry, err := NewRegistry(map[string]*static.Tailnet{
		"corp": {StateDir: t.TempDir(), ControlURL: controlURL, Hostname: "edge", Ephemeral: true, Routes: []string{route.String()}},
	})
	require.NoError(t, err)
	t.Cleanup(registry.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	registry.Start(ctx)

	require.Eventually(t, func() bool {
		routes, _ := advertisedRoutes(control, "edge")
		return slices.Contains(routes, route)
	}, 45*time.Second, 100*time.Millisecond, "the route was never advertised")

	registry.Withdraw(ctx)

	require.Eventually(t, func() bool {
		routes, ok := advertisedRoutes(control, "edge")
		return ok && len(routes) == 0
	}, 10*time.Second, 50*time.Millisecond, "the control plane still holds the route after Withdraw")

	node, err := registry.Node("corp")
	require.NoError(t, err)
	status, err := node.Up(ctx)
	require.NoError(t, err, "the node left the tailnet; it should stay joined while the entryPoints drain")
	require.NotEmpty(t, status.TailscaleIPs)

	// A late re-advertisement -- a join finishing behind the withdrawal --
	// is refused.
	srv, err := node.server()
	require.NoError(t, err)
	require.NoError(t, node.advertiseRoutes(srv))
	time.Sleep(500 * time.Millisecond)
	routes, _ := advertisedRoutes(control, "edge")
	require.Empty(t, routes, "a withdrawn node advertised its routes again")
}

// Withdrawing a registry whose nodes never started, or no registry at all,
// does nothing and does not block.
func TestWithdrawNothingStarted(t *testing.T) {
	var nilRegistry *Registry
	nilRegistry.Withdraw(context.Background())

	registry, err := NewRegistry(map[string]*static.Tailnet{"corp": {StateDir: t.TempDir()}})
	require.NoError(t, err)
	registry.Withdraw(context.Background())
	registry.Close()
}
