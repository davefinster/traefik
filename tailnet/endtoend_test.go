package tailnet

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/observability/metrics"
	"github.com/traefik/traefik/v3/pkg/server"
	tcprouter "github.com/traefik/traefik/v3/pkg/server/router/tcp"
	traefikservice "github.com/traefik/traefik/v3/pkg/server/service"
	"github.com/traefik/traefik/v3/pkg/udp"
)

// tailnetIPv4 waits for the node to join, and returns its IPv4 address on
// the tailnet.
func tailnetIPv4(ctx context.Context, t *testing.T, registry *Registry, name string) netip.Addr {
	t.Helper()

	node, err := registry.Node(name)
	require.NoError(t, err)

	addrs, err := node.Addrs(ctx)
	require.NoError(t, err)

	for _, addr := range addrs {
		if addr.Is4() {
			return addr
		}
	}

	t.Fatalf("node %q has no IPv4 address on the tailnet", name)

	return netip.Addr{}
}

// The whole path, on real nodes joined to a control plane in the test: a
// client on the tailnet reaches an entryPoint that accepts on the tailnet,
// whose handler reaches its server through a serversTransport that dials over
// the tailnet. Nothing of it is on the host network, and everything between
// the registry and the entryPoints and transports goes through the network
// extension point.
func TestTrafficFlowsThroughTheExtensionPoint(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a control plane")
	}

	controlURL, _ := startControl(t)

	tailnets := map[string]*static.Tailnet{}
	for _, name := range []string{"edge", "backend", "client"} {
		tailnets[name] = &static.Tailnet{StateDir: t.TempDir(), ControlURL: controlURL, Hostname: name, Ephemeral: true}
	}

	entryPoints := static.EntryPoints{
		"web": tailnetEntryPoint("edge"),
		"dns": udpEntryPoint(tailnetEntryPoint("edge"), ":8053/udp"),
	}
	entryPoints["web"].Address = ":8080"

	registry, err := New(tailnets, entryPoints)
	require.NoError(t, err)
	t.Cleanup(registry.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	edgeIP := tailnetIPv4(ctx, t, registry, "edge")
	backendIP := tailnetIPv4(ctx, t, registry, "backend")

	// The server: reachable on the backend node's tailnet address only.
	backendNode, err := registry.Node("backend")
	require.NoError(t, err)

	backendListener, err := backendNode.Listen("tcp", ":9090")
	require.NoError(t, err)

	backend := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			_, _ = rw.Write([]byte("served by the backend to " + req.Header.Get("X-Asked-By")))
		}),
	}
	go func() { _ = backend.Serve(backendListener) }()
	t.Cleanup(func() { _ = backend.Close() })

	// Traefik's side: a serversTransport that dials over the edge tailnet...
	transportManager := traefikservice.NewTransportManager(nil)
	transportManager.SetNetworks(registry)
	transportManager.Update(map[string]*dynamic.ServersTransport{"tailnet": {Tailnet: "edge"}})

	roundTripper, err := transportManager.GetRoundTripper("tailnet")
	require.NoError(t, err)

	// ...and entryPoints that accept on it.
	tcpEntryPoints, err := server.NewTCPEntryPoints(entryPoints, nil, metrics.NewVoidRegistry(), registry)
	require.NoError(t, err)
	t.Cleanup(tcpEntryPoints.Stop)

	udpEntryPoints, err := server.NewUDPEntryPoints(entryPoints, registry)
	require.NoError(t, err)
	t.Cleanup(udpEntryPoints.Stop)

	router, err := tcprouter.NewRouter(nil)
	require.NoError(t, err)

	router.SetHTTPHandler(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		out, err := http.NewRequestWithContext(req.Context(), http.MethodGet, "http://"+netip.AddrPortFrom(backendIP, 9090).String()+"/", http.NoBody)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		out.Header.Set("X-Asked-By", req.Header.Get("X-Asked-By"))

		resp, err := roundTripper.RoundTrip(out)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		rw.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(rw, resp.Body)
	}))

	tcpEntryPoints.Start()
	tcpEntryPoints["web"].SwitchRouter(router)

	udpEntryPoints.Start()
	udpEntryPoints.Switch(map[string]udp.Handler{"dns": udp.HandlerFunc(func(conn *udp.Conn) {
		for {
			b := make([]byte, 1024)
			n, err := conn.Read(b)
			if err != nil {
				return
			}

			_, _ = conn.Write(b[:n])
		}
	})})

	// The client: a third node, which has no way to either entryPoint but
	// over the tailnet.
	clientNode, err := registry.Node("client")
	require.NoError(t, err)

	_, err = clientNode.Up(ctx)
	require.NoError(t, err)

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: clientNode.DialContext},
	}
	t.Cleanup(client.CloseIdleConnections)

	// The entryPoints bind lazily, once the edge node has joined.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+netip.AddrPortFrom(edgeIP, 8080).String()+"/", http.NoBody)
		if !assert.NoError(c, err) {
			return
		}
		req.Header.Set("X-Asked-By", "the client")

		resp, err := client.Do(req)
		if !assert.NoError(c, err) {
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if !assert.NoError(c, err) {
			return
		}

		assert.Equal(c, http.StatusOK, resp.StatusCode)
		assert.Equal(c, "served by the backend to the client", string(body))
	}, time.Minute, 500*time.Millisecond)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		conn, err := clientNode.DialContext(ctx, "udp", netip.AddrPortFrom(edgeIP, 8053).String())
		if !assert.NoError(c, err) {
			return
		}
		defer conn.Close()

		if !assert.NoError(c, conn.SetDeadline(time.Now().Add(2*time.Second))) {
			return
		}

		_, err = conn.Write([]byte("over udp"))
		if !assert.NoError(c, err) {
			return
		}

		b := make([]byte, 1024)
		n, err := conn.Read(b)
		if !assert.NoError(c, err) {
			return
		}

		assert.Equal(c, "over udp", string(b[:n]))
	}, time.Minute, 500*time.Millisecond)
}
