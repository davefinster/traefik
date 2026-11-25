package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ptypes "github.com/traefik/paerser/types"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
	"github.com/traefik/traefik/v3/pkg/observability/metrics"
	"github.com/traefik/traefik/v3/pkg/proxy/httputil"
	"github.com/traefik/traefik/v3/pkg/server/middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// fakeNetworks is a networks extension that answers for the serversTransport of one name,
// and reaches a fixed local address whatever the address it is asked for.
type fakeNetworks struct {
	network.Nop

	served string
	target string
	err    error

	seenAddr string
}

func (f *fakeNetworks) HTTPDialer(name string, _ *dynamic.ServersTransport) (network.DialContextFunc, bool) {
	if name != f.served {
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

func teapotServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	return srv
}

func TestTransportDialsThroughTheNetworksExtension(t *testing.T) {
	testCases := []struct {
		desc             string
		serversTransport *dynamic.ServersTransport
	}{
		{
			desc:             "default transport",
			serversTransport: &dynamic.ServersTransport{},
		},
		{
			// The forwarding timeouts path rebuilds DialContext,
			// and must rebuild it from the extension's dial rather than from the host dialer it replaced.
			desc:             "with forwarding timeouts",
			serversTransport: &dynamic.ServersTransport{ForwardingTimeouts: &dynamic.ForwardingTimeouts{}},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			srv := teapotServer(t)

			networks := &fakeNetworks{served: "test", target: srv.Listener.Addr().String()}

			transportManager := NewTransportManager(nil)
			transportManager.SetNetworks(networks)
			transportManager.Update(map[string]*dynamic.ServersTransport{"test": test.serversTransport})

			rt, err := transportManager.GetRoundTripper("test")
			require.NoError(t, err)

			// The host is deliberately unresolvable: only the extension can carry this request,
			// so a pass proves the host network was not used.
			req, err := http.NewRequest(http.MethodGet, "http://backend.invalid:8080/", http.NoBody)
			require.NoError(t, err)

			res, err := rt.RoundTrip(req)
			require.NoError(t, err)
			defer res.Body.Close()

			assert.Equal(t, http.StatusTeapot, res.StatusCode)
			assert.Equal(t, "backend.invalid:8080", networks.seenAddr)
		})
	}
}

// A transport the extension answers for must never quietly fall back to the host network.
func TestTransportOfTheNetworksExtensionNeverFallsBackToTheHostNetwork(t *testing.T) {
	// The target is reachable over the host network: the request must still fail.
	srv := teapotServer(t)

	serversTransport := &dynamic.ServersTransport{}
	networks := &fakeNetworks{served: "test", err: errors.New("network unavailable")}

	transportManager := NewTransportManager(nil)
	transportManager.SetNetworks(networks)
	transportManager.Update(map[string]*dynamic.ServersTransport{"test": serversTransport})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, srv.URL, http.NoBody)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req) //nolint:bodyclose // the request must fail
	require.ErrorContains(t, err, "network unavailable")
}

// The extension's dial has no timeout of its own, so the transport's is applied to it.
func TestTransportBoundsTheNetworksExtensionDialWithItsDialTimeout(t *testing.T) {
	serversTransport := &dynamic.ServersTransport{
		ForwardingTimeouts: &dynamic.ForwardingTimeouts{DialTimeout: ptypes.Duration(50 * time.Millisecond)},
	}

	transportManager := NewTransportManager(nil)
	transportManager.SetNetworks(blockingNetworks{})
	transportManager.Update(map[string]*dynamic.ServersTransport{"test": serversTransport})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "http://backend.invalid:8080/", http.NoBody)
	require.NoError(t, err)

	start := time.Now()
	_, err = rt.RoundTrip(req) //nolint:bodyclose // the request must fail

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
}

// blockingNetworks answers for every serversTransport with a dial that never completes by itself,
// as a network that is not up does.
type blockingNetworks struct {
	network.Nop
}

func (blockingNetworks) HTTPDialer(string, *dynamic.ServersTransport) (network.DialContextFunc, bool) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, true
}

// Without an answer from the extension, nothing about the dial path may change.
func TestTransportTheNetworksExtensionDoesNotAnswerForUsesTheHostNetwork(t *testing.T) {
	srv := teapotServer(t)

	networks := &fakeNetworks{served: "other", target: "127.0.0.1:1"}

	transportManager := NewTransportManager(nil)
	transportManager.SetNetworks(networks)
	transportManager.Update(map[string]*dynamic.ServersTransport{"test": {}})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, srv.URL, http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, http.StatusTeapot, res.StatusCode)
	assert.Empty(t, networks.seenAddr)
}

func TestTransportManager_GetDialContext(t *testing.T) {
	testCases := []struct {
		desc     string
		served   string
		name     string
		expectOK bool
	}{
		{desc: "a transport the extension answers for", served: "served@file", name: "served@file", expectOK: true},
		{desc: "a transport it does not answer for", served: "served@file", name: "host@file"},
		{desc: "a transport that does not exist", served: "unknown@file", name: "unknown@file"},
		{desc: "the default transport, by its name", served: "default@internal", name: "default@internal", expectOK: true},
		{desc: "the default transport, for a service that names none", served: "default@internal", name: "", expectOK: true},
		{desc: "the default transport, when the extension answers for another", served: "served@file", name: ""},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			transportManager := NewTransportManager(nil)
			transportManager.SetNetworks(&fakeNetworks{served: test.served, target: "127.0.0.1:1"})

			// Twice, with settings that are the same and structs that are not:
			// the transports are not rebuilt, and the extension must still tell them apart, which only the name allows.
			for range 2 {
				transportManager.Update(map[string]*dynamic.ServersTransport{
					"served@file":      {},
					"host@file":        {},
					"default@internal": {},
				})
			}

			dialContext, ok := transportManager.GetDialContext(test.name)
			assert.Equal(t, test.expectOK, ok)
			assert.Equal(t, test.expectOK, dialContext != nil)
		})
	}

	// Without an extension, every transport dials over the host network.
	hostOnly := NewTransportManager(nil)
	hostOnly.Update(map[string]*dynamic.ServersTransport{"served@file": {}})

	_, ok := hostOnly.GetDialContext("served@file")
	assert.False(t, ok)
}

// The proxies of the environment are the host network's way out, and not the extension's:
// a transport the extension answers for must dial its servers, not the proxy.
//
// net/http reads the environment once per process, so the request is made in a process of its own.
func TestTransportOfTheNetworksExtensionIgnoresTheProxiesOfTheEnvironment(t *testing.T) {
	if os.Getenv("TRAEFIK_TEST_ENV_PROXY") == "" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
		cmd.Env = append(os.Environ(), "TRAEFIK_TEST_ENV_PROXY=1", "HTTP_PROXY=http://192.0.2.1:3128", "NO_PROXY=")

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))

		return
	}

	srv := teapotServer(t)

	networks := &fakeNetworks{served: "test", target: srv.Listener.Addr().String()}

	transportManager := NewTransportManager(nil)
	transportManager.SetNetworks(networks)
	transportManager.Update(map[string]*dynamic.ServersTransport{"test": {}})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "http://backend.invalid:8080/", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer res.Body.Close()

	// Through the proxy, the extension would have been asked for 192.0.2.1:3128.
	assert.Equal(t, "backend.invalid:8080", networks.seenAddr)
}

// dialedNetworks answers for every serversTransport, and tells which addresses it was asked to dial.
type dialedNetworks struct {
	network.Nop

	target string
	dialed chan string
}

func (d *dialedNetworks) HTTPDialer(string, *dynamic.ServersTransport) (network.DialContextFunc, bool) {
	return func(ctx context.Context, netw, addr string) (net.Conn, error) {
		select {
		case d.dialed <- addr:
		default:
		}

		return (&net.Dialer{}).DialContext(ctx, netw, d.target)
	}, true
}

// The gRPC health check of a service dials by itself, and not through the round tripper of the transport:
// it must be handed the dial of the extension, or it would look for the servers on the host network.
func TestManagerHandsTheNetworksExtensionDialToTheGRPCHealthCheck(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	healthpb.RegisterHealthServer(server, health.NewServer())

	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	networks := &dialedNetworks{target: listener.Addr().String(), dialed: make(chan string, 1)}

	transportManager := NewTransportManager(nil)
	transportManager.SetNetworks(networks)
	transportManager.Update(map[string]*dynamic.ServersTransport{"test@file": {}})

	serviceInfo := &runtime.ServiceInfo{Service: &dynamic.Service{
		LoadBalancer: &dynamic.ServersLoadBalancer{
			// The host is deliberately unresolvable: only the extension can reach the server.
			Servers:          []dynamic.Server{{URL: "http://backend.invalid:8080"}},
			ServersTransport: "test",
			HealthCheck: &dynamic.ServerHealthCheck{
				Mode:     "grpc",
				Interval: ptypes.Duration(50 * time.Millisecond),
				Timeout:  ptypes.Duration(5 * time.Second),
			},
		},
	}}

	// The health check reports the status of the servers to the metrics registry.
	observabilityMgr := middleware.NewObservabilityMgr(static.Configuration{}, metrics.NewVoidRegistry(), nil, nil, nil, nil)

	manager := NewManager(map[string]*runtime.ServiceInfo{"test@file": serviceInfo}, observabilityMgr, nil, transportManager, httputil.NewProxyBuilder(transportManager, nil))

	_, err = manager.BuildHTTP(t.Context(), "test@file")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	manager.LaunchHealthCheck(ctx)

	select {
	case addr := <-networks.dialed:
		assert.Equal(t, "backend.invalid:8080", addr)
	case <-time.After(10 * time.Second):
		t.Fatal("the gRPC health check did not dial through the networks extension")
	}

	// The server is reached, and reports itself as serving: it stays up.
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, runtime.StatusUp, serviceInfo.GetAllStatus()["http://backend.invalid:8080"])
}
