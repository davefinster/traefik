package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
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

	served *dynamic.ServersTransport
	target string
	err    error

	seenAddr string
}

func (f *fakeNetworks) HTTPDialer(serversTransport *dynamic.ServersTransport) (network.DialContextFunc, bool) {
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

			networks := &fakeNetworks{served: test.serversTransport, target: srv.Listener.Addr().String()}

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
	networks := &fakeNetworks{served: serversTransport, err: errors.New("network unavailable")}

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

func (blockingNetworks) HTTPDialer(*dynamic.ServersTransport) (network.DialContextFunc, bool) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, true
}

// Without an answer from the extension, nothing about the dial path may change.
func TestTransportTheNetworksExtensionDoesNotAnswerForUsesTheHostNetwork(t *testing.T) {
	srv := teapotServer(t)

	networks := &fakeNetworks{served: &dynamic.ServersTransport{}, target: "127.0.0.1:1"}

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
