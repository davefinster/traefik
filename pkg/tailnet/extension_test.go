package tailnet

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	traefikservice "github.com/traefik/traefik/v3/pkg/server/service"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

func TestRegistryAnswersOnlyForTransportsNamingATailnet(t *testing.T) {
	testCases := []struct {
		desc     string
		registry *Registry
	}{
		{desc: "with tailnets", registry: testRegistry(t)},
		{desc: "without tailnets"},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			_, ok := test.registry.HTTPDialer(&dynamic.ServersTransport{})
			assert.False(t, ok)

			_, ok = test.registry.HTTPDialer(nil)
			assert.False(t, ok)

			_, ok = test.registry.TCPDialer(&dynamic.TCPServersTransport{})
			assert.False(t, ok)

			_, ok = test.registry.TCPDialer(nil)
			assert.False(t, ok)

			// Known or not, a tailnet that is named is answered for: the dial
			// must fail rather than go out over the host network.
			for _, name := range []string{"corp", "typo"} {
				dial, ok := test.registry.HTTPDialer(&dynamic.ServersTransport{Tailnet: name})
				assert.True(t, ok)
				assert.NotNil(t, dial)

				dial, ok = test.registry.TCPDialer(&dynamic.TCPServersTransport{Tailnet: name})
				assert.True(t, ok)
				assert.NotNil(t, dial)
			}
		})
	}
}

// A transport bound to a tailnet must never quietly fall back to the host
// network, which is what makes it worth binding in the first place.
func TestTailnetTransportFailsClosed(t *testing.T) {
	testCases := []struct {
		desc      string
		registry  *Registry
		expectErr string
	}{
		{desc: "an unknown tailnet", registry: testRegistry(t), expectErr: `unknown tailnet "typo"`},
		{desc: "no tailnet at all", expectErr: "no tailnets configured"},
	}

	// The target is reachable over the host network: the request must still
	// fail, because the transport is bound to an unavailable tailnet.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			transportManager := traefikservice.NewTransportManager(nil)
			transportManager.SetNetworks(test.registry)
			transportManager.Update(map[string]*dynamic.ServersTransport{
				"test": {Tailnet: "typo"},
			})

			rt, err := transportManager.GetRoundTripper("test")
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodGet, srv.URL, http.NoBody)
			require.NoError(t, err)

			_, err = rt.RoundTrip(req) //nolint:bodyclose // the request must fail
			require.ErrorContains(t, err, test.expectErr)
		})
	}
}

// A TCP transport bound to a tailnet must fail rather than reach the backend
// over the host network.
func TestTailnetTCPTransportFailsClosed(t *testing.T) {
	testCases := []struct {
		desc      string
		registry  *Registry
		expectErr string
	}{
		{desc: "an unknown tailnet", registry: testRegistry(t), expectErr: `unknown tailnet "typo"`},
		{desc: "no tailnet at all", expectErr: "no tailnets configured"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			dialerManager := tcp.NewDialerManager(nil)
			dialerManager.SetNetworks(test.registry)

			st := &dynamic.TCPServersTransport{Tailnet: "typo"}
			st.SetDefaults()
			dialerManager.Update(map[string]*dynamic.TCPServersTransport{"test": st})

			dialer, err := dialerManager.Build(&dynamic.TCPServersLoadBalancer{ServersTransport: "test"}, false)
			require.NoError(t, err)

			_, err = dialer.Dial("tcp", srv.Listener.Addr().String(), nil)
			require.ErrorContains(t, err, test.expectErr)
		})
	}
}
