package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// fakeTailnetDialer records the tailnet it was asked for and dials a fixed
// local address instead, standing in for a tsnet node.
type fakeTailnetDialer struct {
	target      string
	seenTailnet string
	seenAddr    string
}

func (f *fakeTailnetDialer) DialContext(ctx context.Context, tailnet, network, addr string) (net.Conn, error) {
	f.seenTailnet = tailnet
	f.seenAddr = addr
	return (&net.Dialer{}).DialContext(ctx, network, f.target)
}

func (f *fakeTailnetDialer) Has(tailnet string) bool { return true }

func TestTailnetTransportDialsThroughTailnetDialer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	dialer := &fakeTailnetDialer{target: srv.Listener.Addr().String()}

	transportManager := NewTransportManager(nil)
	transportManager.SetTailnetDialer(dialer)
	transportManager.Update(map[string]*dynamic.ServersTransport{
		"test": {Tailnet: "global-infrastructure"},
	})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	// The host is deliberately unresolvable: only the tailnet dialer can
	// carry this request, so a pass proves the host network was not used.
	req, err := http.NewRequest(http.MethodGet, "http://backend.tail0000.ts.net:8080/", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, http.StatusTeapot, res.StatusCode)
	assert.Equal(t, "global-infrastructure", dialer.seenTailnet)
	assert.Equal(t, "backend.tail0000.ts.net:8080", dialer.seenAddr)
}

func TestTailnetTransportWithoutDialerFailsClosed(t *testing.T) {
	transportManager := NewTransportManager(nil)
	transportManager.Update(map[string]*dynamic.ServersTransport{
		"test": {Tailnet: "global-infrastructure"},
	})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	// 127.0.0.1 would be dialable over the host network: the request must
	// still fail, because the transport is bound to an unavailable tailnet.
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL, http.NoBody)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req) //nolint:bodyclose // the request must fail
	require.ErrorContains(t, err, "no tsnet tailnets configured")
}
