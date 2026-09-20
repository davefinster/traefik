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
	known       bool
	seenTailnet string
	seenAddr    string
}

func (f *fakeTailnetDialer) DialContext(ctx context.Context, tailnet, network, addr string) (net.Conn, error) {
	f.seenTailnet = tailnet
	f.seenAddr = addr
	return (&net.Dialer{}).DialContext(ctx, network, f.target)
}

func (f *fakeTailnetDialer) Has(string) bool { return f.known }

func TestTailnetTransportDialsThroughTailnetDialer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	dialer := &fakeTailnetDialer{target: srv.Listener.Addr().String(), known: true}

	transportManager := NewTransportManager(nil)
	transportManager.SetTailnetDialer(dialer)
	transportManager.Update(map[string]*dynamic.ServersTransport{
		"test": {Tailnet: "corp"},
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
	assert.Equal(t, "corp", dialer.seenTailnet)
	assert.Equal(t, "backend.tail0000.ts.net:8080", dialer.seenAddr)
}

// A transport bound to a tailnet must never quietly fall back to the host
// network, which is what makes it worth binding in the first place.
func TestTailnetTransportWithoutDialerFailsClosed(t *testing.T) {
	transportManager := NewTransportManager(nil)
	transportManager.Update(map[string]*dynamic.ServersTransport{
		"test": {Tailnet: "corp"},
	})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	// The target is reachable over the host network: the request must still
	// fail, because the transport is bound to an unavailable tailnet.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL, http.NoBody)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req) //nolint:bodyclose // the request must fail
	require.ErrorContains(t, err, "no tailnets configured")
}

// An unknown tailnet is only a warning at build time, so that a transport
// naming one does not take the configuration with it, but it must still fail
// every request rather than reaching the backend over the host network.
func TestTailnetTransportWithUnknownTailnetStillDialsTailnet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	dialer := &fakeTailnetDialer{target: srv.Listener.Addr().String(), known: false}

	transportManager := NewTransportManager(nil)
	transportManager.SetTailnetDialer(dialer)
	transportManager.Update(map[string]*dynamic.ServersTransport{
		"test": {Tailnet: "typo"},
	})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "http://backend.tail0000.ts.net:8080/", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, "typo", dialer.seenTailnet)
}

// The forwarding timeouts path rebuilds DialContext, and must rebuild it
// from the tailnet dial rather than from the host dialer it replaced.
func TestTailnetTransportKeepsTailnetDialWithForwardingTimeouts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	dialer := &fakeTailnetDialer{target: srv.Listener.Addr().String(), known: true}

	transportManager := NewTransportManager(nil)
	transportManager.SetTailnetDialer(dialer)
	transportManager.Update(map[string]*dynamic.ServersTransport{
		"test": {
			Tailnet:            "corp",
			ForwardingTimeouts: &dynamic.ForwardingTimeouts{},
		},
	})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "http://backend.tail0000.ts.net:8080/", http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, http.StatusTeapot, res.StatusCode)
	assert.Equal(t, "corp", dialer.seenTailnet)
}

// Without a tailnet, nothing about the dial path may change.
func TestTransportWithoutTailnetUsesHostNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)

	dialer := &fakeTailnetDialer{target: "127.0.0.1:1", known: true}

	transportManager := NewTransportManager(nil)
	transportManager.SetTailnetDialer(dialer)
	transportManager.Update(map[string]*dynamic.ServersTransport{
		"test": {},
	})

	rt, err := transportManager.GetRoundTripper("test")
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, srv.URL, http.NoBody)
	require.NoError(t, err)

	res, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, http.StatusTeapot, res.StatusCode)
	assert.Empty(t, dialer.seenTailnet)
}
