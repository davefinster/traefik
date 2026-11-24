package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
	tcprouter "github.com/traefik/traefik/v3/pkg/server/router/tcp"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/udp"
)

// fakeSource is a place to accept on that an entryPoint did not open itself.
// It stands in for a network that is not the host's, and uses loopback sockets to do it.
type fakeSource struct {
	name string

	// listener is what Listen returns.
	listener net.Listener

	// packets tells whether the source carries datagrams.
	packets bool
	// up is closed once the network the source is on has come up; ListenPacket waits for it.
	up chan struct{}
	// packetConns is what ListenPacket returns once the network is up.
	packetConns []net.PacketConn
}

func (s *fakeSource) String() string { return s.name }

func (s *fakeSource) Listen(context.Context) net.Listener { return s.listener }

func (s *fakeSource) CarriesPackets() bool { return s.packets }

func (s *fakeSource) ListenPacket(ctx context.Context) ([]net.PacketConn, error) {
	select {
	case <-s.up:
		return s.packetConns, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// streamSource returns a source whose listener is a loopback one.
func streamSource(t *testing.T, name string) *fakeSource {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	return &fakeSource{name: name, listener: listener}
}

// pendingSource returns a source on a network that has not come up:
// its listener never accepts, and its packet conns are not bound.
func pendingSource(name string, packets bool) *fakeSource {
	return &fakeSource{name: name, listener: newStubListener(), packets: packets, up: make(chan struct{})}
}

// packetSource returns a source whose packet conn is a loopback one, on a network that has not come up yet.
// The conn is wrapped, as the conn of a userspace network stack is not a *net.UDPConn either.
func packetSource(t *testing.T, name string) (*fakeSource, net.Addr) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	source := pendingSource(name, true)
	source.packetConns = []net.PacketConn{struct{ net.PacketConn }{conn}}

	return source, conn.LocalAddr()
}

func sourcesEntryPoint(address string) *static.EntryPoint {
	transport := &static.EntryPointsTransport{}
	transport.SetDefaults()

	return &static.EntryPoint{
		Address:          address,
		Transport:        transport,
		ForwardedHeaders: &static.ForwardedHeaders{},
		HTTP2:            &static.HTTP2Config{},
	}
}

// requireAccepts dials address, and requires listener to accept the connection.
func requireAccepts(t *testing.T, listener net.Listener, address string) {
	t.Helper()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	client, err := net.DialTimeout("tcp", address, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
	case <-time.After(5 * time.Second):
		t.Fatalf("no connection was accepted on %s", address)
	}
}

// A primary source takes the place of the entryPoint's own address: nothing is bound on the host.
func TestBuildListenerOnAPrimarySource(t *testing.T) {
	source := streamSource(t, "primary")

	// The address is one nothing could bind, so a listener at all proves the host was left alone.
	listener, err := buildListener(t.Context(), "web", sourcesEntryPoint("192.0.2.1:80"), network.Sources{Primary: source})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	assert.Equal(t, source.listener.Addr(), listener.Addr())

	requireAccepts(t, listener, source.listener.Addr().String())
}

// The entryPoint's proxyProtocol judges the peer of its own address, wherever that address is.
func TestBuildListenerAppliesProxyProtocolToAPrimarySource(t *testing.T) {
	source := streamSource(t, "primary")

	config := sourcesEntryPoint("192.0.2.1:80")
	config.ProxyProtocol = &static.ProxyProtocol{Insecure: true}

	listener, err := buildListener(t.Context(), "web", config, network.Sources{Primary: source})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	client, err := net.DialTimeout("tcp", source.listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 4242 80\r\n"))
	require.NoError(t, err)

	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
		assert.Equal(t, "203.0.113.7:4242", conn.RemoteAddr().String())
	case <-time.After(5 * time.Second):
		t.Fatal("no connection was accepted")
	}
}

// The reason additional sources exist: the entryPoint's host listener and its sources are one entryPoint,
// and the host side serves while a source's network is still unreachable.
func TestBuildListenerMergesAdditionalSources(t *testing.T) {
	up := streamSource(t, "up")
	pending := pendingSource("pending", false)

	listener, err := buildListener(t.Context(), "web", sourcesEntryPoint("127.0.0.1:0"), network.Sources{Additional: []network.Source{up, pending}})
	require.NoError(t, err)

	// The merged listener is known by the entryPoint's own address.
	host, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	assert.NotEqual(t, up.listener.Addr().String(), host.String())

	requireAccepts(t, listener, host.String())
	requireAccepts(t, listener, up.listener.Addr().String())

	require.NoError(t, listener.Close())

	_, err = listener.Accept()
	require.ErrorIs(t, err, net.ErrClosed)

	// Closing the entryPoint's listener closes the sources' too.
	_, err = up.listener.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

// The entryPoint's proxyProtocol wraps its own listener only:
// a peer on an additional source must not be able to claim an address with a header.
func TestBuildListenerKeepsProxyProtocolOffAdditionalSources(t *testing.T) {
	source := streamSource(t, "additional")

	config := sourcesEntryPoint("127.0.0.1:0")
	config.ProxyProtocol = &static.ProxyProtocol{Insecure: true}

	listener, err := buildListener(t.Context(), "web", config, network.Sources{Additional: []network.Source{source}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	client, err := net.DialTimeout("tcp", source.listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Write([]byte("PROXY TCP4 203.0.113.7 198.51.100.1 4242 80\r\n"))
	require.NoError(t, err)

	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
		assert.Equal(t, client.LocalAddr().String(), conn.RemoteAddr().String())
	case <-time.After(5 * time.Second):
		t.Fatal("no connection was accepted")
	}
}

func TestNewHTTP3ServerSources(t *testing.T) {
	testCases := []struct {
		desc        string
		sources     network.Sources
		expectErr   string
		expectHost  bool
		expectNames []string
	}{
		{
			desc:       "no source",
			expectHost: true,
		},
		{
			desc:        "a primary source takes the place of the host conn",
			sources:     network.Sources{Primary: pendingSource("primary", true)},
			expectNames: []string{"primary"},
		},
		{
			desc:      "a primary source that carries no packets",
			sources:   network.Sources{Primary: pendingSource("primary", false)},
			expectErr: "http3 cannot be served on primary: it carries no packets",
		},
		{
			desc: "an additional source that carries no packets is left out",
			sources: network.Sources{Additional: []network.Source{
				pendingSource("stream only", false),
				pendingSource("packets", true),
			}},
			expectHost:  true,
			expectNames: []string{"packets"},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := sourcesEntryPoint("127.0.0.1:0")
			config.HTTP3 = &static.HTTP3Config{}

			// Building the whole entryPoint must not wait for the sources' networks.
			entryPoint, err := newTCPEntryPoint(t.Context(), "websecure", config, nil, nil, test.sources)
			if test.expectErr != "" {
				require.ErrorContains(t, err, test.expectErr)
				return
			}
			require.NoError(t, err)
			t.Cleanup(func() { entryPoint.Shutdown(t.Context()) })

			require.NotNil(t, entryPoint.http3Server)
			assert.Equal(t, test.expectHost, entryPoint.http3Server.http3conn != nil)

			var names []string
			for _, source := range entryPoint.http3Server.sources {
				names = append(names, source.String())
			}
			assert.Equal(t, test.expectNames, names)
		})
	}
}

// HTTP/3 is served on the packet conns a source binds once its network is up, which is after the entryPoint started.
func TestHTTP3ServesOnASourceOnceItsNetworkIsUp(t *testing.T) {
	certContent, err := localhostCert.Read()
	require.NoError(t, err)

	keyContent, err := localhostKey.Read()
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certContent, keyContent)
	require.NoError(t, err)

	source, sourceAddr := packetSource(t, "additional")

	config := sourcesEntryPoint("127.0.0.1:0")
	config.HTTP3 = &static.HTTP3Config{}

	entryPoint, err := newTCPEntryPoint(t.Context(), "websecure", config, nil, nil, network.Sources{Additional: []network.Source{source}})
	require.NoError(t, err)

	router, err := tcprouter.NewRouter(nil)
	require.NoError(t, err)

	router.AddHTTPTLSConfig("*", &tls.Config{Certificates: []tls.Certificate{tlsCert}}, traefiktls.DefaultTLSConfigName)
	router.SetHTTPSHandler(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	}), nil)

	go entryPoint.Start(t.Context())
	entryPoint.SwitchRouter(router)
	t.Cleanup(func() { entryPoint.Shutdown(t.Context()) })

	// The entryPoint is serving already; only now does the source's network come up.
	time.Sleep(100 * time.Millisecond)
	close(source.up)

	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(func() { _ = transport.Close() })

	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		resp, err := client.Get(fmt.Sprintf("https://%s/", sourceAddr))
		if !assert.NoError(c, err) {
			return
		}
		defer resp.Body.Close()

		_, _ = io.Copy(io.Discard, resp.Body)

		assert.Equal(c, http.StatusTeapot, resp.StatusCode)
	}, 10*time.Second, 100*time.Millisecond)
}

func udpSourcesEntryPoint(address string) *static.EntryPoint {
	config := sourcesEntryPoint(address)
	config.UDP = &static.UDPConfig{}
	config.UDP.SetDefaults()

	return config
}

func echoUDPHandler() udp.Handler {
	return udp.HandlerFunc(func(conn *udp.Conn) {
		for {
			b := make([]byte, 1024)
			n, err := conn.Read(b)
			if err != nil {
				return
			}

			_, _ = conn.Write(b[:n])
		}
	})
}

// A UDP entryPoint serves its host address straight away,
// and each source once its network is up, all through the same handler.
func TestUDPEntryPointServesItsSources(t *testing.T) {
	source, sourceAddr := packetSource(t, "additional")

	entryPoint, err := newUDPEntryPoint(udpSourcesEntryPoint("127.0.0.1:0/udp"), "dns", network.Sources{Additional: []network.Source{source}})
	require.NoError(t, err)

	started := make(chan struct{})
	go func() {
		defer close(started)
		entryPoint.Start(t.Context())
	}()
	entryPoint.Switch(echoUDPHandler())

	require.Len(t, entryPoint.listeners, 1)

	host, err := net.Dial("udp", entryPoint.listeners[0].Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = host.Close() })

	// The host address answers while the source's network is still down.
	requireEcho(t, "host", host, 5*time.Second)

	close(source.up)

	client, err := net.Dial("udp", sourceAddr.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	require.Eventually(t, func() bool {
		entryPoint.mu.Lock()
		defer entryPoint.mu.Unlock()

		return len(entryPoint.listeners) == 2
	}, 5*time.Second, 10*time.Millisecond)

	requireEcho(t, "source", client, 5*time.Second)

	entryPoint.Shutdown(t.Context())

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the entryPoint did not stop")
	}
}

// A primary source takes the place of the entryPoint's own address: nothing is bound on the host.
func TestUDPEntryPointOnAPrimarySource(t *testing.T) {
	// The address is one nothing could bind, so an entryPoint at all proves the host was left alone.
	entryPoint, err := newUDPEntryPoint(udpSourcesEntryPoint("192.0.2.1:53/udp"), "dns", network.Sources{Primary: pendingSource("primary", true)})
	require.NoError(t, err)

	assert.Empty(t, entryPoint.listeners)
	assert.Len(t, entryPoint.sources, 1)
}

func TestUDPEntryPointRefusesASourceThatCarriesNoPackets(t *testing.T) {
	_, err := newUDPEntryPoint(udpSourcesEntryPoint("127.0.0.1:0/udp"), "dns", network.Sources{Additional: []network.Source{pendingSource("stream only", false)}})
	require.ErrorContains(t, err, "stream only carries no packets")
}

// Shutting an entryPoint down releases a source that is still waiting for its network.
func TestUDPEntryPointShutdownReleasesAPendingSource(t *testing.T) {
	entryPoint, err := newUDPEntryPoint(udpSourcesEntryPoint("192.0.2.1:53/udp"), "dns", network.Sources{Primary: pendingSource("primary", true)})
	require.NoError(t, err)

	started := make(chan struct{})
	go func() {
		defer close(started)
		entryPoint.Start(t.Context())
	}()

	time.Sleep(50 * time.Millisecond)
	entryPoint.Shutdown(t.Context())

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the entryPoint kept waiting for the network after it was shut down")
	}
}
