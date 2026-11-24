package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/static"
	tcpmuxer "github.com/traefik/traefik/v3/pkg/muxer/tcp"
	"github.com/traefik/traefik/v3/pkg/network"
	"github.com/traefik/traefik/v3/pkg/proxy/fast"
	tcprouter "github.com/traefik/traefik/v3/pkg/server/router/tcp"
	"github.com/traefik/traefik/v3/pkg/server/service/kerberos"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

type http3server struct {
	*http3.Server

	http3conn net.PacketConn

	// The sources' packet conns are not opened at construction:
	// a source waits for its network before it binds them, which a constructor must not.
	// Start binds each source on its own, and serves whatever it binds.
	sources   []network.Source
	done      chan struct{}
	closeOnce sync.Once

	lock   sync.RWMutex
	getter func(data tcpmuxer.ConnData) (*tls.Config, string, error)
}

func newHTTP3Server(ctx context.Context, name string, config *static.EntryPoint, httpsServer *httpServer, sources network.Sources) (*http3server, error) {
	var conn net.PacketConn
	var err error

	if config.HTTP3 == nil {
		return nil, nil
	}

	if config.HTTP3.AdvertisedPort < 0 {
		return nil, errors.New("advertised port must be greater than or equal to zero")
	}

	var packetSources []network.Source
	if sources.Primary != nil {
		if !sources.Primary.CarriesPackets() {
			return nil, fmt.Errorf("http3 cannot be served on %s: it carries no packets", sources.Primary)
		}
		packetSources = append(packetSources, sources.Primary)
	}
	for _, source := range sources.Additional {
		if !source.CarriesPackets() {
			// Not refused: the entryPoint may serve HTTP/3 on its other listeners,
			// and a client reaching it through this source simply stays on TCP.
			log.Ctx(ctx).Info().Msgf("HTTP/3 is not served on %s: it carries no packets", source)
			continue
		}
		packetSources = append(packetSources, source)
	}

	// if we have predefined connections from socket activation
	if sources.Primary == nil && socketActivation.isEnabled() {
		conn, err = socketActivation.getConn(name)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).Str("name", name).Msg("Unable to use socket activation for entrypoint")
		}
	}

	if sources.Primary == nil && conn == nil {
		listenConfig := newListenConfig(config)
		conn, err = listenConfig.ListenPacket(ctx, "udp", config.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("starting listener: %w", err)
		}
	}

	h3 := &http3server{
		http3conn: conn,
		sources:   packetSources,
		done:      make(chan struct{}),
		getter: func(data tcpmuxer.ConnData) (*tls.Config, string, error) {
			return nil, "", errors.New("no TLS config")
		},
	}

	handler := httpsServer.Server.(*http.Server).Handler
	if readTimeout := time.Duration(config.Transport.RespondingTimeouts.ReadTimeout); readTimeout != 0 {
		handler = withReadTimeout(ctx, handler, readTimeout)
	}

	h3.Server = &http3.Server{
		Addr:           config.GetAddress(),
		Port:           config.HTTP3.AdvertisedPort,
		Handler:        handler,
		TLSConfig:      &tls.Config{GetConfigForClient: h3.getTLSConfigForClient},
		MaxHeaderBytes: config.HTTP.MaxHeaderBytes,
		IdleTimeout:    time.Duration(config.Transport.RespondingTimeouts.IdleTimeout),
		QUICConfig: &quic.Config{
			Allow0RTT: false,
		},
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			// This adds an empty struct in order to store a RoundTripper in the ConnContext in case of Kerberos or NTLM.
			ctx = kerberos.AddTransportOnContext(ctx)
			// Same as above for the FastProxy connection pools, storing a dedicated pool in case of Kerberos or NTLM.
			ctx = fast.AddConnPoolsOnContext(ctx)

			// The dedicated round trippers and connection pools have to be released with the connection, whose context
			// is canceled on close.
			context.AfterFunc(c.Context(), func() {
				kerberos.ReleaseTransportOnContext(ctx)
				fast.ReleaseConnPoolsOnContext(ctx)
			})

			tlsOptionsName, err := h3.getTLSOptionsName(c)
			if err != nil {
				log.Error().Msgf("Error getting TLS options name for client: %v", err)
				return ctx
			}

			return tcp.AddTLSOptionsNameInContext(ctx, tlsOptionsName)
		},
	}

	previousHandler := httpsServer.Server.(*http.Server).Handler

	httpsServer.Server.(*http.Server).Handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if err := h3.Server.SetQUICHeaders(rw.Header()); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("Failed to set HTTP3 headers")
		}

		previousHandler.ServeHTTP(rw, req)
	})

	return h3, nil
}

func withReadTimeout(ctx context.Context, next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// quic-go never leaves req.Body nil or equal to http.NoBody, so neither can be used to detect
		// an absent body. ContentLength is 0 only when the client declared no body, and -1 when the
		// length is unknown (no Content-Length header), both of which may still carry a body that
		// needs bounding.
		if req.ContentLength != 0 {
			deadline := time.Now().Add(timeout)
			if err := http.NewResponseController(rw).SetReadDeadline(deadline); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("Failed to set HTTP3 read timeout")
			}
		}
		next.ServeHTTP(rw, req)
	})
}

// Start serves HTTP/3: on the host packet conn opened at construction, when the entryPoint has one,
// and on the packet conns of each source, bound here once its network allows.
// A network that is slow to come up delays only its own conns.
func (e *http3server) Start(ctx context.Context) error {
	var (
		wg     sync.WaitGroup
		errsMu sync.Mutex
		errs   []error
	)

	fail := func(err error) {
		errsMu.Lock()
		defer errsMu.Unlock()

		errs = append(errs, err)
	}

	serve := func(conn net.PacketConn) {
		// quic-go tracks its listeners individually,
		// so one Serve per conn is how a single http3.Server covers them all.
		if err := e.Serve(conn); err != nil {
			fail(err)
		}
	}

	if e.http3conn != nil {
		wg.Go(func() { serve(e.http3conn) })
	}

	for _, source := range e.sources {
		wg.Go(func() {
			conns, err := source.ListenPacket(untilClosed(ctx, e.done))
			if err != nil {
				fail(err)
				return
			}

			log.Ctx(ctx).Info().Stringer("source", source).Int("listeners", len(conns)).Msg("Serving HTTP/3 on network source")

			for _, conn := range conns {
				wg.Go(func() { serve(conn) })
			}
		})
	}

	wg.Wait()

	return errors.Join(errs...)
}

func (e *http3server) Switch(rt *tcprouter.Router) {
	e.lock.Lock()
	defer e.lock.Unlock()

	e.getter = rt.HTTP3TLSConfigMatcherFunc()
}

func (e *http3server) Shutdown(_ context.Context) error {
	// Releases a Start still waiting for a network to come up.
	e.closeOnce.Do(func() { close(e.done) })

	// TODO: use e.Server.CloseGracefully() when available.
	return e.Server.Close()
}

func (e *http3server) getTLSConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
	e.lock.RLock()
	defer e.lock.RUnlock()

	connData, err := tcpmuxer.NewConnData(info.ServerName, info.Conn.RemoteAddr(), info.SupportedProtos)
	if err != nil {
		return nil, fmt.Errorf("creating ConnData from client hello: %w", err)
	}

	conf, _, err := e.getter(connData)
	return conf, err
}

func (e *http3server) getTLSOptionsName(c *quic.Conn) (string, error) {
	e.lock.RLock()
	defer e.lock.RUnlock()

	connData, err := tcpmuxer.NewConnData(c.ConnectionState().TLS.ServerName, c.RemoteAddr(), []string{c.ConnectionState().TLS.NegotiatedProtocol})
	if err != nil {
		return "", fmt.Errorf("creating ConnData from quic Conn: %w", err)
	}

	_, name, err := e.getter(connData)
	return name, err
}
