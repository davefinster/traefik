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
	tcprouter "github.com/traefik/traefik/v3/pkg/server/router/tcp"
	"github.com/traefik/traefik/v3/pkg/server/service"
	"github.com/traefik/traefik/v3/pkg/tailnet"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

type http3server struct {
	*http3.Server

	http3conn net.PacketConn

	// The tailnet sources' packet conns are not opened here: tsnet needs a
	// concrete address for each, which is only known once the node is up,
	// and a Service has none until it is hosted. Start binds each source
	// independently and serves whatever it binds.
	tailnetSources []tailnetSource
	done           chan struct{}
	closeOnce      sync.Once

	lock   sync.RWMutex
	getter func(data tcpmuxer.ConnData) (*tls.Config, string, error)
}

func newHTTP3Server(ctx context.Context, name string, config *static.EntryPoint, httpsServer *httpServer, tailnets *tailnet.Registry) (*http3server, error) {
	var conn net.PacketConn
	var err error

	if config.HTTP3 == nil {
		return nil, nil
	}

	if config.HTTP3.AdvertisedPort < 0 {
		return nil, errors.New("advertised port must be greater than or equal to zero")
	}

	primary, err := primaryTailnetSource(config, tailnets)
	if err != nil {
		return nil, err
	}
	if primary != nil && !primary.carriesPackets() {
		// A tcp-mode Service is forwarded to the entryPoint as TCP, so there
		// is no packet conn for QUIC to read from.
		return nil, errors.New("http3 is not supported on a Tailscale Service entryPoint in tcp mode: use mode tun")
	}

	extra, err := resolveTailnetListeners(config, tailnets)
	if err != nil {
		return nil, err
	}

	var sources []tailnetSource
	if primary != nil {
		sources = append(sources, *primary)
	}
	for _, source := range extra {
		if !source.carriesPackets() {
			// Not refused: the entryPoint may serve HTTP/3 on its other
			// listeners, and a client reaching it through this Service simply
			// stays on TCP.
			log.Ctx(ctx).Info().Msgf("HTTP/3 is not served on %s: in tcp mode it carries TCP only", source.description())
			continue
		}
		sources = append(sources, source)
	}

	// if we have predefined connections from socket activation
	if primary == nil && socketActivation.isEnabled() {
		conn, err = socketActivation.getConn(name)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).Str("name", name).Msg("Unable to use socket activation for entrypoint")
		}
	}

	if primary == nil && conn == nil {
		listenConfig := newListenConfig(config)
		conn, err = listenConfig.ListenPacket(ctx, "udp", config.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("starting listener: %w", err)
		}
	}

	h3 := &http3server{
		http3conn:      conn,
		tailnetSources: sources,
		done:           make(chan struct{}),
		getter: func(data tcpmuxer.ConnData) (*tls.Config, string, error) {
			return nil, "", errors.New("no TLS config")
		},
	}

	handler := httpsServer.Server.(*http.Server).Handler
	if readTimeout := time.Duration(config.Transport.RespondingTimeouts.ReadTimeout); readTimeout != 0 {
		handler = withReadTimeout(ctx, handler, readTimeout)
	}

	quicConfig := &quic.Config{
		Allow0RTT: config.HTTP3.Allow0RTT,
	}
	if config.HTTP3.InitialPacketSize > 0 {
		if config.HTTP3.InitialPacketSize < 1200 {
			return nil, fmt.Errorf("initial packet size can not be less than 1200, got %d", config.HTTP3.InitialPacketSize)
		}
		quicConfig.InitialPacketSize = uint16(config.HTTP3.InitialPacketSize)
	}

	h3.Server = &http3.Server{
		Addr:           config.GetAddress(),
		Port:           config.HTTP3.AdvertisedPort,
		Handler:        handler,
		TLSConfig:      &tls.Config{GetConfigForClient: h3.getTLSConfigForClient},
		MaxHeaderBytes: config.HTTP.MaxHeaderBytes,
		IdleTimeout:    time.Duration(config.Transport.RespondingTimeouts.IdleTimeout),
		QUICConfig:     quicConfig,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			// This adds an empty struct in order to store a RoundTripper in the ConnContext in case of Kerberos or NTLM.
			ctx = service.AddTransportOnContext(ctx)

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

// Start serves HTTP/3: on the host packet conn opened at construction, if
// the entryPoint's own address is on the host, and on each tailnet source's
// conns, bound here once the tailnet allows and retried until it does. A
// tailnet that is slow to come up delays only its own conns.
func (e *http3server) Start(ctx context.Context) error {
	var (
		wg     sync.WaitGroup
		errsMu sync.Mutex
		errs   []error
	)
	serve := func(conn net.PacketConn) {
		// quic-go tracks its listeners individually, so one Serve per conn is
		// how a single http3.Server covers them all.
		if err := e.Serve(conn); err != nil {
			errsMu.Lock()
			errs = append(errs, err)
			errsMu.Unlock()
		}
	}

	if e.http3conn != nil {
		wg.Go(func() { serve(e.http3conn) })
	}

	for _, source := range e.tailnetSources {
		wg.Go(func() {
			conns, err := source.listenPackets(ctx, e.done)
			if err != nil {
				errsMu.Lock()
				errs = append(errs, err)
				errsMu.Unlock()
				return
			}

			log.Ctx(ctx).Info().
				Str("tailnet", source.node.Name()).
				Str("source", source.description()).
				Int("listeners", len(conns)).
				Msg("Serving HTTP/3 on tailnet")

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
	// Releases a Start still waiting for the tailnet to come up; a host
	// entryPoint is never waiting, and closing the channel is harmless.
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
