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

	// On a tailnet entryPoint the packet conns are not opened here: tsnet
	// needs a concrete address for each, which is only known once the node
	// is up. Start binds one per tailnet address and serves them all.
	tailnetNode *tailnet.Node
	tailnetAddr string
	done        chan struct{}
	closeOnce   sync.Once

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

	var node *tailnet.Node
	if config.Tailnet != "" {
		// Binding is deferred to Start: tsnet needs a concrete IP per packet
		// conn, and the node has none until it has joined the tailnet.
		// Waiting for that here would hold up every other entryPoint.
		node, err = tailnets.Node(config.Tailnet)
		if err != nil {
			return nil, err
		}
	}

	// if we have predefined connections from socket activation
	if node == nil && socketActivation.isEnabled() {
		conn, err = socketActivation.getConn(name)
		if err != nil {
			log.Ctx(ctx).Warn().Err(err).Str("name", name).Msg("Unable to use socket activation for entrypoint")
		}
	}

	if node == nil && conn == nil {
		listenConfig := newListenConfig(config)
		conn, err = listenConfig.ListenPacket(ctx, "udp", config.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("starting listener: %w", err)
		}
	}

	h3 := &http3server{
		http3conn:   conn,
		tailnetNode: node,
		tailnetAddr: config.GetAddress(),
		done:        make(chan struct{}),
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

// Start serves HTTP/3. On a host entryPoint that is the single packet conn
// opened at construction; on a tailnet entryPoint it is one conn per tailnet
// address, bound here once the node is up and retried until it is.
func (e *http3server) Start(ctx context.Context) error {
	if e.tailnetNode == nil {
		return e.Serve(e.http3conn)
	}

	conns, err := e.tailnetNode.RetryListenPacketAll(ctx, "udp", e.tailnetAddr, e.done)
	if err != nil {
		return err
	}

	log.Ctx(ctx).Info().
		Str("tailnet", e.tailnetNode.Name()).
		Int("listeners", len(conns)).
		Msg("Serving HTTP/3 on tailnet")

	// quic-go tracks its listeners individually, so one Serve per conn is
	// how a single http3.Server covers both tailnet address families.
	var wg sync.WaitGroup
	errs := make([]error, len(conns))
	for i, conn := range conns {
		wg.Go(func() { errs[i] = e.Serve(conn) })
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
