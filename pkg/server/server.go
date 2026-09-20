package server

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/observability/metrics"
	"github.com/traefik/traefik/v3/pkg/safe"
	"github.com/traefik/traefik/v3/pkg/server/middleware"
	"github.com/traefik/traefik/v3/pkg/tailnet"
)

// Server is the reverse-proxy/load-balancer engine.
type Server struct {
	watcher          *ConfigurationWatcher
	tcpEntryPoints   TCPEntryPoints
	udpEntryPoints   UDPEntryPoints
	observabilityMgr *middleware.ObservabilityMgr

	// tailnets owns the embedded Tailscale nodes that tailnet entryPoints
	// listen on and tailnet serversTransports dial through. Nil when none
	// are configured.
	tailnets *tailnet.Registry

	signals  chan os.Signal
	stopChan chan bool

	routinesPool *safe.Pool
}

// NewServer returns an initialized Server.
func NewServer(routinesPool *safe.Pool, entryPoints TCPEntryPoints, entryPointsUDP UDPEntryPoints, watcher *ConfigurationWatcher, observabilityMgr *middleware.ObservabilityMgr, tailnets *tailnet.Registry) *Server {
	srv := &Server{
		watcher:          watcher,
		tcpEntryPoints:   entryPoints,
		observabilityMgr: observabilityMgr,
		signals:          make(chan os.Signal, 1),
		stopChan:         make(chan bool, 1),
		routinesPool:     routinesPool,
		udpEntryPoints:   entryPointsUDP,
		tailnets:         tailnets,
	}

	srv.configureSignals()

	return srv
}

// Start starts the server and Stop/Close it when context is Done.
func (s *Server) Start(ctx context.Context) {
	go func() {
		<-ctx.Done()
		logger := log.Ctx(ctx)
		logger.Info().Msg("I have to go...")
		logger.Info().Msg("Stopping server gracefully")
		s.Stop()
	}()

	// Before the entryPoints: a tailnet that only advertises routes has no
	// entryPoint to bring it up, and its routes exist only while it is
	// joined.
	s.tailnets.Start(ctx)

	s.tcpEntryPoints.Start()
	s.udpEntryPoints.Start()
	s.watcher.Start()

	s.routinesPool.GoCtx(s.listenSignals)
}

// Wait blocks until the server shutdown.
func (s *Server) Wait() {
	<-s.stopChan
}

// Stop stops the server.
func (s *Server) Stop() {
	defer log.Info().Msg("Server stopped")

	s.tcpEntryPoints.Stop()
	s.udpEntryPoints.Stop()

	s.stopChan <- true
}

// Close destroys the server.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	go func(ctx context.Context) {
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			panic("Timeout while stopping traefik, killing instance ✝")
		}
	}(ctx)

	stopMetricsClients()

	s.routinesPool.Stop()

	signal.Stop(s.signals)
	close(s.signals)

	close(s.stopChan)

	s.observabilityMgr.Close()

	// Last: the tailnet nodes back the entryPoint listeners that have just
	// been shut down, and the transports that dialed backends over them.
	s.tailnets.Close()

	cancel()
}

func stopMetricsClients() {
	metrics.StopDatadog()
	metrics.StopStatsd()
	metrics.StopInfluxDB2()
	metrics.StopOpenTelemetry()
}
