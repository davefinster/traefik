package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
	"github.com/traefik/traefik/v3/pkg/tailnet"
	"github.com/traefik/traefik/v3/pkg/udp"
)

// UDPEntryPoints maps UDP entry points by their names.
type UDPEntryPoints map[string]*UDPEntryPoint

// NewUDPEntryPoints returns all the UDP entry points, keyed by name.
func NewUDPEntryPoints(config static.EntryPoints, tailnets *tailnet.Registry) (UDPEntryPoints, error) {
	entryPoints := make(UDPEntryPoints)
	for entryPointName, entryPoint := range config {
		protocol, err := entryPoint.GetProtocol()
		if err != nil {
			return nil, fmt.Errorf("error while building entryPoint %s: %w", entryPointName, err)
		}

		if protocol != "udp" {
			continue
		}

		ep, err := NewUDPEntryPoint(entryPoint, entryPointName, tailnets)
		if err != nil {
			return nil, fmt.Errorf("error while building entryPoint %s: %w", entryPointName, err)
		}
		entryPoints[entryPointName] = ep
	}
	return entryPoints, nil
}

// Start commences the listening for all the entry points.
func (eps UDPEntryPoints) Start() {
	for entryPointName, ep := range eps {
		ctx := log.With().Str(logs.EntryPointName, entryPointName).Logger().WithContext(context.Background())
		go ep.Start(ctx)
	}
}

// Stop makes all the entry points stop listening, and release associated resources.
func (eps UDPEntryPoints) Stop() {
	var wg sync.WaitGroup

	for epn, ep := range eps {
		wg.Go(func() {
			logger := log.With().Str(logs.EntryPointName, epn).Logger()
			ep.Shutdown(logger.WithContext(context.Background()))

			logger.Debug().Msg("Entry point closed")
		})
	}

	wg.Wait()
}

// Switch swaps out all the given handlers in their associated entrypoints.
func (eps UDPEntryPoints) Switch(handlers map[string]udp.Handler) {
	for epName, handler := range handlers {
		if ep, ok := eps[epName]; ok {
			ep.Switch(handler)
			continue
		}

		log.Error().Str(logs.EntryPointName, epName).Msg("EntryPoint does not exist")
	}
}

// UDPEntryPoint is an entry point where we listen for UDP packets.
type UDPEntryPoint struct {
	switcher               *udp.HandlerSwitcher
	transportConfiguration *static.EntryPointsTransport

	// A tailnet entryPoint binds in Start rather than here: tsnet needs a
	// concrete address per packet conn, which the node only has once it has
	// joined, and it holds one for each address family. Host entryPoints
	// bind a single listener at construction, as before.
	tailnetNode *tailnet.Node
	// tailnetService, when set, means the packets come from a Tailscale
	// Service's addresses rather than the node's own.
	tailnetService string
	tailnetPort    uint16
	address        string
	timeout        time.Duration

	mu        sync.Mutex
	listeners []*udp.Listener
	closed    bool
	done      chan struct{}
}

// NewUDPEntryPoint returns a UDP entry point.
func NewUDPEntryPoint(config *static.EntryPoint, name string, tailnets *tailnet.Registry) (*UDPEntryPoint, error) {
	var listener *udp.Listener
	var err error

	timeout := time.Duration(config.UDP.Timeout)

	ep := &UDPEntryPoint{
		switcher:               &udp.HandlerSwitcher{},
		transportConfiguration: config.Transport,
		address:                config.GetAddress(),
		timeout:                timeout,
		done:                   make(chan struct{}),
	}

	if config.Tailnet != "" {
		if config.ReusePort {
			return nil, errors.New("reusePort is not supported on a tailnet entryPoint")
		}

		ep.tailnetNode, err = tailnets.Node(config.Tailnet)
		if err != nil {
			return nil, err
		}

		if config.TailnetService != "" {
			if !ep.tailnetNode.HasService(config.TailnetService) {
				return nil, fmt.Errorf("unknown Tailscale Service %q on tailnet %q", config.TailnetService, config.Tailnet)
			}
			// Only a Service in TUN mode carries UDP: Tailscale forwards a
			// tcp-mode Service as TCP, so a UDP entryPoint would have
			// nothing to accept from one.
			if ep.tailnetNode.ServiceMode(config.TailnetService) != static.TailnetServiceModeTUN {
				return nil, fmt.Errorf("tailscale Service %q must be in %q mode to carry UDP", config.TailnetService, static.TailnetServiceModeTUN)
			}

			port, err := entryPointPort(config)
			if err != nil {
				return nil, err
			}
			ep.tailnetService = config.TailnetService
			ep.tailnetPort = port
		}

		return ep, nil
	}

	if config.TailnetService != "" {
		return nil, errors.New("tailnetService requires the entryPoint to name a tailnet")
	}

	// if we have predefined connections from socket activation
	if socketActivation.isEnabled() {
		if conn, err := socketActivation.getConn(name); err == nil {
			listener, err = udp.ListenPacketConn(conn, timeout)
			if err != nil {
				log.Warn().Err(err).Str("name", name).Msg("Unable to create socket activation listener")
			}
		} else {
			log.Warn().Err(err).Str("name", name).Msg("Unable to use socket activation for entrypoint")
		}
	}

	if listener == nil {
		listenConfig := newListenConfig(config)
		listener, err = udp.Listen(listenConfig, "udp", config.GetAddress(), timeout)
		if err != nil {
			return nil, fmt.Errorf("error creating listener: %w", err)
		}
	}

	ep.listeners = []*udp.Listener{listener}
	return ep, nil
}

// Start commences the listening for ep.
func (ep *UDPEntryPoint) Start(ctx context.Context) {
	log.Ctx(ctx).Debug().Msg("Start UDP Server")

	listeners, err := ep.bind(ctx)
	if err != nil {
		return
	}

	// A tailnet entryPoint holds one listener per tailnet address, all
	// feeding the same handler switcher.
	var wg sync.WaitGroup
	for _, listener := range listeners {
		wg.Go(func() { ep.accept(listener) })
	}
	wg.Wait()
}

// Shutdown closes ep's listener. It eventually closes all "sessions" and
// releases associated resources, but only after it has waited for a graceTimeout,
// if any was configured.
func (ep *UDPEntryPoint) Shutdown(ctx context.Context) {
	logger := log.Ctx(ctx)

	reqAcceptGraceTimeOut := time.Duration(ep.transportConfiguration.LifeCycle.RequestAcceptGraceTimeout)
	if reqAcceptGraceTimeOut > 0 {
		logger.Info().Msgf("Waiting %s for incoming requests to cease", reqAcceptGraceTimeOut)
		time.Sleep(reqAcceptGraceTimeOut)
	}

	ep.mu.Lock()
	if !ep.closed {
		ep.closed = true
		// Releases a bind still waiting for the tailnet to come up.
		close(ep.done)
	}
	listeners := ep.listeners
	ep.mu.Unlock()

	graceTimeOut := time.Duration(ep.transportConfiguration.LifeCycle.GraceTimeOut)
	for _, listener := range listeners {
		if err := listener.Shutdown(graceTimeOut); err != nil {
			logger.Error().Err(err).Send()
		}
	}
}

// Switch replaces ep's handler with the one given as argument.
func (ep *UDPEntryPoint) Switch(handler udp.Handler) {
	ep.switcher.Switch(handler)
}

// bind returns the listeners to accept on, opening them on the tailnet first
// if this entryPoint is bound to one. It retries until the tailnet answers,
// so a tailnet that is not up at boot does not take the entryPoint with it.
func (ep *UDPEntryPoint) bind(ctx context.Context) ([]*udp.Listener, error) {
	ep.mu.Lock()
	switch {
	case ep.closed:
		ep.mu.Unlock()
		return nil, net.ErrClosed
	case ep.listeners != nil:
		listeners := ep.listeners
		ep.mu.Unlock()
		return listeners, nil
	}
	ep.mu.Unlock()

	var conns []net.PacketConn
	var err error
	if ep.tailnetService != "" {
		conns, err = ep.tailnetNode.RetryListenServicePacketTUN(ctx, ep.tailnetService, ep.tailnetPort, ep.done)
	} else {
		conns, err = ep.tailnetNode.RetryListenPacketAll(ctx, "udp", ep.address, ep.done)
	}
	if err != nil {
		return nil, err
	}

	listeners := make([]*udp.Listener, 0, len(conns))
	for _, conn := range conns {
		listener, err := udp.ListenPacketConn(conn, ep.timeout)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("Error creating tailnet UDP listener")
			_ = conn.Close()
			continue
		}
		listeners = append(listeners, listener)
	}

	// Every address failed. Returning here rather than settling for an empty
	// set keeps the entryPoint from looking started while listening on
	// nothing at all.
	if len(listeners) == 0 {
		return nil, fmt.Errorf("no tailnet listener could be created for entryPoint address %q", ep.address)
	}

	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.closed {
		for _, listener := range listeners {
			_ = listener.Shutdown(0)
		}
		return nil, net.ErrClosed
	}
	ep.listeners = listeners

	log.Ctx(ctx).Info().
		Str("tailnet", ep.tailnetNode.Name()).
		Int("listeners", len(listeners)).
		Msg("Listening for UDP on tailnet")

	return listeners, nil
}

func (ep *UDPEntryPoint) accept(listener *udp.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Only errClosedListener can happen that's why we return
			return
		}

		go ep.switcher.ServeUDP(conn)
	}
}
