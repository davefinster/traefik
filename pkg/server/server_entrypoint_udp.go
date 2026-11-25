package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
	"github.com/traefik/traefik/v3/pkg/observability/logs"
	"github.com/traefik/traefik/v3/pkg/udp"
)

// UDPEntryPoints maps UDP entry points by their names.
type UDPEntryPoints map[string]*UDPEntryPoint

// NewUDPEntryPoints returns all the UDP entry points, keyed by name.
// The networks extension gives the entry points the places they accept on that are not on the host;
// it is nil when there is none.
func NewUDPEntryPoints(config static.EntryPoints, networks network.Extension) (UDPEntryPoints, error) {
	entryPoints := make(UDPEntryPoints)
	for entryPointName, entryPoint := range config {
		protocol, err := entryPoint.GetProtocol()
		if err != nil {
			return nil, fmt.Errorf("error while building entryPoint %s: %w", entryPointName, err)
		}

		if protocol != "udp" {
			continue
		}

		ep, err := newUDPEntryPoint(entryPoint, entryPointName, entryPointSources(networks, entryPointName))
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

	// The sources bind in Start rather than at construction:
	// a source waits for its network before it binds, which a constructor must not.
	// A host address binds a single listener at construction.
	sources []network.Source
	timeout time.Duration

	mu        sync.Mutex
	listeners []*udp.Listener
	closed    bool
	done      chan struct{}
}

// NewUDPEntryPoint returns a UDP entry point, on the host network.
func NewUDPEntryPoint(config *static.EntryPoint, name string) (*UDPEntryPoint, error) {
	return newUDPEntryPoint(config, name, network.Sources{})
}

func newUDPEntryPoint(config *static.EntryPoint, name string, sources network.Sources) (*UDPEntryPoint, error) {
	var listener *udp.Listener
	var err error

	timeout := time.Duration(config.UDP.Timeout)

	ep := &UDPEntryPoint{
		switcher:               &udp.HandlerSwitcher{},
		transportConfiguration: config.Transport,
		sources:                sources.All(),
		timeout:                timeout,
		done:                   make(chan struct{}),
	}

	for _, source := range ep.sources {
		if !source.CarriesPackets() {
			return nil, fmt.Errorf("%s carries no packets, which a UDP entryPoint needs", source)
		}
	}

	// The primary source takes the place of the entryPoint's own address on the host.
	if sources.Primary != nil {
		// A host listener refuses such a timeout when it is created, which stops the startup.
		// A source binds in Start, where the same refusal would only leave the entryPoint listening on nothing.
		if timeout <= 0 {
			return nil, errors.New("timeout should be greater than zero")
		}

		return ep, nil
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

// Start commences the listening for ep: on its host listener straight away,
// and on each source once it has bound, all feeding the same handler switcher.
// A network that is slow to come up delays only its own listeners.
func (ep *UDPEntryPoint) Start(ctx context.Context) {
	log.Ctx(ctx).Debug().Msg("Start UDP Server")

	ep.mu.Lock()
	hostListeners := slices.Clone(ep.listeners)
	ep.mu.Unlock()

	var wg sync.WaitGroup
	for _, listener := range hostListeners {
		wg.Go(func() { ep.accept(listener) })
	}

	for _, source := range ep.sources {
		wg.Go(func() {
			listeners, err := ep.bind(ctx, source)
			if err != nil {
				select {
				case <-ep.done:
					// The shutdown ended the wait for the network, which is no failure.
				default:
					log.Ctx(ctx).Error().Err(err).Stringer("source", source).Msg("Unable to listen for UDP on network source")
				}

				return
			}

			for _, listener := range listeners {
				wg.Go(func() { ep.accept(listener) })
			}
		})
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
		// Releases a bind still waiting for a network to come up.
		close(ep.done)
	}
	listeners := ep.listeners
	ep.mu.Unlock()

	graceTimeOut := time.Duration(ep.transportConfiguration.LifeCycle.GraceTimeOut)

	// Together: one after the other, each listener would go on accepting sessions while the ones before it drained,
	// and the entryPoint would take the grace timeout once per listener to stop.
	var wg sync.WaitGroup
	for _, listener := range listeners {
		wg.Go(func() {
			if err := listener.Shutdown(graceTimeOut); err != nil {
				logger.Error().Err(err).Send()
			}
		})
	}

	wg.Wait()
}

// Switch replaces ep's handler with the one given as argument.
func (ep *UDPEntryPoint) Switch(handler udp.Handler) {
	ep.switcher.Switch(handler)
}

// bind opens a source's listeners, waiting for as long as its network takes to come up,
// so that a network that is not up at startup does not take the entryPoint with it.
// The wait ends when ep is shut down.
func (ep *UDPEntryPoint) bind(ctx context.Context, source network.Source) ([]*udp.Listener, error) {
	conns, err := source.ListenPacket(untilClosed(ctx, ep.done))
	if err != nil {
		return nil, err
	}

	listeners := make([]*udp.Listener, 0, len(conns))
	for _, conn := range conns {
		listener, err := udp.ListenPacketConn(conn, ep.timeout)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Stringer("source", source).Msg("Error creating UDP listener")
			_ = conn.Close()
			continue
		}
		listeners = append(listeners, listener)
	}

	// Every address failed.
	// Returning here rather than settling for an empty set keeps the source from looking bound while listening on nothing.
	if len(listeners) == 0 {
		return nil, fmt.Errorf("no UDP listener could be created for %s", source)
	}

	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.closed {
		for _, listener := range listeners {
			_ = listener.Shutdown(0)
		}
		return nil, net.ErrClosed
	}
	ep.listeners = append(ep.listeners, listeners...)

	log.Ctx(ctx).Info().Stringer("source", source).Int("listeners", len(listeners)).Msg("Listening for UDP on network source")

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
