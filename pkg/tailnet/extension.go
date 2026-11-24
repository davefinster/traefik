package tailnet

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
)

// The registry is how the tailnets reach the rest of Traefik: through the
// network extension point, and through nothing else. A nil *Registry is a
// valid Extension, as it is a valid registry: it serves no entryPoint, and
// fails the dials of every serversTransport that names a tailnet.
var _ network.Extension = (*Registry)(nil)

// New builds the registry for the tailnets of a static configuration, and
// resolves its entryPoints against them: which accept on a tailnet, and where
// on it. A configuration that cannot be served is refused here, at startup,
// rather than on the first connection.
//
// No node is started: each joins on its first use.
func New(tailnets map[string]*static.Tailnet, entryPoints static.EntryPoints) (*Registry, error) {
	registry, err := NewRegistry(tailnets)
	if err != nil {
		return nil, fmt.Errorf("creating tailnet registry: %w", err)
	}

	sources, err := registry.resolveEntryPoints(entryPoints)
	if err != nil {
		return nil, err
	}

	// Without tailnets there is no registry, and no entryPoint names one
	// either, or resolving them would have failed.
	if registry != nil {
		registry.sources = sources
	}

	return registry, nil
}

// Sources returns where on the tailnets the named entryPoint accepts, as
// resolved by New.
func (r *Registry) Sources(entryPoint string) network.Sources {
	if r == nil {
		return network.Sources{}
	}

	return r.sources[entryPoint]
}

// HTTPDialer returns the dial of a serversTransport that names a tailnet.
func (r *Registry) HTTPDialer(serversTransport *dynamic.ServersTransport) (network.DialContextFunc, bool) {
	if serversTransport == nil || serversTransport.Tailnet == "" {
		return nil, false
	}

	if !r.Has(serversTransport.Tailnet) {
		warnUnknownTailnet("ServersTransport", serversTransport.Tailnet, "requests")
	}

	return r.dialer(serversTransport.Tailnet), true
}

// TCPDialer returns the dial of a TCP serversTransport that names a tailnet.
func (r *Registry) TCPDialer(serversTransport *dynamic.TCPServersTransport) (network.DialContextFunc, bool) {
	if serversTransport == nil || serversTransport.Tailnet == "" {
		return nil, false
	}

	if !r.Has(serversTransport.Tailnet) {
		warnUnknownTailnet("TCPServersTransport", serversTransport.Tailnet, "connections")
	}

	return r.dialer(serversTransport.Tailnet), true
}

// dialer dials over the named tailnet, whether or not it is configured. A
// dial over an unknown tailnet fails on use rather than when the transport is
// built, so that a transport naming one does not take the rest of the
// configuration with it. Falling back to the host network is the one outcome
// a tailnet-bound transport must never have.
func (r *Registry) dialer(tailnet string) network.DialContextFunc {
	return func(ctx context.Context, netw, addr string) (net.Conn, error) {
		return r.DialContext(ctx, tailnet, netw, addr)
	}
}

// warnedTailnets holds the unknown tailnets already warned about. The dialers
// are asked for every time a proxy is built, which with the fast proxy
// enabled is once per service on every configuration change.
var warnedTailnets sync.Map

func warnUnknownTailnet(kind, tailnet, what string) {
	if _, warned := warnedTailnets.LoadOrStore(kind+"\x00"+tailnet, struct{}{}); warned {
		return
	}

	log.Warn().Msgf("%s references tailnet %q, which is not in the static configuration; %s through it will fail", kind, tailnet, what)
}
