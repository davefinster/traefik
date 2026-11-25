package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
)

// errNoTailnets is what a traefik command built without the tailnets answers to a configuration that asks for one.
var errNoTailnets = errors.New("the tailnets are not part of this build of Traefik: they are in the tailnet module, whose cmd/traefik is the build that has them")

// setupNetworks returns the extension that gives the entryPoints and the serversTransports the networks the host does not have.
//
// It is the one the options build. The tailnets are one, and the only one there is:
// their implementation embeds a Tailscale node, and lives in a module of its own so that this module does not depend on it.
// A command built without them, as the traefik binary of this module is, gets an extension that refuses them instead.
func setupNetworks(staticConfiguration *static.Configuration, options Options) (network.Extension, error) {
	if options.Networks == nil {
		return withoutTailnets(staticConfiguration)
	}

	return options.Networks(staticConfiguration)
}

// withoutTailnets returns the extension of a command built without the tailnets.
//
// The options that ask for a tailnet are part of the configuration either way,
// so that such a command refuses them rather than ignore them:
// ignored, an entryPoint meant for a tailnet would listen on the host network instead, for anyone who can reach it.
func withoutTailnets(staticConfiguration *static.Configuration) (network.Extension, error) {
	if len(staticConfiguration.Tailnets) > 0 {
		return nil, errNoTailnets
	}

	for name, entryPoint := range staticConfiguration.EntryPoints {
		if entryPoint == nil {
			continue
		}

		if entryPoint.Tailnet != "" || entryPoint.TailnetService != "" || len(entryPoint.TailnetListeners) > 0 {
			return nil, fmt.Errorf("entryPoint %s: %w", name, errNoTailnets)
		}
	}

	return &noTailnets{}, nil
}

// noTailnets fails the dials of the serversTransports that name a tailnet.
// They come from the dynamic configuration, which cannot be refused at startup,
// and must not reach their servers over the host network instead.
type noTailnets struct {
	network.Nop

	// warned holds the tailnets already warned about:
	// the dialers are asked for every time a proxy or a health check is built.
	warned sync.Map
}

func (n *noTailnets) HTTPDialer(_ string, serversTransport *dynamic.ServersTransport) (network.DialContextFunc, bool) {
	if serversTransport == nil || serversTransport.Tailnet == "" {
		return nil, false
	}

	return n.refuse(serversTransport.Tailnet), true
}

func (n *noTailnets) TCPDialer(_ string, serversTransport *dynamic.TCPServersTransport) (network.DialContextFunc, bool) {
	if serversTransport == nil || serversTransport.Tailnet == "" {
		return nil, false
	}

	return n.refuse(serversTransport.Tailnet), true
}

func (n *noTailnets) refuse(tailnet string) network.DialContextFunc {
	if _, warned := n.warned.LoadOrStore(tailnet, struct{}{}); !warned {
		log.Warn().Err(errNoTailnets).Msgf("A serversTransport references tailnet %q; connections through it will fail", tailnet)
	}

	return func(_ context.Context, _, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("dialing %q over tailnet %q: %w", addr, tailnet, errNoTailnets)
	}
}
