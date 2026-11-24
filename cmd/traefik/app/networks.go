package app

import (
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
	"github.com/traefik/traefik/v3/pkg/tailnet"
)

// setupNetworks returns the extension that gives the entryPoints and the serversTransports the networks the host does not have.
//
// It is the one the options build, and without one, the tailnets of the static configuration.
// That is never a nil Extension, even without a tailnet, where it holds a nil registry:
// a serversTransport that names a tailnet must fail to dial then, and not reach its servers over the host network.
func setupNetworks(staticConfiguration *static.Configuration, options Options) (network.Extension, error) {
	if options.Networks == nil {
		return tailnet.New(staticConfiguration.Tailnets, staticConfiguration.EntryPoints)
	}

	return options.Networks(staticConfiguration)
}
