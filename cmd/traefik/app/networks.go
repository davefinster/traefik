package app

import (
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
)

// setupNetworks returns the extension that gives the entryPoints and the serversTransports the networks the host does not have.
//
// None is built in: it is the one the options build, and without one Traefik serves on the host network only.
func setupNetworks(staticConfiguration *static.Configuration, options Options) (network.Extension, error) {
	if options.Networks == nil {
		return nil, nil
	}

	return options.Networks(staticConfiguration)
}
