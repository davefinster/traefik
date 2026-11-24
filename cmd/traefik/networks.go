package main

import (
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
)

// setupNetworks returns the extension that gives the entryPoints and the serversTransports the networks the host does not have.
//
// None is built in, so Traefik serves on the host network only.
// This is where a build that links an extension in constructs it, from its own part of the static configuration.
func setupNetworks(_ *static.Configuration) (network.Extension, error) {
	return nil, nil
}
