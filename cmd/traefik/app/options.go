// Package app is the traefik command: everything the traefik binary does, short of its main function.
//
// It is a package of its own so that the command can be built from another module, with more linked in.
// Such a module has a main function that calls Main with its Options,
// and the dependencies of what it links in stay in its own go.mod rather than in this module's.
package app

import (
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
)

// Options are what a build of the traefik command adds to it.
// The zero value adds nothing, and is the traefik binary of this module.
type Options struct {
	// Networks builds, from the static configuration, the extension that gives the entryPoints and the serversTransports the networks the host does not have.
	// It is called once, before the entryPoints are created, and a configuration it cannot serve is an error that stops the command.
	// Without it Traefik serves on the host network only.
	Networks func(staticConfiguration *static.Configuration) (network.Extension, error)
}
