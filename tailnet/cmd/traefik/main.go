// The traefik command with the tailnets linked in.
//
// It is the command of the traefik module, cmd/traefik, and nothing else:
// the same options, the same subcommands, the same binary name. What it adds
// is the implementation behind the tailnet options, which the traefik module
// refuses to start with, as it does not depend on Tailscale.
package main

import (
	"github.com/traefik/traefik/tailnet"
	"github.com/traefik/traefik/v3/cmd/traefik/app"
)

func main() {
	app.Main(app.Options{Networks: tailnet.Extension})
}
