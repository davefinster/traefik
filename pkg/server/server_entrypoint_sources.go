package server

import (
	"context"

	"github.com/traefik/traefik/v3/pkg/network"
)

// entryPointSources returns the sources the networks extension gives the named entryPoint,
// which is none without an extension.
func entryPointSources(networks network.Extension, name string) network.Sources {
	if networks == nil {
		return network.Sources{}
	}

	return networks.Sources(name)
}

// untilClosed returns a context that is done once ctx is, or once done is closed.
// It is how an entryPoint that is shut down releases a source still waiting for its network.
func untilClosed(ctx context.Context, done <-chan struct{}) context.Context {
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		select {
		case <-done:
		case <-ctx.Done():
		}

		cancel()
	}()

	return ctx
}
