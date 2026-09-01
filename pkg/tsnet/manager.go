// Package tsnet manages the embedded Tailscale nodes (tailscale.com/tsnet)
// that serversTransports can dial backends through. Each configured tailnet
// is one in-process userspace Tailscale node: no TUN device, no routing-table
// or netfilter footprint, so it coexists with a host tailscaled.
package tsnet

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/static"
	tailscaletsnet "tailscale.com/tsnet"
)

// Manager holds one tsnet server per configured tailnet. A nil *Manager is
// valid and refuses every dial, so callers need no configured-or-not checks.
type Manager struct {
	mu      sync.Mutex
	servers map[string]*tailscaletsnet.Server
	// started tracks the servers a dial has touched: tsnet starts a server
	// on its first Dial, and closing a never-started server panics.
	started map[string]bool
}

// NewManager builds the servers from static configuration without starting
// them: each node connects lazily on its first dial, so a tailnet outage at
// boot degrades those backends instead of blocking startup.
func NewManager(cfg *static.TsnetConfig) (*Manager, error) {
	if cfg == nil || len(cfg.Tailnets) == 0 {
		return nil, nil
	}

	m := &Manager{
		servers: make(map[string]*tailscaletsnet.Server),
		started: make(map[string]bool),
	}
	for name, tn := range cfg.Tailnets {
		if tn == nil {
			return nil, fmt.Errorf("tsnet tailnet %q: missing configuration", name)
		}
		if tn.StateDir == "" {
			// tsnet's default directory is derived from the binary name and
			// so cannot be shared by several nodes; require it explicitly.
			return nil, fmt.Errorf("tsnet tailnet %q: stateDir is required", name)
		}

		authKey := tn.AuthKey
		if tn.AuthKeyFile != "" {
			content, err := os.ReadFile(tn.AuthKeyFile)
			if err != nil {
				return nil, fmt.Errorf("tsnet tailnet %q: reading authKeyFile: %w", name, err)
			}
			authKey = strings.TrimSpace(string(content))
		}

		logger := log.With().Str("tailnet", name).Logger()
		srv := &tailscaletsnet.Server{
			Hostname:   tn.Hostname,
			Dir:        tn.StateDir,
			AuthKey:    authKey,
			ControlURL: tn.ControlURL,
			Ephemeral:  tn.Ephemeral,
			UserLogf: func(format string, args ...any) {
				logger.Info().Msgf(format, args...)
			},
			Logf: func(format string, args ...any) {
				logger.Trace().Msgf(format, args...)
			},
		}
		m.servers[name] = srv
	}

	return m, nil
}

// DialContext dials addr over the named tailnet. The first dial on a tailnet
// starts its node (joining with the auth key when the state directory holds
// no identity yet).
func (m *Manager) DialContext(ctx context.Context, tailnet, network, addr string) (net.Conn, error) {
	if m == nil {
		return nil, fmt.Errorf("dialing %q over tailnet %q: no tsnet tailnets configured", addr, tailnet)
	}

	m.mu.Lock()
	srv, ok := m.servers[tailnet]
	if ok {
		// Before the dial: even a failed dial attempt starts the server.
		m.started[tailnet] = true
	}
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("dialing %q: unknown tsnet tailnet %q", addr, tailnet)
	}

	return srv.Dial(ctx, network, addr)
}

// Has reports whether the named tailnet is configured, letting transport
// builders fail fast on a typo instead of on the first request through it.
func (m *Manager) Has(tailnet string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.servers[tailnet]
	return ok
}

// Close shuts down every started node; never-started servers hold nothing to
// release (and tsnet panics on closing them).
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, srv := range m.servers {
		if !m.started[name] {
			continue
		}
		if err := srv.Close(); err != nil {
			log.Debug().Err(err).Str("tailnet", name).Msg("Closing tsnet server")
		}
	}
}
