// Package tailnet manages the embedded Tailscale nodes (tailscale.com/tsnet)
// that Traefik uses for native tailnet connectivity. Each configured tailnet
// is one in-process userspace Tailscale node: no TUN device, no routing-table
// or netfilter footprint, so it coexists with a tailscaled on the same host.
//
// A node serves both directions. EntryPoints referencing a tailnet accept
// connections on it (Node.Listen, Node.ListenPacket), and serversTransports
// referencing one dial their backends over it (Node.DialContext), with names
// resolved through the tailnet's MagicDNS rather than the host resolver.
//
// Nodes are built lazily and rebuilt on failure: a tailnet that cannot reach
// its control plane degrades the routes that use it, and never keeps Traefik
// from starting or serving everything else.
package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"

	// Registers support for OAuth client secrets (tskey-client-...) as auth
	// keys. Without it, tsnet would send the client secret to the control
	// plane as though it were an auth key, and the join would be rejected.
	_ "tailscale.com/feature/oauthkey"
)

// ErrNoTailnets is returned for any operation naming a tailnet when none are
// configured at all, which is a likelier mistake than a mistyped name.
var ErrNoTailnets = errors.New("no tailnets configured")

// Registry holds one Node per configured tailnet, keyed by the name that
// entryPoints and serversTransports reference. A nil *Registry is valid and
// refuses every operation, so callers need no configured-or-not checks.
type Registry struct {
	nodes map[string]*Node
}

// NewRegistry validates the tailnet configuration and prepares a node for
// each entry. No node is started here: joining happens on the first listen or
// dial, so a tailnet outage at boot degrades only what depends on it.
func NewRegistry(cfg map[string]*static.Tailnet) (*Registry, error) {
	if len(cfg) == 0 {
		return nil, nil
	}

	r := &Registry{nodes: make(map[string]*Node, len(cfg))}
	for name, tn := range cfg {
		if tn == nil {
			return nil, fmt.Errorf("tailnet %q: missing configuration", name)
		}
		if tn.StateDir == "" {
			// tsnet's default directory is derived from the binary name and
			// so cannot be shared by several nodes in one process.
			return nil, fmt.Errorf("tailnet %q: stateDir is required", name)
		}
		if tn.AuthKey != "" && tn.AuthKeyFile != "" {
			return nil, fmt.Errorf("tailnet %q: authKey and authKeyFile are mutually exclusive", name)
		}

		r.nodes[name] = &Node{name: name, cfg: tn}
	}

	return r, nil
}

// Node returns the node for the named tailnet.
func (r *Registry) Node(name string) (*Node, error) {
	if r == nil {
		return nil, ErrNoTailnets
	}
	node, ok := r.nodes[name]
	if !ok {
		return nil, fmt.Errorf("unknown tailnet %q", name)
	}
	return node, nil
}

// Has reports whether the named tailnet is configured, letting builders warn
// about a typo at configuration time rather than on the first request.
func (r *Registry) Has(name string) bool {
	if r == nil {
		return false
	}
	_, ok := r.nodes[name]
	return ok
}

// DialContext dials addr over the named tailnet, joining it if this is the
// first use. Host names in addr resolve through that tailnet's MagicDNS.
func (r *Registry) DialContext(ctx context.Context, tailnet, network, addr string) (net.Conn, error) {
	node, err := r.Node(tailnet)
	if err != nil {
		return nil, fmt.Errorf("dialing %q: %w", addr, err)
	}
	return node.DialContext(ctx, network, addr)
}

// Close shuts down every node that was started.
func (r *Registry) Close() {
	if r == nil {
		return
	}
	for _, node := range r.nodes {
		node.Close()
	}
}

// Node is one embedded Tailscale node. The underlying tsnet.Server is built
// on first use and discarded if it fails to start, because tsnet caches a
// failed start forever on the server it happened to: retrying has to happen
// on a fresh one.
type Node struct {
	name string
	cfg  *static.Tailnet

	// startMu serialises join attempts. It is deliberately not n.mu:
	// tsnet.Server.Start takes no context and can block for as long as the
	// control plane keeps it waiting, and Close must not queue behind it.
	startMu sync.Mutex

	mu     sync.Mutex
	srv    *tsnet.Server
	closed bool
}

// Name returns the configured name of the tailnet, as entryPoints and
// serversTransports reference it.
func (n *Node) Name() string { return n.name }

// server returns a started tsnet.Server, building and joining as needed.
func (n *Node) server() (*tsnet.Server, error) {
	if srv, err, ok := n.current(); ok {
		return srv, err
	}

	n.startMu.Lock()
	defer n.startMu.Unlock()

	// Another caller may have joined while this one waited for the lock.
	if srv, err, ok := n.current(); ok {
		return srv, err
	}

	srv, err := n.build()
	if err != nil {
		return nil, err
	}

	// tsnet.Server.Start cleans up after itself on failure, so a server that
	// failed here needs no Close; dropping it means the next attempt gets a
	// fresh sync.Once rather than the cached error, which is the whole
	// reason a failed node is rebuilt instead of retried in place.
	if err := srv.Start(); err != nil {
		return nil, fmt.Errorf("tailnet %q: joining: %w", n.name, err)
	}

	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		// Closed while this join was in flight. The server did start, so it
		// owns resources and must be released.
		_ = srv.Close()
		return nil, net.ErrClosed
	}
	n.srv = srv
	n.mu.Unlock()

	return srv, nil
}

// current reports the node's settled state: a joined server, or the closed
// error. ok is false when a join still has to happen.
func (n *Node) current() (*tsnet.Server, error, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	switch {
	case n.closed:
		return nil, net.ErrClosed, true
	case n.srv != nil:
		return n.srv, nil, true
	default:
		return nil, nil, false
	}
}

// build assembles an unstarted tsnet.Server from the configuration, resolving
// the auth key file now: reading it at build time rather than at startup lets
// a key delivered late by an external system be picked up on a retry.
func (n *Node) build() (*tsnet.Server, error) {
	authKey := n.cfg.AuthKey
	if n.cfg.AuthKeyFile != "" {
		content, err := os.ReadFile(n.cfg.AuthKeyFile)
		if err != nil {
			return nil, fmt.Errorf("tailnet %q: reading authKeyFile: %w", n.name, err)
		}
		authKey = strings.TrimSpace(string(content))
	}

	logger := log.With().Str("tailnet", n.name).Logger()

	return &tsnet.Server{
		Hostname:      n.cfg.Hostname,
		Dir:           n.cfg.StateDir,
		AuthKey:       authKey,
		ControlURL:    n.cfg.ControlURL,
		Ephemeral:     n.cfg.Ephemeral,
		AdvertiseTags: n.cfg.AdvertiseTags,
		Port:          n.cfg.Port,
		UserLogf: func(format string, args ...any) {
			logger.Info().Msgf(format, args...)
		},
		Logf: func(format string, args ...any) {
			logger.Trace().Msgf(format, args...)
		},
	}, nil
}

// DialContext dials addr over the tailnet, joining it on first use.
func (n *Node) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	srv, err := n.server()
	if err != nil {
		return nil, fmt.Errorf("dialing %q over tailnet %q: %w", addr, n.name, err)
	}
	return srv.Dial(ctx, network, addr)
}

// Listen announces on the tailnet only. An empty host in addr (":443") binds
// every address the node holds, as it does for a host listener.
func (n *Node) Listen(network, addr string) (net.Listener, error) {
	srv, err := n.server()
	if err != nil {
		return nil, err
	}
	return srv.Listen(network, addr)
}

// ListenPacket announces a packet conn on the tailnet.
//
// Unlike Listen, tsnet requires a concrete address here, so this binds one
// address family. Use ListenPacketAll to cover every address the node holds.
func (n *Node) ListenPacket(network, addr string) (net.PacketConn, error) {
	srv, err := n.server()
	if err != nil {
		return nil, err
	}
	return srv.ListenPacket(network, addr)
}

// Up joins the tailnet and waits until the node is running, returning its
// status. It is how a caller that needs the node's addresses (a packet
// listener) waits for them.
func (n *Node) Up(ctx context.Context) (*ipnstate.Status, error) {
	srv, err := n.server()
	if err != nil {
		return nil, err
	}

	status, err := srv.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("tailnet %q: waiting to come up: %w", n.name, err)
	}
	return status, nil
}

// Addrs returns the node's tailnet addresses once it is up.
func (n *Node) Addrs(ctx context.Context) ([]netip.Addr, error) {
	status, err := n.Up(ctx)
	if err != nil {
		return nil, err
	}

	addrs := make([]netip.Addr, 0, len(status.TailscaleIPs))
	for _, addr := range status.TailscaleIPs {
		if addr.IsValid() {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("tailnet %q: node is up with no tailnet address", n.name)
	}
	return addrs, nil
}

// Close shuts the node down if it was started. A node that never started
// holds nothing to release, and tsnet panics on closing one.
func (n *Node) Close() {
	n.mu.Lock()
	srv := n.srv
	n.srv = nil
	n.closed = true
	n.mu.Unlock()

	if srv == nil {
		return
	}
	if err := srv.Close(); err != nil {
		log.Debug().Err(err).Str("tailnet", n.name).Msg("Closing tailnet node")
	}
}
