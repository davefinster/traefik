// Package tailnet manages the embedded Tailscale nodes (tailscale.com/tsnet)
// that Traefik uses for native tailnet connectivity. Each configured tailnet
// is one in-process userspace Tailscale node: no operating-system TUN device,
// no routing-table or netfilter footprint, so it coexists with a tailscaled on
// the same host.
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
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/static"
	// Registers support for OAuth client secrets (tskey-client-...) as auth
	// keys. Without it, tsnet would send the client secret to the control
	// plane as though it were an auth key, and the join would be rejected.
	_ "tailscale.com/feature/oauthkey"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

// servicePrefix is the prefix every Tailscale Service name carries; tailcfg
// validates against it but exports no constant for it.
const servicePrefix = "svc:"

// advertiseTimeout bounds the local API calls that publish routes and
// Services, so a wedged backend surfaces as a retry rather than a hang.
const advertiseTimeout = 30 * time.Second

// ErrNoTailnets is returned for any operation naming a tailnet when none are
// configured at all, which is a likelier mistake than a mistyped name.
var ErrNoTailnets = errors.New("no tailnets configured")

// Registry holds one Node per configured tailnet, keyed by the name that
// entryPoints and serversTransports reference. A nil *Registry is valid and
// refuses every operation, so callers need no configured-or-not checks.
type Registry struct {
	nodes map[string]*Node

	stopOnce sync.Once
	stop     chan struct{}
}

// NewRegistry validates the tailnet configuration and prepares a node for
// each entry. No node is started here: joining happens on the first listen or
// dial, so a tailnet outage at boot degrades only what depends on it.
func NewRegistry(cfg map[string]*static.Tailnet) (*Registry, error) {
	if len(cfg) == 0 {
		return nil, nil
	}

	r := &Registry{nodes: make(map[string]*Node, len(cfg)), stop: make(chan struct{})}
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

		routes, err := parseRoutes(tn.Routes)
		if err != nil {
			return nil, fmt.Errorf("tailnet %q: %w", name, err)
		}

		services, err := parseServices(tn.Services)
		if err != nil {
			return nil, fmt.Errorf("tailnet %q: %w", name, err)
		}

		// Hosting a Service requires a tagged node, and an untagged one is
		// refused by the control plane rather than by us, on the first
		// listen. Catching it here names the configuration that is wrong.
		if len(services) > 0 && len(tn.AdvertiseTags) == 0 {
			return nil, fmt.Errorf("tailnet %q: hosting a Tailscale Service requires advertiseTags: only tagged nodes may host one", name)
		}

		// Routes are answered from the local stack too, whether or not a
		// Service needs it: one path for every address this node answers for
		// that is not its own. Left to tsnet's own subnet handling, IPv6 to a
		// routed address went unanswered on the flyscale Fly edges while IPv4
		// worked (2026-09-21); the local stack serves both families alike, as
		// it does for TUN-mode Services.
		node := &Node{name: name, cfg: tn, routes: routes, services: services, tun: len(routes) > 0}
		for _, svc := range services {
			if svc.cfg.Mode == static.TailnetServiceModeTUN {
				node.tun = true
			}
		}

		r.nodes[name] = node
	}

	return r, nil
}

// parseRoutes turns the configured CIDR prefixes into the form the tailnet
// preferences take, rejecting a malformed one at startup rather than on the
// first join.
func parseRoutes(routes []string) ([]netip.Prefix, error) {
	if len(routes) == 0 {
		return nil, nil
	}

	parsed := make([]netip.Prefix, 0, len(routes))
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return nil, fmt.Errorf("parsing route %q: %w", route, err)
		}
		// A prefix carrying host bits is rejected by the control plane, and
		// silently masking it would advertise something other than what was
		// written.
		if prefix.Masked() != prefix {
			return nil, fmt.Errorf("route %q has bits set beyond its prefix length, did you mean %q?", route, prefix.Masked())
		}
		parsed = append(parsed, prefix)
	}

	return parsed, nil
}

// parseServices resolves each Service's name and validates it, so that a
// typo is a startup error rather than a Service that never comes up.
func parseServices(services map[string]*static.TailnetService) (map[string]*service, error) {
	if len(services) == 0 {
		return nil, nil
	}

	parsed := make(map[string]*service, len(services))
	for key, cfg := range services {
		if cfg == nil {
			return nil, fmt.Errorf("service %q: missing configuration", key)
		}

		name := cfg.Name
		if name == "" {
			name = servicePrefix + key
		}

		svcName := tailcfg.ServiceName(name)
		if err := svcName.Validate(); err != nil {
			return nil, fmt.Errorf("service %q: invalid name %q: %w", key, name, err)
		}

		if cfg.ProxyProtocol < 0 || cfg.ProxyProtocol > 2 {
			return nil, fmt.Errorf("service %q: proxyProtocol must be 0, 1 or 2, got %d", key, cfg.ProxyProtocol)
		}

		switch cfg.Mode {
		case "", static.TailnetServiceModeTCP, static.TailnetServiceModeTUN:
		default:
			return nil, fmt.Errorf("service %q: unknown mode %q, want %q or %q",
				key, cfg.Mode, static.TailnetServiceModeTCP, static.TailnetServiceModeTUN)
		}

		parsed[key] = &service{name: svcName, cfg: cfg}
	}

	return parsed, nil
}

// service is one configured Tailscale Service, with its name resolved.
type service struct {
	name tailcfg.ServiceName
	cfg  *static.TailnetService
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

// Start joins the nodes that have something to publish before anything asks
// them for a listener or a dial. A node advertising routes is the case that
// matters: the routes exist only while it is joined, so waiting for an
// entryPoint that may never reference it would leave them unadvertised.
//
// It does not block. Each node joins in the background and retries, so a
// tailnet that is not up yet costs nothing at startup.
func (r *Registry) Start(ctx context.Context) {
	if r == nil {
		return
	}

	for _, node := range r.nodes {
		if len(node.routes) == 0 {
			continue
		}

		go node.joinAndRetry(ctx, r.stop)
	}
}

// LogUnhostedServices warns about Services that are configured but that no
// entryPoint hosts. Hosting is what advertises a Service, so one nothing
// references is inert, which is easy to write and hard to notice.
func (r *Registry) LogUnhostedServices(hosted map[string]map[string]struct{}) {
	if r == nil {
		return
	}

	for name, node := range r.nodes {
		for key, svc := range node.services {
			if _, ok := hosted[name][key]; ok {
				continue
			}

			log.Warn().
				Str("tailnet", name).
				Str("service", svc.name.String()).
				Msgf("Tailscale Service %q is configured but no entryPoint hosts it; set tailnetService on an entryPoint to advertise it", key)
		}
	}
}

// Close shuts down every node that was started.
func (r *Registry) Close() {
	if r == nil {
		return
	}

	r.stopOnce.Do(func() { close(r.stop) })

	for _, node := range r.nodes {
		node.Close()
	}
}

// Node is one embedded Tailscale node. The underlying tsnet.Server is built
// on first use and discarded if it fails to start, because tsnet caches a
// failed start forever on the server it happened to: retrying has to happen
// on a fresh one.
type Node struct {
	name     string
	cfg      *static.Tailnet
	routes   []netip.Prefix
	services map[string]*service

	// startMu serializes join attempts. It is deliberately not n.mu:
	// tsnet.Server.Start takes no context and can block for as long as the
	// control plane keeps it waiting, and Close must not queue behind it.
	startMu sync.Mutex

	// serveMu serializes read-modify-write of the node's serve
	// configuration. Two entryPoints hosting Services on one node otherwise
	// race, and the loser is rejected with an etag mismatch.
	serveMu sync.Mutex

	// tun is set when a Service on this tailnet is served in TUN mode, or
	// the node advertises routes. Either makes the node hand its declined
	// packets to an in-process stack rather than to a (fake) device that
	// discards them, and those packets include everything for the node's
	// advertised routes, which the local stack then answers.
	tun bool

	mu     sync.Mutex
	srv    *tsnet.Server
	dev    *memTUN
	local  *localStack
	closed bool
}

// Name returns the configured name of the tailnet, as entryPoints and
// serversTransports reference it.
func (n *Node) Name() string { return n.name }

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
	if routed, ok := n.routedAddr(addr); ok {
		return n.listenRoutedTCP(routed)
	}
	return srv.Listen(network, addr)
}

// HasService reports whether the named Tailscale Service is configured on
// this tailnet, letting an entryPoint fail on a typo at startup.
func (n *Node) HasService(name string) bool {
	_, ok := n.services[name]
	return ok
}

// ServiceMode returns how the named Service is served, which decides whether
// an entryPoint takes it from Tailscale's serve configuration or from the
// in-process stack. It returns "" for a Service that is not configured.
func (n *Node) ServiceMode(name string) string {
	svc, ok := n.services[name]
	if !ok {
		return ""
	}
	if svc.cfg.Mode == "" {
		return static.TailnetServiceModeTCP
	}
	return svc.cfg.Mode
}

// ListenService announces the named Tailscale Service on the given port and
// returns a listener for it. Hosting a Service advertises it from this node,
// which the tailnet must still approve, and requires the node to be tagged.
//
// The returned listener is a local socket that Tailscale forwards the
// Service's traffic to, so its connections come from the loopback address
// rather than from the peer. With the Service's PROXY protocol enabled, the
// listener parses the header Tailscale sends and reports the peer's real
// address, which is what keeps access logs and IP allow-lists meaningful.
func (n *Node) ListenService(name string, port uint16) (net.Listener, error) {
	svc, ok := n.services[name]
	if !ok {
		return nil, fmt.Errorf("tailnet %q: unknown Service %q", n.name, name)
	}

	srv, err := n.server()
	if err != nil {
		return nil, err
	}

	listener, err := srv.ListenService(svc.name.String(), tsnet.ServiceModeTCP{
		Port:                 port,
		TerminateTLS:         svc.cfg.TerminateTLS,
		PROXYProtocolVersion: svc.cfg.ProxyProtocol,
	})
	if err != nil {
		return nil, fmt.Errorf("tailnet %q: hosting Service %q: %w", n.name, svc.name, err)
	}

	log.Info().
		Str("tailnet", n.name).
		Str("service", svc.name.String()).
		Str("fqdn", listener.FQDN).
		Uint16("port", port).
		Msg("Hosting Tailscale Service")

	if svc.cfg.ProxyProtocol == 0 {
		return listener, nil
	}

	// Tailscale forwards over loopback, so the header it writes is the only
	// account of who the peer was. Trusting it unconditionally is safe here
	// precisely because nothing else can reach this socket.
	return &proxyproto.Listener{
		Listener: listener,
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			// REQUIRE, not USE: we asked Tailscale for a header, so a
			// connection without one did not come through the Service and
			// has no business being served as though it had.
			return proxyproto.REQUIRE, nil
		},
	}, nil
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
	if routed, ok := n.routedAddr(addr); ok {
		return n.listenRoutedUDP(routed)
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
	srv, dev, local := n.srv, n.dev, n.local
	n.srv, n.dev, n.local = nil, nil, nil
	n.closed = true
	n.mu.Unlock()

	if srv != nil {
		if err := srv.Close(); err != nil {
			log.Debug().Err(err).Str("tailnet", n.name).Msg("Closing tailnet node")
		}
	}

	// After the node: it writes into the device, so releasing the stack
	// first would drop packets it is still handing over.
	if local != nil {
		local.close()
	}
	if dev != nil {
		_ = dev.Close()
	}
}

// routedAddr reports whether addr is an address inside one of the node's
// advertised routes, on a node whose packets for it reach the local stack.
//
// That is a node with a device, which every node advertising routes has.
// Given one, tsnet stops taking subnet traffic into its own netstack and
// releases it to the device instead, so a listener tsnet opened on a routed
// address would never see a packet.
func (n *Node) routedAddr(addr string) (netip.AddrPort, bool) {
	if !n.tun {
		return netip.AddrPort{}, false
	}

	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil {
		return netip.AddrPort{}, false
	}

	ip := addrPort.Addr().Unmap()
	for _, route := range n.routes {
		if route.Contains(ip) {
			return netip.AddrPortFrom(ip, addrPort.Port()), true
		}
	}
	return netip.AddrPort{}, false
}

// listenRoutedTCP accepts TCP for a routed address on the local stack.
func (n *Node) listenRoutedTCP(addr netip.AddrPort) (net.Listener, error) {
	local, err := n.holdRouted(addr.Addr())
	if err != nil {
		return nil, err
	}

	ln, err := local.listenTCP(addr)
	if err != nil {
		return nil, fmt.Errorf("tailnet %q: %w", n.name, err)
	}
	return ln, nil
}

// listenRoutedUDP accepts UDP for a routed address on the local stack.
func (n *Node) listenRoutedUDP(addr netip.AddrPort) (net.PacketConn, error) {
	local, err := n.holdRouted(addr.Addr())
	if err != nil {
		return nil, err
	}

	conn, err := local.listenUDP(addr)
	if err != nil {
		return nil, fmt.Errorf("tailnet %q: %w", n.name, err)
	}
	return conn, nil
}

// holdRouted gives the local stack a routed address to answer for.
func (n *Node) holdRouted(addr netip.Addr) (*localStack, error) {
	n.mu.Lock()
	local := n.local
	n.mu.Unlock()
	if local == nil {
		return nil, fmt.Errorf("tailnet %q: no local stack for routed address %s", n.name, addr)
	}

	if err := local.addAddr(addr); err != nil {
		return nil, fmt.Errorf("tailnet %q: %w", n.name, err)
	}
	return local, nil
}

// server returns a started tsnet.Server, building and joining as needed.
func (n *Node) server() (*tsnet.Server, error) {
	if srv, settled, err := n.current(); settled {
		return srv, err
	}

	n.startMu.Lock()
	defer n.startMu.Unlock()

	// Another caller may have joined while this one waited for the lock.
	if srv, settled, err := n.current(); settled {
		return srv, err
	}

	srv, local, err := n.build()
	if err != nil {
		return nil, err
	}

	// tsnet.Server.Start cleans up after itself on failure, so a server that
	// failed here needs no Close; dropping it means the next attempt gets a
	// fresh sync.Once rather than the cached error, which is the whole
	// reason a failed node is rebuilt instead of retried in place. The local
	// stack was built for this server alone, so it goes with it: kept, every
	// retry against an unreachable tailnet would leave one more behind.
	if err := srv.Start(); err != nil {
		local.release()
		return nil, fmt.Errorf("tailnet %q: joining: %w", n.name, err)
	}

	// Routes are advertised through the preferences, which tsnet does not
	// carry on its Server, so they are applied once the node has joined. A
	// failure here drops the server so the next attempt is a clean retry:
	// keeping a node that advertises nothing it was told to would be a
	// tailnet that looks healthy and routes nothing.
	if err := n.advertiseRoutes(srv); err != nil {
		_ = srv.Close()
		local.release()
		return nil, err
	}

	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		// Closed while this join was in flight. The server did start, so it
		// owns resources and must be released.
		_ = srv.Close()
		local.release()
		return nil, net.ErrClosed
	}
	n.srv = srv
	if local != nil {
		n.dev, n.local = local.dev, local
	}
	n.mu.Unlock()

	return srv, nil
}

// current reports the node's settled state: a joined server, or the closed
// error. settled is false when a join still has to happen.
func (n *Node) current() (srv *tsnet.Server, settled bool, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	switch {
	case n.closed:
		return nil, true, net.ErrClosed
	case n.srv != nil:
		return n.srv, true, nil
	default:
		return nil, false, nil
	}
}

// build assembles an unstarted tsnet.Server from the configuration, resolving
// the auth key file now: reading it at build time rather than at startup lets
// a key delivered late by an external system be picked up on a retry.
//
// On a node that needs one it also returns the local stack, with the device
// it reads from. Neither is published on the node until the server has
// started, so a Close meanwhile never races a build, and a failed join
// releases its own.
func (n *Node) build() (*tsnet.Server, *localStack, error) {
	authKey := n.cfg.AuthKey
	if n.cfg.AuthKeyFile != "" {
		content, err := os.ReadFile(n.cfg.AuthKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("tailnet %q: reading authKeyFile: %w", n.name, err)
		}
		authKey = strings.TrimSpace(string(content))
	}

	logger := log.With().Str("tailnet", n.name).Logger()

	srv := &tsnet.Server{
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
	}

	if n.tun {
		// With a device attached, tsnet keeps handling its own addresses
		// (through registered gVisor endpoints) and releases everything else
		// — the Service's virtual IPs and the advertised routes among it — to
		// the device.
		dev := newMemTUN()
		local, err := newLocalStack(dev)
		if err != nil {
			_ = dev.Close()
			return nil, nil, fmt.Errorf("tailnet %q: %w", n.name, err)
		}

		srv.Tun = dev
		return srv, local, nil
	}

	return srv, nil, nil
}

// advertiseRoutes sets the node's advertised routes to exactly what the
// configuration names. It is a no-op when none are configured, so a node
// that never advertised any is not made to talk to its local API.
func (n *Node) advertiseRoutes(srv *tsnet.Server) error {
	if len(n.routes) == 0 {
		return nil
	}

	client, err := srv.LocalClient()
	if err != nil {
		return fmt.Errorf("tailnet %q: local client: %w", n.name, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), advertiseTimeout)
	defer cancel()

	if _, err := client.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		Prefs:              ipn.Prefs{AdvertiseRoutes: n.routes},
	}); err != nil {
		return fmt.Errorf("tailnet %q: advertising routes: %w", n.name, err)
	}

	log.Info().
		Str("tailnet", n.name).
		Strs("routes", n.cfg.Routes).
		Msg("Advertised routes into the tailnet; they serve traffic only where an entryPoint binds the address, and need approval in the tailnet's ACLs")

	return nil
}

// joinAndRetry brings the node up, retrying with a capped backoff until it
// succeeds, the registry stops, or the context is done.
func (n *Node) joinAndRetry(ctx context.Context, stop <-chan struct{}) {
	logger := log.Ctx(ctx).With().Str("tailnet", n.name).Logger()

	for interval := retryInitialInterval; ; interval = min(interval*2, retryMaxInterval) {
		joined := make(chan error, 1)
		// tsnet's join takes no context, so it is abandoned rather than
		// canceled; the node itself releases what it built when closed.
		go func() {
			_, err := n.server()
			joined <- err
		}()

		select {
		case err := <-joined:
			if err == nil {
				return
			}
			// A closed node is not coming back.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Warn().Err(err).Str("retryIn", interval.String()).Msg("Cannot join tailnet yet, retrying")
		case <-stop:
			return
		case <-ctx.Done():
			return
		}

		select {
		case <-time.After(interval):
		case <-stop:
			return
		case <-ctx.Done():
			return
		}
	}
}
