package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
)

// source is one place on a tailnet an entryPoint takes traffic from: an
// address on the node (its own, or one inside an advertised route), or a
// Tailscale Service. The entryPoint's own tailnet address is one, and so is
// each of its tailnetListeners.
type source struct {
	node *Node

	// service is the Service's key on the node, empty for an address.
	service string
	// mode is the Service's mode, for a Service.
	mode string
	// port is the port a Service is accepted on.
	port uint16

	// address is the host:port to accept on, for an address.
	address string
}

// String names the source for logs and errors.
func (s source) String() string {
	if s.service != "" {
		return fmt.Sprintf("Service %q on tailnet %q", s.service, s.node.Name())
	}
	return fmt.Sprintf("%s on tailnet %q", s.address, s.node.Name())
}

// Listen returns a stream listener on the source. It binds nothing yet: a
// tailnet listener binds on its first Accept and retries until it can, so a
// tailnet that is slow or unreachable costs only its own listener.
func (s source) Listen(ctx context.Context) net.Listener {
	switch {
	case s.service == "":
		return s.node.LazyListen(ctx, "tcp", s.address)
	case s.mode == static.TailnetServiceModeTUN:
		return s.node.LazyListenServiceTUN(ctx, s.service, s.port)
	default:
		return s.node.LazyListenService(ctx, s.service, s.port)
	}
}

// CarriesPackets reports whether the source can deliver UDP at all. A Service
// in tcp mode cannot: Tailscale forwards it as TCP.
func (s source) CarriesPackets() bool {
	return s.service == "" || s.mode == static.TailnetServiceModeTUN
}

// ListenPacket binds the source's packet conns, retrying until it can or
// until ctx is done.
func (s source) ListenPacket(ctx context.Context) ([]net.PacketConn, error) {
	if s.service != "" {
		return s.node.RetryListenServicePacketTUN(ctx, s.service, s.port, ctx.Done())
	}
	return s.node.RetryListenPacketAll(ctx, "udp", s.address, ctx.Done())
}

// key identifies what the source binds, so that one taken twice is caught.
func (s source) key() string {
	if s.service != "" {
		return s.node.Name() + "\x00service\x00" + s.service
	}
	return s.node.Name() + "\x00address\x00" + s.address
}

// resolveEntryPoints resolves every entryPoint against the tailnets, and
// refuses the configurations that cannot be served. It is called on a nil
// registry too: an entryPoint naming a tailnet when none is configured is as
// much a mistake as one naming a tailnet that does not exist.
func (r *Registry) resolveEntryPoints(entryPoints static.EntryPoints) (map[string]network.Sources, error) {
	resolved := make(map[string]network.Sources)
	// Tracks which Tailscale Services actually get hosted, so the ones that
	// were configured and forgotten can be called out.
	hosted := make(map[string]map[string]struct{})

	for name, config := range entryPoints {
		if config == nil {
			continue
		}

		sources, err := r.resolveEntryPoint(config)
		if err != nil {
			return nil, fmt.Errorf("error while building entryPoint %s: %w", name, err)
		}

		all := sources.All()
		if len(all) == 0 {
			continue
		}
		resolved[name] = sources

		for _, src := range all {
			if svc := src.(source); svc.service != "" {
				if hosted[svc.node.Name()] == nil {
					hosted[svc.node.Name()] = map[string]struct{}{}
				}
				hosted[svc.node.Name()][svc.service] = struct{}{}
			}
		}
	}

	r.LogUnhostedServices(hosted)

	return resolved, nil
}

// resolveEntryPoint returns where on the tailnets one entryPoint accepts,
// which is nowhere for an entryPoint that names none.
func (r *Registry) resolveEntryPoint(config *static.EntryPoint) (network.Sources, error) {
	// Resolved first, so that a mistake in one is reported whatever the
	// entryPoint's own address turns out to be.
	additional, err := r.listenerSources(config)
	if err != nil {
		return network.Sources{}, err
	}

	primary, err := r.primarySource(config)
	if err != nil {
		return network.Sources{}, err
	}

	var sources network.Sources
	for _, src := range additional {
		sources.Additional = append(sources.Additional, src)
	}
	if primary == nil {
		return sources, validatePackets(config, sources)
	}
	sources.Primary = *primary

	if config.ReusePort {
		// The listener is a socket on the in-process network stack, so there
		// is no host socket for SO_REUSEPORT to apply to, and nothing for a
		// second process to share.
		return network.Sources{}, errors.New("reusePort is not supported on a tailnet entryPoint")
	}

	if config.ProxyProtocol != nil && primary.service != "" && primary.mode != static.TailnetServiceModeTUN {
		// A Service forwarded by Tailscale reaches the entryPoint over a
		// loopback socket, so the peer is never the client and a
		// trusted-IP policy has nothing to judge. The Service's own
		// proxyProtocol option carries the client address instead, and
		// is read before the entryPoint sees the connection. A Service in
		// TUN mode has no such hop: the peer is the client, so the option
		// means what it usually means.
		return network.Sources{}, errors.New("proxyProtocol is not supported on a Tailscale Service entryPoint in tcp mode: use the Service's own proxyProtocol option, or mode tun")
	}

	return sources, validatePackets(config, sources)
}

// validatePackets refuses the sources that cannot carry what the entryPoint
// serves over UDP, with the reason a Service cannot, which the entryPoint
// itself has no way to know.
func validatePackets(config *static.EntryPoint, sources network.Sources) error {
	protocol, err := config.GetProtocol()
	if err != nil {
		return err
	}

	if protocol == "udp" {
		for _, src := range sources.All() {
			// Only a Service in TUN mode carries UDP: Tailscale forwards a
			// tcp-mode Service as TCP, so a UDP entryPoint would have nothing
			// to accept from one.
			if !src.CarriesPackets() {
				return fmt.Errorf("tailscale Service %q must be in %q mode to carry UDP", src.(source).service, static.TailnetServiceModeTUN)
			}
		}
		return nil
	}

	// A tcp-mode Service among the tailnetListeners is not refused: the
	// entryPoint may serve HTTP/3 on its other listeners, and leaves this
	// one out.
	if config.HTTP3 != nil && sources.Primary != nil && !sources.Primary.CarriesPackets() {
		// A tcp-mode Service is forwarded to the entryPoint as TCP, so there
		// is no packet conn for QUIC to read from.
		return errors.New("http3 is not supported on a Tailscale Service entryPoint in tcp mode: use mode tun")
	}

	return nil
}

// primarySource returns the source for the entryPoint's own address when
// that address is on a tailnet, and nil when it is on the host.
func (r *Registry) primarySource(config *static.EntryPoint) (*source, error) {
	if config.Tailnet == "" {
		if config.TailnetService != "" {
			return nil, errors.New("tailnetService requires the entryPoint to name a tailnet")
		}
		return nil, nil
	}

	node, err := r.Node(config.Tailnet)
	if err != nil {
		return nil, err
	}

	if config.TailnetService == "" {
		return &source{node: node, address: config.GetAddress()}, nil
	}

	return serviceSource(node, config.TailnetService, config)
}

// serviceSource resolves a Service on node, taking its port from the
// entryPoint's own address so that the two cannot disagree.
func serviceSource(node *Node, service string, config *static.EntryPoint) (*source, error) {
	if !node.HasService(service) {
		return nil, fmt.Errorf("unknown Tailscale Service %q on tailnet %q", service, node.Name())
	}

	port, err := entryPointPort(config)
	if err != nil {
		return nil, err
	}

	return &source{node: node, service: service, mode: node.ServiceMode(service), port: port}, nil
}

// entryPointPort is the port a Tailscale Service advertises, taken from the
// entryPoint's own address so that the two cannot disagree.
func entryPointPort(config *static.EntryPoint) (uint16, error) {
	_, portStr, err := net.SplitHostPort(config.GetAddress())
	if err != nil {
		return 0, fmt.Errorf("parsing entryPoint address %q: %w", config.GetAddress(), err)
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return 0, fmt.Errorf("parsing entryPoint port %q: %w", portStr, err)
	}

	if port == 0 {
		// tsnet refuses to advertise port 0, and a Service on an
		// arbitrary port could not be reached by name anyway.
		return 0, errors.New("a Tailscale Service entryPoint must name the port it advertises, not port 0")
	}

	return uint16(port), nil
}

// listenerSources validates the entryPoint's tailnetListeners and returns a
// source for each.
func (r *Registry) listenerSources(config *static.EntryPoint) ([]source, error) {
	if len(config.TailnetListeners) == 0 {
		return nil, nil
	}

	primary, err := r.primarySource(config)
	if err != nil {
		return nil, err
	}

	// A source taken twice is a bind that fails forever on the retry, which
	// is a configuration mistake better named at startup.
	seen := map[string]int{}
	if primary != nil {
		seen[primary.key()] = -1
	}

	sources := make([]source, 0, len(config.TailnetListeners))
	for i, listener := range config.TailnetListeners {
		src, err := r.listenerSource(config, listener)
		if err != nil {
			return nil, fmt.Errorf("tailnetListeners[%d]: %w", i, err)
		}

		key := src.key()
		if prev, ok := seen[key]; ok {
			if prev < 0 {
				return nil, fmt.Errorf("tailnetListeners[%d]: %s is already the entryPoint's own address", i, src)
			}
			return nil, fmt.Errorf("tailnetListeners[%d]: %s is already tailnetListeners[%d]", i, src, prev)
		}
		seen[key] = i

		sources = append(sources, *src)
	}

	return sources, nil
}

func (r *Registry) listenerSource(config *static.EntryPoint, listener *static.TailnetListener) (*source, error) {
	if listener == nil || listener.Tailnet == "" {
		return nil, errors.New("tailnet is required")
	}
	if listener.Service != "" && listener.Address != "" {
		return nil, errors.New("service and address are mutually exclusive")
	}

	node, err := r.Node(listener.Tailnet)
	if err != nil {
		return nil, err
	}

	if listener.Service != "" {
		return serviceSource(node, listener.Service, config)
	}

	address, err := listenerAddress(config, listener.Address)
	if err != nil {
		return nil, err
	}
	return &source{node: node, address: address}, nil
}

// listenerAddress resolves a tailnet listener's address against the
// entryPoint's own port.
func listenerAddress(config *static.EntryPoint, address string) (string, error) {
	_, port, err := net.SplitHostPort(config.GetAddress())
	if err != nil {
		return "", fmt.Errorf("parsing entryPoint address %q: %w", config.GetAddress(), err)
	}

	if address == "" {
		return net.JoinHostPort("", port), nil
	}

	if ip, err := netip.ParseAddr(address); err == nil {
		return net.JoinHostPort(ip.String(), port), nil
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("address %q: want an IP, an IP and port, or a port alone", address)
	}
	// A tailnet binds addresses, never names: there is no resolver on the
	// listening side to turn one into the other.
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("address %q: the host must be an IP", address)
		}
	}
	return address, nil
}
