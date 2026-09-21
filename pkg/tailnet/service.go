package tailnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// vipWaitTimeout bounds how long a listener waits for the control plane to
// assign the Service its addresses. An advertisement that no auto-approver
// covers waits on a human, which is a configuration problem rather than a
// slow one, so this fails and lets the retry say so again.
const vipWaitTimeout = 90 * time.Second

// hostTUNService advertises the Service in TUN mode and returns the addresses
// the control plane assigned it.
//
// TUN mode is what makes the Service's packets arrive here at all: it
// advertises every port and protocol, and in exchange tsnet's own netstack
// stops handling them. The local stack then answers for the addresses this
// returns.
func (n *Node) hostTUNService(ctx context.Context, svc *service) ([]netip.Addr, error) {
	srv, err := n.server()
	if err != nil {
		return nil, err
	}

	client, err := srv.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("tailnet %q: local client: %w", n.name, err)
	}

	// Only tagged nodes may host a Service; saying so here names the
	// configuration that is wrong instead of leaving a listener retrying
	// against a refusal that will not change.
	status, err := client.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("tailnet %q: reading status: %w", n.name, err)
	}
	if status.Self == nil || status.Self.Tags == nil || status.Self.Tags.Len() == 0 {
		return nil, fmt.Errorf("tailnet %q: hosting Service %q requires a tagged node; set advertiseTags", n.name, svc.name)
	}

	if err := n.setServiceTUN(ctx, svc.name); err != nil {
		return nil, err
	}
	if err := n.advertiseService(ctx, svc.name); err != nil {
		return nil, err
	}

	addrs, err := n.awaitServiceAddrs(ctx, svc.name)
	if err != nil {
		return nil, err
	}

	n.mu.Lock()
	local := n.local
	n.mu.Unlock()
	if local == nil {
		return nil, fmt.Errorf("tailnet %q: no local stack for Service %q", n.name, svc.name)
	}

	for _, addr := range addrs {
		if err := local.addAddr(addr); err != nil {
			return nil, fmt.Errorf("tailnet %q: %w", n.name, err)
		}
	}

	log.Info().
		Str("tailnet", n.name).
		Str("service", svc.name.String()).
		Strs("addresses", addrStrings(addrs)).
		Msg("Hosting Tailscale Service in TUN mode")

	return addrs, nil
}

// setServiceTUN marks the Service as TUN mode in the node's serve
// configuration, leaving any other Service's entry alone.
func (n *Node) setServiceTUN(ctx context.Context, svc tailcfg.ServiceName) error {
	srv, err := n.server()
	if err != nil {
		return err
	}
	client, err := srv.LocalClient()
	if err != nil {
		return err
	}

	// Read-modify-write, serialized: the serve configuration is the node's,
	// not this Service's. Replacing it wholesale would drop every other one,
	// and two entryPoints reading the same version and both writing it back
	// means the second is rejected on its etag.
	n.serveMu.Lock()
	defer n.serveMu.Unlock()

	current, err := client.GetServeConfig(ctx)
	if err != nil {
		return fmt.Errorf("tailnet %q: reading serve config: %w", n.name, err)
	}
	if current == nil {
		current = &ipn.ServeConfig{}
	}
	if current.Services == nil {
		current.Services = map[tailcfg.ServiceName]*ipn.ServiceConfig{}
	}

	// TUN mode and TCP or web handlers are mutually exclusive, and
	// tailscaled refuses a write that holds both. An entry left from a
	// previous configuration is replaced rather than merged.
	current.Services[svc] = &ipn.ServiceConfig{Tun: true}

	if err := client.SetServeConfig(ctx, current); err != nil {
		return fmt.Errorf("tailnet %q: setting serve config for %q: %w", n.name, svc, err)
	}
	return nil
}

// advertiseService adds the Service to the node's advertised set, which is
// what tells the control plane this node hosts it.
func (n *Node) advertiseService(ctx context.Context, svc tailcfg.ServiceName) error {
	srv, err := n.server()
	if err != nil {
		return err
	}
	client, err := srv.LocalClient()
	if err != nil {
		return err
	}

	prefs, err := client.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("tailnet %q: reading prefs: %w", n.name, err)
	}

	for _, s := range prefs.AdvertiseServices {
		if s == svc.String() {
			return nil
		}
	}

	advertised := append(append([]string{}, prefs.AdvertiseServices...), svc.String())
	if _, err := client.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseServicesSet: true,
		Prefs:                ipn.Prefs{AdvertiseServices: advertised},
	}); err != nil {
		return fmt.Errorf("tailnet %q: advertising Service %q: %w", n.name, svc, err)
	}
	return nil
}

// awaitServiceAddrs waits for the control plane to assign the Service its
// virtual IPs, which it does a netmap update after approving the
// advertisement.
func (n *Node) awaitServiceAddrs(ctx context.Context, svc tailcfg.ServiceName) ([]netip.Addr, error) {
	srv, err := n.server()
	if err != nil {
		return nil, err
	}
	client, err := srv.LocalClient()
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(vipWaitTimeout)
	for {
		status, err := client.Status(ctx)
		if err == nil && status.Self != nil {
			maps, err := tailcfg.UnmarshalNodeCapJSON[tailcfg.ServiceIPMappings](status.Self.CapMap, tailcfg.NodeAttrServiceHost)
			if err == nil {
				for _, m := range maps {
					if addrs, ok := m[svc]; ok && len(addrs) > 0 {
						return addrs, nil
					}
				}
			}
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("tailnet %q: Service %q has no addresses after %s; is its advertisement approved in the tailnet policy?", n.name, svc, vipWaitTimeout)
		}

		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// ListenServiceTUN accepts TCP for the named Service on every address the
// control plane gave it.
func (n *Node) ListenServiceTUN(ctx context.Context, name string, port uint16) (net.Listener, error) {
	svc, local, addrs, err := n.prepareTUNService(ctx, name)
	if err != nil {
		return nil, err
	}

	listeners := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		ln, err := local.listenTCP(netip.AddrPortFrom(addr, port))
		if err != nil {
			closeAll(listeners)
			return nil, fmt.Errorf("tailnet %q: Service %q: %w", n.name, svc.name, err)
		}
		listeners = append(listeners, ln)
	}

	return newMultiListener(listeners, serviceAddr{service: svc.name.String(), port: port}), nil
}

// ListenServicePacketTUN accepts UDP for the named Service on every address
// the control plane gave it.
func (n *Node) ListenServicePacketTUN(ctx context.Context, name string, port uint16) ([]net.PacketConn, error) {
	svc, local, addrs, err := n.prepareTUNService(ctx, name)
	if err != nil {
		return nil, err
	}

	conns := make([]net.PacketConn, 0, len(addrs))
	for _, addr := range addrs {
		pc, err := local.listenUDP(netip.AddrPortFrom(addr, port))
		if err != nil {
			for _, open := range conns {
				_ = open.Close()
			}
			return nil, fmt.Errorf("tailnet %q: Service %q: %w", n.name, svc.name, err)
		}
		conns = append(conns, pc)
	}

	return conns, nil
}

// prepareTUNService resolves the Service, hosts it, and returns the stack and
// addresses its listeners belong on.
func (n *Node) prepareTUNService(ctx context.Context, name string) (*service, *localStack, []netip.Addr, error) {
	svc, ok := n.services[name]
	if !ok {
		return nil, nil, nil, fmt.Errorf("tailnet %q: unknown Service %q", n.name, name)
	}
	if svc.cfg.Mode != static.TailnetServiceModeTUN {
		return nil, nil, nil, fmt.Errorf("tailnet %q: Service %q is not in %q mode", n.name, name, static.TailnetServiceModeTUN)
	}

	addrs, err := n.hostTUNService(ctx, svc)
	if err != nil {
		return nil, nil, nil, err
	}

	n.mu.Lock()
	local := n.local
	n.mu.Unlock()
	if local == nil {
		return nil, nil, nil, fmt.Errorf("tailnet %q: no local stack", n.name)
	}

	return svc, local, addrs, nil
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func closeAll(listeners []net.Listener) {
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

// serviceAddr names a Service listener by the Service rather than by one of
// its addresses: it accepts on every one, so no single address describes it.
type serviceAddr struct {
	service string
	port    uint16
}

func (a serviceAddr) Network() string { return "tcp" }
func (a serviceAddr) String() string  { return fmt.Sprintf("%s:%d", a.service, a.port) }

// multiListener presents several listeners as one. A Service has an address
// per family, and an entryPoint is one listener, so the two are joined here
// rather than by running an entryPoint per address.
type multiListener struct {
	listeners []net.Listener
	addr      net.Addr

	accepted  chan acceptResult
	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func newMultiListener(listeners []net.Listener, addr net.Addr) net.Listener {
	m := &multiListener{
		listeners: listeners,
		addr:      addr,
		accepted:  make(chan acceptResult),
		done:      make(chan struct{}),
	}

	for _, ln := range listeners {
		m.wg.Add(1)
		go m.accept(ln)
	}

	return m
}

func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case res := <-m.accepted:
		return res.conn, res.err
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *multiListener) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)
		closeAll(m.listeners)
	})
	m.wg.Wait()
	return nil
}

func (m *multiListener) Addr() net.Addr { return m.addr }

func (m *multiListener) accept(ln net.Listener) {
	defer m.wg.Done()

	for {
		conn, err := ln.Accept()
		select {
		case m.accepted <- acceptResult{conn: conn, err: err}:
		case <-m.done:
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
		if err != nil {
			return
		}
	}
}
