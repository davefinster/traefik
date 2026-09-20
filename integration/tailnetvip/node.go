package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"

	_ "tailscale.com/feature/oauthkey"
)

// node is one tsnet server brought up for the duration of a run.
type node struct {
	srv *tsnet.Server
	lc  *local.Client
}

// startNode joins the tailnet with the given hostname and auth key, and waits
// for it to come up.
func startNode(ctx context.Context, dir, hostname, authKey string, tags []string) (*node, error) {
	srv := &tsnet.Server{
		Hostname:      hostname,
		Dir:           dir,
		AuthKey:       authKey,
		Ephemeral:     true,
		AdvertiseTags: tags,
		UserLogf:      func(string, ...any) {},
		Logf:          func(string, ...any) {},
	}

	if _, err := srv.Up(ctx); err != nil {
		srv.Close()
		return nil, fmt.Errorf("node %q: coming up: %w", hostname, err)
	}

	lc, err := srv.LocalClient()
	if err != nil {
		srv.Close()
		return nil, fmt.Errorf("node %q: local client: %w", hostname, err)
	}

	return &node{srv: srv, lc: lc}, nil
}

func (n *node) close() {
	if n != nil && n.srv != nil {
		n.srv.Close()
	}
}

// tagged reports whether control accepted this node's tags, which hosting a
// Service requires.
func (n *node) tagged(ctx context.Context) (bool, []string, error) {
	st, err := n.lc.Status(ctx)
	if err != nil {
		return false, nil, err
	}
	if st.Self == nil || st.Self.Tags == nil || st.Self.Tags.Len() == 0 {
		return false, nil, nil
	}
	return true, st.Self.Tags.AsSlice(), nil
}

// serviceVIPs returns the addresses control has assigned to the named
// Service for this node, discovered the way `tailscale serve status` does:
// the service-host node capability.
func (n *node) serviceVIPs(ctx context.Context, svc tailcfg.ServiceName) ([]netip.Addr, error) {
	st, err := n.lc.Status(ctx)
	if err != nil {
		return nil, err
	}
	if st.Self == nil {
		return nil, fmt.Errorf("status carried no self node")
	}

	maps, err := tailcfg.UnmarshalNodeCapJSON[tailcfg.ServiceIPMappings](st.Self.CapMap, tailcfg.NodeAttrServiceHost)
	if err != nil {
		return nil, fmt.Errorf("decoding %s capability: %w", tailcfg.NodeAttrServiceHost, err)
	}

	for _, m := range maps {
		if addrs, ok := m[svc]; ok {
			return addrs, nil
		}
	}
	return nil, nil
}

// awaitServiceVIPs polls until control has assigned the Service's addresses
// to this node, which happens a netmap update after the advertisement.
func (n *node) awaitServiceVIPs(ctx context.Context, svc tailcfg.ServiceName, timeout time.Duration) ([]netip.Addr, error) {
	deadline := time.Now().Add(timeout)
	for {
		addrs, err := n.serviceVIPs(ctx, svc)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return nil, fmt.Errorf("waiting for %s addresses: %w", svc, err)
			}
			return nil, fmt.Errorf("waiting for %s addresses: none assigned within %s", svc, timeout)
		}
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// setServeConfig replaces this node's serve configuration.
func (n *node) setServeConfig(ctx context.Context, sc *ipn.ServeConfig) error {
	return n.lc.SetServeConfig(ctx, sc)
}

// advertiseService adds the Service to the node's advertised set, which is
// what tells control this node hosts it.
func (n *node) advertiseService(ctx context.Context, svc tailcfg.ServiceName) error {
	prefs, err := n.lc.GetPrefs(ctx)
	if err != nil {
		return err
	}

	advertised := append([]string{}, prefs.AdvertiseServices...)
	for _, s := range advertised {
		if s == svc.String() {
			return nil
		}
	}
	advertised = append(advertised, svc.String())

	_, err = n.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseServicesSet: true,
		Prefs:                ipn.Prefs{AdvertiseServices: advertised},
	})
	return err
}

// unadvertiseService removes the Service from the node's advertised set. It
// must happen before the Service is deleted and recreated, or the node keeps
// claiming a Service that no longer exists and control never re-approves the
// replacement.
func (n *node) unadvertiseService(ctx context.Context, svc tailcfg.ServiceName) error {
	prefs, err := n.lc.GetPrefs(ctx)
	if err != nil {
		return err
	}

	kept := make([]string, 0, len(prefs.AdvertiseServices))
	for _, s := range prefs.AdvertiseServices {
		if s != svc.String() {
			kept = append(kept, s)
		}
	}
	if len(kept) == len(prefs.AdvertiseServices) {
		return nil
	}

	_, err = n.lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		AdvertiseServicesSet: true,
		Prefs:                ipn.Prefs{AdvertiseServices: kept},
	})
	return err
}

// clearServeConfig empties the serve configuration. tailscaled refuses to
// move a Service between TUN mode and TCP handlers in one write, so each
// variant starts from nothing rather than from its predecessor.
func (n *node) clearServeConfig(ctx context.Context) error {
	return n.lc.SetServeConfig(ctx, &ipn.ServeConfig{})
}

// dialTCP connects to addr over this node's tailnet.
func (n *node) dialTCP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return n.srv.Dial(ctx, "tcp", addr)
}

// dialUDP opens a packet conn to addr over this node's tailnet.
func (n *node) dialUDP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return n.srv.Dial(ctx, "udp", addr)
}
