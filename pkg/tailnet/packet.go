package tailnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/rs/zerolog/log"
)

// ListenPacketAll binds a packet conn on every address the node holds, and
// waits for the node to come up in order to learn them.
//
// tsnet requires a concrete IP for a packet conn, where a stream listener
// accepts an empty host and binds everything. So an address such as ":443"
// becomes one conn per tailnet address, which is how an entryPoint reaches
// both address families. An address that names a host binds only that one.
//
// The conns are returned together; on error none are left open.
func (n *Node) ListenPacketAll(ctx context.Context, network, addr string) ([]net.PacketConn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("tailnet %q: parsing address %q: %w", n.name, addr, err)
	}

	// An explicit, specified host is the operator pinning one address; take
	// it as given rather than expanding to the node's own addresses.
	if host != "" {
		if ip, err := netip.ParseAddr(host); err == nil && !ip.IsUnspecified() {
			conn, err := n.ListenPacket(network, addr)
			if err != nil {
				return nil, err
			}
			return []net.PacketConn{conn}, nil
		}
	}

	addrs, err := n.Addrs(ctx)
	if err != nil {
		return nil, err
	}

	conns := make([]net.PacketConn, 0, len(addrs))
	for _, ip := range addrs {
		conn, err := n.ListenPacket(network, net.JoinHostPort(ip.String(), port))
		if err != nil {
			for _, opened := range conns {
				_ = opened.Close()
			}
			return nil, fmt.Errorf("tailnet %q: listening on %s: %w", n.name, ip, err)
		}
		conns = append(conns, conn)
	}

	return conns, nil
}

// RetryListenPacketAll keeps trying ListenPacketAll with a capped backoff
// until it succeeds, ctx is canceled, or done is closed. It is how a UDP or
// HTTP/3 entryPoint waits out a tailnet that is not up yet without holding up
// the rest of Traefik.
func (n *Node) RetryListenPacketAll(ctx context.Context, network, addr string, done <-chan struct{}) ([]net.PacketConn, error) {
	logger := log.Ctx(ctx).With().Str("tailnet", n.name).Logger()

	for interval := retryInitialInterval; ; interval = min(interval*2, retryMaxInterval) {
		conns, err := n.ListenPacketAll(ctx, network, addr)
		if err == nil {
			return conns, nil
		}

		logger.Warn().Err(err).Str("retryIn", interval.String()).Msg("Cannot listen for packets on tailnet yet, retrying")

		select {
		case <-time.After(interval):
		case <-done:
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
