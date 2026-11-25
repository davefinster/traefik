// Package network is the extension point for the networks Traefik serves on
// besides the host's own.
//
// Out of the box an entryPoint listens on a host socket and a serversTransport
// dials through the host's network stack, and nothing here is involved. An
// Extension adds places to listen and ways to dial that the host does not
// have: a VPN node embedded in the process, for one, has neither a socket to
// bind nor a route to dial over.
//
// The package holds no implementation and depends on none. An Extension is
// built by whatever links one in, from its own part of the configuration, and
// handed to the entryPoints, the transport managers and the server. With none,
// which is a nil Extension, Traefik serves on the host network only.
package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// DialContextFunc opens a connection to a server. It has the signature of
// net.Dialer.DialContext, which is what it takes the place of.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// WithTimeout bounds each dial with timeout, which net.Dialer does by itself
// and a DialContextFunc from an Extension does not. Zero means no bound.
func (d DialContextFunc) WithTimeout(timeout time.Duration) DialContextFunc {
	if timeout <= 0 {
		return d
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		return d(ctx, network, address)
	}
}

// Extension supplies what the host network does not: places for entryPoints
// to accept on, and ways for serversTransports to reach their servers.
//
// Which entryPoints and serversTransports it serves is the Extension's own
// business, decided from its own configuration: the rest of Traefik asks, and
// falls back to the host network when the answer is no.
type Extension interface {
	// Sources returns where the named entryPoint accepts besides, or instead
	// of, its own address on the host. The zero Sources means the entryPoint
	// is on the host only.
	//
	// A configuration that cannot be honored is refused when the Extension
	// is built, not here.
	Sources(entryPoint string) Sources

	// HTTPDialer returns how an HTTP serversTransport reaches its servers,
	// and false when it does so over the host network.
	//
	// A transport that asks for a network the Extension cannot give it still
	// gets a dialer, one that fails: falling back to the host network would
	// send the traffic the one way its configuration ruled out.
	//
	// It is called every time a proxy is built for the transport, so it
	// should do no more than look the transport up. The transport's dial
	// timeout arrives as the deadline of the context the dialer is called
	// with.
	HTTPDialer(serversTransport *dynamic.ServersTransport) (DialContextFunc, bool)

	// TCPDialer is HTTPDialer for a TCP serversTransport.
	TCPDialer(serversTransport *dynamic.TCPServersTransport) (DialContextFunc, bool)

	// Start is called once, before the entryPoints start accepting. It must
	// not wait for the network: an Extension that has something to bring up
	// does so in the background.
	Start(ctx context.Context)

	// Withdraw is the first step of a graceful shutdown, called before any
	// entryPoint stops accepting. It asks the Extension to stop attracting
	// new connections while it still serves the ones that arrive, so that
	// peers have moved elsewhere by the time the listeners close. It is
	// bounded by ctx.
	Withdraw(ctx context.Context)

	// Close is the last step of a shutdown, called once every entryPoint has
	// stopped and nothing dials anymore.
	Close()
}

// Nop is the Extension that supplies nothing: every entryPoint and every
// serversTransport stays on the host network. It is there to be embedded, by
// an Extension that answers for only part of what the interface covers.
type Nop struct{}

// Sources returns no source.
func (Nop) Sources(string) Sources { return Sources{} }

// HTTPDialer answers for no serversTransport.
func (Nop) HTTPDialer(*dynamic.ServersTransport) (DialContextFunc, bool) { return nil, false }

// TCPDialer answers for no serversTransport.
func (Nop) TCPDialer(*dynamic.TCPServersTransport) (DialContextFunc, bool) { return nil, false }

// Start does nothing.
func (Nop) Start(context.Context) {}

// Withdraw does nothing.
func (Nop) Withdraw(context.Context) {}

// Close does nothing.
func (Nop) Close() {}

// Sources are the places an Extension gives one entryPoint to accept on.
type Sources struct {
	// Primary takes the place of the entryPoint's own address: when it is
	// set, nothing is bound on the host for the entryPoint.
	Primary Source

	// Additional sources accept alongside the entryPoint's own address,
	// wherever that is, and feed the same entryPoint.
	Additional []Source
}

// All returns every source, the primary one first.
func (s Sources) All() []Source {
	if s.Primary == nil {
		return s.Additional
	}

	all := make([]Source, 0, 1+len(s.Additional))
	all = append(all, s.Primary)

	return append(all, s.Additional...)
}

// Source is one place an entryPoint accepts on that is not a host socket.
//
// A Source is asked for a stream listener by a TCP entryPoint, and for packet
// conns by a UDP entryPoint and by a TCP entryPoint serving HTTP/3.
type Source interface {
	// String names the source, for logs and errors.
	fmt.Stringer

	// Listen returns a stream listener on the source. It must not wait for
	// the network: a listener that cannot bind yet is returned all the same,
	// and binds within Accept. A network that is slow or unreachable at
	// startup then costs only the entryPoints that are on it.
	//
	// The connections it accepts must be able to close their write half, with
	// a CloseWrite method as *net.TCPConn has: the entryPoint closes the ones
	// that cannot.
	Listen(ctx context.Context) net.Listener

	// CarriesPackets reports whether the source can deliver datagrams at
	// all. One that cannot is refused by a UDP entryPoint, and left out of
	// HTTP/3.
	CarriesPackets() bool

	// ListenPacket binds the source's packet conns and returns them
	// together: one for each address the source has, as a userspace network
	// stack has no wildcard socket to cover several. Unlike Listen it waits
	// for the network, for as long as it takes, and gives up when ctx is
	// done.
	//
	// The conns belong to the entryPoint from then on, which closes them
	// when it shuts down.
	ListenPacket(ctx context.Context) ([]net.PacketConn, error)
}
