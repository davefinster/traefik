package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/tailnet"
)

// tailnetSource is one place on a tailnet an entryPoint takes traffic from:
// an address on the node (its own, or one inside an advertised route), or a
// Tailscale Service. The entryPoint's own tailnet address is one, and so is
// each of its tailnetListeners.
type tailnetSource struct {
	node *tailnet.Node

	// service is the Service's key on the node, empty for an address.
	service string
	// mode is the Service's mode, for a Service.
	mode string
	// port is the port a Service is accepted on.
	port uint16

	// address is the host:port to accept on, for an address.
	address string
}

// description names the source for logs and errors.
func (s tailnetSource) description() string {
	if s.service != "" {
		return fmt.Sprintf("Service %q on tailnet %q", s.service, s.node.Name())
	}
	return fmt.Sprintf("%s on tailnet %q", s.address, s.node.Name())
}

// listen returns a stream listener on the source. It binds nothing yet: a
// tailnet listener binds on its first Accept and retries until it can, so a
// tailnet that is slow or unreachable costs only its own listener.
func (s tailnetSource) listen(ctx context.Context) net.Listener {
	switch {
	case s.service == "":
		return s.node.LazyListen(ctx, "tcp", s.address)
	case s.mode == static.TailnetServiceModeTUN:
		return s.node.LazyListenServiceTUN(ctx, s.service, s.port)
	default:
		return s.node.LazyListenService(ctx, s.service, s.port)
	}
}

// carriesPackets reports whether the source can deliver UDP at all. A Service
// in tcp mode cannot: Tailscale forwards it as TCP.
func (s tailnetSource) carriesPackets() bool {
	return s.service == "" || s.mode == static.TailnetServiceModeTUN
}

// listenPackets binds the source's packet conns, retrying until it can or
// until done is closed.
func (s tailnetSource) listenPackets(ctx context.Context, done <-chan struct{}) ([]net.PacketConn, error) {
	if s.service != "" {
		return s.node.RetryListenServicePacketTUN(ctx, s.service, s.port, done)
	}
	return s.node.RetryListenPacketAll(ctx, "udp", s.address, done)
}

// primaryTailnetSource returns the source for the entryPoint's own address
// when that address is on a tailnet, and nil when it is on the host.
func primaryTailnetSource(config *static.EntryPoint, tailnets *tailnet.Registry) (*tailnetSource, error) {
	if config.Tailnet == "" {
		if config.TailnetService != "" {
			return nil, errors.New("tailnetService requires the entryPoint to name a tailnet")
		}
		return nil, nil
	}

	node, err := tailnets.Node(config.Tailnet)
	if err != nil {
		return nil, err
	}

	if config.TailnetService == "" {
		return &tailnetSource{node: node, address: config.GetAddress()}, nil
	}

	return serviceSource(node, config.TailnetService, config)
}

// serviceSource resolves a Service on node, taking its port from the
// entryPoint's own address so that the two cannot disagree.
func serviceSource(node *tailnet.Node, service string, config *static.EntryPoint) (*tailnetSource, error) {
	if !node.HasService(service) {
		return nil, fmt.Errorf("unknown Tailscale Service %q on tailnet %q", service, node.Name())
	}

	port, err := entryPointPort(config)
	if err != nil {
		return nil, err
	}

	return &tailnetSource{node: node, service: service, mode: node.ServiceMode(service), port: port}, nil
}

// resolveTailnetListeners validates the entryPoint's tailnetListeners and
// returns a source for each.
func resolveTailnetListeners(config *static.EntryPoint, tailnets *tailnet.Registry) ([]tailnetSource, error) {
	if len(config.TailnetListeners) == 0 {
		return nil, nil
	}

	primary, err := primaryTailnetSource(config, tailnets)
	if err != nil {
		return nil, err
	}

	// A source taken twice is a bind that fails forever on the retry, which
	// is a configuration mistake better named at startup.
	seen := map[string]int{}
	if primary != nil {
		seen[sourceKey(*primary)] = -1
	}

	sources := make([]tailnetSource, 0, len(config.TailnetListeners))
	for i, listener := range config.TailnetListeners {
		source, err := resolveTailnetListener(config, listener, tailnets)
		if err != nil {
			return nil, fmt.Errorf("tailnetListeners[%d]: %w", i, err)
		}

		key := sourceKey(*source)
		if prev, ok := seen[key]; ok {
			if prev < 0 {
				return nil, fmt.Errorf("tailnetListeners[%d]: %s is already the entryPoint's own address", i, source.description())
			}
			return nil, fmt.Errorf("tailnetListeners[%d]: %s is already tailnetListeners[%d]", i, source.description(), prev)
		}
		seen[key] = i

		sources = append(sources, *source)
	}

	return sources, nil
}

func resolveTailnetListener(config *static.EntryPoint, listener *static.TailnetListener, tailnets *tailnet.Registry) (*tailnetSource, error) {
	if listener == nil || listener.Tailnet == "" {
		return nil, errors.New("tailnet is required")
	}
	if listener.Service != "" && listener.Address != "" {
		return nil, errors.New("service and address are mutually exclusive")
	}

	node, err := tailnets.Node(listener.Tailnet)
	if err != nil {
		return nil, err
	}

	if listener.Service != "" {
		return serviceSource(node, listener.Service, config)
	}

	address, err := tailnetListenerAddress(config, listener.Address)
	if err != nil {
		return nil, err
	}
	return &tailnetSource{node: node, address: address}, nil
}

// tailnetListenerAddress resolves a tailnet listener's address against the
// entryPoint's own port.
func tailnetListenerAddress(config *static.EntryPoint, address string) (string, error) {
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

func sourceKey(s tailnetSource) string {
	if s.service != "" {
		return s.node.Name() + "\x00service\x00" + s.service
	}
	return s.node.Name() + "\x00address\x00" + s.address
}

// mergedListener accepts on several listeners as one, which is how an
// entryPoint takes connections from its own address and from tailnets alike.
//
// A listener that fails for good is dropped rather than taking the others
// down with it: a tailnet going away must not stop the host listener. Accept
// fails for good only once every listener has.
type mergedListener struct {
	listeners []net.Listener
	addr      net.Addr

	conns chan net.Conn
	errs  chan error

	closeOnce sync.Once
	done      chan struct{}

	// exhausted is closed once every listener has stopped, with lastErr the
	// reason the last of them gave.
	exhausted chan struct{}
	lastErrMu sync.Mutex
	lastErr   error
}

// newMergedListener accepts on every listener, reporting the first one's
// address as its own: that is the entryPoint's own address.
func newMergedListener(ctx context.Context, listeners []net.Listener) *mergedListener {
	m := &mergedListener{
		listeners: listeners,
		addr:      listeners[0].Addr(),
		conns:     make(chan net.Conn),
		errs:      make(chan error),
		done:      make(chan struct{}),
		exhausted: make(chan struct{}),
	}

	var wg sync.WaitGroup
	for _, ln := range listeners {
		wg.Go(func() { m.serve(ctx, ln) })
	}
	go func() {
		wg.Wait()
		close(m.exhausted)
	}()

	return m
}

func (m *mergedListener) Accept() (net.Conn, error) {
	select {
	case conn := <-m.conns:
		return conn, nil
	case err := <-m.errs:
		return nil, err
	case <-m.done:
		return nil, net.ErrClosed
	case <-m.exhausted:
		m.lastErrMu.Lock()
		defer m.lastErrMu.Unlock()
		if m.lastErr == nil {
			return nil, net.ErrClosed
		}
		return nil, m.lastErr
	}
}

func (m *mergedListener) Close() error {
	var errs []error
	m.closeOnce.Do(func() {
		close(m.done)
		for _, ln := range m.listeners {
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
	})
	return errors.Join(errs...)
}

func (m *mergedListener) Addr() net.Addr { return m.addr }

// serve accepts on one listener until it fails for good or the merged
// listener is closed. A temporary error is handed to Accept, whose caller
// logs it and carries on, exactly as it would for a single listener.
func (m *mergedListener) serve(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err == nil {
			select {
			case m.conns <- conn:
			case <-m.done:
				_ = conn.Close()
				return
			}
			continue
		}

		select {
		case <-m.done:
			return
		default:
		}

		if isTemporaryAcceptError(err) {
			select {
			case m.errs <- err:
			case <-m.done:
				return
			}
			continue
		}

		log.Ctx(ctx).Error().Err(err).Stringer("address", ln.Addr()).
			Msg("Listener stopped; the entryPoint keeps accepting on its other listeners")

		m.lastErrMu.Lock()
		m.lastErr = err
		m.lastErrMu.Unlock()
		return
	}
}

// isTemporaryAcceptError reports whether an Accept error is one the
// entryPoint's accept loop retries after, rather than stopping on.
func isTemporaryAcceptError(err error) bool {
	if opErr, ok := errors.AsType[*net.OpError](err); ok && opErr.Temporary() {
		return true
	}
	if urlErr, ok := errors.AsType[*url.Error](err); ok && urlErr.Temporary() {
		return true
	}
	return false
}
