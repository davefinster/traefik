package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	retryInitialInterval = 1 * time.Second
	retryMaxInterval     = 30 * time.Second
)

// LazyListen returns a listener on the tailnet straight away, before the node
// has joined it. Accept blocks until the bind succeeds, retrying with a capped
// backoff.
//
// Binding eagerly would mean a tailnet that is slow or unreachable at boot
// holds up every other entryPoint, and an auth key delivered a moment late
// takes the whole proxy down. Deferring it costs nothing: an entryPoint has
// no traffic to serve until it can accept, and the retry heals without a
// restart once the tailnet answers.
func (n *Node) LazyListen(ctx context.Context, network, addr string) net.Listener {
	return &lazyListener{
		node: n,
		bind: func() (net.Listener, error) { return n.Listen(network, addr) },
		addr: pendingAddr{network: network, addr: addr},
		ctx:  ctx,
		done: make(chan struct{}),
	}
}

// LazyListenService is LazyListen for a Tailscale Service. Hosting a Service
// needs more of the tailnet than a plain listener does: the node must have
// joined, be tagged, and have its advertisement accepted. All of that is
// waited out on the retry rather than at startup, for the same reason.
func (n *Node) LazyListenService(ctx context.Context, name string, port uint16) net.Listener {
	return &lazyListener{
		node: n,
		bind: func() (net.Listener, error) { return n.ListenService(name, port) },
		addr: pendingAddr{network: "tcp", addr: fmt.Sprintf("%s:%d", name, port)},
		ctx:  ctx,
		done: make(chan struct{}),
	}
}

// LazyListenServiceTUN is LazyListen for a Service served in TUN mode.
// Hosting one asks the most of the tailnet of anything here — the node must
// have joined, be tagged, have its advertisement approved, and be given the
// Service's addresses — so it is waited out on the retry rather than at
// startup, like everything else.
func (n *Node) LazyListenServiceTUN(ctx context.Context, name string, port uint16) net.Listener {
	return &lazyListener{
		node: n,
		bind: func() (net.Listener, error) { return n.ListenServiceTUN(ctx, name, port) },
		addr: serviceAddr{service: name, port: port},
		ctx:  ctx,
		done: make(chan struct{}),
	}
}

type lazyListener struct {
	node *Node
	bind func() (net.Listener, error)
	// addr stands in for the listener's address until it has one.
	addr net.Addr
	ctx  context.Context

	mu     sync.Mutex
	ln     net.Listener
	closed bool
	done   chan struct{}
}

// Accept waits for the tailnet listener to bind, then accepts on it.
func (l *lazyListener) Accept() (net.Conn, error) {
	ln, err := l.listener()
	if err != nil {
		return nil, err
	}
	return ln.Accept()
}

// Close releases the underlying listener and stops any pending retry.
func (l *lazyListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	ln := l.ln
	l.ln = nil
	close(l.done)
	l.mu.Unlock()

	if ln == nil {
		return nil
	}
	return ln.Close()
}

// Addr reports the bound tailnet address, or the address it is still trying
// to bind while the node comes up.
func (l *lazyListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.ln != nil {
		return l.ln.Addr()
	}
	return l.addr
}

// listener returns the bound tailnet listener, binding it on first call and
// retrying until it succeeds or the listener is closed.
func (l *lazyListener) listener() (net.Listener, error) {
	l.mu.Lock()
	switch {
	case l.closed:
		l.mu.Unlock()
		return nil, net.ErrClosed
	case l.ln != nil:
		ln := l.ln
		l.mu.Unlock()
		return ln, nil
	}
	l.mu.Unlock()

	logger := log.Ctx(l.ctx).With().Str("tailnet", l.node.Name()).Logger()

	for interval := retryInitialInterval; ; interval = min(interval*2, retryMaxInterval) {
		// The bind runs on its own goroutine because joining a tailnet is
		// not cancellable: tsnet's Start takes no context and can block for
		// as long as the control plane keeps it waiting. A shutdown has to
		// be able to abandon the attempt, and the goroutine hands over or
		// releases whatever it eventually binds.
		bound := make(chan error, 1)
		go func() { bound <- l.tryBind() }()

		var err error
		select {
		case err = <-bound:
			if err == nil {
				l.mu.Lock()
				ln := l.ln
				l.mu.Unlock()
				if ln != nil {
					logger.Info().Stringer("address", ln.Addr()).Msg("Listening on tailnet")
					return ln, nil
				}
				return nil, net.ErrClosed
			}

			// A closed node is not coming back, so there is nothing to
			// retry towards.
			if errors.Is(err, net.ErrClosed) {
				return nil, net.ErrClosed
			}
		case <-l.done:
			return nil, net.ErrClosed
		case <-l.ctx.Done():
			return nil, net.ErrClosed
		}

		logger.Warn().Err(err).Str("retryIn", interval.String()).Msg("Cannot listen on tailnet yet, retrying")

		select {
		case <-time.After(interval):
		case <-l.done:
			return nil, net.ErrClosed
		case <-l.ctx.Done():
			return nil, net.ErrClosed
		}
	}
}

// bind makes one attempt to listen on the tailnet, storing the listener on
// success. It closes what it bound if the lazyListener was closed meanwhile,
// or if another attempt got there first, so an abandoned attempt leaks
// nothing.
func (l *lazyListener) tryBind() error {
	ln, err := l.bind()
	if err != nil {
		return err
	}

	l.mu.Lock()
	if l.closed || l.ln != nil {
		l.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	l.ln = ln
	l.mu.Unlock()

	return nil
}

// pendingAddr stands in for the tailnet address before the node has one, so
// that anything reading Addr while the entryPoint waits (logs, the HTTP
// server) sees the configured address rather than nil.
type pendingAddr struct {
	network string
	addr    string
}

func (a pendingAddr) Network() string { return a.network }
func (a pendingAddr) String() string  { return a.addr }
