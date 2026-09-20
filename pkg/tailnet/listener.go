package tailnet

import (
	"context"
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
		node:    n,
		network: network,
		addr:    addr,
		ctx:     ctx,
		done:    make(chan struct{}),
	}
}

type lazyListener struct {
	node    *Node
	network string
	addr    string
	ctx     context.Context

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
		ln, err := l.node.Listen(l.network, l.addr)
		if err == nil {
			l.mu.Lock()
			// Closed while we were binding: the listener we just opened is
			// nobody's to accept on.
			if l.closed {
				l.mu.Unlock()
				_ = ln.Close()
				return nil, net.ErrClosed
			}
			l.ln = ln
			l.mu.Unlock()

			logger.Info().Stringer("address", ln.Addr()).Msg("Listening on tailnet")
			return ln, nil
		}

		logger.Warn().Err(err).Dur("retryIn", interval).Msg("Cannot listen on tailnet yet, retrying")

		select {
		case <-time.After(interval):
		case <-l.done:
			return nil, net.ErrClosed
		case <-l.ctx.Done():
			return nil, net.ErrClosed
		}
	}
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
	return pendingAddr{network: l.network, addr: l.addr}
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
