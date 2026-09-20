package tailnet

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
)

func testNode(t *testing.T, cfg *static.Tailnet) *Node {
	t.Helper()

	registry, err := NewRegistry(map[string]*static.Tailnet{"corp": cfg})
	require.NoError(t, err)
	t.Cleanup(registry.Close)

	node, err := registry.Node("corp")
	require.NoError(t, err)

	return node
}

// unstartableNode cannot join, because its state directory can never be
// created: the parent is a regular file. It is how the retry path is
// exercised without a control plane.
func unstartableNode(t *testing.T) *Node {
	t.Helper()

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))

	return testNode(t, &static.Tailnet{StateDir: filepath.Join(blocker, "state")})
}

// Before the node has joined, Addr reports the address the listener is
// trying to bind, so that logs and the HTTP server see something meaningful
// rather than nil.
func TestLazyListenerAddrBeforeBind(t *testing.T) {
	listener := unstartableNode(t).LazyListen(t.Context(), "tcp", ":8443")
	t.Cleanup(func() { _ = listener.Close() })

	addr := listener.Addr()
	require.NotNil(t, addr)
	assert.Equal(t, "tcp", addr.Network())
	assert.Equal(t, ":8443", addr.String())
}

// A tailnet that cannot be joined must not fail the entryPoint outright:
// Accept keeps retrying, and only a Close ends it. This is what keeps one
// undeliverable auth key from taking the whole proxy down.
func TestLazyListenerRetriesUntilClosed(t *testing.T) {
	listener := unstartableNode(t).LazyListen(t.Context(), "tcp", ":8443")

	accepted := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		accepted <- err
	}()

	// Long enough for several failed binds; Accept must still be waiting.
	select {
	case err := <-accepted:
		t.Fatalf("Accept returned %v instead of retrying", err)
	case <-time.After(1500 * time.Millisecond):
	}

	require.NoError(t, listener.Close())

	select {
	case err := <-accepted:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}

	// Close is idempotent: the entryPoint shutdown path may reach it twice.
	require.NoError(t, listener.Close())
}

// Cancelling the context abandons a bind that has not succeeded, so a
// listener nobody is waiting for does not retry forever.
func TestLazyListenerContextCancelAbandonsPendingBind(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	listener := unstartableNode(t).LazyListen(ctx, "tcp", ":8443")
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		accepted <- err
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-accepted:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after the context was cancelled")
	}
}

// Accept on a listener whose node is already closed must fail immediately:
// a closed node is not coming back, so there is nothing to retry towards.
func TestLazyListenerAcceptAfterNodeCloseFailsFast(t *testing.T) {
	node := unstartableNode(t)
	listener := node.LazyListen(t.Context(), "tcp", ":8443")
	t.Cleanup(func() { _ = listener.Close() })

	node.Close()

	accepted := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		accepted <- err
	}()

	select {
	case err := <-accepted:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(retryInitialInterval):
		t.Fatal("Accept retried against a closed node instead of failing fast")
	}
}

func TestListenPacketAllRejectsBadAddress(t *testing.T) {
	_, err := unstartableNode(t).ListenPacketAll(t.Context(), "udp", "no-port")
	require.ErrorContains(t, err, "parsing address")
}

// The packet path retries the same way the stream path does.
func TestRetryListenPacketAllAbandonsOnDone(t *testing.T) {
	node := unstartableNode(t)

	done := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := node.RetryListenPacketAll(t.Context(), "udp", ":8443", done)
		result <- err
	}()

	select {
	case err := <-result:
		t.Fatalf("RetryListenPacketAll returned %v instead of retrying", err)
	case <-time.After(1500 * time.Millisecond):
	}

	close(done)

	select {
	case err := <-result:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("RetryListenPacketAll did not return after done was closed")
	}
}
