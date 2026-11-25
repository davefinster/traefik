package healthcheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/testhelpers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// servingGRPCServer starts a gRPC server that reports itself as serving, and returns its address.
func servingGRPCServer(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	healthpb.RegisterHealthServer(server, health.NewServer())

	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	return listener.Addr().String()
}

// The gRPC health check dials by itself, and not through the transport of the service as the HTTP one does:
// it has to be told how to reach servers that are not on the host network.
func TestServiceHealthChecker_checkHealthGRPC_dialContext(t *testing.T) {
	serverAddr := servingGRPCServer(t)

	healthChecker := NewServiceHealthChecker(t.Context(), nil, &dynamic.ServerHealthCheck{Mode: modeGRPC}, nil, nil, http.DefaultTransport, nil, "")

	var seenAddr string
	healthChecker.SetDialContext(func(ctx context.Context, netw, addr string) (net.Conn, error) {
		seenAddr = addr

		return (&net.Dialer{}).DialContext(ctx, netw, serverAddr)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// The host is deliberately unresolvable: only the dial context can reach the server,
	// so a pass proves the host network was not used.
	err := healthChecker.checkHealthGRPC(ctx, testhelpers.MustParseURL("http://backend.invalid:8080"))
	require.NoError(t, err)

	assert.Equal(t, "backend.invalid:8080", seenAddr)
}

// A dial context that fails must fail the health check, whatever the host network can reach.
func TestServiceHealthChecker_checkHealthGRPC_dialContextNeverFallsBackToTheHostNetwork(t *testing.T) {
	// The server is reachable over the host network: the health check must still fail.
	serverAddr := servingGRPCServer(t)

	healthChecker := NewServiceHealthChecker(t.Context(), nil, &dynamic.ServerHealthCheck{Mode: modeGRPC}, nil, nil, http.DefaultTransport, nil, "")
	healthChecker.SetDialContext(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("network unavailable")
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	err := healthChecker.checkHealthGRPC(ctx, testhelpers.MustParseURL("http://"+serverAddr))
	require.ErrorContains(t, err, "network unavailable")
}
