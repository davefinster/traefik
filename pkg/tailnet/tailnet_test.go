package tailnet

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
)

func TestNewRegistry(t *testing.T) {
	testCases := []struct {
		desc        string
		cfg         map[string]*static.Tailnet
		expectNil   bool
		expectErr   string
		expectNames []string
	}{
		{
			desc:      "no tailnets configured",
			cfg:       nil,
			expectNil: true,
		},
		{
			desc:      "empty map is the same as none",
			cfg:       map[string]*static.Tailnet{},
			expectNil: true,
		},
		{
			desc:      "nil entry",
			cfg:       map[string]*static.Tailnet{"corp": nil},
			expectErr: `tailnet "corp": missing configuration`,
		},
		{
			desc: "stateDir is required",
			// tsnet derives one default directory from the binary name,
			// which several nodes in one process cannot share.
			cfg:       map[string]*static.Tailnet{"corp": {Hostname: "traefik"}},
			expectErr: `tailnet "corp": stateDir is required`,
		},
		{
			desc: "authKey and authKeyFile are mutually exclusive",
			cfg: map[string]*static.Tailnet{"corp": {
				StateDir:    "/tmp/corp",
				AuthKey:     "tskey-auth-xxx",
				AuthKeyFile: "/run/secrets/corp",
			}},
			expectErr: `tailnet "corp": authKey and authKeyFile are mutually exclusive`,
		},
		{
			desc: "valid",
			cfg: map[string]*static.Tailnet{
				"corp": {StateDir: "/tmp/corp"},
				"edge": {StateDir: "/tmp/edge"},
			},
			expectNames: []string{"corp", "edge"},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			registry, err := NewRegistry(test.cfg)

			if test.expectErr != "" {
				require.EqualError(t, err, test.expectErr)
				return
			}
			require.NoError(t, err)

			if test.expectNil {
				assert.Nil(t, registry)
				return
			}

			for _, name := range test.expectNames {
				assert.True(t, registry.Has(name), name)

				node, err := registry.Node(name)
				require.NoError(t, err)
				assert.Equal(t, name, node.Name())
			}
		})
	}
}

// A nil registry stands for "no tailnets configured" everywhere, so that
// callers need no configured-or-not checks.
func TestNilRegistry(t *testing.T) {
	var registry *Registry

	assert.False(t, registry.Has("corp"))

	_, err := registry.Node("corp")
	require.ErrorIs(t, err, ErrNoTailnets)

	_, err = registry.DialContext(t.Context(), "corp", "tcp", "backend:80")
	require.ErrorIs(t, err, ErrNoTailnets)

	// Must not panic.
	registry.Close()
}

func TestRegistryUnknownTailnet(t *testing.T) {
	registry, err := NewRegistry(map[string]*static.Tailnet{"corp": {StateDir: t.TempDir()}})
	require.NoError(t, err)
	t.Cleanup(registry.Close)

	assert.False(t, registry.Has("typo"))

	_, err = registry.Node("typo")
	require.ErrorContains(t, err, `unknown tailnet "typo"`)

	_, err = registry.DialContext(t.Context(), "typo", "tcp", "backend:80")
	require.ErrorContains(t, err, `unknown tailnet "typo"`)
}

// The auth key file resolves when the node is built rather than at startup,
// so that a key delivered late by an external system is picked up by a retry
// instead of holding up the whole process.
func TestNodeBuildReadsAuthKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "authkey")

	registry, err := NewRegistry(map[string]*static.Tailnet{
		"corp": {StateDir: dir, AuthKeyFile: keyFile},
	})
	require.NoError(t, err)

	node, err := registry.Node("corp")
	require.NoError(t, err)

	// Absent file: the build fails, and nothing is cached.
	_, err = node.build()
	require.ErrorContains(t, err, "reading authKeyFile")

	// The key arrives, and trailing whitespace is trimmed.
	require.NoError(t, os.WriteFile(keyFile, []byte("tskey-auth-secret\n"), 0o600))

	srv, err := node.build()
	require.NoError(t, err)
	assert.Equal(t, "tskey-auth-secret", srv.AuthKey)
}

func TestNodeBuildCarriesConfiguration(t *testing.T) {
	dir := t.TempDir()

	registry, err := NewRegistry(map[string]*static.Tailnet{
		"corp": {
			Hostname:      "traefik-edge",
			StateDir:      dir,
			AuthKey:       "tskey-auth-secret",
			ControlURL:    "https://headscale.example.com",
			Ephemeral:     true,
			AdvertiseTags: []string{"tag:proxy"},
			Port:          41641,
		},
	})
	require.NoError(t, err)

	node, err := registry.Node("corp")
	require.NoError(t, err)

	srv, err := node.build()
	require.NoError(t, err)

	assert.Equal(t, "traefik-edge", srv.Hostname)
	assert.Equal(t, dir, srv.Dir)
	assert.Equal(t, "tskey-auth-secret", srv.AuthKey)
	assert.Equal(t, "https://headscale.example.com", srv.ControlURL)
	assert.True(t, srv.Ephemeral)
	assert.Equal(t, []string{"tag:proxy"}, srv.AdvertiseTags)
	assert.Equal(t, uint16(41641), srv.Port)
}

// Close must be safe on a node that never joined: tsnet panics on closing a
// server it never started, and an unused tailnet is the common case for a
// configuration that names more than it uses.
func TestNodeCloseNeverStarted(t *testing.T) {
	registry, err := NewRegistry(map[string]*static.Tailnet{"corp": {StateDir: t.TempDir()}})
	require.NoError(t, err)

	assert.NotPanics(t, registry.Close)

	// Closed nodes refuse further use rather than joining a tailnet during
	// shutdown.
	node, err := registry.Node("corp")
	require.NoError(t, err)

	_, err = node.Listen("tcp", ":80")
	require.ErrorIs(t, err, net.ErrClosed)
}
