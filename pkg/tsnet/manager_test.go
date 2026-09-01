package tsnet

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
)

func TestNewManagerNilConfig(t *testing.T) {
	m, err := NewManager(nil)
	require.NoError(t, err)
	require.Nil(t, m)

	// The nil manager must be usable: refusing every dial, knowing no tailnet.
	assert.False(t, m.Has("global-infrastructure"))
	_, err = m.DialContext(context.Background(), "global-infrastructure", "tcp", "host:80")
	assert.ErrorContains(t, err, "no tsnet tailnets configured")
	m.Close()
}

func TestNewManagerRequiresStateDir(t *testing.T) {
	_, err := NewManager(&static.TsnetConfig{
		Tailnets: map[string]*static.TsnetTailnet{
			"global-infrastructure": {Hostname: "edge"},
		},
	})
	require.ErrorContains(t, err, "stateDir is required")
}

func TestManagerUnknownTailnet(t *testing.T) {
	m, err := NewManager(&static.TsnetConfig{
		Tailnets: map[string]*static.TsnetTailnet{
			"global-infrastructure": {StateDir: t.TempDir()},
		},
	})
	require.NoError(t, err)
	t.Cleanup(m.Close)

	assert.True(t, m.Has("global-infrastructure"))
	assert.False(t, m.Has("homelab"))

	_, err = m.DialContext(context.Background(), "homelab", "tcp", "host:80")
	assert.ErrorContains(t, err, `unknown tsnet tailnet "homelab"`)
}

func TestManagerReadsAuthKeyFile(t *testing.T) {
	_, err := NewManager(&static.TsnetConfig{
		Tailnets: map[string]*static.TsnetTailnet{
			"global-infrastructure": {
				StateDir:    t.TempDir(),
				AuthKeyFile: "/does/not/exist",
			},
		},
	})
	require.ErrorContains(t, err, "reading authKeyFile")
}
