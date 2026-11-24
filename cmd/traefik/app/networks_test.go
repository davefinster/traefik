package app

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
)

func TestSetupNetworks(t *testing.T) {
	staticConfiguration := &static.Configuration{}
	networks := &network.Nop{}
	failure := errors.New("cannot be served")

	testCases := []struct {
		desc      string
		options   Options
		expect    network.Extension
		expectErr error
	}{
		{
			// Not nothing: the extension that refuses the tailnets.
			desc:   "without networks",
			expect: &noTailnets{},
		},
		{
			desc: "with networks",
			options: Options{Networks: func(got *static.Configuration) (network.Extension, error) {
				assert.Same(t, staticConfiguration, got)
				return networks, nil
			}},
			expect: networks,
		},
		{
			desc: "with networks that cannot serve the configuration",
			options: Options{Networks: func(*static.Configuration) (network.Extension, error) {
				return nil, failure
			}},
			expectErr: failure,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			got, err := setupNetworks(staticConfiguration, test.options)
			require.ErrorIs(t, err, test.expectErr)

			assert.Equal(t, test.expect, got)
		})
	}
}

// A command built without the tailnets must refuse a configuration that asks for one:
// served anyway, an entryPoint meant for a tailnet would be listening on the host network.
func TestSetupNetworksRefusesTheTailnetsItWasNotBuiltWith(t *testing.T) {
	testCases := []struct {
		desc   string
		config *static.Configuration
	}{
		{
			desc:   "a tailnet",
			config: &static.Configuration{Tailnets: map[string]*static.Tailnet{"corp": {StateDir: "/var/lib/traefik/corp"}}},
		},
		{
			desc:   "an entryPoint on a tailnet",
			config: &static.Configuration{EntryPoints: static.EntryPoints{"web": {Address: ":80", Tailnet: "corp"}}},
		},
		{
			desc:   "an entryPoint on a Tailscale Service",
			config: &static.Configuration{EntryPoints: static.EntryPoints{"web": {Address: ":80", TailnetService: "web"}}},
		},
		{
			desc: "an entryPoint with a tailnet listener",
			config: &static.Configuration{EntryPoints: static.EntryPoints{"web": {
				Address:          ":80",
				TailnetListeners: []*static.TailnetListener{{Tailnet: "corp"}},
			}}},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			_, err := setupNetworks(test.config, Options{})
			require.ErrorIs(t, err, errNoTailnets)
		})
	}
}

// A serversTransport comes from the dynamic configuration, which is not refused at startup:
// one that names a tailnet must fail to dial rather than reach its servers over the host network.
func TestSetupNetworksFailsTheDialsOverATailnetItWasNotBuiltWith(t *testing.T) {
	networks, err := setupNetworks(&static.Configuration{EntryPoints: static.EntryPoints{"web": {Address: ":80"}}}, Options{})
	require.NoError(t, err)
	require.NotNil(t, networks)

	_, ok := networks.HTTPDialer(&dynamic.ServersTransport{})
	assert.False(t, ok)

	_, ok = networks.TCPDialer(&dynamic.TCPServersTransport{})
	assert.False(t, ok)

	dial, ok := networks.HTTPDialer(&dynamic.ServersTransport{Tailnet: "corp"})
	require.True(t, ok)

	_, err = dial(t.Context(), "tcp", "127.0.0.1:80")
	require.ErrorIs(t, err, errNoTailnets)

	dial, ok = networks.TCPDialer(&dynamic.TCPServersTransport{Tailnet: "corp"})
	require.True(t, ok)

	_, err = dial(t.Context(), "tcp", "127.0.0.1:80")
	require.ErrorIs(t, err, errNoTailnets)
}
