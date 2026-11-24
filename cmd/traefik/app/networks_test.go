package app

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/network"
	"github.com/traefik/traefik/v3/pkg/tailnet"
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
			// Without tailnets the registry is nil, and the extension must not be.
			desc:   "without networks",
			expect: (*tailnet.Registry)(nil),
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
