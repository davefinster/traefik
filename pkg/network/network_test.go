package network

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type namedSource struct {
	Source

	name string
}

func (s namedSource) String() string { return s.name }

func TestSources_All(t *testing.T) {
	primary := namedSource{name: "primary"}
	additional := []Source{namedSource{name: "first"}, namedSource{name: "second"}}

	testCases := []struct {
		desc    string
		sources Sources
		expect  []Source
	}{
		{
			desc: "no source",
		},
		{
			desc:    "a primary source only",
			sources: Sources{Primary: primary},
			expect:  []Source{primary},
		},
		{
			desc:    "additional sources only",
			sources: Sources{Additional: additional},
			expect:  additional,
		},
		{
			desc:    "the primary source comes first",
			sources: Sources{Primary: primary, Additional: additional},
			expect:  []Source{primary, additional[0], additional[1]},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			assert.Equal(t, test.expect, test.sources.All())
		})
	}
}

func TestDialContextFunc_WithTimeout(t *testing.T) {
	// A dial that never completes by itself, as a network that is not up does.
	var dial DialContextFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	start := time.Now()
	_, err := dial.WithTimeout(50*time.Millisecond)(t.Context(), "tcp", "192.0.2.1:80")

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestDialContextFunc_WithTimeout_zeroIsNoBound(t *testing.T) {
	var hasDeadline bool
	var dial DialContextFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		_, hasDeadline = ctx.Deadline()
		return nil, nil
	}

	_, err := dial.WithTimeout(0)(t.Context(), "tcp", "192.0.2.1:80")

	require.NoError(t, err)
	assert.False(t, hasDeadline)
}
