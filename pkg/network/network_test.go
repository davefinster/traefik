package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
