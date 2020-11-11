package merkle

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	hasher := DefaultHasher

	var tests = []*struct {
		desc      string
		ids       [][32]byte
		expString string
	}{
		// echo -n | b2sum --length 256
		{
			desc:      "empty",
			ids:       nil,
			expString: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		},
		{
			desc:      "single null leaf",
			ids:       [][32]byte{{}},
			expString: "d8908c165dee785924e7421a0fd0418a19d5daeec395fd505a92a0fd3117e428",
		},
		{
			desc:      "single node",
			ids:       [][32]byte{{}, {}},
			expString: "81f23eaa2dae423d5cb1b4d2dae4d0dffa86b7749bed58724b12786e3e53395b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			expBytes, err := hex.DecodeString(tt.expString)
			require.NoError(t, err)
			assert.Equal(t, expBytes, hasher.TreeHash(tt.ids))
		})
	}
}
