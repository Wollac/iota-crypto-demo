package merkle

import (
	"encoding/hex"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	hasher := DefaultHasher

	var tests = []*struct {
		desc      string
		hashes    []trinary.Hash
		expString string
	}{
		// echo -n | b2sum
		{
			desc:      "empty",
			hashes:    nil,
			expString: "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		},
		{
			desc:      "single null leaf",
			hashes:    []trinary.Hash{consts.NullHashTrytes},
			expString: "0c18f7cbf23c3c8eda01ab64c79379ff0bf0d854125cbdf7dba43ca7630171d84c042673b731cb9f92cf937d738152306a8db092d9413d531dd8a4299c05278f",
		},
		{
			desc:      "single node",
			hashes:    []trinary.Hash{consts.NullHashTrytes, consts.NullHashTrytes},
			expString: "876b38297f865de8b89fa69d7daa4da0fc31f562228ac4b5b71009ec10e878a7aec06f48ddf98a16460b742673ed47f308ff57768426bf72a6aee27d1c4ba5fd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			expBytes, err := hex.DecodeString(tt.expString)
			require.NoError(t, err)
			assert.Equal(t, expBytes, hasher.TreeHash(tt.hashes))
		})
	}
}
