package merkle

import (
	"crypto"
	"encoding"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "golang.org/x/crypto/blake2b" // BLAKE2b_256 is the default hashing algorithm
)

type marshalerFunc func() ([]byte, error)

func (m marshalerFunc) MarshalBinary() ([]byte, error) { return m() }

func TestHash(t *testing.T) {
	hasher := NewHasher(crypto.BLAKE2b_256)

	var tests = []*struct {
		desc      string
		ids       []encoding.BinaryMarshaler
		expString string
	}{
		// echo -n | b2sum --length 256
		{
			desc:      "empty",
			ids:       nil,
			expString: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		},
		{
			desc: "single leaf",
			ids: []encoding.BinaryMarshaler{
				marshalerFunc(func() ([]byte, error) { return hex.DecodeString("000102030405060708090a0b0c0d0e0f") }),
			},
			expString: "4a0d1cf99df47c8482ee0cfddb5f71620a5fba6c80939f278384c3e85fc62bca",
		},
		{
			desc: "single node",
			ids: []encoding.BinaryMarshaler{
				marshalerFunc(func() ([]byte, error) { return hex.DecodeString("0001020304050607") }),
				marshalerFunc(func() ([]byte, error) { return hex.DecodeString("08090a0b0c0d0e0f") }),
			},
			expString: "83581f3f9a2fcfe6d52b3d236f4604c51e313b9357ef238187fc2205fb2b3310",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			expBytes, err := hex.DecodeString(tt.expString)
			require.NoError(t, err)
			bytes, err := hasher.Hash(tt.ids)
			assert.Equal(t, expBytes, bytes)
			assert.NoError(t, err)
		})
	}
}
