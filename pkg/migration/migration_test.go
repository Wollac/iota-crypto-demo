package migration

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecode(t *testing.T) {
	var expected [Ed25519AddressSize]byte
	for i := 0; i < 1000; i++ {
		rand.Read(expected[:])
		trytes := Encode(expected)
		address, err := Decode(trytes)
		require.NoError(t, err)
		require.Equal(t, expected, address)
	}
}
