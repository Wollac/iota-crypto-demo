package vrf

import (
	"math/rand"
	"testing"

	"github.com/iotaledger/iota-crypto-demo/internal/hexutil"
	"github.com/stretchr/testify/require"
)

func TestNewPointFromCanonicalBytes(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		err      error
	}{
		{
			name:     "y=0,sign+",
			encoding: "0000000000000000000000000000000000000000000000000000000000000000",
			err:      nil,
		},
		{
			name:     "y=p-1,sign+",
			encoding: "ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      nil,
		},
		// all non-canonical point encodings
		{
			name:     "y=p,sign+",
			encoding: "EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		},
		{
			name:     "y=p,sign-",
			encoding: "EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		},
		{
			name:     "y=p+1,sign+",
			encoding: "EEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		},
		{
			name:     "y=p+1,sign-",
			encoding: "EEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		},
		{
			name:     "y=p+3,sign+",
			encoding: "F0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+3,sign-",
			encoding: "F0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+4,sign+",
			encoding: "F1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+4,sign-",
			encoding: "F1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+5,sign+",
			encoding: "F2FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+5,sign-",
			encoding: "F2FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+6,sign+",
			encoding: "F3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+6,sign-",
			encoding: "F3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+9,sign+",
			encoding: "F6FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+9,sign-",
			encoding: "F6FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+10,sign+",
			encoding: "F7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+10,sign-",
			encoding: "F7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+14,sign+",
			encoding: "FBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+14,sign-",
			encoding: "FBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+15,sign+",
			encoding: "FCFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+15,sign-",
			encoding: "FCFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+16,sign+",
			encoding: "FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+16,sign-",
			encoding: "FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+18,sign+",
			encoding: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p+18,sign-",
			encoding: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		}, {
			name:     "y=1,sign-",
			encoding: "0100000000000000000000000000000000000000000000000000000000000080",
			err:      ErrNonCanonical,
		}, {
			name:     "y=p-1,sign-",
			encoding: "ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
			err:      ErrNonCanonical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newPointFromCanonicalBytes(hexutil.MustDecodeString(tt.encoding))
			require.ErrorIs(t, err, tt.err)
		})
	}
}

func BenchmarkNewPointFromCanonicalBytes(b *testing.B) {
	data := make([][32]byte, b.N)
	for i := range data {
		rand.Read(data[i][:])
	}

	b.ResetTimer()
	for i := range data {
		_, _ = newPointFromCanonicalBytes(data[i][:])
	}
}
