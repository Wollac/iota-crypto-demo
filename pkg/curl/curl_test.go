package curl

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	iotagocurl "github.com/iotaledger/iota.go/curl"
	"github.com/iotaledger/iota.go/curl/bct"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/require"
)

type Test struct {
	In   trinary.Trytes `json:"in"`
	Hash trinary.Trytes `json:"hash"`
}

func TestSingleGolden(t *testing.T) {
	var tests []Test
	b, err := os.ReadFile(filepath.Join("testdata", "curlp81.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &tests))

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test vector#%d", i), func(t *testing.T) {
			inTrits := trinary.MustTrytesToTrits(tt.In)
			hashTrits := trinary.MustTrytesToTrits(tt.Hash)

			c := NewCurlP81()
			require.NoError(t, c.Absorb([]trinary.Trits{inTrits}, len(inTrits)))

			dst := make([]trinary.Trits, 1)
			require.NoError(t, c.Squeeze(dst, len(hashTrits)))
			require.Equal(t, []trinary.Trits{hashTrits}, dst)
		})
	}
}

func TestCurl(t *testing.T) {
	tests := []struct {
		name    string
		src     []trinary.Trits
		hashLen int
	}{
		{"trits and hash", Trits(bct.MaxBatchSize, consts.HashTrinarySize), consts.HashTrinarySize},
		{"multi trits and hash", Trits(bct.MaxBatchSize, consts.TransactionTrinarySize), consts.HashTrinarySize},
		{"trits and multi squeeze", Trits(bct.MaxBatchSize, consts.HashTrinarySize), 3 * consts.HashTrinarySize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCurlP81()
			require.NoError(t, c.Absorb(tt.src, len(tt.src[0])))

			dst := make([]trinary.Trits, len(tt.src))
			require.NoError(t, c.Squeeze(dst, tt.hashLen))

			for i := range dst {
				// compare against the non batched Curl implementation from iota.go
				require.Equal(t, CurlSum(tt.src[i], tt.hashLen), dst[i])
			}
		})
	}
}

func TestTransformCompare(t *testing.T) {
	// use local deterministic RNG
	r := rand.New(rand.NewSource(0))

	var srcL, srcH, tmpL, tmpH [StateSize]uint
	for i := 0; i < 1000; i++ {
		for j := 0; j < StateSize; j++ {
			srcL[j] = uint(r.Uint64())
			srcH[j] = uint(r.Uint64())
		}

		var dstGenericL, dstGenericH [StateSize]uint
		tmpL, tmpH = srcL, srcH
		transformGeneric(&dstGenericL, &dstGenericH, &tmpL, &tmpH)

		var dstL, dstH [StateSize]uint
		tmpL, tmpH = srcL, srcH
		transform(&dstL, &dstH, &tmpL, &tmpH)

		require.Equal(t, dstGenericL, dstL)
		require.Equal(t, dstGenericH, dstH)
	}
}

func Trits(size int, tritsCount int) []trinary.Trits {
	trytesCount := tritsCount / consts.TritsPerTryte
	src := make([]trinary.Trits, size)
	for i := range src {
		trytes := strings.Repeat("ABC", trytesCount/3+1)[:trytesCount-2] + trinary.IntToTrytes(int64(i), 2)
		src[i] = trinary.MustTrytesToTrits(trytes)
	}
	return src
}

func CurlSum(data trinary.Trits, tritsCount int) trinary.Trits {
	c := iotagocurl.NewCurlP81()
	if err := c.Absorb(data); err != nil {
		panic(err)
	}
	out, err := c.Squeeze(tritsCount)
	if err != nil {
		panic(err)
	}
	return out
}
