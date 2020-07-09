package t5b1

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/require"
)

func TestTrits(t *testing.T) {
	for i := 0; i < 1000; i++ {
		test := randomTrits(consts.TransactionTrinarySize)

		bytes := Encode(test)
		trits, err := Decode(bytes)
		require.NoError(t, err)
		require.Equal(t, test, trits[:consts.TransactionTrinarySize])
	}
}

func BenchmarkEncode(b *testing.B) {
	data := make([]trinary.Trits, b.N)
	for i := range data {
		data[i] = randomTrits(5 * 200)
	}
	b.ResetTimer()

	for i := range data {
		_ = Encode(data[i])
	}
}

func BenchmarkDecode(b *testing.B) {
	data := make([][]byte, b.N)
	for i := range data {
		tmp := randomTrits(5 * 200)
		data[i] = Encode(tmp)
	}
	b.ResetTimer()

	for i := range data {
		_, _ = Decode(data[i])
	}
}

func randomTrits(n int) trinary.Trits {
	trytes := randomTrytes(n/3 + 1)
	return trinary.MustTrytesToTrits(trytes)[:n]
}

func randomTrytes(n int) trinary.Trytes {
	var result strings.Builder
	result.Grow(n)
	for i := 0; i < n; i++ {
		result.WriteByte(consts.TryteAlphabet[rand.Intn(len(consts.TryteAlphabet))])
	}
	return result.String()
}
