package curl_test

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-crypto-demo/pkg/curl"
)

func BenchmarkCurlTransaction(b *testing.B) {
	src := make([][]trinary.Trits, b.N)
	for i := range src {
		src[i] = make([]trinary.Trits, curl.MaxBatchSize)
		for j := range src[i] {
			src[i][j] = randomTrits(consts.TransactionTrinarySize)
		}
	}
	dst := make([]trinary.Trits, curl.MaxBatchSize)
	b.ResetTimer()

	for i := range src {
		c := curl.NewCurlP81()
		c.Absorb(src[i], consts.TransactionTrinarySize)
		c.Squeeze(dst, consts.HashTrinarySize)
	}
}

func BenchmarkCurlHash(b *testing.B) {
	src := make([][]trinary.Trits, b.N)
	for i := range src {
		src[i] = make([]trinary.Trits, curl.MaxBatchSize)
		for j := range src[i] {
			src[i][j] = randomTrits(consts.HashTrinarySize)
		}
	}
	dst := make([]trinary.Trits, curl.MaxBatchSize)
	b.ResetTimer()

	for i := range src {
		c := curl.NewCurlP81()
		c.Absorb(src[i], consts.HashTrinarySize)
		c.Squeeze(dst, consts.HashTrinarySize)
	}
}

func randomTrits(n int) trinary.Trits {
	trytes := randomTrytes((n + 2) / 3)
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
