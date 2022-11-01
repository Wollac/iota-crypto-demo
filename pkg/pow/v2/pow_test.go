package v2

import (
	"context"
	"encoding/binary"
	"math"
	"math/big"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/trinary"
)

const (
	workers            = 2
	targetScore uint64 = 4000
)

var testWorker = New(workers)

func TestWorker_Mine(t *testing.T) {
	msg := append([]byte("Hello, World!"), make([]byte, nonceBytes)...)
	nonce, err := testWorker.Mine(context.Background(), msg[:len(msg)-nonceBytes], targetScore)
	require.NoError(t, err)

	// add nonce to message and check the resulting PoW score
	binary.LittleEndian.PutUint64(msg[len(msg)-nonceBytes:], nonce)
	score := Score(msg)
	assert.GreaterOrEqual(t, score, targetScore)
	t.Log(nonce, score)
}

func TestToInt(t *testing.T) {
	require.Zero(t, toInt(make(trinary.Trits, consts.HashTrinarySize)).Cmp(one))
	require.Zero(t, toInt(largest(0)).Cmp(maxHash))
}

func TestSufficientTrailingZeros(t *testing.T) {
	const dataLen = 9
	for score := uint64(1); score <= math.MaxUint64/dataLen; score *= 3 {
		// the largest possible hash should be feasible
		s := sufficientTrailingZeros(make([]byte, dataLen-nonceBytes), score)
		largestDifficulty := new(big.Int).Quo(maxHash, toInt(largest(s))).Uint64()
		require.GreaterOrEqual(t, largestDifficulty, dataLen*score)

		// the smallest possible hash should be infeasible
		r := s - 1
		smallestDifficulty := new(big.Int).Quo(maxHash, toInt(smallest(r))).Uint64()
		require.Less(t, smallestDifficulty, dataLen*score)
	}
}

func smallest(trailing int) trinary.Trits {
	trits := make(trinary.Trits, consts.HashTrinarySize)
	trits[consts.HashTrinarySize-(trailing+1)] = 1
	return trits
}

func largest(trailing int) trinary.Trits {
	trits := make(trinary.Trits, consts.HashTrinarySize)
	for i := 0; i < consts.HashTrinarySize-trailing; i++ {
		trits[i] = -1
	}
	return trits
}

func BenchmarkTritsToInt(b *testing.B) {
	src := make([]trinary.Trits, b.N)
	for i := range src {
		src[i] = randomTrits(consts.HashTrinarySize)
	}
	b.ResetTimer()

	for i := range src {
		_ = toInt(src[i])
	}
}

const benchBytesLen = 1600

func BenchmarkScore(b *testing.B) {
	data := make([][]byte, b.N)
	for i := range data {
		data[i] = make([]byte, benchBytesLen)
		if _, err := rand.Read(data[i]); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()

	for i := range data {
		_ = Score(data[i])
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
