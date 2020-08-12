package pow

import (
	"context"
	"crypto"
	"encoding/binary"
	"math"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/curl"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wollac/iota-crypto-demo/pkg/encoding/b1t6"
	"github.com/wollac/iota-crypto-demo/pkg/encoding/b1t8"
	"golang.org/x/crypto/blake2b"
)

const (
	workers = 2
	target  = 6
)

var testWorker = New(crypto.BLAKE2b_256, workers)

func TestWorker_Mine(t *testing.T) {
	msg := append([]byte("test"), make([]byte, NonceBytes)...)
	nonce, err := testWorker.Mine(context.Background(), msg[:len(msg)-NonceBytes], target)
	require.NoError(t, err)

	binary.LittleEndian.PutUint64(msg[len(msg)-NonceBytes:], nonce)
	id, pow := testWorker.PoW(msg)
	assert.Equal(t, blake2b.Sum256(msg), id)
	assert.GreaterOrEqual(t, pow, math.Pow(3, target)/float64(len(msg)))
}

func TestWorker_Validate(t *testing.T) {
	tests := []*struct {
		msg    []byte
		expPoW float64
		expErr error
	}{
		{msg: []byte{0, 0, 0, 0, 0, 0, 0, 0}, expPoW: math.Pow(3, 1) / 8, expErr: nil},
		{msg: []byte{249, 189, 170, 170, 170, 170, 170, 170}, expPoW: math.Pow(3, 10) / 8, expErr: nil},
		{msg: []byte{77, 32, 10, 0, 0, 0, 0, 0}, expPoW: math.Pow(3, 15) / 8, expErr: nil},
		{msg: make([]byte, 10000), expPoW: math.Pow(3, 0) / 10000, expErr: nil},
	}

	for _, tt := range tests {
		_, pow := testWorker.PoW(tt.msg)
		assert.Equal(t, tt.expPoW, pow)
	}
}

func TestWorker_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var err error
	go func() {
		_, err = testWorker.Mine(ctx, nil, math.MaxInt32)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()

	assert.Eventually(t, func() bool { return err == ErrCancelled }, time.Second, 10*time.Millisecond)
}

func TestEncodeNonce(t *testing.T) {
	const nonce = 12345678901234567890
	var nonceBuf [NonceBytes]byte
	binary.LittleEndian.PutUint64(nonceBuf[:], nonce)

	exp := make(trinary.Trits, 64)
	b1t8.Encode(exp, nonceBuf[:])
	actual := make(trinary.Trits, 64)
	encodeNonce(actual, nonce)
	assert.Equal(t, exp, actual)
}

func BenchmarkPoW(b *testing.B) {
	data := make([][]byte, b.N)
	for i := range data {
		data[i] = make([]byte, 1500)
		if _, err := rand.Read(data[i]); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()

	for i := range data {
		_, _ = testWorker.PoW(data[i])
	}
}

func BenchmarkID(b *testing.B) {
	data := make([][]byte, b.N)
	for i := range data {
		data[i] = make([]byte, 1500)
		if _, err := rand.Read(data[i]); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()

	for i := range data {
		// compute the Blake2b hash corresponding to the ID
		_ = blake2b.Sum256(data[i])
	}
}

func BenchmarkCurlPoW(b *testing.B) {
	data := make([][]byte, b.N)
	for i := range data {
		data[i] = make([]byte, 1500)
		if _, err := rand.Read(data[i]); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()

	for i := range data {
		// compute the Blake2b hash corresponding to the ID
		_ = blake2b.Sum256(data[i])
		// convert entire message to trits
		trits := make(trinary.Trits, b1t6.EncodedLen(1500))
		b1t6.Encode(trits, data[i])
		// compute the Curl-P-81 hash to validate the PoW
		c := curl.NewCurlP81()
		_ = c.Absorb(trits)
		_, _ = c.Squeeze(consts.HashTrinarySize)
	}
}

func BenchmarkWorker(b *testing.B) {
	var (
		w       = New(crypto.BLAKE2b_256, 1)
		buf     = make([]byte, 1024)
		done    uint32
		counter uint64
	)
	go func() {
		_, _ = w.worker(buf, 0, math.MaxInt32, &done, &counter)
	}()
	b.ResetTimer()
	for atomic.LoadUint64(&counter) < uint64(b.N) {
	}
	atomic.StoreUint32(&done, 1)
}
