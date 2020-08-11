package pow

import (
	"context"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iotaledger/iota.go/curl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	workers = 2
	target  = 6
)

var testWorker = New(curl.NewCurlP81, workers)

func TestWorker_Work(t *testing.T) {
	nonce, err := testWorker.Mine(context.Background(), nil, target)
	require.NoError(t, err)
	zeros, err := testWorker.TrailingZeros(nil, nonce)
	assert.GreaterOrEqual(t, zeros, target)
	assert.NoError(t, err)
}

func TestWorker_Validate(t *testing.T) {
	tests := []*struct {
		msg      []byte
		nonce    uint64
		expZeros int
		expPoW   float64
		expErr   error
	}{
		{msg: nil, nonce: 0, expZeros: 0, expPoW: math.Inf(1), expErr: nil},
		{msg: []byte{0}, nonce: 10540996613548938299, expZeros: 16, expPoW: math.Pow(3, 16), expErr: nil},
		{msg: make([]byte, 10240), nonce: 0, expZeros: 1, expPoW: 3. / 10240, expErr: nil},
	}

	for _, tt := range tests {
		zeros, err := testWorker.TrailingZeros(tt.msg, tt.nonce)
		pow, _ := testWorker.PoW(tt.msg, tt.nonce)
		assert.Equal(t, tt.expZeros, zeros)
		assert.Equal(t, tt.expPoW, pow)
		assert.Equal(t, tt.expErr, err)
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

func BenchmarkWorker(b *testing.B) {
	var (
		w       = New(curl.NewCurlP81, 1)
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
