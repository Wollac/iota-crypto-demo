// Package pow implements the Curl-based proof of work for arbitrary binary data.
package pow

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"github.com/iotaledger/iota.go/consts"
	sponge "github.com/iotaledger/iota.go/signing/utils"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-crypto-demo/pkg/encoding/b1t6"
)

// errors returned by the PoW
var (
	ErrCancelled = errors.New("canceled")
	ErrDone      = errors.New("done")
)

const nonceTrits = 64

// The Worker provides PoW functionality using an arbitrary hash function.
type Worker struct {
	hash       sponge.SpongeFunctionCreator
	numWorkers int
}

// New creates a new PoW based on the provided hash.
// The optional numWorkers specifies how many go routines are used to mine.
func New(hash sponge.SpongeFunctionCreator, numWorkers ...int) *Worker {
	w := &Worker{
		hash:       hash,
		numWorkers: 1,
	}
	if len(numWorkers) > 0 && numWorkers[0] > 0 {
		w.numWorkers = numWorkers[0]
	}
	return w
}

// Mine performs the PoW.
// It increments the nonce until the target number of trailing zeroes in the 243-trit hash is reached.
// The computation can be be canceled anytime using the provided ctx.
func (w *Worker) Mine(ctx context.Context, msg []byte, target int) (uint64, error) {
	var (
		done    uint32
		counter uint64
		wg      sync.WaitGroup
		results = make(chan uint64, w.numWorkers)
		closing = make(chan struct{})
	)

	// stop when the context has been canceled
	go func() {
		select {
		case <-ctx.Done():
			atomic.StoreUint32(&done, 1)
		case <-closing:
			return
		}
	}()

	workerWidth := math.MaxUint64 / uint64(w.numWorkers)
	for i := 0; i < w.numWorkers; i++ {
		startNonce := uint64(i) * workerWidth
		wg.Add(1)
		go func() {
			defer wg.Done()

			nonce, workerErr := w.worker(msg, startNonce, target, &done, &counter)
			if workerErr != nil {
				return
			}
			atomic.StoreUint32(&done, 1)
			results <- nonce
		}()
	}
	wg.Wait()
	close(results)
	close(closing)

	nonce, ok := <-results
	if !ok {
		return 0, ErrCancelled
	}
	return nonce, nil
}

// PoW returns the proof of work of msg.
func (w *Worker) PoW(msg []byte, nonce uint64) (float64, error) {
	difficulty, err := w.TrailingZeros(msg, nonce)
	if err != nil {
		return 0, err
	}
	x := math.Pow(3, float64(difficulty))
	x /= float64(len(msg))
	return x, nil
}

// TrailingZeros returns the number of trailing zeros in the ternary digest of msg.
func (w *Worker) TrailingZeros(msg []byte, nonce uint64) (int, error) {
	encoded := make(trinary.Trits, b1t6.EncodedLen(len(msg)))
	b1t6.Encode(encoded, msg)
	trits := pad(encoded, nonceTrits)
	// write nonce into the buffer
	encodeNonce(trits[len(trits)-nonceTrits:], nonce)

	h := w.hash()
	defer h.Reset()

	if err := h.Absorb(trits); err != nil {
		return 0, err
	}
	digest, err := h.Squeeze(consts.HashTrinarySize)
	if err != nil {
		return 0, err
	}
	return trinary.TrailingZeros(digest), nil
}

func (w *Worker) worker(data []byte, startNonce uint64, target int, done *uint32, counter *uint64) (uint64, error) {
	encoded := make(trinary.Trits, b1t6.EncodedLen(len(data)))
	b1t6.Encode(encoded, data)
	buf := pad(encoded, nonceTrits)

	h := w.hash()
	defer h.Reset()

	// absorb everything but the last 243-trit block
	if len(buf) > consts.HashTrinarySize {
		if err := h.Absorb(buf[:len(buf)-consts.HashTrinarySize]); err != nil {
			return 0, err
		}
	}

	var (
		lastBlock = buf[len(buf)-consts.HashTrinarySize:]
		nonceBuf  = lastBlock[consts.HashTrinarySize-nonceTrits:]
	)
	for nonce := startNonce; atomic.LoadUint32(done) == 0; nonce++ {
		atomic.AddUint64(counter, 1)

		// update nonce in the last block
		encodeNonce(nonceBuf, nonce)

		// clone the hash state and only absorb the last block
		dup := h.Clone()
		if err := dup.Absorb(lastBlock); err != nil {
			return 0, err
		}
		digest, err := dup.Squeeze(consts.HashTrinarySize)
		if err != nil {
			return 0, err
		}
		if trinary.TrailingZeros(digest) >= target {
			return nonce, nil
		}
	}
	return 0, ErrDone
}

// pad applies the 1*0 padding to return a multiple of 243 trits where the last r trits are reserved.
func pad(trits trinary.Trits, r int) trinary.Trits {
	// round to the nearest multiple of 243
	paddedLen := ((len(trits) + r + consts.HashTrinarySize) / consts.HashTrinarySize) * consts.HashTrinarySize
	buf := make(trinary.Trits, paddedLen)
	copy(buf, trits)
	buf[len(trits)] = 1 // always at least add the 1
	return buf
}

// encodeNonce encodes nonce as 64 trits using the b1t8 encoding.
func encodeNonce(dst trinary.Trits, nonce uint64) {
	if len(dst) < 64 {
		panic(consts.ErrInvalidTritsLength)
	}
	for i := 0; i < 64; i++ {
		dst[i] = int8((nonce >> i) & 1)
	}
}
