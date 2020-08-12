// Package pow implements the Curl-based proof of work for arbitrary binary data.
package pow

import (
	"context"
	"encoding/binary"
	"errors"
	"hash"
	"math"
	"sync"
	"sync/atomic"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/curl"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-crypto-demo/pkg/encoding/b1t6"
)

// errors returned by the PoW
var (
	ErrCancelled = errors.New("canceled")
	ErrDone      = errors.New("done")
)

const (
	NonceBytes = 8
	nonceTrits = NonceBytes * 8
)

// Hash identifies a cryptographic hash function that is implemented in another package.
type Hash interface {
	// New returns a new hash.Hash calculating the given hash function.
	New() hash.Hash
}

// The Worker provides PoW functionality using an arbitrary hash function.
type Worker struct {
	hash       Hash
	numWorkers int
}

// New creates a new PoW based on the provided hash.
// The optional numWorkers specifies how many go routines are used to mine.
func New(hash Hash, numWorkers ...int) *Worker {
	w := &Worker{
		hash:       hash,
		numWorkers: 1,
	}
	if len(numWorkers) > 0 && numWorkers[0] > 0 {
		w.numWorkers = numWorkers[0]
	}
	return w
}

// PoW returns the ID and the proof-of-work score of the message.
func (w *Worker) PoW(msg []byte) (id [32]byte, x float64) {
	h := w.hash.New()
	dataLen := len(msg) - NonceBytes
	// the PoW digest is the hash of msg without the nonce
	h.Write(msg[:dataLen])
	powDigest := h.Sum(nil)
	// the message ID is the hash of msg including the nonce
	h.Write(msg[dataLen:])
	h.Sum(id[:0])

	// extract the nonce from msg and compute the number of trailing zeros
	nonce := binary.LittleEndian.Uint64(msg[dataLen:])
	zeros := trailingZeros(powDigest, nonce)

	x = math.Pow(3, float64(zeros))
	x /= float64(len(msg))
	return
}

// Mine performs the PoW for data.
// It increments the nonce until the target number of trailing zeroes in the 243-trit hash is reached.
// The computation can be be canceled anytime using the provided ctx.
func (w *Worker) Mine(ctx context.Context, data []byte, targetZeros int) (uint64, error) {
	var (
		done    uint32
		counter uint64
		wg      sync.WaitGroup
		results = make(chan uint64, w.numWorkers)
		closing = make(chan struct{})
	)

	h := w.hash.New()
	h.Write(data)
	powDigest := h.Sum(nil)

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

			nonce, workerErr := w.worker(powDigest, startNonce, targetZeros, &done, &counter)
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

func trailingZeros(powDigest []byte, nonce uint64) int {
	buf := make(trinary.Trits, consts.HashTrinarySize)
	b1t6.Encode(buf, powDigest)
	// set nonce in the buffer
	encodeNonce(buf[consts.HashTrinarySize-nonceTrits:], nonce)

	c := curl.NewCurlP81()
	_ = c.Absorb(buf)
	digest, _ := c.Squeeze(consts.HashTrinarySize)
	return trinary.TrailingZeros(digest)
}

func (w *Worker) worker(powDigest []byte, startNonce uint64, target int, done *uint32, counter *uint64) (uint64, error) {
	buf := make(trinary.Trits, consts.HashTrinarySize)
	b1t6.Encode(buf, powDigest)

	c := curl.NewCurlP81()
	nonceBuf := buf[consts.HashTrinarySize-nonceTrits:]
	for nonce := startNonce; atomic.LoadUint32(done) == 0; nonce++ {
		atomic.AddUint64(counter, 1)

		// update nonce in the last block
		encodeNonce(nonceBuf, nonce)

		c.Reset()
		_ = c.Absorb(buf)
		digest, _ := c.Squeeze(consts.HashTrinarySize)
		if trinary.TrailingZeros(digest) >= target {
			return nonce, nil
		}
	}
	return 0, ErrDone
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
