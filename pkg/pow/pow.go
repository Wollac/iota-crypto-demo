// Package pow implements the Curl-based proof of work for arbitrary binary data.
package pow

import (
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"sync/atomic"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/curl"
	"github.com/iotaledger/iota.go/curl/bct"
	"github.com/iotaledger/iota.go/encoding/b1t6"
	"github.com/iotaledger/iota.go/trinary"
	_ "golang.org/x/crypto/blake2b" // BLAKE2b_256 is the default hash function for the PoW digest
)

// errors returned by the PoW
var (
	ErrCancelled = errors.New("canceled")
	ErrDone      = errors.New("done")
)

// Hash defines the hash function that is used to compute the PoW digest.
var Hash = crypto.BLAKE2b_256

// The Worker provides PoW functionality.
type Worker struct {
	numWorkers int
}

const (
	nonceBytes = 8 // len(uint64)
)

// New creates a new PoW based on the provided hash.
// The optional numWorkers specifies how many go routines are used to mine.
func New(numWorkers ...int) *Worker {
	w := &Worker{
		numWorkers: 1,
	}
	if len(numWorkers) > 0 && numWorkers[0] > 0 {
		w.numWorkers = numWorkers[0]
	}
	return w
}

// PoW returns the ID and the proof-of-work score of the message.
func PoW(msg []byte) float64 {
	h := Hash.New()
	dataLen := len(msg) - nonceBytes
	// the PoW digest is the hash of msg without the nonce
	h.Write(msg[:dataLen])
	powDigest := h.Sum(nil)

	// extract the nonce from msg and compute the number of trailing zeros
	nonce := binary.LittleEndian.Uint64(msg[dataLen:])
	zeros := trailingZeros(powDigest, nonce)

	x := math.Pow(consts.TrinaryRadix, float64(zeros))
	x /= float64(len(msg))
	return x
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

	h := Hash.New()
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
	// allocate exactly one Curl block
	buf := make(trinary.Trits, consts.HashTrinarySize)
	n := b1t6.Encode(buf, powDigest)
	// add the nonce to the trit buffer
	encodeNonce(buf[n:], nonce)

	c := curl.NewCurlP81()
	if err := c.Absorb(buf); err != nil {
		panic(err)
	}
	digest, _ := c.Squeeze(consts.HashTrinarySize)
	return trinary.TrailingZeros(digest)
}

func (w *Worker) worker(powDigest []byte, startNonce uint64, target int, done *uint32, counter *uint64) (uint64, error) {
	// use batched Curl hashing
	c := bct.NewCurlP81()
	hashes := make([]trinary.Trits, bct.MaxBatchSize)

	// allocate exactly one Curl block for each batch index and fill it with the encoded digest
	buf := make([]trinary.Trits, bct.MaxBatchSize)
	for i := range buf {
		buf[i] = make(trinary.Trits, consts.HashTrinarySize)
		b1t6.Encode(buf[i], powDigest)
	}

	digestTritsLen := b1t6.EncodedLen(len(powDigest))
	for nonce := startNonce; atomic.LoadUint32(done) == 0; nonce += bct.MaxBatchSize {
		// add the nonce to each trit buffer
		for i := range buf {
			nonceBuf := buf[i][digestTritsLen:]
			encodeNonce(nonceBuf, nonce+uint64(i))
		}

		// process the batch
		c.Reset()
		if err := c.Absorb(buf, consts.HashTrinarySize); err != nil {
			return 0, err
		}
		if err := c.Squeeze(hashes, consts.HashTrinarySize); err != nil {
			return 0, err
		}
		atomic.AddUint64(counter, bct.MaxBatchSize)

		// check each hash, whether it has the sufficient amount of trailing zeros
		for i := range hashes {
			if trinary.TrailingZeros(hashes[i]) >= target {
				return nonce + uint64(i), nil
			}
		}
	}
	return 0, ErrDone
}

// encodeNonce encodes nonce as 64 trits using the b1t8 encoding.
func encodeNonce(dst trinary.Trits, nonce uint64) {
	var nonceBuf [nonceBytes]byte
	binary.LittleEndian.PutUint64(nonceBuf[:], nonce)
	b1t6.Encode(dst, nonceBuf[:])
}
