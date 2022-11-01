package v2

import (
	"context"
	"errors"
	"math"
	"math/big"
	"math/bits"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/blake2b"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/curl/bct"
	"github.com/iotaledger/iota.go/encoding/b1t6"
	"github.com/iotaledger/iota.go/trinary"
)

// errors returned by the PoW
var (
	ErrCancelled = errors.New("canceled")
	ErrDone      = errors.New("done")
)

// The Worker performs the PoW.
type Worker struct {
	numWorkers int
}

// New creates a new PoW Worker.
// The optional numWorkers specifies how many go routines should be used to perform the PoW.
func New(numWorkers ...int) *Worker {
	w := &Worker{
		numWorkers: 1,
	}
	if len(numWorkers) > 0 && numWorkers[0] > 0 {
		w.numWorkers = numWorkers[0]
	}
	return w
}

// Mine performs the PoW for data.
// It returns a nonce that appended to data results in a PoW score of at least targetScore.
// The computation can be canceled anytime using ctx.
func (w *Worker) Mine(ctx context.Context, data []byte, targetScore uint64) (uint64, error) {
	// for the zero target score, the solution is trivial
	if targetScore == 0 {
		return 0, nil
	}

	var (
		done    uint32
		counter uint64
		wg      sync.WaitGroup
		results = make(chan uint64, w.numWorkers)
		closing = make(chan struct{})
	)

	// compute the digest
	powDigest := blake2b.Sum256(data)

	// stop when the context has been canceled
	go func() {
		select {
		case <-ctx.Done():
			atomic.StoreUint32(&done, 1)
		case <-closing:
			return
		}
	}()

	sufficientTrailing := sufficientTrailingZeros(data, targetScore)
	target := targetHash(data, targetScore)

	workerWidth := math.MaxUint64 / uint64(w.numWorkers)
	for i := 0; i < w.numWorkers; i++ {
		startNonce := uint64(i) * workerWidth
		wg.Add(1)
		go func() {
			defer wg.Done()

			nonce, workerErr := w.worker(powDigest[:], startNonce, sufficientTrailing, target, &done, &counter)
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

// sufficientTrailingZeros returns 𝑠 s.t. any hash with 𝑠 trailing zeroes is feasible, i.e. smallest 𝑠 with 3^𝑠 ≥ 𝑙·𝑥.
// It panics when 𝑙·𝑥 overflows an uint64.
// It is sufficient to show that the largest (worst) hash h with 𝑠 trailing zeroes is feasible i.e. ⌊ maxHash / h ⌋ ≥ 𝑙·𝑥
// ⌊ maxHash / h ⌋ ≥ ⌊ 3^243 / 3^(243 - 𝑠) ⌋ = ⌊ 3^𝑠 ⌋ = 3^𝑠 ≥ 𝑙·𝑥
func sufficientTrailingZeros(data []byte, targetScore uint64) int {
	// assure that (len(data)+nonceBytes) * targetScore <= MaxUint64
	if (math.MaxUint64-1)/(uint64(len(data)+nonceBytes))+1 < targetScore {
		panic("pow: invalid target score")
	}
	lx := uint64(len(data)+nonceBytes) * targetScore

	// in order to prevent floating point rounding errors, compute the exact integer logarithm
	for s, v := 0, uint64(1); s <= tritsPerUint64; s++ {
		if v >= lx {
			return s
		}
		v *= 3
	}
	return tritsPerUint64 + 1
}

// targetHash returns 𝑡 s.t. any hash with h ≤ 𝑡 is feasible, i.e. h = ⌊ maxHash / (𝑙·𝑥 + 1) ⌋.
// It panics when 𝑙·𝑥 overflows an uint64.
// It is sufficient to show that for the hash h with h = ⌊ maxHash / (𝑙·𝑥 + 1) ⌋, ⌊ maxHash / h ⌋ ≥ 𝑙·𝑥 always holds:
// h = ⌊ maxHash / (𝑙·𝑥 + 1) ⌋ ≤ maxHash / (𝑙·𝑥 + 1) ⇔ 𝑙·𝑥 + 1 ≤ maxHash / h ⇔ 𝑙·𝑥 ≤ maxHash / h - 1 ⇔ 𝑙·𝑥 < ⌊ maxHash / h ⌋
func targetHash(data []byte, targetScore uint64) *big.Int {
	// return ⌊ maxHash / (𝑙·𝑥 + 1) ⌋
	z := new(big.Int).SetUint64(targetScore)
	z.Mul(z, big.NewInt(int64(len(data)+nonceBytes)))
	z.Add(z, one)
	return z.Quo(maxHash, z)
}

func (w *Worker) worker(powDigest []byte, startNonce uint64, sufficientTrailing int, target *big.Int, done *uint32, counter *uint64) (uint64, error) {
	if sufficientTrailing > consts.HashTrinarySize {
		panic("pow: invalid trailing zeros target")
	}

	// use batched Curl hashing
	c := bct.NewCurlP81()
	var l, h [consts.HashTrinarySize]uint

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
		c.CopyState(l[:], h[:]) // the first 243 entries of the state correspond to the resulting hashes
		atomic.AddUint64(counter, bct.MaxBatchSize)

		// check the state whether it corresponds to a hash with sufficient amount of trailing zeros
		// this is equivalent to computing the hashes with Squeeze and then checking TrailingZeros of each
		if i := checkStateTrits(&l, &h, sufficientTrailing, target); i < bct.MaxBatchSize {
			// if i := checkStateTrits2(&l, &h, target); i < bct.MaxBatchSize {
			return nonce + uint64(i), nil
		}
	}
	return 0, ErrDone
}

func checkStateTrits(l, h *[consts.HashTrinarySize]uint, sufficientTrailing int, target *big.Int) int {
	var v uint

	requiredTrailing := sufficientTrailing - 1
	for i := consts.HashTrinarySize - requiredTrailing; i < consts.HashTrinarySize; i++ {
		v |= l[i] ^ h[i] // 0 if trit is zero, 1 otherwise
	}
	// no hash has at least sufficientTrailing number of trailing zeroes
	if v == ^uint(0) {
		// there cannot be a valid hash
		return bct.MaxBatchSize
	}

	// find hashes with at least sufficientTrailing+1 number of trailing zeroes
	w := v | (l[consts.HashTrinarySize-sufficientTrailing] ^ h[consts.HashTrinarySize-sufficientTrailing])
	// if there is one this is sufficient, and we can return the index
	if w != ^uint(0) {
		// return the index of the first zero bit, this corresponds to the hash with sufficient trailing zeros
		return bits.TrailingZeros(^w)
	}

	// otherwise, we have to convert all hashes with at least sufficientTrailing number of trailing zeroes and check
	lo, hi := bits.TrailingZeros(^v), bits.Len(^v)
	for i := lo; i < hi; i++ {
		if (v>>i)&1 == 0 && stateToInt(l, h, uint(i)).Cmp(target) <= 0 {
			return i
		}
	}
	return bct.MaxBatchSize
}

func stateToInt(l, h *[consts.HashTrinarySize]uint, idx uint) *big.Int {
	idx &= bits.UintSize - 1 // hint to the compiler that shifts don't need guard code

	var trits [consts.HashTrinarySize]int8
	for j := consts.HashTrinarySize - 1; j >= 0; j-- {
		trits[j] = int8((h[j]>>idx)&1) - int8((l[j]>>idx)&1)
	}
	return toInt(trits[:])
}
