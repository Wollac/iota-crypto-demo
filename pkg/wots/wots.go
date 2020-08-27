package wots

import (
	"hash"
	"io"
	"math/big"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/kerl/sha3"
	"github.com/iotaledger/iota.go/signing"
	"github.com/iotaledger/iota.go/trinary"
	"github.com/wollac/iota-crypto-demo/pkg/encoding/t5b1"
)

const (
	// NonceSize is the size, in bytes, of the nonce used to randomize the message hash.
	NonceSize = 16
)

var (
	// a cryptographic hash function to compute the message hash
	newDigestHash = sha3.NewLegacyKeccak384
	// a one-way function for the W-OTS chain
	newChainHash = kerl.NewKerl
)

// Sign signs the message using privateKey. It returns the signature together with a random nonce.
// The security of the signature depends on the entropy of rand.
func Sign(rand io.Reader, privateKey trinary.Trits, message []byte) (nonce [NonceSize]byte, sig []byte, err error) {
	if len(privateKey)%consts.KeyFragmentLength != 0 {
		err = consts.ErrInvalidTritsLength
		return
	}
	securityLevel := len(privateKey) / consts.KeyFragmentLength
	if securityLevel < 1 || securityLevel > consts.MaxSecurityLevel {
		err = consts.ErrInvalidSecurityLevel
		return
	}

	// create a random nonce and compute the hash
	_, err = io.ReadFull(rand, nonce[:])
	if err != nil {
		return
	}
	msgHash := messageHash(newDigestHash, nonce[:], message)

	h := newChainHash()
	sigTrits := make(trinary.Trits, 0, securityLevel*consts.KeyFragmentLength)
	for i := 0; i < securityLevel; i++ {
		// generate the signed signature fragment by supplying the correct
		// parts of the normalized bundle hash and private key
		frag, err := signing.SignatureFragment(
			msgHash[i*consts.KeySegmentsPerFragment:(i+1)*consts.KeySegmentsPerFragment],
			privateKey[i*consts.KeyFragmentLength:(i+1)*consts.KeyFragmentLength],
			h,
		)
		if err != nil {
			return [NonceSize]byte{}, nil, err
		}
		sigTrits = append(sigTrits, frag...)
	}
	sig = make([]byte, t5b1.EncodedLen(len(sigTrits)))
	t5b1.Encode(sig, sigTrits)
	return
}

// Verify verifies the signature in nonce,sig of message by publicKey using address.
func Verify(address trinary.Trits, message []byte, nonce [NonceSize]byte, sig []byte) bool {
	sigTrits := make(trinary.Trits, t5b1.DecodedLen(len(sig)))
	if _, err := t5b1.Decode(sigTrits, sig); err != nil {
		return false
	}
	// signature must have the correct zero padding
	if len(sigTrits)%consts.KeyFragmentLength > 4 ||
		trinary.TrailingZeros(sigTrits) < len(sigTrits)%consts.KeyFragmentLength {
		return false
	}

	numFragments := len(sigTrits) / consts.KeyFragmentLength
	maxFragment := consts.MaxSecurityLevel
	if numFragments < maxFragment {
		maxFragment = numFragments
	}

	// compute the message hash with the given nonce
	msgHash := messageHash(newDigestHash, nonce[:], message)

	h := newChainHash()
	digests := make(trinary.Trits, 0, len(sigTrits)/consts.KeyFragmentLength*consts.HashTrinarySize)
	for i := 0; i < len(sigTrits)/consts.KeyFragmentLength; i++ {
		// for longer signatures (multisig) cycle through the hash fragments to compute the digest
		frag := i % (consts.HashTrytesSize / consts.KeySegmentsPerFragment)
		digest, err := signing.Digest(
			msgHash[frag*consts.KeySegmentsPerFragment:(frag+1)*consts.KeySegmentsPerFragment],
			sigTrits[i*consts.KeyFragmentLength:(i+1)*consts.KeyFragmentLength],
			h,
		)
		if err != nil {
			return false
		}
		digests = append(digests, digest...)
	}

	addressTrits, err := signing.Address(digests, h)
	if err != nil {
		return false
	}
	equal, _ := trinary.TritsEqual(address, addressTrits)
	return equal
}

// messageHash computes the message hash. The provided f must not be vulnerable to length extension attacks.
func messageHash(f func() hash.Hash, key, message []byte) []int8 {
	h := f()
	// for modern hash functions like Keccak h(k||m) is a secure MAC
	h.Write(key)
	h.Write(message)
	d := h.Sum(nil)

	hash := base27(d, consts.HashTrytesSize)
	for i := 0; i < consts.HashTrytesSize/consts.KeySegmentsPerFragment; i++ {
		normalizeBase27(hash[i*consts.KeySegmentsPerFragment : (i+1)*consts.KeySegmentsPerFragment])
	}
	return hash
}

var big27 = big.NewInt(27)

// base27 converts m to its base-27 representation of length l.
// It returns a slice where is element is in [-13, 13].
func base27(m []byte, l int) []int8 {
	result := make([]int8, l)

	b := new(big.Int).SetBytes(m)
	rem := new(big.Int)
	for i := 0; i < l; i++ {
		b.QuoRem(b, big27, rem)
		result[i] = int8(rem.Uint64()) - consts.MaxTryteValue
	}
	return result
}

func normalizeBase27(fragmentTryteValues []int8) {
	sum := 0
	for i := range fragmentTryteValues {
		sum += int(fragmentTryteValues[i])
	}

	for i := range fragmentTryteValues {
		v := int(fragmentTryteValues[i]) - sum
		if v < consts.MinTryteValue {
			sum = consts.MinTryteValue - v
			fragmentTryteValues[i] = consts.MinTryteValue
		} else if v > consts.MaxTryteValue {
			sum = consts.MaxTryteValue - v
			fragmentTryteValues[i] = consts.MaxTryteValue
		} else {
			fragmentTryteValues[i] = int8(v)
			break
		}
	}
}
