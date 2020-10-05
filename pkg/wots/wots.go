package wots

import (
	"fmt"
	"hash"
	"io"
	"math/bits"

	"github.com/iotaledger/iota.go/consts"
	"github.com/iotaledger/iota.go/encoding/t5b1"
	"github.com/iotaledger/iota.go/kerl"
	"github.com/iotaledger/iota.go/kerl/sha3"
	"github.com/iotaledger/iota.go/signing"
	"github.com/iotaledger/iota.go/signing/key"
	"github.com/iotaledger/iota.go/trinary"
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

// PrivateKey is the type of W-OTS private keys.
type PrivateKey trinary.Trits

// GenerateKey creates a private key.
func GenerateKey(entropy trinary.Trits, securityLevel consts.SecurityLevel) (PrivateKey, error) {
	return key.Shake(entropy, securityLevel)
}

// Address returns the public key address corresponding to privateKey.
func (privateKey PrivateKey) Address() trinary.Trits {
	// copy the private key before passing it to Digests
	digests, err := signing.Digests(append(trinary.Trits{}, privateKey...))
	if err != nil {
		panic(err)
	}
	address, _ := signing.Address(digests)
	return address
}

// String returns a human readable version of the PrivateKey.
func (privateKey PrivateKey) String() string {
	return trinary.MustTritsToTrytes(privateKey)
}

// Signature is the type of W-OTS signatures.
type Signature trinary.Trits

// String returns a human readable version of the Signature.
func (sig Signature) String() string {
	return trinary.MustTritsToTrytes(sig)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (sig Signature) MarshalBinary() (data []byte, err error) {
	tmp := make(trinary.Trits, 0, len(sig)/consts.HashTrinarySize*(consts.HashTrinarySize-1))
	for frag := sig; len(frag) >= consts.HashTrinarySize; frag = frag[consts.HashTrinarySize:] {
		tmp = append(tmp, frag[:consts.HashTrinarySize-1]...)
	}
	b := make([]byte, t5b1.EncodedLen(len(tmp)))
	t5b1.Encode(b, tmp)
	return b, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (sig *Signature) UnmarshalBinary(data []byte) error {
	buf := make(trinary.Trits, t5b1.DecodedLen(len(data)))
	if _, err := t5b1.Decode(buf, data); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	// signature must have the correct zero padding
	if rem := len(buf) % (consts.HashTrinarySize - 1); rem >= 5 || trailingZeros(buf) < rem {
		return fmt.Errorf("invalid signature padding: %v", buf[len(buf)-rem:])
	}

	*sig = make(trinary.Trits, 0, len(buf)/(consts.HashTrinarySize-1)*consts.HashTrinarySize)
	for len(buf) >= consts.HashTrinarySize-1 {
		*sig = append(*sig, buf[:consts.HashTrinarySize-1]...)
		*sig = append(*sig, 0) // insert missing 0 trit
		buf = buf[consts.HashTrinarySize-1:]
	}
	return nil
}

// counts the number of trailing zeros up to 5
func trailingZeros(t trinary.Trits) int {
	n := len(t) - 1
	v := 1<<5 | (uint(t[n-4])&1)<<4 | (uint(t[n-3])&1)<<3 | (uint(t[n-2])&1)<<2 | (uint(t[n-1])&1)<<1 | (uint(t[n]) & 1)
	return bits.TrailingZeros(v)
}

// Sign signs the message using privateKey. It returns the signature together with a random nonce.
// The security of the signature depends on the entropy of rand.
func Sign(rand io.Reader, privateKey PrivateKey, message []byte) (nonce [NonceSize]byte, sig Signature, err error) {
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
	sig = make(trinary.Trits, 0, securityLevel*consts.KeyFragmentLength)
	for i := 0; i < securityLevel; i++ {
		// generate the signed signature fragment by supplying the correct
		// parts of the normalized bundle hash and private key
		frag, err := signing.SignatureFragment(
			msgHash[i*consts.KeySegmentsPerFragment:(i+1)*consts.KeySegmentsPerFragment],
			privateKey[i*consts.KeyFragmentLength:(i+1)*consts.KeyFragmentLength],
			h,
		)
		if err != nil {
			return [16]byte{}, nil, err
		}
		sig = append(sig, frag...)
	}
	return
}

// Verify verifies the signature in nonce,sig of message by publicKey using address.
func Verify(address trinary.Trits, message []byte, nonce [NonceSize]byte, sig Signature) bool {
	if len(sig)%consts.KeyFragmentLength != 0 {
		return false
	}
	numFragments := len(sig) / consts.KeyFragmentLength
	maxFragment := consts.MaxSecurityLevel
	if numFragments < maxFragment {
		maxFragment = numFragments
	}

	// compute the message hash with the given nonce
	msgHash := messageHash(newDigestHash, nonce[:], message)

	h := newChainHash()
	digests := make(trinary.Trits, 0, len(sig)/consts.KeyFragmentLength*consts.HashTrinarySize)
	for i := 0; i < len(sig)/consts.KeyFragmentLength; i++ {
		// for longer signatures (multisig) cycle through the hash fragments to compute the digest
		frag := i % (consts.HashTrytesSize / consts.KeySegmentsPerFragment)
		digest, err := signing.Digest(
			msgHash[frag*consts.KeySegmentsPerFragment:(frag+1)*consts.KeySegmentsPerFragment],
			sig[i*consts.KeyFragmentLength:(i+1)*consts.KeyFragmentLength],
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
	d, _ := kerl.KerlBytesToTrytes(h.Sum(nil))
	// return the normalized hash
	return signing.NormalizedBundleHash(d)
}
