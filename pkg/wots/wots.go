package wots

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash"
	"io"
	"math/big"

	"github.com/iotaledger/iota.go/kerl/sha3"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 48
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = fragmentLength * 48
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = PrivateKeySize
)

const fragmentLength = 27

type PrivateKey []byte

type PublicKey []byte

// Public returns the PublicKey corresponding to priv.
func (k PrivateKey) Public() PublicKey {
	// a one-way function for the W-OTS chain
	f := sha3.NewLegacyKeccak384()

	key := k
	digest := make([]byte, 0, len(k))
	fragment := make([]byte, 48)
	for len(key) >= 48 {
		copy(fragment, key)
		for j := 0; j < 27-1; j++ {
			f.Reset()
			f.Write(fragment)
			f.Sum(fragment[:0])
		}
		key = key[48:]
		digest = append(digest, fragment...)
	}

	// the public key is the hash of the digest
	publicKey := make([]byte, PublicKeySize)
	f.Reset()
	f.Write(digest)
	f.Sum(publicKey[:0])
	return publicKey
}

func GenerateKey(r io.Reader) (PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}

	privateKey := make([]byte, PrivateKeySize)
	if _, err := io.ReadFull(r, privateKey); err != nil {
		return nil, err
	}

	return privateKey, nil
}

// Sign signs the message digest fragment with the corresponding fragIdx and returns the nonce an the signature.
func Sign(key PrivateKey, fragIdx int, message []byte) (uint64, []byte) {
	// a cryptographic hash function for the message digest
	g := sha3.NewLegacyKeccak384()

	var (
		base27 []int
		nonce  uint64
	)
	// find a nonce so that the message digest is normalized
	for {
		base27 = messageDigest(g, message, nonce)[fragIdx*fragmentLength : (fragIdx+1)*fragmentLength]
		if isNormalize(base27) {
			break
		}
		nonce++
	}

	// a one-way function for the W-OTS chain
	f := sha3.NewLegacyKeccak384()

	signature := make([]byte, 0, SignatureSize)
	fragment := make([]byte, 48)
	for i := 0; len(key) >= 48; i++ {
		copy(fragment, key)
		for j := 0; j < base27[i]; j++ {
			f.Reset()
			f.Write(fragment)
			f.Sum(fragment[:0])
		}
		key = key[48:]
		signature = append(signature, fragment...)
	}

	return nonce, signature
}

func Verify(publicKey PublicKey, fragIdx int, message []byte, nonce uint64, sig []byte) bool {
	// a cryptographic hash function for the message digest
	g := sha3.NewLegacyKeccak384()
	base27 := messageDigest(g, message, nonce)[fragIdx*fragmentLength : (fragIdx+1)*fragmentLength]
	if !isNormalize(base27) {
		return false
	}

	// a one-way function for the W-OTS chain
	f := sha3.NewLegacyKeccak384()

	digest := make([]byte, 0, SignatureSize)
	fragment := make([]byte, 48)
	for i := 0; len(sig) >= 48; i++ {
		copy(fragment, sig)
		for j := base27[i]; j < 27-1; j++ {
			f.Reset()
			f.Write(fragment)
			f.Sum(fragment[:0])
		}

		sig = sig[48:]
		digest = append(digest, fragment...)
	}

	// the public key is the hash of the digest
	checkPub := make([]byte, PublicKeySize)
	f.Reset()
	f.Write(digest)
	f.Sum(checkPub[:0])
	return bytes.Equal(publicKey, checkPub)
}

var big27 = big.NewInt(27)

// computes the base27 message digest
func messageDigest(h hash.Hash, message []byte, nonce uint64) []int {
	defer h.Reset()

	// hash the message together with the nonce
	h.Write(message)
	var nonceBytes [8]byte
	binary.LittleEndian.PutUint64(nonceBytes[:], nonce)
	h.Write(nonceBytes[:])

	digest := h.Sum(nil)

	// convert to base27
	bigInt := new(big.Int).SetBytes(digest[:])
	base27 := make([]int, fragmentLength)

	rem := new(big.Int)
	for i := range base27 {
		bigInt.QuoRem(bigInt, big27, rem)
		base27[i] = int(rem.Uint64())
	}
	return base27
}

func isNormalize(base27 []int) bool {
	var sum int
	for _, x := range base27 {
		sum += x
	}
	if sum == 13*len(base27) {
		return true
	}
	return false
}
