package ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"
	"io"
	"strconv"

	"github.com/wollac/iota-crypto-demo/pkg/ed25519/internal/edwards25519"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = ed25519.PublicKeySize
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = ed25519.PrivateKeySize
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = ed25519.SignatureSize
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = ed25519.SeedSize
)

type (
	// PublicKey is the type of Ed25519 public keys.
	PublicKey = ed25519.PublicKey
	// PrivateKey is the type of Ed25519 private keys. It implements crypto.Signer.
	PrivateKey = ed25519.PrivateKey
)

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return ed25519.GenerateKey(rand)
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
	// Outline the function body so that the returned key can be stack-allocated.
	privateKey := make([]byte, PrivateKeySize)
	newKeyFromSeed(privateKey, seed)
	return privateKey
}

func newKeyFromSeed(privateKey, seed []byte) {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	digest := sha512.Sum512(seed)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest[:])
	edwards25519.GeScalarMultBase(&A, &hBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	copy(privateKey, seed)
	copy(privateKey[32:], publicKeyBytes[:])
}

// Sign signs the message with privateKey and returns a signature. It will
// panic if len(privateKey) is not PrivateKeySize.
func Sign(privateKey PrivateKey, message []byte) []byte {
	// Outline the function body so that the returned key can be stack-allocated.
	signature := make([]byte, SignatureSize)
	sign(signature, privateKey, message)
	return signature
}

func sign(signature, privateKey, message []byte) {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()
	h.Write(privateKey[:32])

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	h.Reset()
	h.Write(digest1[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	h.Write(privateKey[32:])
	h.Write(message)
	h.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])
}

// Verify reports whether sig is a valid signature of message by publicKey.
// It uses precisely-specified validation criteria (ZIP 215) suitable for use in consensus-critical contexts.
func Verify(publicKey PublicKey, message, sig []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	// ZIP215: this works because FromBytes does not check that encodings are canonical.
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var r [32]byte
	copy(r[:], sig[:32])
	var checkR edwards25519.ExtendedGroupElement
	// ZIP215: this works because FromBytes does not check that encodings are canonical.
	if !checkR.FromBytes(&r) {
		return false
	}

	var s [32]byte
	copy(s[:], sig[32:])

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	// ZIP215: This is also required by ZIP215.
	if !edwards25519.ScMinimal(&s) {
		return false
	}

	var Rproj edwards25519.ProjectiveGroupElement
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeDoubleScalarMultVartime(&Rproj, &hReduced, &A, &s)
	Rproj.ToExtended(&R)

	// ZIP215: We want to check [8](R - R') == 0
	return edwards25519.CofactorEqual(&R, &checkR)
}
